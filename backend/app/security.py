from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import Case, CaseMember, User

_bearer = HTTPBearer(auto_error=False)
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def create_token(user: User) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user.id), "usr": user.username, "role": user.role, "iat": now, "exp": now + timedelta(minutes=s.token_minutes)}
    return jwt.encode(payload, s.secret_key, algorithm="HS256")


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        data = jwt.decode(creds.credentials, get_settings().secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.get(User, int(data["sub"]))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
    return user


def require_writer(user: User = Depends(current_user)) -> User:
    if user.role == "viewer":
        raise HTTPException(403, "Viewers have read-only access")
    return user


def get_case_for(db: Session, user: User, case_id: str, write: bool = False) -> Case:
    """Case-level access control. Owners/admins always; others via CaseMember."""
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if user.role == "admin" or case.owner_id == user.id:
        if write and user.role == "viewer":
            raise HTTPException(403, "Read-only access")
        return case
    m = db.query(CaseMember).filter_by(case_id=case_id, user_id=user.id).first()
    if not m:
        raise HTTPException(404, "Case not found")  # don't leak existence
    if write and (m.access != "write" or user.role == "viewer"):
        raise HTTPException(403, "Read-only access to this case")
    return case


class RateLimiter:
    """Small in-memory sliding-window limiter (per key). Good enough for a single instance."""

    def __init__(self, limit: int, window_s: int):
        self.limit, self.window = limit, window_s
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            raise HTTPException(429, "Too many requests, slow down")
        q.append(now)

    def reset(self) -> None:
        self.hits.clear()


login_limiter = RateLimiter(10, 60)
lookup_limiter = RateLimiter(30, 60)
ai_limiter = RateLimiter(12, 60)


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"
