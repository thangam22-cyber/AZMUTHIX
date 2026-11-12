from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..models import User
from ..schemas import Credentials, LoginIn, TokenOut
from ..security import client_key, create_token, current_user, hash_password, login_limiter, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])
_DUMMY = hash_password("not-a-real-password")  # constant-time-ish response for unknown users


@router.get("/status")
def status(db: Session = Depends(get_db)):
    has_users = db.query(User).count() > 0
    return {"has_users": has_users, "registration_open": (not has_users) or get_settings().allow_registration}


@router.post("/register", response_model=TokenOut, status_code=201)
def register(body: Credentials, request: Request, db: Session = Depends(get_db)):
    login_limiter.check("reg:" + client_key(request))
    first = db.query(User).count() == 0
    if not first and not get_settings().allow_registration:
        raise HTTPException(403, "Registration is disabled. Ask an administrator for an account.")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already taken")
    u = User(username=body.username, password_hash=hash_password(body.password), role="admin" if first else "analyst")
    db.add(u)
    db.commit()
    audit.log(db, u.username, "auth.register", detail=f"role={u.role}")
    return TokenOut(access_token=create_token(u), username=u.username, role=u.role)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    login_limiter.check("login:" + client_key(request))
    u = db.query(User).filter(User.username == body.username).first()
    ok = verify_password(body.password, u.password_hash if u else _DUMMY)
    if not (u and ok):
        audit.log(db, body.username[:64], "auth.login_failed", detail=f"ip={client_key(request)}")
        raise HTTPException(401, "Incorrect username or password")
    audit.log(db, u.username, "auth.login", detail=f"ip={client_key(request)}")
    return TokenOut(access_token=create_token(u), username=u.username, role=u.role)


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}
