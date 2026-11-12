"""Tamper-evident audit trail: every row stores SHA-256(prev_hash | canonical row)."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import AuditLog, utcnow

GENESIS = "0" * 64
_lock = threading.Lock()


def _canon(dt: datetime) -> str:
    """Canonical UTC timestamp string, stable across SQLite (naive) and PostgreSQL (aware)."""
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    return dt.replace(microsecond=0).isoformat()


def _digest(prev: str, ts: str, actor: str, action: str, case_id: str, target: str, detail: str) -> str:
    body = json.dumps([prev, ts, actor, action, case_id, target, detail], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def log(db: Session, actor: str, action: str, case_id: str = "", target: str = "", detail: str = "") -> AuditLog:
    detail = detail[:2000]
    with _lock:
        last = db.query(AuditLog).order_by(AuditLog.seq.desc()).first()
        prev = last.hash if last else GENESIS
        ts = utcnow().replace(microsecond=0)
        h = _digest(prev, _canon(ts), actor, action, case_id, target, detail)
        row = AuditLog(ts=ts, actor=actor, action=action, case_id=case_id, target=target, detail=detail, prev_hash=prev, hash=h)
        db.add(row)
        db.commit()
        return row


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    count = 0
    for row in db.query(AuditLog).order_by(AuditLog.seq.asc()).yield_per(500):
        expected = _digest(prev, _canon(row.ts), row.actor, row.action, row.case_id, row.target, row.detail)
        if row.prev_hash != prev or row.hash != expected:
            return {"valid": False, "entries": count, "broken_at": row.seq}
        prev = row.hash
        count += 1
    return {"valid": True, "entries": count, "head": prev}
