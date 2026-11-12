from __future__ import annotations

import shlex
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..forensics import hashing
from ..intelligence import enrich
from ..models import AuditLog, Case, Event, Evidence, Finding, IntelResult, User
from ..schemas import HashTextIn, LookupIn, TerminalIn
from ..security import ai_limiter, client_key, current_user, get_case_for, lookup_limiter
from ..services import ai_analyst, analysis
from .cases import list_cases

VERSION = "1.0.0"
router = APIRouter(prefix="/api", tags=["tools"])


@router.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(__import__("sqlalchemy").text("SELECT 1"))
    s = get_settings()
    return {"status": "ok", "service": "AZMUTHIX API", "version": VERSION, "env": s.env,
            "ai_mode": "llm" if s.anthropic_api_key else "local", "intel": {"abuseipdb": bool(s.abuseipdb_key), "virustotal": bool(s.virustotal_key)}}


@router.post("/forensics/hash-text")
def hash_text(body: HashTextIn, user: User = Depends(current_user)):
    return {"algorithm": "SHA-256", "sha256": hashing.sha256_text(body.text), "input_type": "text", "note": "Text fingerprint, not a file hash"}


@router.post("/intel/lookup")
def intel_lookup(body: LookupIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    lookup_limiter.check(f"lk:{user.id}")
    try:
        t, v, results = enrich.lookup(body.value)
    except enrich.LookupError_ as e:
        raise HTTPException(422, str(e))
    if body.case_id:
        get_case_for(db, user, body.case_id, write=True)
        for r in results:
            if r["verdict"] == "unknown" and not r["details"].get("signals"):
                continue
            db.add(IntelResult(case_id=body.case_id, indicator_type=t, indicator_value=v, source=r["source"], external=int(r["external"]),
                               verdict=r["verdict"], score=r["score"], summary=r["summary"], details=r["details"]))
        db.commit()
    audit.log(db, user.username, "intel.lookup", body.case_id or "", v[:100], ",".join(r["source"] for r in results))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"type": t, "value": v, "retrieved_at": now, "results": results}


@router.get("/audit")
def audit_list(case_id: str | None = None, limit: int = 100, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(AuditLog)
    if case_id:
        get_case_for(db, user, case_id)
        q = q.filter_by(case_id=case_id)
    elif user.role != "admin":
        q = q.filter_by(actor=user.username)
    rows = q.order_by(AuditLog.seq.desc()).limit(min(max(limit, 1), 500)).all()
    return [{"seq": r.seq, "ts": r.ts.isoformat(), "actor": r.actor, "action": r.action, "case_id": r.case_id, "target": r.target, "detail": r.detail, "hash": r.hash} for r in rows]


@router.get("/audit/verify")
def audit_verify(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return audit.verify_chain(db)


@router.get("/system/stats")
def stats(user: User = Depends(current_user), db: Session = Depends(get_db)):
    cases = list_cases(user, db)
    ids = [c.id for c in cases]
    sev = dict(db.query(Finding.severity, func.count(Finding.id)).filter(Finding.case_id.in_(ids)).group_by(Finding.severity).all()) if ids else {}
    ev = db.query(Evidence).filter(Evidence.case_id.in_(ids)).order_by(Evidence.created_at.desc()) if ids else None
    bad_intel = (db.query(IntelResult).filter(IntelResult.case_id.in_(ids), IntelResult.verdict.in_(["malicious", "suspicious"]))
                 .order_by(IntelResult.score.desc()).limit(8).all()) if ids else []
    top_findings = db.query(Finding).filter(Finding.case_id.in_(ids)).all() if ids else []
    top_findings.sort(key=lambda f: (-ai_analyst.SEV.get(f.severity, 0), -f.confidence))
    return {
        "cases": {"total": len(cases), "open": sum(c.status != "closed" for c in cases)},
        "evidence": {"total": ev.count() if ev is not None else 0, "not_intact": sum(1 for e in (ev.all() if ev is not None else []) if e.status in {"modified", "missing"})},
        "events": db.query(func.count(Event.id)).filter(Event.case_id.in_(ids)).scalar() if ids else 0,
        "findings_by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "recent_evidence": [{"id": e.id, "case_id": e.case_id, "filename": e.filename, "sha256": e.sha256, "status": e.status, "created_at": e.created_at.isoformat()} for e in (ev.limit(6).all() if ev is not None else [])],
        "threat_indicators": [{"indicator": r.indicator_value, "type": r.indicator_type, "verdict": r.verdict, "score": r.score, "source": r.source, "case_id": r.case_id} for r in bad_intel],
        "top_findings": [{"id": f"FND-{f.id}", "case_id": f.case_id, "title": f.title, "severity": f.severity, "confidence": f.confidence} for f in top_findings[:6]],
    }


# ---- controlled terminal: a fixed command allowlist, no shell, no subprocess -----------------
HELP = """AZMUTHIX terminal. Commands (no shell access, allowlisted only):
  help                      this list
  whoami | status | version
  cases                     list your cases
  evidence                  evidence in the active case
  findings                  findings in the active case
  timeline [n]              last n events (default 15)
  hash <text>               SHA-256 of text
  hashfile <EV-ID>          stored SHA-256 of an evidence item
  verify <EV-ID|all>        re-hash stored evidence and check integrity
  ioc <indicator>           threat-intel lookup (IP, domain, hash, URL, CVE)
  ask <question>            ask the evidence-grounded analyst
  audit [n]                 recent audit entries
  verify-audit              verify the audit hash chain
  clear                     clear the screen"""


@router.post("/terminal/exec")
def terminal(body: TerminalIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        parts = shlex.split(body.command)
    except ValueError:
        return {"output": "parse error: unbalanced quotes", "ok": False}
    if not parts:
        return {"output": "", "ok": True}
    cmd, args = parts[0].lower(), parts[1:]
    case = get_case_for(db, user, body.case_id) if body.case_id else None

    def need_case():
        if not case:
            raise HTTPException(409, "No active case. Select or create a case first.")
        return case

    ok = True
    if cmd == "help":
        out = HELP
    elif cmd == "whoami":
        out = f"{user.username} ({user.role})"
    elif cmd == "version":
        out = f"AZMUTHIX {VERSION}"
    elif cmd == "status":
        h = health(db)
        out = f"api: {h['status']}  env: {h['env']}  ai: {h['ai_mode']}  active case: {case.id if case else 'none'}"
    elif cmd == "cases":
        out = "\n".join(f"{c.id}  [{c.severity:<8}] {c.status:<13} {c.title}" for c in list_cases(user, db)) or "no cases"
    elif cmd == "evidence":
        c = need_case()
        out = "\n".join(f"{e.id}  {e.status:<8} {e.size_bytes:>10}  {e.sha256[:16]}…  {e.filename}" for e in db.query(Evidence).filter_by(case_id=c.id)) or "no evidence"
    elif cmd == "findings":
        c = need_case()
        rows = db.query(Finding).filter_by(case_id=c.id).all()
        rows.sort(key=lambda f: (-ai_analyst.SEV.get(f.severity, 0), -f.confidence))
        out = "\n".join(f"FND-{f.id:<4} {f.severity:<8} {f.confidence:>3}%  {f.title}" for f in rows) or "no findings"
    elif cmd == "timeline":
        c = need_case()
        n = min(int(args[0]), 100) if args and args[0].isdigit() else 15
        rows = db.query(Event).filter_by(case_id=c.id).order_by(Event.ts.desc(), Event.id.desc()).limit(n).all()[::-1]
        out = "\n".join(f"EVT-{e.id:<5} {(e.ts.isoformat(timespec='seconds') if e.ts else 'undated'):<20} {e.severity:<7} {e.message[:90]}" for e in rows) or "no events"
    elif cmd == "hash":
        out = hashing.sha256_text(" ".join(args)) if args else "usage: hash <text>"
    elif cmd == "hashfile":
        ev = db.get(Evidence, args[0].upper()) if args else None
        if ev:
            get_case_for(db, user, ev.case_id)
        out = f"{ev.sha256}  {ev.filename}" if ev else "usage: hashfile <EV-ID> (not found)"
    elif cmd == "verify":
        if args and args[0].lower() == "all":
            c = need_case()
            out = "\n".join(f"{e.id}  {analysis.verify_evidence(db, e, user.username).status}" for e in db.query(Evidence).filter_by(case_id=c.id)) or "no evidence"
        else:
            ev = db.get(Evidence, args[0].upper()) if args else None
            if ev:
                get_case_for(db, user, ev.case_id)
                out = f"{ev.id}  {analysis.verify_evidence(db, ev, user.username).status}"
            else:
                out = "usage: verify <EV-ID|all>"
    elif cmd == "ioc":
        if not args:
            out = "usage: ioc <indicator>"
        else:
            lookup_limiter.check(f"lk:{user.id}")
            try:
                t, v, res = enrich.lookup(args[0])
                out = f"{t} {v}\n" + "\n".join(f"  [{r['verdict']:<10} {r['score']:>3}] {r['source']}{' (external)' if r['external'] else ''}: {r['summary']}" for r in res)
            except enrich.LookupError_ as e:
                out, ok = str(e), False
    elif cmd == "ask":
        c = need_case()
        ai_limiter.check(f"ai:{user.id}")
        a = ai_analyst.analyse(db, c, " ".join(args))
        out = a["summary"] + "\n" + "\n".join(f" • {k['text']}  [{', '.join(k['refs'][:4])}]" for k in a["key_findings"][:4]) + f"\n(mode: {a['mode']})"
    elif cmd == "audit":
        n = min(int(args[0]), 50) if args and args[0].isdigit() else 10
        rows = db.query(AuditLog).order_by(AuditLog.seq.desc()).limit(n).all()[::-1] if user.role == "admin" else db.query(AuditLog).filter_by(actor=user.username).order_by(AuditLog.seq.desc()).limit(n).all()[::-1]
        out = "\n".join(f"#{r.seq:<4} {r.ts.isoformat(timespec='seconds')} {r.actor:<10} {r.action} {r.target}" for r in rows) or "empty"
    elif cmd == "verify-audit":
        r = audit.verify_chain(db)
        out = f"audit chain: {'VALID' if r['valid'] else 'BROKEN at #' + str(r.get('broken_at'))}  entries={r['entries']}"
        ok = r["valid"]
    else:
        out, ok = f"unknown command: {cmd[:40]}. Type 'help'.", False
    audit.log(db, user.username, "terminal.exec", body.case_id or "", cmd[:32])
    return {"output": out, "ok": ok}
