from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..forensics.hashing import UploadTooLarge
from ..models import Case, CaseMember, Event, Evidence, Finding, Indicator, IntelResult, Note, User
from ..schemas import (AskIn, CaseIn, CaseOut, CasePatch, EventOut, EvidenceOut, FindingOut, IndicatorOut, IntelOut, NoteIn, NoteOut, ShareIn)
from ..security import ai_limiter, current_user, get_case_for, require_writer
from ..services import ai_analyst, analysis, case_io, graph, reports

router = APIRouter(prefix="/api", tags=["cases"])


# ---- cases ---------------------------------------------------------------------------------
@router.get("/cases", response_model=list[CaseOut])
def list_cases(user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Case)
    if user.role != "admin":
        shared = [m.case_id for m in db.query(CaseMember).filter_by(user_id=user.id)]
        q = q.filter(or_(Case.owner_id == user.id, Case.id.in_(shared)))
    return q.order_by(Case.updated_at.desc()).all()


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(body: CaseIn, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    c = Case(**body.model_dump(), owner_id=user.id)
    db.add(c)
    db.commit()
    audit.log(db, user.username, "case.create", c.id, c.id, c.title)
    return c


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return get_case_for(db, user, case_id)


@router.patch("/cases/{case_id}", response_model=CaseOut)
def patch_case(case_id: str, body: CasePatch, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    c = get_case_for(db, user, case_id, write=True)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(c, k, v)
    db.commit()
    audit.log(db, user.username, "case.update", c.id, c.id, ", ".join(f"{k}={v}" for k, v in changes.items() if k != "description"))
    return c


@router.delete("/cases/{case_id}", status_code=204)
def delete_case(case_id: str, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    c = get_case_for(db, user, case_id, write=True)
    if user.role != "admin" and c.owner_id != user.id:
        raise HTTPException(403, "Only the case owner can delete a case")
    for ev in db.query(Evidence).filter_by(case_id=c.id):
        if ev.status != "purged":
            analysis.purge_evidence(db, ev, user.username, "case deleted")
    for model in (Event, Indicator, IntelResult, Finding, Note, CaseMember):
        db.query(model).filter_by(case_id=c.id).delete()
    db.query(Evidence).filter_by(case_id=c.id).delete()
    db.delete(c)
    db.commit()
    audit.log(db, user.username, "case.delete", c.id, c.id, "case and derived data removed; audit trail retained")
    return Response(status_code=204)


@router.post("/cases/{case_id}/share", status_code=204)
def share_case(case_id: str, body: ShareIn, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    c = get_case_for(db, user, case_id, write=True)
    if user.role != "admin" and c.owner_id != user.id:
        raise HTTPException(403, "Only the owner can share a case")
    target = db.query(User).filter_by(username=body.username).first()
    if not target:
        raise HTTPException(404, "User not found")
    m = db.query(CaseMember).filter_by(case_id=c.id, user_id=target.id).first() or CaseMember(case_id=c.id, user_id=target.id)
    m.access = body.access
    db.add(m)
    db.commit()
    audit.log(db, user.username, "case.share", c.id, target.username, body.access)
    return Response(status_code=204)


# ---- evidence ------------------------------------------------------------------------------
@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_case_for(db, user, case_id)
    return db.query(Evidence).filter_by(case_id=case_id).order_by(Evidence.created_at.desc()).all()


@router.post("/cases/{case_id}/evidence", response_model=EvidenceOut, status_code=201)
def upload_evidence(case_id: str, file: UploadFile = File(...), user: User = Depends(require_writer), db: Session = Depends(get_db)):
    case = get_case_for(db, user, case_id, write=True)
    try:
        return analysis.ingest(db, case, file.filename or "upload", file.file, user.username)
    except UploadTooLarge as e:
        raise HTTPException(413, str(e))


@router.post("/evidence/{evidence_id}/verify", response_model=EvidenceOut)
def verify(evidence_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    get_case_for(db, user, ev.case_id)
    return analysis.verify_evidence(db, ev, user.username)


@router.get("/evidence/{evidence_id}/download")
def download(evidence_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    get_case_for(db, user, ev.case_id)
    p = analysis.file_path(ev)
    if ev.status == "purged" or not p.exists():
        raise HTTPException(410, "Evidence file is no longer available")
    audit.log(db, user.username, "evidence.download", ev.case_id, ev.id)
    return FileResponse(p, filename=ev.filename, media_type="application/octet-stream")


@router.delete("/evidence/{evidence_id}", status_code=204)
def purge(evidence_id: str, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    get_case_for(db, user, ev.case_id, write=True)
    analysis.purge_evidence(db, ev, user.username)
    return Response(status_code=204)


# ---- derived data --------------------------------------------------------------------------
@router.post("/cases/{case_id}/analyze")
def reanalyze(case_id: str, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    return analysis.analyze_case(db, get_case_for(db, user, case_id, write=True), user.username)


@router.get("/cases/{case_id}/events")
def events(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db), severity: str | None = None, action: str | None = None,
           ip: str | None = None, q: str | None = Query(None, max_length=200), evidence_id: str | None = None,
           start: datetime | None = None, end: datetime | None = None, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)):
    get_case_for(db, user, case_id)
    qs = db.query(Event).filter_by(case_id=case_id)
    if severity:
        qs = qs.filter(Event.severity.in_(severity.split(",")))
    if action:
        qs = qs.filter(Event.action.in_(action.split(",")))
    if ip:
        qs = qs.filter(Event.ip == ip)
    if evidence_id:
        qs = qs.filter(Event.evidence_id == evidence_id)
    if q:
        qs = qs.filter(Event.message.ilike(f"%{q.replace('%', '')}%"))
    if start:
        qs = qs.filter(Event.ts >= start)
    if end:
        qs = qs.filter(Event.ts <= end)
    total = qs.count()
    rows = qs.order_by(Event.ts.asc(), Event.id.asc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [EventOut.model_validate(r).model_dump(mode="json") for r in rows]}


@router.get("/cases/{case_id}/timeline")
def timeline(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_case_for(db, user, case_id)
    rows = db.query(Event.ts, Event.severity).filter(Event.case_id == case_id, Event.ts.isnot(None)).all()
    if not rows:
        return {"bucket": "none", "buckets": [], "undated": db.query(Event).filter_by(case_id=case_id).count()}
    tss = [r[0] if r[0].tzinfo else r[0].replace(tzinfo=timezone.utc) for r in rows]
    span = max(tss) - min(tss)
    step, label = (timedelta(minutes=1), "minute") if span <= timedelta(hours=3) else (timedelta(hours=1), "hour") if span <= timedelta(days=3) else (timedelta(days=1), "day")
    origin = min(tss).replace(second=0, microsecond=0)
    if label != "minute":
        origin = origin.replace(minute=0)
    if label == "day":
        origin = origin.replace(hour=0)
    b: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for (ts, sev), t in zip(rows, tss):
        b[int((t - origin) / step)][sev] += 1
    last = max(b)
    out = []
    for i in range(min(last + 1, 500)):
        c = b.get(i, {})
        out.append({"t": (origin + i * step).isoformat(), "total": sum(c.values()), **{k: c.get(k, 0) for k in ("info", "low", "medium", "high", "critical")}})
    return {"bucket": label, "buckets": out, "undated": db.query(Event).filter(Event.case_id == case_id, Event.ts.is_(None)).count()}


@router.get("/cases/{case_id}/indicators")
def indicators(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_case_for(db, user, case_id)
    intel: dict[tuple[str, str], list] = defaultdict(list)
    for r in db.query(IntelResult).filter_by(case_id=case_id):
        intel[(r.indicator_type, r.indicator_value)].append(IntelOut.model_validate(r).model_dump(mode="json"))
    merged: dict[tuple[str, str], dict] = {}
    for i in db.query(Indicator).filter_by(case_id=case_id).order_by(Indicator.count.desc()).limit(4000):
        key = (i.type, i.value)
        m = merged.get(key)
        if m is None:
            d = IndicatorOut.model_validate(i).model_dump(mode="json")
            d["ref"], d["evidence_ids"], d["intel"] = f"IOC-{i.id}", [i.evidence_id], intel.get(key, [])
            merged[key] = d
        else:  # same indicator seen in another evidence file: merge, don't list twice
            m["count"] += i.count
            m["evidence_ids"].append(i.evidence_id)
            fs, ls = i.first_seen.isoformat() if i.first_seen else None, i.last_seen.isoformat() if i.last_seen else None
            if fs and (not m["first_seen"] or fs < m["first_seen"]):
                m["first_seen"] = fs
            if ls and (not m["last_seen"] or ls > m["last_seen"]):
                m["last_seen"] = ls
    return sorted(merged.values(), key=lambda d: -d["count"])[:2000]


@router.get("/cases/{case_id}/findings", response_model=list[FindingOut])
def findings(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_case_for(db, user, case_id)
    rows = db.query(Finding).filter_by(case_id=case_id).all()
    rows.sort(key=lambda f: (-ai_analyst.SEV.get(f.severity, 0), -f.confidence))
    return rows


@router.get("/cases/{case_id}/graph")
def case_graph(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return graph.build(db, get_case_for(db, user, case_id))


# ---- notes ---------------------------------------------------------------------------------
@router.get("/cases/{case_id}/notes", response_model=list[NoteOut])
def list_notes(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    get_case_for(db, user, case_id)
    return db.query(Note).filter_by(case_id=case_id).order_by(Note.id.desc()).all()


@router.post("/cases/{case_id}/notes", response_model=NoteOut, status_code=201)
def add_note(case_id: str, body: NoteIn, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    get_case_for(db, user, case_id, write=True)
    n = Note(case_id=case_id, author=user.username, **body.model_dump())
    db.add(n)
    db.commit()
    audit.log(db, user.username, f"case.{body.kind}", case_id, str(n.id), body.text[:200])
    return n


# ---- AI, reports, export -------------------------------------------------------------------
@router.post("/cases/{case_id}/ask")
def ask(case_id: str, body: AskIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ai_limiter.check(f"ai:{user.id}")
    case = get_case_for(db, user, case_id)
    out = ai_analyst.analyse(db, case, body.question.strip())
    audit.log(db, user.username, "ai.ask", case_id, out["mode"], body.question[:200])
    return out


@router.get("/cases/{case_id}/report")
def report(case_id: str, format: str = Query("json", pattern="^(json|pdf|md)$"), user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = get_case_for(db, user, case_id)
    r = reports.build_report(db, case, user.username)
    if format == "json":
        return Response(content=__import__("json").dumps(r, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{case.id}-report.json"'})
    if format == "md":
        return Response(content=reports.to_markdown(r), media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="{case.id}-report.md"'})
    return Response(content=reports.to_pdf(r), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{case.id}-report.pdf"'})


@router.get("/cases/{case_id}/export")
def export(case_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = get_case_for(db, user, case_id)
    return Response(content=case_io.export_case(db, case, user.username), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{case.id}.azmx.zip"'})


@router.post("/cases/import", response_model=CaseOut, status_code=201)
def import_(file: UploadFile = File(...), user: User = Depends(require_writer), db: Session = Depends(get_db)):
    data = file.file.read(get_settings().max_upload_bytes * 4 + 1)
    if len(data) > get_settings().max_upload_bytes * 4:
        raise HTTPException(413, "Archive too large")
    try:
        return case_io.import_case(db, data, user)
    except case_io.ImportError_ as e:
        raise HTTPException(400, str(e))
    except UploadTooLarge as e:
        raise HTTPException(413, str(e))
