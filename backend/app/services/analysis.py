"""Ingest pipeline: store -> hash -> parse -> events -> indicators -> findings (all auditable)."""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..forensics import detections, hashing, indicators, logparse
from ..intelligence import enrich
from ..models import Case, Event, Evidence, Finding, Indicator, IntelResult, utcnow

TEXT_EXT = {".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson", ".syslog", ".out"}
MAGIC = [(b"MZ", "PE executable (Windows)"), (b"\x7fELF", "ELF executable (Linux)"), (b"%PDF", "PDF document"), (b"PK\x03\x04", "ZIP container"),
         (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"\x1f\x8b", "GZIP archive"), (b"SQLite format 3", "SQLite database"),
         (b"\xd0\xcf\x11\xe0", "OLE2 document (legacy Office)"), (b"Rar!", "RAR archive")]


def file_path(ev: Evidence) -> Path:
    return get_settings().evidence_dir / ev.case_id / ev.storage_name


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    return round(-sum(n / len(data) * math.log2(n / len(data)) for n in c.values()), 3)


def _looks_text(head: bytes) -> bool:
    return b"\x00" not in head and sum(1 for b in head if b < 9 or 13 < b < 32) / max(len(head), 1) < 0.02


def ingest(db: Session, case: Case, filename: str, stream: BinaryIO, actor: str) -> Evidence:
    s = get_settings()
    name = hashing.safe_filename(filename)
    stored = hashing.store_stream(stream, s.evidence_dir / case.id, s.max_upload_bytes)
    path: Path = stored["path"]
    head = path.read_bytes()[:65536]
    magic = next((label for sig, label in MAGIC if head.startswith(sig)), "")
    is_text = _looks_text(head[:8192]) if head else False
    ev = Evidence(
        case_id=case.id, filename=name, size_bytes=stored["size"], sha256=stored["sha256"], md5=stored["md5"],
        storage_name=stored["storage_name"], hash_ms=stored["ms"], uploaded_by=actor, last_verified_at=utcnow(),
        kind="log" if is_text else "file",
        meta={"magic": magic or ("text" if is_text else "unknown binary"), "entropy": _entropy(head), "original_name": filename[:255]},
    )
    db.add(ev)
    db.commit()
    audit.log(db, actor, "evidence.upload", case.id, ev.id, f"{name} sha256={ev.sha256} size={ev.size_bytes}")

    if ev.kind == "log":
        text = path.read_text(encoding="utf-8", errors="replace")
        fmt, parsed = logparse.parse_text(text, name)
        ev.parsed_format = fmt
        db.add_all([
            Event(case_id=case.id, evidence_id=ev.id, ts=p.ts, source=p.source[:64], host=p.host[:128], user=p.user[:128], ip=p.ip[:64],
                  action=p.action[:64], severity=p.severity, message=p.message, line_no=p.line_no, fields=p.fields)
            for p in parsed
        ])
        db.commit()
        audit.log(db, actor, "evidence.parse", case.id, ev.id, f"format={fmt} events={len(parsed)}")
    # the file's own hash is an observed indicator
    _upsert_indicator(db, case.id, ev.id, "sha256", ev.sha256, 1, None, None, [], internal=False)
    db.commit()
    analyze_case(db, case, actor)
    return ev


def _upsert_indicator(db: Session, case_id: str, evidence_id: str, typ: str, val: str, count: int, first, last, event_ids: list, internal: bool) -> None:
    row = db.query(Indicator).filter_by(case_id=case_id, evidence_id=evidence_id, type=typ, value=val).first()
    if row:
        row.count, row.first_seen, row.last_seen, row.event_ids = count, first, last, event_ids
    else:
        db.add(Indicator(case_id=case_id, evidence_id=evidence_id, type=typ, value=val[:512], count=count, first_seen=first, last_seen=last,
                         event_ids=event_ids, is_internal=int(internal)))


def analyze_case(db: Session, case: Case, actor: str = "system") -> dict:
    """(Re)derive indicators, local intel and findings from stored events. Idempotent."""
    events = db.query(Event).filter_by(case_id=case.id).all()
    by_ev: dict[str, list[Event]] = {}
    for e in events:
        by_ev.setdefault(e.evidence_id, []).append(e)
    for evid, evs in by_ev.items():
        for (typ, val), h in indicators.extract_from_events(evs).items():
            _upsert_indicator(db, case.id, evid, typ, val, h.count, h.first_seen, h.last_seen, h.event_ids, h.internal)
    db.commit()

    # Local (offline) enrichment: feed + heuristics. External APIs are only called on explicit lookup.
    seen = {(r.indicator_type, r.indicator_value, r.source) for r in db.query(IntelResult).filter_by(case_id=case.id)}
    for ind in db.query(Indicator).filter_by(case_id=case.id, is_internal=0).all():
        if ind.type in {"url", "email"}:
            continue
        try:
            t, v, results = enrich.lookup_local(ind.type, ind.value)
        except enrich.LookupError_:
            continue
        for r in results:
            if (t, v, r["source"]) in seen or r["verdict"] == "unknown":
                continue
            seen.add((t, v, r["source"]))
            db.add(IntelResult(case_id=case.id, indicator_type=t, indicator_value=v, source=r["source"], external=int(r["external"]),
                               verdict=r["verdict"], score=r["score"], summary=r["summary"], details=r["details"]))
    db.commit()

    db.query(Finding).filter_by(case_id=case.id).delete()
    raw = detections.run_rules(events)
    for f in raw:
        db.add(Finding(case_id=case.id, rule=f.rule, title=f.title, severity=f.severity, confidence=f.confidence, description=f.description,
                       mitre=f.mitre, event_ids=f.event_ids, indicators=f.indicators))
    db.commit()
    audit.log(db, actor, "case.analyze", case.id, "", f"events={len(events)} findings={len(raw)}")
    return {"events": len(events), "findings": len(raw)}


def verify_evidence(db: Session, ev: Evidence, actor: str) -> Evidence:
    if ev.status == "purged":
        return ev
    p = file_path(ev)
    if not p.exists():
        ev.status = "missing"
    else:
        digest, size = hashing.sha256_file(p)
        ev.status = "intact" if digest == ev.sha256 and size == ev.size_bytes else "modified"
    ev.last_verified_at = utcnow()
    db.commit()
    audit.log(db, actor, "evidence.verify", ev.case_id, ev.id, f"status={ev.status}")
    return ev


def purge_evidence(db: Session, ev: Evidence, actor: str, reason: str = "manual") -> None:
    p = file_path(ev)
    if p.exists():
        p.chmod(0o640)
        p.unlink()
    ev.status = "purged"
    db.commit()
    audit.log(db, actor, "evidence.purge", ev.case_id, ev.id, f"file deleted, record + sha256 retained ({reason})")


def retention_sweep(db: Session) -> int:
    days = get_settings().retention_days
    if days <= 0:
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    n = 0
    for ev in db.query(Evidence).filter(Evidence.status != "purged").all():
        created = ev.created_at if ev.created_at.tzinfo else ev.created_at.replace(tzinfo=timezone.utc)
        if created.timestamp() < cutoff:
            purge_evidence(db, ev, "system", f"retention>{days}d")
            n += 1
    return n
