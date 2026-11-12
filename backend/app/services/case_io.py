"""Case export/import as a self-verifying ZIP (manifest + evidence files)."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..forensics import hashing
from ..models import Case, Event, Evidence, Note, User
from . import analysis

MAX_ENTRIES = 1000
MAX_UNCOMPRESSED = 300 * 1024 * 1024


def export_case(db: Session, case: Case, actor: str) -> bytes:
    evs = db.query(Evidence).filter_by(case_id=case.id).all()
    manifest = {
        "format": "azmuthix-case/1", "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "exported_by": actor,
        "case": {"title": case.title, "description": case.description, "severity": case.severity, "status": case.status, "original_id": case.id},
        "evidence": [], "notes": [{"author": n.author, "kind": n.kind, "text": n.text, "refs": n.refs, "at": n.created_at.isoformat()}
                     for n in db.query(Note).filter_by(case_id=case.id)],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for e in evs:
            p = analysis.file_path(e)
            entry = {"id": e.id, "filename": e.filename, "sha256": e.sha256, "md5": e.md5, "size_bytes": e.size_bytes, "included": False,
                     "uploaded_by": e.uploaded_by, "status_at_export": e.status}
            if e.status != "purged" and p.exists():
                z.write(p, f"evidence/{e.id}.bin")
                entry["included"] = True
            manifest["evidence"].append(entry)
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
    audit.log(db, actor, "case.export", case.id, "", f"evidence={len(evs)}")
    return buf.getvalue()


class ImportError_(Exception):
    pass


def import_case(db: Session, data: bytes, user: User) -> Case:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ImportError_("Not a valid ZIP archive")
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
        raise ImportError_("Archive too large")
    for i in infos:
        if i.filename.startswith(("/", "..")) or ".." in i.filename.split("/"):
            raise ImportError_("Unsafe path in archive")
    try:
        m = json.loads(z.read("manifest.json"))
    except (KeyError, json.JSONDecodeError):
        raise ImportError_("manifest.json missing or invalid")
    if m.get("format") != "azmuthix-case/1":
        raise ImportError_("Unsupported case format")
    c = m["case"]
    case = Case(title=str(c["title"])[:200] + " (imported)", description=str(c.get("description", ""))[:5000],
                severity=c.get("severity") if c.get("severity") in {"low", "medium", "high", "critical"} else "medium", owner_id=user.id)
    db.add(case)
    db.commit()
    report = []
    for e in m.get("evidence", []):
        if not e.get("included"):
            report.append({"id": e.get("id"), "result": "not included (purged or unavailable)"})
            continue
        raw = z.read(f"evidence/{e['id']}.bin")
        actual = hashlib.sha256(raw).hexdigest()
        ev = analysis.ingest(db, case, e["filename"], io.BytesIO(raw), user.username)
        res = "verified" if actual == e["sha256"] else "HASH MISMATCH vs manifest"
        if actual != e["sha256"]:
            ev.status = "modified"
            db.commit()
        report.append({"id": ev.id, "original_id": e["id"], "result": res})
    for n in m.get("notes", []):
        db.add(Note(case_id=case.id, author=str(n.get("author", "import"))[:64], kind="decision" if n.get("kind") == "decision" else "note",
                    text=str(n.get("text", ""))[:5000], refs=[]))
    db.commit()
    audit.log(db, user.username, "case.import", case.id, "", json.dumps(report)[:1800])
    return case
