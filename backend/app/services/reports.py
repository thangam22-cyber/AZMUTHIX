from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session
from xml.sax.saxutils import escape

from .. import audit
from ..models import AuditLog, Case, Event, Evidence, Finding, Indicator, IntelResult, Note
from . import ai_analyst

LIMITATIONS = [
    "Findings are produced by deterministic pattern rules; a match is a lead, not proof of compromise.",
    "Threat-intelligence verdicts depend on the sources listed; the bundled demo feed is not a production reputation source.",
    "Log time zones were not verified and some events may lack timestamps.",
    "Co-occurrence of indicators in the same events does not establish that they are part of one attack.",
]


def build_report(db: Session, case: Case, actor: str) -> dict:
    evs = db.query(Evidence).filter_by(case_id=case.id).all()
    findings = db.query(Finding).filter_by(case_id=case.id).all()
    findings.sort(key=lambda f: (-ai_analyst.SEV.get(f.severity, 0), -f.confidence))
    intel = db.query(IntelResult).filter_by(case_id=case.id).all()
    inds = db.query(Indicator).filter_by(case_id=case.id).order_by(Indicator.count.desc()).limit(200).all()
    notes = db.query(Note).filter_by(case_id=case.id).order_by(Note.id).all()
    trail = db.query(AuditLog).filter_by(case_id=case.id).order_by(AuditLog.seq).limit(300).all()
    ctx = ai_analyst.build_context(db, case)
    analysis = ai_analyst.local_analyst(ctx)  # deterministic => reproducible report
    n_events = db.query(Event).filter_by(case_id=case.id).count()
    body = {
        "case": {"id": case.id, "title": case.title, "description": case.description, "severity": case.severity, "status": case.status,
                 "created_at": case.created_at.isoformat()},
        "evidence": [{"id": e.id, "filename": e.filename, "size_bytes": e.size_bytes, "sha256": e.sha256, "md5": e.md5, "integrity": e.status,
                      "last_verified_at": e.last_verified_at.isoformat() if e.last_verified_at else None, "uploaded_by": e.uploaded_by,
                      "uploaded_at": e.created_at.isoformat()} for e in evs],
        "event_count": n_events,
        "summary": analysis["summary"],
        "findings": [{"id": f"FND-{f.id}", "title": f.title, "severity": f.severity, "confidence": f.confidence, "mitre": f.mitre,
                      "description": f.description, "event_refs": [f"EVT-{i}" for i in f.event_ids[:10]], "indicators": f.indicators} for f in findings],
        "indicators": [{"id": f"IOC-{i.id}", "type": i.type, "value": i.value, "count": i.count, "internal": bool(i.is_internal)} for i in inds],
        "intelligence": [{"id": f"INT-{r.id}", "indicator": r.indicator_value, "type": r.indicator_type, "source": r.source, "external": bool(r.external),
                          "verdict": r.verdict, "score": r.score, "summary": r.summary, "retrieved_at": r.retrieved_at.isoformat()} for r in intel],
        "analyst_notes": [{"author": n.author, "kind": n.kind, "text": n.text, "at": n.created_at.isoformat()} for n in notes],
        "audit_excerpt": [{"seq": a.seq, "ts": a.ts.isoformat(), "actor": a.actor, "action": a.action, "target": a.target} for a in trail],
        "limitations": LIMITATIONS,
        "recommended_next_steps": analysis["next_steps"],
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    out = {"report_version": "1.0", "generated_by": "AZMUTHIX", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "generated_for": actor, "content_sha256": hashlib.sha256(canon.encode()).hexdigest(), **body}
    audit.log(db, actor, "report.generate", case.id, "", f"sha256={out['content_sha256']}")
    return out


def to_markdown(r: dict) -> str:
    c = r["case"]
    L = [f"# AZMUTHIX Investigation Report: {c['title']}", "", f"- **Case:** {c['id']}  \n- **Severity:** {c['severity']}  \n- **Status:** {c['status']}",
         f"- **Generated:** {r['generated_at']} by {r['generated_for']}", f"- **Content SHA-256:** `{r['content_sha256']}`", "", "## Summary", r["summary"], "", "## Evidence integrity", ""]
    L += ["| ID | File | SHA-256 | Integrity |", "|---|---|---|---|"] + [f"| {e['id']} | {e['filename']} | `{e['sha256']}` | {e['integrity']} |" for e in r["evidence"]]
    L += ["", "## Findings", ""]
    for f in r["findings"] or []:
        L += [f"### {f['id']} · {f['title']} ({f['severity']}, {f['confidence']}% confidence)", f["description"], f"*MITRE:* {f['mitre'] or 'n/a'} · *Events:* {', '.join(f['event_refs'])}", ""]
    L += ["## Threat intelligence", ""] + [f"- **{i['indicator']}** ({i['type']}): {i['verdict']} per *{i['source']}*{' [external]' if i['external'] else ''}, retrieved {i['retrieved_at']}. {i['summary']}" for i in r["intelligence"] if i["verdict"] != "unknown"]
    L += ["", "## Analyst notes and decisions", ""] + [f"- [{n['kind']}] {n['author']} @ {n['at']}: {n['text']}" for n in r["analyst_notes"]]
    L += ["", "## Recommended next steps", ""] + [f"1. {s}" for s in r["recommended_next_steps"]]
    L += ["", "## Limitations", ""] + [f"- {s}" for s in r["limitations"]]
    return "\n".join(L) + "\n"


SEV_COLOR = {"critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706", "low": "#0891b2", "info": "#475569"}


def to_pdf(r: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"AZMUTHIX report {r['case']['id']}", author="AZMUTHIX")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#0e7490"), fontSize=20)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#0f172a"), fontSize=13, spaceBefore=12)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    mono = ParagraphStyle("m", parent=body, fontName="Courier", fontSize=7.5, leading=9)
    P = lambda t, s=body: Paragraph(escape(str(t)), s)  # noqa: E731
    c = r["case"]
    st = [Paragraph("AZMUTHIX", h1), P(f"Investigation report · {c['id']} · {c['title']}"), Spacer(1, 4),
          P(f"Severity: {c['severity']}   Status: {c['status']}   Generated: {r['generated_at']} by {r['generated_for']}"),
          P(f"Content SHA-256: {r['content_sha256']}", mono), Paragraph("Summary", h2), P(r["summary"])]
    st.append(Paragraph("Evidence integrity", h2))
    rows = [["ID", "File", "Size", "Integrity"]] + [[e["id"], e["filename"][:34], f"{e['size_bytes']:,}", e["integrity"]] for e in r["evidence"]]
    t = Table(rows, colWidths=[28 * mm, 70 * mm, 28 * mm, 28 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8"))]))
    st += [t, Spacer(1, 4)] + [P(f"{e['id']}  {e['sha256']}", mono) for e in r["evidence"]]
    st.append(Paragraph("Findings", h2))
    if not r["findings"]:
        st.append(P("No rule-based findings."))
    for f in r["findings"]:
        col = SEV_COLOR.get(f["severity"], "#475569")
        st.append(Paragraph(f'<font color="{col}"><b>{escape(f["severity"].upper())}</b></font> · {escape(f["id"])} · {escape(f["title"])} ({f["confidence"]}% confidence)', body))
        st.append(P(f["description"] + (f"  [MITRE {f['mitre']}]" if f["mitre"] else "")))
        st.append(P("Evidence: " + ", ".join(f["event_refs"]), mono))
        st.append(Spacer(1, 4))
    st.append(Paragraph("Threat intelligence", h2))
    ti = [i for i in r["intelligence"] if i["verdict"] != "unknown"]
    st += [P(f"{i['indicator']} → {i['verdict']} ({i['source']}{', external' if i['external'] else ''}; retrieved {i['retrieved_at'][:19]}). {i['summary']}") for i in ti] or [P("No intelligence matches.")]
    if r["analyst_notes"]:
        st.append(Paragraph("Analyst notes and decisions", h2))
        st += [P(f"[{n['kind']}] {n['author']}: {n['text']}") for n in r["analyst_notes"]]
    st.append(Paragraph("Recommended next steps", h2))
    st += [P(f"{i}. {s}") for i, s in enumerate(r["recommended_next_steps"], 1)]
    st.append(Paragraph("Limitations", h2))
    st += [P("• " + s) for s in r["limitations"]]
    doc.build(st)
    return buf.getvalue()
