"""Evidence-to-Intelligence graph. Nodes are classed so a co-occurrence is never shown as proof of an attack.

  observed  -> directly present in uploaded evidence (files, extracted indicators)
  derived   -> computed by AZMUTHIX (detection findings, heuristic scores, the case itself)
  external  -> reputation data from a feed or third-party API (carries source + retrieval time)
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import Case, Event, Evidence, Finding, Indicator, IntelResult

MAX_INDICATORS = 120
VERDICT_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "benign": 0}


def build(db: Session, case: Case) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(id_: str, label: str, kind: str, cls: str, **extra):
        nodes[id_] = {"id": id_, "label": label, "kind": kind, "cls": cls, **extra}

    def edge(a: str, b: str, rel: str, cls: str):
        if a in nodes and b in nodes:
            edges.append({"source": a, "target": b, "relation": rel, "cls": cls})

    node(case.id, case.title, "case", "derived", severity=case.severity)
    for ev in db.query(Evidence).filter_by(case_id=case.id):
        node(ev.id, ev.filename, "evidence", "observed", status=ev.status, sha256=ev.sha256)
        edge(case.id, ev.id, "contains", "observed")

    intel: dict[tuple[str, str], list[IntelResult]] = {}
    for r in db.query(IntelResult).filter_by(case_id=case.id):
        intel.setdefault((r.indicator_type, r.indicator_value), []).append(r)

    inds = db.query(Indicator).filter_by(case_id=case.id).all()
    def weight(i: Indicator) -> tuple:
        worst = max((VERDICT_RANK.get(r.verdict, 0) for r in intel.get((i.type, i.value), [])), default=0)
        return (worst, 0 if i.is_internal else 1, i.count)
    inds.sort(key=weight, reverse=True)
    kept = inds[:MAX_INDICATORS]
    ind_key: dict[tuple[str, str], str] = {}
    for i in kept:
        key = (i.type, i.value)
        nid = f"IOC-{i.id}"
        if key in ind_key:  # same value from another evidence file
            edge(i.evidence_id, ind_key[key], "contains", "observed")
            continue
        ind_key[key] = nid
        rs = intel.get(key, [])
        worst = max(rs, key=lambda r: VERDICT_RANK.get(r.verdict, 0), default=None)
        node(nid, i.value if len(i.value) < 40 else i.value[:37] + "…", i.type, "observed", count=i.count, internal=bool(i.is_internal),
             verdict=worst.verdict if worst else "unknown", value=i.value)
        edge(i.evidence_id, nid, "contains", "observed")
        for r in rs:
            iid = f"INT-{r.id}"
            ext = bool(r.external) or r.source.endswith("feed")
            node(iid, f"{r.source}: {r.verdict}", "intel", "external" if ext else "derived", verdict=r.verdict, score=r.score,
                 source=r.source, summary=r.summary, retrieved_at=r.retrieved_at.isoformat())
            edge(nid, iid, "enriched by", "external" if ext else "derived")

    for f in db.query(Finding).filter_by(case_id=case.id):
        fid = f"FND-{f.id}"
        node(fid, f.title, "finding", "derived", severity=f.severity, confidence=f.confidence, mitre=f.mitre)
        edge(case.id, fid, "has finding", "derived")
        for v in f.indicators:
            for typ in ("ipv4", "domain"):
                if (typ, v) in ind_key:
                    edge(fid, ind_key[(typ, v)], "involves", "derived")

    # Co-occurrence (observed, NOT causal): indicators that share events.
    by_event: dict[int, list[str]] = {}
    for i in kept:
        for eid in (i.event_ids or [])[:50]:
            by_event.setdefault(eid, []).append(ind_key[(i.type, i.value)])
    pairs: dict[tuple[str, str], int] = {}
    for ids in by_event.values():
        ids = sorted(set(ids))
        for a in range(len(ids)):
            for b in range(a + 1, len(ids)):
                pairs[(ids[a], ids[b])] = pairs.get((ids[a], ids[b]), 0) + 1
    for (a, b), n in sorted(pairs.items(), key=lambda kv: -kv[1])[:150]:
        edges.append({"source": a, "target": b, "relation": f"co-occur ×{n}", "cls": "observed", "weak": True})

    return {"nodes": list(nodes.values()), "edges": edges,
            "legend": {"observed": "Present in uploaded evidence", "derived": "Computed by AZMUTHIX (findings, heuristics)", "external": "Reputation data from a feed/API"},
            "caution": "Two indicators appearing together is a lead, not proof of a connected attack."}
