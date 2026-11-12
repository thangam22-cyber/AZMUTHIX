# AZMUTHIX architecture

```
 React + TypeScript + Tailwind desktop UI (Vite)
   boot / lock · launcher · status bar · taskbar · widgets · draggable windows
   apps: Cases · Forensics · Intelligence · Evidence graph · AI analyst · Reports · Terminal · Audit
        │  REST + JWT (Bearer)
 FastAPI  /api/*   validation (pydantic) · security headers · rate limits · case-level ACL
   ├─ forensics/    hashing (chunked SHA-256) · log parsers · IOC extraction · detection rules
   ├─ intelligence/ validators · offline feed · heuristics · optional AbuseIPDB / VirusTotal
   ├─ services/     analysis pipeline · graph builder · AI analyst · report/export engines
   └─ audit.py      hash-chained, tamper-evident audit log
 SQLite (dev) → PostgreSQL (prod) via SQLAlchemy      evidence files on a private volume
```

## Investigation flow
1. **Ingest**: the upload is streamed to an isolated, randomly named, read-only file while SHA-256 and MD5 are computed in the same pass. The original is never modified. The size limit is enforced mid-stream.
2. **Parse**: auto-detects JSON, JSONL, CSV, syslog/auth.log, and nginx/Apache combined logs into normalised events (time, host, user, IP, action, severity).
3. **Extract**: IPv4, domains, URLs, e-mails, MD5/SHA1/SHA256 and CVEs are extracted (defang-aware). Internal ranges are tagged; RFC 5737 documentation ranges are treated as non-internal so demo data behaves like real data but is never sent to third parties.
4. **Detect**: explainable rules (brute force, success-after-brute-force, suspicious commands, web attacks, scanner user-agents, enumeration, off-hours admin) each produce a finding with severity, **confidence**, MITRE ATT&CK technique and the event IDs that triggered it.
5. **Enrich**: offline feed + heuristics at ingest; AbuseIPDB / VirusTotal on explicit lookup when keys exist. Every result stores source, external flag and retrieval time.
6. **Explain**: the AI analyst answers only from stored records and cites them.
7. **Report**: JSON (with content hash), PDF and Markdown; case export/import as a self-verifying ZIP.

## Evidence-to-Intelligence graph
Nodes are classed **observed** (in the evidence), **derived** (computed here) or **external** (feed/API). Co-occurrence links are drawn faintly and labelled as such so two indicators sharing a log line are never presented as a proven attack.

## What is different from a typical "log viewer"
- **Chain of custody built in**: each upload, parse, verify, lookup, decision and export is written to a SHA-256 hash-chained audit log; `Verify chain` (UI, API and terminal) proves nothing was edited afterwards.
- **Re-verification**: stored evidence can be re-hashed at any time; `modified` / `missing` states propagate to the dashboard and reports.
- **Citation guard for AI**: model output is parsed as JSON, every reference is validated against real record IDs, and uncited claims are removed. Log text is treated as hostile (prompt-injection lines are detected and flagged).
- **Honest uncertainty**: findings carry confidence; reports state limitations; analyst answers list what is uncertain.
- **Runs offline**: the deterministic analyst and bundled feed mean the product works without any API key.
- **Retention**: optional automatic purge of evidence files (hashes and records are kept).

## Extending
- New log format: add a branch in `forensics/logparse.py`.
- New detection: add a rule in `forensics/detections.py` returning `RawFinding`.
- New intel source: add a function in `intelligence/enrich.py` against a fixed host allowlist.
- Schema migrations: tables are created on start (`create_all`). Before changing columns in a live deployment, introduce Alembic.
