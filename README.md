# AZMUTHIX

A cyber-forensics and threat-intelligence investigation workstation that runs in the browser as a dark desktop: left app launcher, status bar, taskbar, dashboard widgets and draggable windows.

Upload evidence → **SHA-256 chain of custody** → parse logs into a timeline → extract indicators → run explainable detections → enrich with threat intelligence → explore the **evidence-to-intelligence graph** → ask an **evidence-grounded AI analyst** → export a **PDF/JSON/Markdown report**.

| Window | What it does |
|---|---|
| Cases | Create, share (read/write), close, export/import investigations |
| Forensics | Drag-and-drop evidence, chunked SHA-256, integrity re-verification, event timeline and filters |
| Intelligence | Indicator lookup (IP/domain/URL/hash/CVE), per-source verdicts with retrieval time |
| Evidence graph | Observed / derived / external nodes, details panel, co-occurrence labelled as "not proof" |
| AI analyst | Cited summaries, uncertainty and next steps; offline rules or Claude via server-side key |
| Reports | PDF/JSON/Markdown with content hash and limitations; notes and decisions |
| Terminal | Allowlisted commands (`help`, `hash`, `verify all`, `ioc`, `ask`…), no shell |
| Audit trail | Tamper-evident hash-chained log with one-click verification |

## Quick start
```bash
# Windows 11 (PowerShell)         # macOS / Linux
.\scripts\dev.ps1                 sh scripts/dev.sh
```
Open http://localhost:5173, create the first account (becomes admin) and click **Load sample investigation**. API docs: http://127.0.0.1:8000/docs.

Manual: `cd backend && pip install -r requirements-dev.txt && uvicorn app.main:app --reload` and `cd frontend && npm install && npm run dev`.

## Tests
`make test` (or `cd backend && python -m pytest`, `cd frontend && npm test`). Backend tests cover hashing, tamper detection, ACLs, detections, intel validation, terminal allowlist, audit chain, reports, ZIP safety.

## Deploy
`docker compose up --build`, a Render blueprint, or Vercel + API host. See [docs/DEPLOY.md](docs/DEPLOY.md). Security mapping: [docs/SECURITY.md](docs/SECURITY.md). Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Optional integrations (server env only)
`ANTHROPIC_API_KEY` (AI analyst), `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`. Without them everything still works offline.

## Responsible use
Use synthetic or explicitly authorised evidence only. `sample-data/` is synthetic and uses RFC 5737 documentation addresses. Detections are leads with stated confidence, not verdicts.
