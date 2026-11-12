#!/usr/bin/env sh
# macOS / Linux dev launcher. Run from the repo root:  sh scripts/dev.sh
set -e
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r backend/requirements-dev.txt
[ -d frontend/node_modules ] || (cd frontend && npm install)
(cd backend && ../.venv/bin/python -m uvicorn app.main:app --reload --port 8000) &
API=$!; trap 'kill $API' EXIT
cd frontend && npm run dev
