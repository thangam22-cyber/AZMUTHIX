# Windows 11 / PowerShell dev launcher. Run from the repo root:  .\scripts\dev.ps1
$ErrorActionPreference = "Stop"
if (-not (Test-Path .venv)) { python -m venv .venv }
.\.venv\Scripts\python.exe -m pip install -q -r backend\requirements-dev.txt
if (-not (Test-Path frontend\node_modules)) { Push-Location frontend; npm install; Pop-Location }
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$PWD\backend'; ..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"
Push-Location frontend; npm run dev; Pop-Location
