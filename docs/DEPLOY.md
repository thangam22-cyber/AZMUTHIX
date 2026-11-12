# Deployment

## Option A: one container, anywhere (recommended)
API and UI ship in one image, which avoids CORS entirely.
```bash
cp .env.example .env        # set AZMUTHIX_SECRET_KEY and POSTGRES_PASSWORD
docker compose up --build   # http://localhost:8000
```
Create the first account in the browser (it becomes the administrator), then set `AZMUTHIX_ALLOW_REGISTRATION=false`.

## Option B: Render (Blueprint)
Push to GitHub → Render → New → Blueprint → select the repo (`render.yaml`). It creates a Docker web service, a managed PostgreSQL database and a persistent disk mounted at `/data` for evidence. Add optional API keys in the dashboard. Free tiers sleep and have no persistent disk, so check current plan terms before relying on them for evidence.

## Option C: split hosting (Vercel UI + Python API host)
1. Deploy the container (or just `backend/`) to any Python host with PostgreSQL.
2. Set `AZMUTHIX_CORS_ORIGINS=https://your-ui.vercel.app` on the API.
3. In Vercel, project root `frontend/`, env `VITE_API_URL=https://your-api.example.com`.

## Production checklist
- [ ] `AZMUTHIX_ENV=production`, strong `AZMUTHIX_SECRET_KEY`, PostgreSQL `DATABASE_URL`
- [ ] Evidence volume is persistent, private and backed up (database backups too)
- [ ] HTTPS terminated by the platform/proxy; registration disabled after setup
- [ ] `GET /api/health` wired to your uptime monitor; logs shipped (JSON-ish lines with request IDs)
- [ ] `AZMUTHIX_RETENTION_DAYS` set to your retention policy
- [ ] Run `Verify chain` periodically (or alert on `/api/audit/verify`)
