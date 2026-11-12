# syntax=docker/dockerfile:1
# ---- 1) build the React desktop UI ----
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2) python API + static UI in one small image ----
FROM python:3.12-slim AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    AZMUTHIX_ENV=production AZMUTHIX_FRONTEND_DIST=/app/frontend/dist AZMUTHIX_EVIDENCE_DIR=/data/evidence
RUN useradd --system --create-home --uid 10001 azmuthix && mkdir -p /data/evidence && chown -R azmuthix /data
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt
COPY backend/app ./app
COPY --from=web /web/dist /app/frontend/dist
USER azmuthix
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'), timeout=3)"
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
