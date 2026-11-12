from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import auth, cases, tools
from .config import get_settings
from .db import init_engine, session_factory
from .services import analysis

log = logging.getLogger("azmuthix")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    s.evidence_dir.mkdir(parents=True, exist_ok=True)
    init_engine()
    with session_factory()() as db:
        n = analysis.retention_sweep(db)
        if n:
            log.info("retention sweep purged %d evidence file(s)", n)
    log.info("AZMUTHIX API started (env=%s, ai=%s)", s.env, "llm" if s.anthropic_api_key else "local")
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title="AZMUTHIX API", version=tools.VERSION, lifespan=lifespan,
                  docs_url="/docs" if s.env != "production" else None, redoc_url=None, openapi_url="/openapi.json" if s.env != "production" else None)
    app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH", "DELETE"],
                       allow_headers=["Content-Type", "Authorization"])

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        rid = uuid.uuid4().hex[:8]
        t0 = time.perf_counter()
        try:
            resp = await call_next(request)
        except Exception:
            log.exception("unhandled error rid=%s %s %s", rid, request.method, request.url.path)
            resp = JSONResponse({"detail": "Internal server error", "request_id": rid}, status_code=500)
        resp.headers.update({
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "X-Request-ID": rid,
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        })
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
            log.info("%s %s -> %s %.0fms rid=%s", request.method, request.url.path, resp.status_code, (time.perf_counter() - t0) * 1000, rid)
        return resp

    @app.exception_handler(RequestValidationError)
    async def validation(_: Request, exc: RequestValidationError):
        return JSONResponse({"detail": "Invalid request", "errors": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()]}, status_code=422)

    app.include_router(auth.router)
    app.include_router(cases.router)
    app.include_router(tools.router)

    dist = s.frontend_dist
    if dist.exists() and (dist / "index.html").exists():
        root = dist.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                raise HTTPException(404, "Not found")
            f = (root / path).resolve()
            if path and f.is_file() and root in f.parents:
                return FileResponse(f, headers={"Cache-Control": "public, max-age=31536000, immutable"} if "assets/" in path else None)
            return FileResponse(root / "index.html", headers={"Cache-Control": "no-cache"})
    return app


app = create_app()
