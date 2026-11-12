import os
import tempfile
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[2] / "sample-data"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AZMUTHIX_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("AZMUTHIX_EVIDENCE_DIR", str(tmp_path / "ev"))
    monkeypatch.setenv("AZMUTHIX_SECRET_KEY", "test-secret-key-test-secret-key-0123456789")
    monkeypatch.setenv("AZMUTHIX_MAX_UPLOAD_MB", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    monkeypatch.setenv("AZMUTHIX_FRONTEND_DIST", str(tmp_path / "nodist"))
    from app import config, db, security

    config.reset_settings()
    db._engine = None
    db._SessionLocal = None
    for lim in (security.login_limiter, security.lookup_limiter, security.ai_limiter):
        lim.reset()
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def register(client, name="alice", pw="correct-horse-battery"):
    r = client.post("/api/auth/register", json={"username": name, "password": pw})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def auth(client):
    return register(client)


@pytest.fixture()
def case_id(client, auth):
    r = client.post("/api/cases", json={"title": "Test intrusion", "severity": "high"}, headers=auth)
    assert r.status_code == 201
    return r.json()["id"]


def upload(client, auth, case_id, name):
    p = SAMPLES / name
    with p.open("rb") as f:
        return client.post(f"/api/cases/{case_id}/evidence", files={"file": (name, f)}, headers=auth)
