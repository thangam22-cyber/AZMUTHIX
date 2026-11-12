import hashlib
import io
import json
import zipfile

from .conftest import SAMPLES, register, upload


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_auth_required_and_first_user_admin(client):
    assert client.get("/api/cases").status_code == 401
    h = register(client)
    assert client.get("/api/auth/me", headers=h).json()["role"] == "admin"
    h2 = register(client, "bob")
    assert client.get("/api/auth/me", headers=h2).json()["role"] == "analyst"


def test_weak_password_rejected_and_bad_login(client):
    assert client.post("/api/auth/register", json={"username": "carol", "password": "short"}).status_code == 422
    register(client)
    assert client.post("/api/auth/login", json={"username": "alice", "password": "wrong-password-x"}).status_code == 401


def test_case_level_access_control(client, case_id, auth):
    h2 = register(client, "bob")
    assert client.get(f"/api/cases/{case_id}", headers=h2).status_code == 404  # existence not leaked
    assert client.get("/api/cases", headers=h2).json() == []
    assert client.post(f"/api/cases/{case_id}/share", json={"username": "bob", "access": "read"}, headers=auth).status_code == 204
    assert client.get(f"/api/cases/{case_id}", headers=h2).status_code == 200
    assert client.post(f"/api/cases/{case_id}/notes", json={"text": "x"}, headers=h2).status_code == 403  # read-only


def test_file_hash_is_correct_and_integrity_detects_tamper(client, auth, case_id, tmp_path):
    r = upload(client, auth, case_id, "harmless-test.txt")
    assert r.status_code == 201
    ev = r.json()
    assert ev["sha256"] == hashlib.sha256((SAMPLES / "harmless-test.txt").read_bytes()).hexdigest()
    assert client.post(f"/api/evidence/{ev['id']}/verify", headers=auth).json()["status"] == "intact"
    stored = next((tmp_path / "ev" / case_id).glob("*.bin"))
    stored.chmod(0o640)
    stored.write_bytes(stored.read_bytes() + b"tamper")
    assert client.post(f"/api/evidence/{ev['id']}/verify", headers=auth).json()["status"] == "modified"


def test_upload_size_limit_and_filename_sanitised(client, auth, case_id):
    big = io.BytesIO(b"A" * (1024 * 1024 + 10))
    assert client.post(f"/api/cases/{case_id}/evidence", files={"file": ("big.log", big)}, headers=auth).status_code == 413
    r = client.post(f"/api/cases/{case_id}/evidence", files={"file": ("../../etc/pass wd<>.txt", io.BytesIO(b"hello"))}, headers=auth)
    assert r.status_code == 201 and "/" not in r.json()["filename"] and "<" not in r.json()["filename"]


def test_full_investigation_flow(client, auth, case_id):
    for n in ("auth.log", "access.log", "app-events.jsonl"):
        assert upload(client, auth, case_id, n).status_code == 201
    f = client.get(f"/api/cases/{case_id}/findings", headers=auth).json()
    rules = {x["rule"] for x in f}
    assert {"brute_force", "success_after_bruteforce", "suspicious_command", "web_attack", "scanner_ua"} <= rules
    assert f[0]["severity"] == "critical"
    inds = client.get(f"/api/cases/{case_id}/indicators", headers=auth).json()
    vals = {i["value"]: i for i in inds}
    assert "203.0.113.45" in vals and vals["203.0.113.45"]["intel"][0]["verdict"] == "malicious"
    assert vals["10.0.0.50"]["is_internal"] == 1
    assert "update-secure-login.example" in vals
    ev = client.get(f"/api/cases/{case_id}/events", params={"q": "Failed password", "limit": 5}, headers=auth).json()
    assert ev["total"] >= 18 and len(ev["items"]) == 5
    tl = client.get(f"/api/cases/{case_id}/timeline", headers=auth).json()
    assert tl["buckets"] and sum(b["total"] for b in tl["buckets"]) > 50


def test_graph_classes_and_caution(client, auth, case_id):
    upload(client, auth, case_id, "auth.log")
    g = client.get(f"/api/cases/{case_id}/graph", headers=auth).json()
    assert {n["cls"] for n in g["nodes"]} >= {"observed", "derived", "external"}
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    assert "not proof" in g["caution"]


def test_ai_citations_are_real_and_injection_is_flagged(client, auth, case_id):
    upload(client, auth, case_id, "auth.log")
    a = client.post(f"/api/cases/{case_id}/ask", json={"question": "what happened with brute force?"}, headers=auth).json()
    assert a["mode"] == "local" and a["key_findings"] and a["next_steps"]
    from app.services import ai_analyst
    from app.db import session_factory
    from app.models import Case
    with session_factory()() as db:
        ctx = ai_analyst.build_context(db, db.get(Case, case_id))
    ok = ai_analyst.valid_refs(ctx)
    assert set(a["refs"]) <= ok
    assert any("prompt-injection" in u for u in a["uncertainties"])


def test_audit_chain_valid_then_detects_tampering(client, auth, case_id):
    upload(client, auth, case_id, "harmless-test.txt")
    assert client.get("/api/audit/verify", headers=auth).json()["valid"] is True
    from app.db import session_factory
    from app.models import AuditLog
    with session_factory()() as db:
        row = db.query(AuditLog).filter_by(action="evidence.upload").first()
        row.detail = "forged"
        db.commit()
    assert client.get("/api/audit/verify", headers=auth).json()["valid"] is False


def test_terminal_is_allowlisted_not_a_shell(client, auth, case_id):
    t = lambda c: client.post("/api/terminal/exec", json={"command": c, "case_id": case_id}, headers=auth).json()
    assert "help" in t("help")["output"]
    for evil in ("ls -la", "cat /etc/passwd", "help; id", "$(whoami)", "rm -rf /"):
        r = t(evil)
        assert "uid=" not in r["output"] and "root:" not in r["output"]
    assert t("rm -rf /")["ok"] is False
    assert t("hash abc")["output"] == hashlib.sha256(b"abc").hexdigest()


def test_intel_validation_and_no_private_ip_leak(client, auth):
    assert client.post("/api/intel/lookup", json={"value": "not an indicator!!"}, headers=auth).status_code == 422
    r = client.post("/api/intel/lookup", json={"value": "10.1.2.3"}, headers=auth).json()
    assert r["results"][0]["verdict"] == "benign" and not any(x["external"] for x in r["results"])
    r = client.post("/api/intel/lookup", json={"value": "203[.]0[.]113[.]45"}, headers=auth).json()
    assert r["value"] == "203.0.113.45" and r["results"][0]["verdict"] == "malicious"


def test_reports_json_pdf_md(client, auth, case_id):
    upload(client, auth, case_id, "auth.log")
    j = client.get(f"/api/cases/{case_id}/report", headers=auth).json()
    body = {k: v for k, v in j.items() if k not in {"report_version", "generated_by", "generated_at", "generated_for", "content_sha256"}}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    assert hashlib.sha256(canon.encode()).hexdigest() == j["content_sha256"]
    assert j["limitations"] and j["evidence"][0]["integrity"] == "intact"
    pdf = client.get(f"/api/cases/{case_id}/report", params={"format": "pdf"}, headers=auth)
    assert pdf.content[:5] == b"%PDF-"
    assert "AZMUTHIX Investigation Report" in client.get(f"/api/cases/{case_id}/report", params={"format": "md"}, headers=auth).text


def test_export_import_roundtrip_and_zip_safety(client, auth, case_id):
    upload(client, auth, case_id, "auth.log")
    z = client.get(f"/api/cases/{case_id}/export", headers=auth).content
    r = client.post("/api/cases/import", files={"file": ("c.zip", io.BytesIO(z))}, headers=auth)
    assert r.status_code == 201
    new = r.json()["id"]
    assert new != case_id
    assert len(client.get(f"/api/cases/{new}/findings", headers=auth).json()) >= 3
    assert client.get(f"/api/cases/{new}/evidence", headers=auth).json()[0]["status"] == "intact"
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../evil", "x")
        zf.writestr("manifest.json", "{}")
    assert client.post("/api/cases/import", files={"file": ("e.zip", io.BytesIO(evil.getvalue()))}, headers=auth).status_code == 400


def test_purge_keeps_record_removes_file(client, auth, case_id, tmp_path):
    ev = upload(client, auth, case_id, "harmless-test.txt").json()
    assert client.delete(f"/api/evidence/{ev['id']}", headers=auth).status_code == 204
    assert not list((tmp_path / "ev" / case_id).glob("*.bin"))
    assert client.get(f"/api/cases/{case_id}/evidence", headers=auth).json()[0]["status"] == "purged"
    assert client.get(f"/api/evidence/{ev['id']}/download", headers=auth).status_code == 410


def test_stats_dashboard(client, auth, case_id):
    upload(client, auth, case_id, "auth.log")
    s = client.get("/api/system/stats", headers=auth).json()
    assert s["cases"]["total"] == 1 and s["findings_by_severity"]["critical"] >= 1 and s["threat_indicators"]


def test_timestamps_are_utc_aware(client, auth, case_id):
    upload(client, auth, case_id, "auth.log")
    ev = client.get(f"/api/cases/{case_id}/evidence", headers=auth).json()[0]
    assert ev["created_at"].endswith(("Z", "+00:00"))
    items = client.get(f"/api/cases/{case_id}/events", params={"limit": 3}, headers=auth).json()["items"]
    assert all(i["ts"].endswith(("Z", "+00:00")) for i in items if i["ts"])
