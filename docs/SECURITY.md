# Security model

AZMUTHIX handles sensitive evidence, so the platform is designed defensively. This table maps each requirement to the code that implements it and the test that checks it.

| Requirement | Implementation | Test |
|---|---|---|
| Evidence safety | Streamed to a random `.bin` name outside the web root, `0440`, size cap enforced during streaming, filename sanitised, never executed | `test_upload_size_limit_and_filename_sanitised`, `test_file_hash_is_correct_and_integrity_detects_tamper` |
| No arbitrary shell | Terminal is a fixed allowlist of Python functions; no `subprocess`, no `shell=True` | `test_terminal_is_allowlisted_not_a_shell` |
| Secrets | API keys only in server env; never sent to the browser; production refuses to start without `AZMUTHIX_SECRET_KEY` | config guard |
| SSRF | Lookups validate indicator type first; third-party calls go only to `api.abuseipdb.com` and `www.virustotal.com`; user input is never used as a URL host; no redirects; private/documentation IPs never leave the server | `test_intel_validation_and_no_private_ip_leak` |
| Authentication | scrypt password hashes, JWT (HS256, expiring), login/register rate limiting, constant-time-style unknown-user path, registration can be disabled | `test_auth_required_and_first_user_admin`, `test_weak_password_rejected_and_bad_login` |
| Case-level access | Owner/admin or explicit share (`read`/`write`); non-members get 404 to avoid leaking existence; viewers are read-only | `test_case_level_access_control` |
| AI safety | Data is delimited and declared untrusted; no tools; output must be JSON; citations validated; injection-like log lines flagged | `test_ai_citations_are_real_and_injection_is_flagged` |
| Privacy | Retention sweep, purge keeps hash + record, case delete purges files | `test_purge_keeps_record_removes_file` |
| Auditability | Hash-chained audit log, verifiable via API/UI/terminal | `test_audit_chain_valid_then_detects_tampering` |
| Import safety | ZIP path traversal rejected, entry count and uncompressed size limits, hashes re-verified | `test_export_import_roundtrip_and_zip_safety` |
| Web hardening | CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `Cache-Control: no-store` on API, docs disabled in production, request IDs, no stack traces to clients | `test_health` |

## Known limits (be honest in interviews)
- Rate limiting is in-memory per instance; put a reverse proxy / WAF in front for multiple replicas.
- Tokens live in `sessionStorage` (cleared on tab close). An httpOnly-cookie session with CSRF protection is a reasonable next step.
- Detections are pattern rules, not ML. They produce leads with stated confidence.
- The bundled intel feed is a **demo**. Configure AbuseIPDB / VirusTotal for real reputation data.
- Use only synthetic or explicitly authorised evidence. Do not upload data you are not permitted to process.
