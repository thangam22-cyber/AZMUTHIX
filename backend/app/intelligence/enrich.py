"""Threat-intelligence enrichment.

Design rules (see docs/SECURITY.md):
  * Indicators are validated before any lookup.
  * External requests only go to a fixed allowlist of hostnames (no user-controlled URLs -> no SSRF).
  * Private/reserved IPs are never sent to third parties.
  * Every result records its source, whether it is external, and the retrieval time.
  * Results from third parties are untrusted data.
"""
from __future__ import annotations

import base64
import json
import math
from collections import Counter
from pathlib import Path

import httpx

from ..config import get_settings
from ..forensics.indicators import INTERNAL_SCOPES, classify_value, ip_scope, refang

FEED = json.loads((Path(__file__).with_name("local_feed.json")).read_text())
ALLOWED_HOSTS = {"api.abuseipdb.com", "www.virustotal.com"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "monster"}
TIMEOUT = httpx.Timeout(6.0, connect=4.0)


class LookupError_(Exception):
    pass


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def validate(value: str) -> tuple[str, str]:
    v = refang(value.strip())
    if len(v) > 512:
        raise LookupError_("Indicator too long")
    t = classify_value(v)
    if not t:
        raise LookupError_("Unrecognised indicator. Supported: IPv4, domain, URL, email, MD5/SHA1/SHA256, CVE")
    if t in {"domain", "email", "cve"}:
        v = v.lower() if t != "cve" else v.upper()
    elif t in {"md5", "sha1", "sha256"}:
        v = v.lower()
    return t, v


def _local(t: str, v: str) -> dict | None:
    hit = FEED.get(t, {}).get(v)
    if not hit:
        return None
    return {
        "source": "azmuthix-demo-feed", "external": False, "verdict": hit["verdict"], "score": hit["score"],
        "summary": hit["summary"], "details": {"tags": hit["tags"], "feed": FEED["_meta"]["name"]},
    }


def _heuristic(t: str, v: str) -> dict:
    notes: list[str] = []
    score = 0
    if t == "ipv4":
        scope = ip_scope(v)
        if scope in INTERNAL_SCOPES:
            return {"source": "azmuthix-heuristics", "external": False, "verdict": "benign", "score": 0,
                    "summary": f"{v} is a {scope} address; not routable on the public internet.", "details": {"scope": scope}}
        notes.append("Documentation-range address (RFC 5737) with no local data." if scope == "documentation" else "Public address with no local reputation data.")
    elif t in {"domain", "email", "url"}:
        host = v
        if t == "email":
            host = v.split("@", 1)[1]
        elif t == "url":
            host = v.split("://", 1)[1].split("/")[0].split(":")[0]
        labels = host.split(".")
        tld = labels[-1]
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        if tld in SUSPICIOUS_TLDS:
            score += 20
            notes.append(f"TLD .{tld} is frequently abused.")
        if host.startswith("xn--") or ".xn--" in host:
            score += 20
            notes.append("Punycode label (possible homograph).")
        if len(sld) >= 10 and _entropy(sld) > 3.5:
            score += 25
            notes.append(f"High-entropy label '{sld}' (possible generated domain).")
        if len(labels) >= 5:
            score += 10
            notes.append("Unusually deep subdomain nesting.")
    elif t in {"md5", "sha1", "sha256"}:
        notes.append("Hash not in local feed; configure VirusTotal for file reputation.")
    verdict = "suspicious" if score >= 40 else "unknown"
    return {"source": "azmuthix-heuristics", "external": False, "verdict": verdict, "score": min(score, 60),
            "summary": " ".join(notes) or "No local intelligence available.", "details": {"signals": notes}}


def _abuseipdb(ip: str, key: str) -> dict:
    r = httpx.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                  headers={"Key": key, "Accept": "application/json"}, timeout=TIMEOUT, follow_redirects=False)
    r.raise_for_status()
    d = r.json()["data"]
    s = int(d.get("abuseConfidenceScore", 0))
    return {"source": "abuseipdb", "external": True, "verdict": "malicious" if s >= 75 else "suspicious" if s >= 25 else "benign", "score": s,
            "summary": f"AbuseIPDB: {s}% confidence of abuse, {d.get('totalReports', 0)} reports ({d.get('countryCode') or '??'}, {d.get('isp') or 'unknown ISP'}).",
            "details": {k: d.get(k) for k in ("countryCode", "isp", "usageType", "totalReports", "lastReportedAt", "domain")}}


def _virustotal(t: str, v: str, key: str) -> dict:
    if t == "ipv4":
        path = f"ip_addresses/{v}"
    elif t == "domain":
        path = f"domains/{v}"
    elif t in {"md5", "sha1", "sha256"}:
        path = f"files/{v}"
    elif t == "url":
        path = "urls/" + base64.urlsafe_b64encode(v.encode()).decode().strip("=")
    else:
        raise LookupError_("VirusTotal does not support this type")
    r = httpx.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key}, timeout=TIMEOUT, follow_redirects=False)
    if r.status_code == 404:
        return {"source": "virustotal", "external": True, "verdict": "unknown", "score": 0, "summary": "VirusTotal has no record of this indicator.", "details": {}}
    r.raise_for_status()
    stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
    mal, sus, total = stats.get("malicious", 0), stats.get("suspicious", 0), sum(stats.values()) or 1
    verdict = "malicious" if mal >= 5 else "suspicious" if mal + sus >= 1 else "benign"
    return {"source": "virustotal", "external": True, "verdict": verdict, "score": int(100 * (mal + sus) / total),
            "summary": f"VirusTotal: {mal} malicious / {sus} suspicious of {total} engines.", "details": {"stats": stats}}


def lookup(value: str) -> tuple[str, str, list[dict]]:
    """Return (type, normalised value, results[]). Never raises for upstream failures; records them as notes."""
    t, v = validate(value)
    results: list[dict] = []
    local = _local(t, v)
    results.append(local or _heuristic(t, v))
    s = get_settings()
    public_ok = not (t == "ipv4" and ip_scope(v) != "public")  # never send private/documentation IPs to third parties
    if public_ok:
        for name, key, fn in (("abuseipdb", s.abuseipdb_key, lambda: _abuseipdb(v, s.abuseipdb_key) if t == "ipv4" else None),
                              ("virustotal", s.virustotal_key, lambda: _virustotal(t, v, s.virustotal_key))):
            if not key:
                continue
            try:
                res = fn()
                if res:
                    results.append(res)
            except (httpx.HTTPError, LookupError_, KeyError, ValueError) as e:
                results.append({"source": name, "external": True, "verdict": "unknown", "score": 0,
                                "summary": f"{name} lookup failed ({type(e).__name__}); result not used.", "details": {"error": True}})
    return t, v, results


def lookup_local(t: str, v: str) -> tuple[str, str, list[dict]]:
    """Offline-only enrichment used during ingest (no network)."""
    t2, v2 = validate(v) if classify_value(v) == t else (t, v)
    local = _local(t2, v2)
    return t2, v2, [local] if local else [_heuristic(t2, v2)]
