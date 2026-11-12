"""Indicator-of-compromise extraction with validation, de-fanging support and internal-IP tagging."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
URL = re.compile(r"\bhttps?://[^\s\"'<>\]\)]+", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,})\b", re.I)
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# File-ish suffixes that look like domains but aren't.
NOT_TLDS = {"log", "txt", "conf", "cfg", "py", "js", "json", "sh", "exe", "dll", "so", "php", "html", "css", "png", "jpg", "gif", "ico",
            "pid", "sock", "tmp", "bak", "yml", "yaml", "xml", "csv", "md", "gz", "zip", "tar", "pem", "key", "service", "local", "lan", "internal"}


def refang(text: str) -> str:
    return (text.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@").replace("[at]", "@"))


@dataclass
class Hit:
    type: str
    value: str
    internal: bool = False
    count: int = 0
    event_ids: list[int] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
INTERNAL_SCOPES = {"private", "loopback", "link-local", "reserved"}


def ip_scope(value: str) -> str:
    """public | private | loopback | link-local | reserved | documentation (RFC 5737, used by sample data)."""
    ip = ipaddress.ip_address(value)
    if any(ip in n for n in DOC_NETS):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "reserved"
    return "public"


def extract(text: str) -> list[tuple[str, str]]:
    """Return unique (type, value) pairs found in `text`."""
    text = refang(text)
    found: dict[tuple[str, str], None] = {}
    urls = URL.findall(text)
    for u in urls:
        found[("url", u.rstrip(".,;"))] = None
    scrubbed = URL.sub(" ", text)
    for e in EMAIL.findall(scrubbed):
        found[("email", e.lower())] = None
    scrubbed2 = EMAIL.sub(" ", scrubbed)
    for ip in IPV4.findall(scrubbed2):
        try:
            ipaddress.ip_address(ip)
            found[("ipv4", ip)] = None
        except ValueError:
            pass
    for h in SHA256.findall(scrubbed2):
        found[("sha256", h.lower())] = None
    cleaned = SHA256.sub(" ", scrubbed2)
    for h in SHA1.findall(cleaned):
        found[("sha1", h.lower())] = None
    cleaned = SHA1.sub(" ", cleaned)
    for h in MD5.findall(cleaned):
        found[("md5", h.lower())] = None
    for c in CVE.findall(scrubbed2):
        found[("cve", c.upper())] = None
    no_ip = IPV4.sub(" ", scrubbed2)
    for d in DOMAIN.findall(no_ip):
        d = d.lower().rstrip(".")
        tld = d.rsplit(".", 1)[-1]
        if tld in NOT_TLDS or d.replace(".", "").isdigit():
            continue
        found[("domain", d)] = None
    # domains that are only the host of an extracted URL are already implied
    for u in urls:
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0].split("@")[-1].lower()
        if host and not IPV4.fullmatch(host):
            tld = host.rsplit(".", 1)[-1]
            if tld not in NOT_TLDS:
                found[("domain", host)] = None
        elif host:
            found[("ipv4", host)] = None
    return list(found)


def extract_from_events(events: list) -> dict[tuple[str, str], Hit]:
    """`events` are ORM Event rows (id, ts, message, ip). Aggregates counts and time bounds."""
    hits: dict[tuple[str, str], Hit] = {}
    for ev in events:
        blob = f"{ev.message} {ev.ip or ''}"
        for typ, val in extract(blob):
            key = (typ, val)
            h = hits.get(key)
            if not h:
                internal = False
                if typ == "ipv4":
                    internal = ip_scope(val) in INTERNAL_SCOPES
                h = hits[key] = Hit(typ, val, internal=internal)
            h.count += 1
            if len(h.event_ids) < 200:
                h.event_ids.append(ev.id)
            if ev.ts:
                if not h.first_seen or ev.ts < h.first_seen:
                    h.first_seen = ev.ts
                if not h.last_seen or ev.ts > h.last_seen:
                    h.last_seen = ev.ts
    return hits


def classify_value(value: str) -> str | None:
    """Detect the indicator type of a user-supplied value (for lookups)."""
    v = refang(value.strip())
    if re.fullmatch(IPV4, v):
        try:
            ipaddress.ip_address(v)
            return "ipv4"
        except ValueError:
            return None
    if re.fullmatch(SHA256, v):
        return "sha256"
    if re.fullmatch(SHA1, v):
        return "sha1"
    if re.fullmatch(MD5, v):
        return "md5"
    if re.fullmatch(CVE, v):
        return "cve"
    if re.fullmatch(EMAIL, v):
        return "email"
    if re.fullmatch(r"https?://[^\s]+", v, re.I):
        return "url"
    if re.fullmatch(DOMAIN, v):
        return "domain"
    return None
