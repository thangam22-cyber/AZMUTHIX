"""Explainable detection rules over normalised events. Every finding cites its events and a confidence."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .indicators import ip_scope


@dataclass
class RawFinding:
    rule: str
    title: str
    severity: str
    confidence: int
    description: str
    mitre: str = ""
    event_ids: list[int] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)


SUSPICIOUS_CMD = [
    (re.compile(r"(curl|wget)[^|;\n]*\|\s*(sudo\s+)?(ba)?sh", re.I), "Remote script piped to shell", "T1059.004"),
    (re.compile(r"base64\s+(-d|--decode)", re.I), "Base64-decoded payload", "T1140"),
    (re.compile(r"\bnc(at)?\b[^\n]*\s-e\s", re.I), "Netcat with command execution (reverse shell pattern)", "T1059"),
    (re.compile(r"/dev/tcp/\d", re.I), "Bash /dev/tcp reverse shell pattern", "T1059.004"),
    (re.compile(r"chmod\s+\+?[0-7]*7[0-7]*\s+/tmp/", re.I), "Executable permission set on file in /tmp", "T1222"),
    (re.compile(r"(cat|less|tail)\s+/etc/shadow", re.I), "Read of /etc/shadow", "T1003.008"),
    (re.compile(r"useradd|adduser", re.I), "New account created", "T1136.001"),
    (re.compile(r"crontab\s+-[el]|/etc/cron", re.I), "Cron modification (persistence candidate)", "T1053.003"),
]
WEB_ATTACK = [
    (re.compile(r"(\.\./){2,}|%2e%2e%2f", re.I), "Path traversal attempt", "T1190"),
    (re.compile(r"union(\s|\+|%20)+select|or(\s|\+|%20)+1=1|sleep\(\d+\)|information_schema", re.I), "SQL injection pattern", "T1190"),
    (re.compile(r"<script|javascript:|onerror=", re.I), "Cross-site scripting pattern", "T1189"),
    (re.compile(r"\$\{jndi:", re.I), "JNDI lookup (Log4Shell-style) pattern", "T1190"),
    (re.compile(r"/(wp-login|xmlrpc)\.php|/\.env|/\.git/|phpmyadmin", re.I), "Probe for common sensitive path", "T1595.002"),
]
SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan", re.I)


def _sev_rank(s: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)


def run_rules(events: list) -> list[RawFinding]:
    findings: list[RawFinding] = []
    events = sorted(events, key=lambda e: (e.ts is None, e.ts, e.id))

    # 1) Brute force + success-after-failure per source IP
    fails: dict[str, list] = defaultdict(list)
    succ: dict[str, list] = defaultdict(list)
    for e in events:
        if e.action == "auth_failure" and e.ip:
            fails[e.ip].append(e)
        elif e.action == "auth_success" and e.ip:
            succ[e.ip].append(e)
    for ip, evs in fails.items():
        if len(evs) < 5:
            continue
        window_ok = True
        span = None
        if evs[0].ts and evs[-1].ts:
            span = evs[-1].ts - evs[0].ts
            window_ok = span <= timedelta(hours=1)
        users = {e.user for e in evs if e.user}
        scope = ip_scope(ip)
        conf = 55 + min(len(evs), 30) + (10 if window_ok else -15) + (5 if len(users) > 1 else 0)
        sev = "high" if len(evs) >= 10 and window_ok else "medium"
        findings.append(RawFinding(
            "brute_force", f"Repeated authentication failures from {ip}", sev, max(30, min(conf, 95)),
            f"{len(evs)} failed logins from {ip} ({scope})" + (f" within {int(span.total_seconds())}s" if span else "") +
            (f" targeting {len(users)} account(s): {', '.join(sorted(users)[:5])}" if users else "") + ".",
            "T1110", [e.id for e in evs[:100]], [ip]))
        # success after failures = possible compromise
        later = [s for s in succ.get(ip, []) if not evs[-1].ts or not s.ts or s.ts >= evs[0].ts]
        if later:
            findings.append(RawFinding(
                "success_after_bruteforce", f"Successful login from {ip} after {len(evs)} failures", "critical", 80 if len(evs) >= 10 else 65,
                f"{ip} authenticated successfully as {later[0].user or 'unknown'} after repeated failures. This is consistent with a guessed credential, "
                "but could also be a legitimate user mistyping a password; verify with the account owner.",
                "T1078", [e.id for e in evs[-5:]] + [s.id for s in later[:3]], [ip]))

    # 2) Privilege use
    priv = [e for e in events if e.action == "privilege_use"]
    if priv:
        users = sorted({e.user for e in priv if e.user})
        findings.append(RawFinding(
            "privilege_use", "Privileged command / root session activity", "medium", 50,
            f"{len(priv)} privileged action(s) observed" + (f" by {', '.join(users[:5])}" if users else "") + ". Review whether they were expected.",
            "T1548", [e.id for e in priv[:50]], []))

    # 3) Suspicious commands
    seen: dict[str, list] = defaultdict(list)
    for e in events:
        for rx, label, tech in SUSPICIOUS_CMD:
            if rx.search(e.message):
                seen[(label, tech)].append(e)  # type: ignore[index]
    for (label, tech), evs in seen.items():  # type: ignore[misc]
        findings.append(RawFinding(
            "suspicious_command", label, "high", 70,
            f"{len(evs)} event(s) match a command pattern commonly associated with attacker tooling. A matching pattern is not proof of malice; confirm context.",
            tech, [e.id for e in evs[:50]], sorted({e.ip for e in evs if e.ip})[:10]))

    # 4) Web attacks / scanners / 404 bursts
    web = [e for e in events if e.source == "web"]
    for rx, label, tech in WEB_ATTACK:
        evs = [e for e in web if rx.search(e.message)]
        if evs:
            ips = sorted({e.ip for e in evs})
            ok = [e for e in evs if str(e.fields.get("status", "")).startswith("2")]
            findings.append(RawFinding(
                "web_attack", label, "high" if ok else "medium", 75 if ok else 60,
                f"{len(evs)} request(s) from {len(ips)} source(s) matched '{label}'." +
                (f" {len(ok)} returned HTTP 2xx, which warrants checking whether the payload had effect." if ok else " None returned 2xx."),
                tech, [e.id for e in evs[:60]], ips[:10]))
    scan = [e for e in web if SCANNER_UA.search(str(e.fields.get("ua", "")))]
    if scan:
        ips = sorted({e.ip for e in scan})
        findings.append(RawFinding("scanner_ua", "Known scanner user-agent", "medium", 85,
            f"Scanner tooling user-agent observed from {', '.join(ips[:5])} ({len(scan)} request(s)).", "T1595",
            [e.id for e in scan[:60]], ips[:10]))
    nf: dict[str, list] = defaultdict(list)
    for e in web:
        if str(e.fields.get("status")) == "404":
            nf[e.ip].append(e)
    for ip, evs in nf.items():
        if len(evs) >= 15:
            findings.append(RawFinding("web_enum", f"Possible content enumeration from {ip}", "medium", 60,
                f"{len(evs)} HTTP 404 responses to {ip}; consistent with directory brute-forcing.", "T1595.003", [e.id for e in evs[:60]], [ip]))

    # 5) Off-hours admin activity (soft signal)
    off = [e for e in events if e.ts and e.action in {"privilege_use", "auth_success"} and e.ts.hour in (0, 1, 2, 3, 4) and e.user in {"root", "admin", "administrator"}]
    if len(off) >= 2:
        findings.append(RawFinding("off_hours_admin", "Administrative activity during off-hours (00:00–04:59 UTC)", "low", 35,
            f"{len(off)} admin-account events between 00:00 and 04:59 UTC. Time zone of the host is unknown, so treat as a weak signal.",
            "T1078", [e.id for e in off[:30]], []))

    findings.sort(key=lambda f: (-_sev_rank(f.severity), -f.confidence))
    return findings
