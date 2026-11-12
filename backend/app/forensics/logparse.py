"""Log parsing into normalised events. Supports JSON/JSONL, CSV, syslog/auth.log, nginx/apache combined."""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Iterator

MAX_EVENTS = 50_000

SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+?)(?:\[\d+\])?:\s+(?P<msg>.*)$")
ISO_SYSLOG = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+?)(?:\[\d+\])?:\s+(?P<msg>.*)$")
WEB = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"(?:for (?:invalid user )?|user[= ]|Invalid user |session opened for user )(?P<u>[\w.@-]+)")


@dataclass
class ParsedEvent:
    ts: datetime | None
    source: str = ""
    host: str = ""
    user: str = ""
    ip: str = ""
    action: str = ""
    severity: str = "info"
    message: str = ""
    line_no: int = 0
    fields: dict = field(default_factory=dict)


def parse_ts(value: str | int | float | None, default_year: int | None = None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value)):
        v = float(value)
        if v > 1e11:
            v /= 1000
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            d = datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def classify(message: str) -> tuple[str, str]:
    """Return (action, severity) from message heuristics."""
    m = message.lower()
    if "failed password" in m or "authentication failure" in m or "invalid user" in m or "failed login" in m:
        return "auth_failure", "medium"
    if "accepted password" in m or "accepted publickey" in m or "successful login" in m:
        return "auth_success", "info"
    if "sudo" in m and "command=" in m:
        return "privilege_use", "medium"
    if "session opened for user root" in m or "su:" in m and "root" in m:
        return "privilege_use", "medium"
    if any(k in m for k in ("segfault", "panic", "fatal", "critical")):
        return "error", "high"
    if "error" in m or "denied" in m:
        return "error", "low"
    return "event", "info"


def _syslog_ts(mon: str, day: str, tm: str, year: int) -> datetime | None:
    try:
        h, mi, s = map(int, tm.split(":"))
        return datetime(year, MONTHS[mon], int(day), h, mi, s, tzinfo=timezone.utc)
    except (KeyError, ValueError):
        return None


def detect_format(text: str, filename: str = "") -> str:
    head = text.lstrip()[:4000]
    if head.startswith("["):
        return "json"
    first = head.split("\n", 1)[0].strip()
    if first.startswith("{"):
        return "jsonl"
    if filename.lower().endswith(".csv") or (first.count(",") >= 2 and not SYSLOG.match(first) and not WEB.match(first)):
        return "csv"
    if WEB.match(first):
        return "web"
    return "syslog"


def parse_text(text: str, filename: str = "", year: int | None = None) -> tuple[str, list[ParsedEvent]]:
    fmt = detect_format(text, filename)
    year = year or datetime.now(timezone.utc).year
    gen: Iterable[ParsedEvent]
    if fmt in ("json", "jsonl"):
        gen = _parse_json(text, fmt)
    elif fmt == "csv":
        gen = _parse_csv(text)
    elif fmt == "web":
        gen = _parse_lines(text, year, web_first=True)
    else:
        gen = _parse_lines(text, year)
    out: list[ParsedEvent] = []
    for ev in gen:
        out.append(ev)
        if len(out) >= MAX_EVENTS:
            break
    return fmt, out


def _from_mapping(d: dict, line_no: int) -> ParsedEvent:
    low = {str(k).lower(): v for k, v in d.items()}

    def pick(*keys: str) -> str:
        for k in keys:
            v = low.get(k)
            if v not in (None, ""):
                return str(v)
        return ""

    msg = pick("message", "msg", "event", "description", "log", "text") or json.dumps(d, default=str)[:500]
    action, sev = classify(msg)
    sev_in = pick("severity", "level", "priority").lower()
    if sev_in in {"critical", "fatal", "high", "error", "warning", "warn", "medium", "low", "info"}:
        sev = {"fatal": "critical", "error": "high", "warning": "medium", "warn": "medium"}.get(sev_in, sev_in) if sev_in not in {"info"} else sev
    ip = pick("ip", "src_ip", "source_ip", "client_ip", "remote_addr", "clientip", "src")
    if not ip:
        m = IP_RE.search(msg)
        ip = m.group(0) if m else ""
    user = pick("user", "username", "account", "user_name")
    if not user:
        um = USER_RE.search(msg)
        user = um.group("u") if um else ""
    return ParsedEvent(
        ts=parse_ts(pick("timestamp", "time", "ts", "@timestamp", "date", "datetime")),
        source=pick("source", "service", "app", "program", "process") or "json",
        host=pick("host", "hostname", "computer", "device"),
        user=user,
        ip=ip,
        action=pick("action", "event_type", "category") or action,
        severity=sev,
        message=msg[:2000],
        line_no=line_no,
        fields={k: v for k, v in list(d.items())[:30] if isinstance(v, (str, int, float, bool, type(None)))},
    )


def _parse_json(text: str, fmt: str) -> Iterator[ParsedEvent]:
    if fmt == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        if isinstance(data, dict):
            data = data.get("events") or data.get("records") or [data]
        for i, d in enumerate(data, 1):
            if isinstance(d, dict):
                yield _from_mapping(d, i)
    else:
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(d, dict):
                yield _from_mapping(d, i)


def _parse_csv(text: str) -> Iterator[ParsedEvent]:
    reader = csv.DictReader(io.StringIO(text))
    for i, row in enumerate(reader, 2):
        yield _from_mapping({k: v for k, v in row.items() if k}, i)


def _parse_lines(text: str, year: int, web_first: bool = False) -> Iterator[ParsedEvent]:
    for i, line in enumerate(text.splitlines(), 1):
        line = line.rstrip()
        if not line:
            continue
        w = WEB.match(line)
        if w:
            status = int(w["status"])
            path = w["path"]
            sev = "info"
            action = "http_request"
            if status in (401, 403):
                sev, action = "low", "http_denied"
            elif status >= 500:
                sev, action = "medium", "http_error"
            elif status == 404:
                sev, action = "info", "http_not_found"
            yield ParsedEvent(
                ts=parse_ts(w["ts"]), source="web", ip=w["ip"], user="" if w["user"] == "-" else w["user"],
                action=action, severity=sev, message=line[:2000], line_no=i,
                fields={"method": w["method"], "path": path, "status": status, "ua": w["ua"] or ""},
            )
            continue
        s = SYSLOG.match(line)
        iso = None if s else ISO_SYSLOG.match(line)
        if s:
            ts, host, proc, msg = _syslog_ts(s["mon"], s["day"], s["time"], year), s["host"], s["proc"], s["msg"]
        elif iso:
            ts, host, proc, msg = parse_ts(iso["ts"]), iso["host"], iso["proc"], iso["msg"]
        else:
            ts, host, proc, msg = None, "", "raw", line
        action, sev = classify(msg)
        ipm = IP_RE.search(msg)
        um = USER_RE.search(msg)
        yield ParsedEvent(ts=ts, source=proc, host=host, user=um.group("u") if um else "", ip=ipm.group(0) if ipm else "",
                          action=action, severity=sev, message=msg[:2000], line_no=i)
