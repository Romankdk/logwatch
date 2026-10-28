"""Detection rules: turn a pile of events into a short list of alerts worth a human's attention."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List
from urllib.parse import unquote

from .events import FW_BLOCK, SSH_FAIL, SSH_INVALID, SSH_OK, WEB, Event

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Settings:
    brute_force_failures: int = 10  # failed logins from one IP...
    brute_force_window: timedelta = timedelta(minutes=5)  # ...within this window
    compromise_failures: int = 5  # a success after at least this many failures...
    compromise_window: timedelta = timedelta(hours=1)  # ...within this long before it is suspicious
    spray_users: int = 5  # distinct usernames tried by one IP
    probe_404s: int = 20  # "not found" responses to one IP...
    probe_window: timedelta = timedelta(minutes=5)  # ...within this window
    scan_ports: int = 10  # distinct ports one IP was blocked on...
    scan_window: timedelta = timedelta(minutes=1)  # ...within this window


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    summary: str
    first: datetime
    last: datetime
    count: int
    advice: str = ""
    evidence: List[str] = field(default_factory=list)  # a few example source lines


def _evidence(events: List[Event], limit: int = 4) -> List[str]:
    picked = events if len(events) <= limit else events[: limit - 1] + events[-1:]
    return [f"{e.source}  {e.raw}" for e in picked]


def _max_in_window(events: List[Event], window: timedelta, key=None) -> int:
    """Largest number of events (or distinct keys) inside any sliding window of this length. O(n)."""
    key = key or id  # without a key, every event counts on its own
    counts: Dict[object, int] = defaultdict(int)
    best = start = 0
    for e in events:
        counts[key(e)] += 1
        while e.time - events[start].time > window:
            k = key(events[start])
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            start += 1
        best = max(best, len(counts))
    return best


def _by_ip(events: List[Event], *kinds: str) -> Dict[str, List[Event]]:
    groups: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.kind in kinds:
            groups[e.ip].append(e)
    return groups


# --- SSH ------------------------------------------------------------------------

def _attempts(events: List[Event]) -> List[Event]:
    """One event per login attempt. sshd logs "Invalid user x" and then usually
    "Failed password for invalid user x" for the same attempt; count that once."""
    out: List[Event] = []
    for i, e in enumerate(events):
        if e.kind == SSH_INVALID and any(
            f.kind == SSH_FAIL and f.user == e.user and timedelta(0) <= f.time - e.time <= timedelta(seconds=30)
            for f in events[i + 1:i + 6]
        ):
            continue
        out.append(e)
    return out


def ssh_rules(events: List[Event], s: Settings) -> List[Alert]:
    alerts: List[Alert] = []
    failures = {ip: _attempts(evs) for ip, evs in _by_ip(events, SSH_FAIL, SSH_INVALID).items()}

    for ip, fails in failures.items():
        peak = _max_in_window(fails, s.brute_force_window)
        if peak >= s.brute_force_failures:
            minutes = int(s.brute_force_window.total_seconds() // 60)
            alerts.append(Alert(
                "ssh-brute-force", "high", ip,
                f"{len(fails)} failed SSH logins (up to {peak} within {minutes} min)",
                fails[0].time, fails[-1].time, len(fails),
                "Block this IP, disable password logins (use SSH keys) and consider fail2ban.",
                _evidence(fails)))
        users = {e.user for e in fails if e.user}
        if len(users) >= s.spray_users:
            sample = ", ".join(sorted(users)[:6]) + ("..." if len(users) > 6 else "")
            alerts.append(Alert(
                "ssh-user-guessing", "medium", ip,
                f"Tried {len(users)} different usernames ({sample})",
                fails[0].time, fails[-1].time, len(fails),
                "Someone is guessing account names. Make sure no account has a weak password.",
                _evidence(fails)))

    # The one that matters most: a burst of failures, then a success, from the same place.
    # Only failures since that IP's previous successful login, and within the window, count.
    logins = _by_ip(events, SSH_OK)
    for ip, oks in logins.items():
        fails, i = failures.get(ip, []), 0
        for ok in oks:
            recent: List[Event] = []
            while i < len(fails) and fails[i].time <= ok.time:
                if ok.time - fails[i].time <= s.compromise_window:
                    recent.append(fails[i])
                i += 1
            if len(recent) >= s.compromise_failures:
                alerts.append(Alert(
                    "ssh-login-after-failures", "critical", ip,
                    f"Logged in as '{ok.user}' ({ok.method}) after {len(recent)} failed attempts",
                    recent[0].time, ok.time, len(recent) + 1,
                    f"Treat the '{ok.user}' account as compromised: change its password, check what it did, "
                    "and look for new SSH keys or users.",
                    _evidence(recent, 3) + _evidence([ok], 1)))
    return alerts


# --- Web ------------------------------------------------------------------------

WEB_ATTACKS = {
    "path traversal": re.compile(r"\.\./|\.\.\\"),
    "SQL injection": re.compile(r"(?i)union\s+(all\s+)?select|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bsleep\(\d+\)|information_schema"),
    "cross-site scripting": re.compile(r"(?i)<script|javascript:|onerror\s*="),
    "command injection": re.compile(r"(?i)[;|`]\s*(cat|wget|curl|bash|sh|id|whoami)\b|\$\("),
    "sensitive file probe": re.compile(r"(?i)/\.env\b|/\.git/|wp-config\.php|/etc/passwd|/\.aws/|/\.ssh/|\.htpasswd|/server-status"),
}
SCANNER_AGENTS = re.compile(r"(?i)nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|nuclei|acunetix|nessus|openvas|wfuzz|ffuf")


def classify_request(path: str) -> List[str]:
    """Which attack categories does this request path look like? Checks the URL-decoded form too."""
    decoded = unquote(unquote(path)).replace("+", " ")
    return [name for name, rx in WEB_ATTACKS.items() if rx.search(path) or rx.search(decoded)]


def web_rules(events: List[Event], s: Settings) -> List[Alert]:
    alerts: List[Alert] = []
    for ip, reqs in _by_ip(events, WEB).items():
        attacks = [(e, classify_request(e.path)) for e in reqs]
        attacks = [(e, cats) for e, cats in attacks if cats]
        if attacks:
            cats = sorted({c for _, cats in attacks for c in cats})
            succeeded = [e for e, _ in attacks if 200 <= e.status < 300]
            severity = "high" if succeeded else "medium"
            note = f"; {len(succeeded)} got a success (2xx) response" if succeeded else "; all were rejected"
            alerts.append(Alert(
                "web-attack", severity, ip,
                f"{len(attacks)} attack-like requests: {', '.join(cats)}{note}",
                attacks[0][0].time, attacks[-1][0].time, len(attacks),
                ("Check what those successful requests returned; a 200 for a file like .env means secrets may have leaked."
                 if succeeded else "The requests failed, but block the IP and keep the site patched."),
                _evidence(succeeded or [e for e, _ in attacks])))

        tools = sorted({m.group(0).lower() for e in reqs for m in [SCANNER_AGENTS.search(e.agent)] if m})
        not_found = [e for e in reqs if e.status == 404]
        peak = _max_in_window(not_found, s.probe_window) if not_found else 0
        if tools or peak >= s.probe_404s:
            why = f"identifies as {', '.join(tools)}" if tools else f"{peak} 'not found' pages within {int(s.probe_window.total_seconds() // 60)} min"
            alerts.append(Alert(
                "web-scanner", "medium", ip,
                f"Automated vulnerability scanning ({why}); {len(reqs)} requests, {len(not_found)} not found",
                reqs[0].time, reqs[-1].time, len(reqs),
                "Usually bots looking for known weaknesses. Keep software updated and consider rate limiting.",
                _evidence(not_found or reqs)))
    return alerts


# --- Firewall -------------------------------------------------------------------

def firewall_rules(events: List[Event], s: Settings) -> List[Alert]:
    alerts: List[Alert] = []
    for ip, blocks in _by_ip(events, FW_BLOCK).items():
        blocks = [e for e in blocks if e.port]  # ICMP and other port-less packets aren't port probes
        if not blocks:
            continue
        peak = _max_in_window(blocks, s.scan_window, key=lambda e: e.port)
        if peak >= s.scan_ports:
            ports = sorted({e.port for e in blocks if e.port})
            shown = ", ".join(map(str, ports[:12])) + ("..." if len(ports) > 12 else "")
            alerts.append(Alert(
                "port-scan", "medium", ip,
                f"Probed {len(ports)} different ports (up to {peak} within {int(s.scan_window.total_seconds())}s): {shown}",
                blocks[0].time, blocks[-1].time, len(blocks),
                "Someone mapped your open ports; the firewall blocked these. Check nothing unexpected is allowed through.",
                _evidence(blocks)))
    return alerts


RULES = [ssh_rules, web_rules, firewall_rules]


def detect(events: List[Event], settings: Settings = None) -> List[Alert]:
    settings = settings or Settings()
    events = sorted(events, key=lambda e: e.time)
    alerts = [a for rule in RULES for a in rule(events, settings)]
    return sorted(alerts, key=lambda a: (-SEVERITY_ORDER[a.severity], a.first))
