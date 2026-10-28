"""Turn raw log lines into Events. Each line's format is detected automatically."""

from __future__ import annotations

import calendar
import gzip
import ipaddress
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from .events import FW_BLOCK, SSH_FAIL, SSH_INVALID, SSH_OK, WEB, Event

# --- timestamps -----------------------------------------------------------
#
# Times are kept as the server wrote them (its own clock), whatever computer runs the analysis.
# Classic syslog lines have no zone at all, so converting only the lines that do have one would
# shift web events hours away from SSH and firewall events from the same server.

# Classic syslog: "Oct 28 03:14:07 host prog[pid]: message" (no year in the line)
SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<hms>\d\d:\d\d:\d\d) (?P<host>\S+) (?P<rest>.*)$")
# Newer systemd/rsyslog: "2026-10-28T03:14:07.123456+00:00 host prog[pid]: message"
ISO = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(?P<tz>Z|[+-]\d\d:?\d\d)? (?P<host>\S+) (?P<rest>.*)$")


def as_written(dt: datetime) -> datetime:
    """Drop the zone but keep the clock time the server wrote."""
    return dt.replace(tzinfo=None)


class Clock:
    """Supplies the year for syslog lines, which don't include one.

    With an explicit year, that year is used. Otherwise lines are assumed to be from the last
    12 months: a date that would be in the future (e.g. December lines read in January) belongs
    to last year.
    """

    def __init__(self, year: Optional[int] = None, now: Optional[datetime] = None):
        self.year = year
        self.now = now or datetime.now()

    def resolve(self, mon: str, day: str, hms: str) -> Optional[datetime]:
        year = self.year or self.now.year
        if mon == "Feb" and day == "29" and not calendar.isleap(year):
            year -= 1  # a Feb 29 line can only come from a leap year
            while not calendar.isleap(year):
                year -= 1
        try:
            ts = datetime.strptime(f"{year} {mon} {day} {hms}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        if self.year is None and ts > self.now + timedelta(days=1):
            try:
                ts = ts.replace(year=ts.year - 1)
            except ValueError:  # Feb 29 has no counterpart last year
                pass
        return ts


def syslog_time(line: str, clock: Clock) -> Optional[Tuple[datetime, str]]:
    """Return (timestamp, text after the hostname) for a syslog-style line."""
    m = ISO.match(line)
    if m:
        tz = m["tz"] or ""
        tz = "+00:00" if tz == "Z" else (f"{tz[:3]}:{tz[3:]}" if tz and ":" not in tz else tz)
        try:
            return as_written(datetime.fromisoformat(m["iso"] + tz)), m["rest"]
        except ValueError:
            return None
    m = SYSLOG.match(line)
    if m:
        ts = clock.resolve(m["mon"], m["day"], m["hms"])
        return (ts, m["rest"]) if ts else None
    return None


def valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# --- SSH (Linux /var/log/auth.log or /var/log/secure) -----------------------

SSHD = re.compile(r"^sshd(?:-session)?\[\d+\]: (?P<msg>.*)$")
# rsyslog collapses identical lines: "message repeated 50 times: [ Failed password for ... ]"
REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<msg>.*?) ?\]$")
# The username is chosen by whoever connects and can contain " from 1.2.3.4 port 22".
# sshd always appends the real address last, so the greedy (.*) makes us take the LAST "from ... port".
SSH_PATTERNS = [
    (SSH_FAIL, re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*) from (?P<ip>\S+) port \d+")),
    (SSH_OK, re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*) from (?P<ip>\S+) port \d+")),
    (SSH_INVALID, re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+) port \d+")),
]
MAX_REPEAT = 100_000


def parse_ssh(line: str, clock: Clock) -> Optional[List[Event]]:
    parsed = syslog_time(line, clock)
    if not parsed:
        return None
    ts, rest = parsed
    m = SSHD.match(rest)
    if not m:
        return None
    msg, times = m["msg"], 1
    rep = REPEATED.match(msg)
    if rep:
        msg, times = rep["msg"], min(int(rep["n"]), MAX_REPEAT)
    for kind, pattern in SSH_PATTERNS:
        hit = pattern.match(msg)
        if hit and valid_ip(hit["ip"]):
            d = hit.groupdict()
            return [Event(ts, kind, d["ip"], user=d.get("user", ""), method=d.get("method", ""), raw=line)
                    for _ in range(times)]
    return None


# --- Firewall (UFW / iptables kernel log lines) ------------------------------

FIREWALL = re.compile(r"(?:\[UFW BLOCK\]|IPTABLES|iptables|DROP|REJECT).*?\bSRC=(?P<src>\S+) DST=(?P<dst>\S+).*?\bPROTO=(?P<proto>\S+)(?:.*?\bDPT=(?P<dpt>\d+))?")


def parse_firewall(line: str, clock: Clock) -> Optional[List[Event]]:
    parsed = syslog_time(line, clock)
    if not parsed:
        return None
    ts, rest = parsed
    m = FIREWALL.search(rest)
    if not m or not valid_ip(m["src"]):
        return None
    return [Event(ts, FW_BLOCK, m["src"], method=m["proto"], port=int(m["dpt"] or 0), path=m["dst"], raw=line)]


# --- Web server access logs (Apache/Nginx "combined" format) -----------------

ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+'
    r'(?: "[^"]*" "(?P<agent>[^"]*)")?'
)


def parse_access(line: str, clock: Clock) -> Optional[List[Event]]:
    m = ACCESS.match(line)
    if not m or not valid_ip(m["ip"]):
        return None
    try:
        ts = as_written(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        return None
    return [Event(ts, WEB, m["ip"], method=m["method"], path=m["path"], status=int(m["status"]),
                  agent=m["agent"] or "", raw=line)]


PARSERS: List[Callable[[str, Clock], Optional[List[Event]]]] = [parse_access, parse_ssh, parse_firewall]


def parse_lines(lines: Iterable[str], source: str = "", year: Optional[int] = None,
                now: Optional[datetime] = None) -> Tuple[List[Event], int]:
    """Parse lines of any supported format. Returns (events, number of lines we skipped)."""
    clock = Clock(year, now)
    events: List[Event] = []
    skipped = 0
    for n, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        for parser in PARSERS:
            found = parser(line, clock)
            if found:
                for event in found:
                    event.source = f"{source}:{n}" if source else str(n)
                events.extend(found)
                break
        else:
            skipped += 1
    return events, skipped


def parse_file(path: Path, year: Optional[int] = None) -> Tuple[List[Event], int]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        return parse_lines(f, path.name, year)
