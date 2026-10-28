"""Render alerts as terminal text, JSON, or a self-contained HTML page."""

from __future__ import annotations

import html
import json
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from typing import List, Optional

from .detect import SEVERITY_ORDER, Alert
from .events import Event

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"


def clean(text: str) -> str:
    """Log lines can contain attacker-controlled bytes; never send control characters to the terminal."""
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def _when(a: Alert) -> str:
    if a.first == a.last:
        return f"{a.first:%Y-%m-%d %H:%M:%S}"
    end = f"{a.last:%H:%M:%S}" if a.first.date() == a.last.date() else f"{a.last:%Y-%m-%d %H:%M:%S}"
    return f"{a.first:%Y-%m-%d %H:%M:%S} -> {end}"


def stats_line(events: List[Event], skipped: int, files: int) -> str:
    kinds = Counter(e.kind for e in events)
    parts = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in kinds.most_common())
    return f"Read {files} file(s): {len(events)} events ({parts or 'none'}); {skipped} lines not recognized"


def render_text(alerts: List[Alert], stats: str, color: Optional[bool] = None) -> str:
    if color is None:
        color = sys.stdout.isatty()
    out = [stats, ""]
    if not alerts:
        out.append("No signs of attacks found.")
        return "\n".join(out)
    counts = Counter(a.severity for a in alerts)
    out.append("Alerts: " + ", ".join(f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: -SEVERITY_ORDER[s])))
    for a in alerts:
        sev = f"[{a.severity.upper()}]"
        sev = f"{COLORS[a.severity]}{sev}{RESET}" if color else sev
        out += ["", f"{sev} {a.rule} from {a.ip}", f"  {clean(a.summary)}", f"  When: {_when(a)}"]
        if a.advice:
            out.append(f"  What to do: {a.advice}")
        out.append("  Evidence:")
        out += [f"    {clean(line)[:300]}" for line in a.evidence]
    return "\n".join(out)


def render_timeline(events: List[Event], ip: str) -> str:
    mine = sorted((e for e in events if e.ip == ip), key=lambda e: e.time)
    if not mine:
        return f"No events from {ip}."
    lines = [f"Timeline for {ip} ({len(mine)} events):"]
    for e in mine:
        what = {
            "ssh_fail": f"SSH failed login as '{e.user}'",
            "ssh_invalid_user": f"SSH attempt for unknown user '{e.user}'",
            "ssh_ok": f"SSH LOGIN SUCCEEDED as '{e.user}' ({e.method})",
            "web": f"{e.method} {e.path} -> {e.status}",
            "fw_block": f"firewall blocked {e.method} port {e.port}",
        }.get(e.kind, e.kind)
        lines.append(f"  {e.time:%Y-%m-%d %H:%M:%S}  {clean(what)[:160]}")
    return "\n".join(lines)


def render_json(alerts: List[Alert], stats: str) -> str:
    return json.dumps({"stats": stats, "alerts": [asdict(a) for a in alerts]}, indent=2, default=str)


CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e4e4df;
--critical:#b42318;--high:#d4380d;--medium:#b7791f;--low:#2b6cb0;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--fg:#ecece8;--muted:#9a9a93;--line:#33332f;
--critical:#ff6b5e;--high:#ff8a4c;--medium:#e6b450;--low:#6ba8ff;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}h1{font-size:26px;margin:0 0 4px}
h2{font-size:17px;margin:0 0 4px}.muted{color:var(--muted)}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:24px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:110px}
.tile b{display:block;font-size:24px}.tile span{font-size:13px;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-left-width:5px;border-radius:12px;padding:16px 18px;margin:14px 0}
.card.critical{border-left-color:var(--critical)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}.card.low{border-left-color:var(--low)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff;margin-right:6px}
.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}
.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow-x:auto;font-size:12px;margin:8px 0 0}
"""


def render_html(alerts: List[Alert], stats: str, when: Optional[datetime] = None) -> str:
    e = lambda t: html.escape(str(t), quote=True)  # noqa: E731
    when = when or datetime.now()
    counts = Counter(a.severity for a in alerts)
    body = [f"<main><h1>Log analysis report</h1><div class='muted'>{e(stats)} &middot; {when:%Y-%m-%d %H:%M}</div>",
            "<div class='tiles'>", f"<div class='tile'><b>{len(alerts)}</b><span>alerts</span></div>",
            f"<div class='tile'><b>{len({a.ip for a in alerts})}</b><span>suspicious IPs</span></div>"]
    for sev in ("critical", "high", "medium", "low"):
        if counts[sev]:
            body.append(f"<div class='tile'><b>{counts[sev]}</b><span class='badge {sev}'>{sev}</span></div>")
    body.append("</div>")
    if not alerts:
        body.append("<p>No signs of attacks found.</p>")
    for a in alerts:
        evidence = "\n".join(clean(line) for line in a.evidence)
        body.append(
            f"<section class='card {e(a.severity)}'><h2><span class='badge {e(a.severity)}'>{e(a.severity)}</span>"
            f"{e(a.rule)} from {e(a.ip)}</h2><div>{e(a.summary)}</div><div class='muted'>{e(_when(a))}</div>"
            f"<div><b>What to do:</b> {e(a.advice)}</div><pre>{e(evidence)}</pre></section>")
    body.append("<p class='muted'>Generated by logwatch.</p></main>")
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'><title>Log analysis report</title>"
            f"<style>{CSS}</style></head><body>{''.join(body)}</body></html>")
