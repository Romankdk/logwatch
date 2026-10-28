"""Command-line entry point: python3 -m logwatch <log files or folders> [options]"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional

from .detect import SEVERITY_ORDER, Settings, detect
from .parsers import parse_file
from .report import clean, render_html, render_json, render_text, render_timeline, stats_line

SYSTEM_LOGS = ["/var/log/auth.log", "/var/log/secure", "/var/log/ufw.log",
               "/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"]

EPILOG = """examples:
  python3 -m logwatch samples/                       # try it on the included example logs
  python3 -m logwatch /var/log/auth.log              # a Linux server's SSH log
  python3 -m logwatch access.log --html report.html  # web server log, HTML report
  python3 -m logwatch samples/ --timeline 203.0.113.99
  sudo python3 -m logwatch --system                  # common Linux log locations

exit codes: 0 no alerts, 1 error, 2 bad arguments, 3 alerts found"""


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="logwatch", description="Find signs of attacks in SSH, web server and firewall logs.",
                                 epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    ap.add_argument("paths", nargs="*", type=Path, help="log files (.log, .gz) or folders of them")
    ap.add_argument("--system", action="store_true", help="read common Linux log locations (needs sudo)")
    ap.add_argument("--year", type=int, help="year for syslog lines, which don't include one (default: this year)")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low", help="hide alerts below this")
    ap.add_argument("--timeline", metavar="IP", help="show everything one IP did, in order")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report")
    ap.add_argument("--no-color", action="store_true", help="disable colored output")
    tune = ap.add_argument_group("detection thresholds")
    tune.add_argument("--brute-force", type=int, default=10, metavar="N", help="failed logins within 5 min to alert (default 10)")
    tune.add_argument("--scan-ports", type=int, default=10, metavar="N", help="blocked ports within 1 min to call a port scan (default 10)")
    return ap


# Names of text logs, including rotated copies like auth.log.1, auth.log.2.gz and secure-20261027.
LOG_NAME = re.compile(r"(\.log|\.txt|^(auth|secure|syslog|messages|kern|ufw|access|error)[\w-]*)(\.\d+)?(\.gz)?$")


def looks_binary(path: Path) -> bool:
    if path.suffix == ".gz":
        return False
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(4096)
    except OSError:
        return False


def collect(paths: List[Path]) -> List[Path]:
    """Expand folders into log files. Each file is listed once, however it was named."""
    files: List[Path] = []
    seen = set()

    def add(f: Path) -> None:
        key = f.resolve()
        if key not in seen:
            seen.add(key)
            files.append(f)

    for p in paths:
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and not f.name.startswith(".") and LOG_NAME.search(f.name) and not looks_binary(f):
                    add(f)
        else:
            add(p)
    return files


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    paths = list(args.paths)
    if args.system:
        paths += [Path(p) for p in SYSTEM_LOGS if Path(p).exists()]
    if not paths:
        print("error: give log files or folders to read, or --system (try: python3 -m logwatch samples/)", file=sys.stderr)
        return 2
    if args.brute_force < 1 or args.scan_ports < 1:
        print("error: thresholds must be at least 1", file=sys.stderr)
        return 2
    if args.timeline and (args.json or args.html):
        print("error: --timeline prints a plain-text timeline; it can't be combined with --json or --html", file=sys.stderr)
        return 2

    events, skipped, read = [], 0, 0
    for path in collect(paths):
        try:
            evs, skip = parse_file(path, args.year)
        except FileNotFoundError:
            print(f"  skip {path}: not found", file=sys.stderr)
            continue
        except PermissionError:
            print(f"  skip {path}: permission denied (try sudo)", file=sys.stderr)
            continue
        except (OSError, EOFError) as e:
            print(f"  skip {path}: {e}", file=sys.stderr)
            continue
        events += evs
        skipped += skip
        read += 1
    if not read:
        print("error: no readable log files", file=sys.stderr)
        return 1

    if args.timeline:
        print(render_timeline(events, args.timeline))
        return 0

    settings = Settings(brute_force_failures=args.brute_force, scan_ports=args.scan_ports)
    floor = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in detect(events, settings) if SEVERITY_ORDER[a.severity] >= floor]
    stats = stats_line(events, skipped, read)

    if args.json:
        print(render_json(alerts, stats))
    else:
        print(render_text(alerts, stats, color=False if args.no_color else None))
        if alerts:
            worst = alerts[0]
            print(f"\nTip: see everything {worst.ip} did with --timeline {clean(worst.ip)}")
    if args.html:
        try:
            Path(args.html).write_text(render_html(alerts, stats), encoding="utf-8")
            print(f"HTML report written to {args.html}", file=sys.stderr)
        except OSError as e:
            print(f"error: could not write {args.html}: {e}", file=sys.stderr)
            return 1
    return 3 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
