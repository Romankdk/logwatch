import contextlib
import gzip
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from logwatch.__main__ import main
from logwatch.detect import Settings, classify_request, detect
from logwatch.events import FW_BLOCK, SSH_FAIL, SSH_OK, Event
from logwatch.parsers import parse_lines
from logwatch.report import clean, render_html

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
T0 = datetime(2026, 10, 27, 12, 0, 0)


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


def ssh_line(seconds, msg):
    ts = T0 + timedelta(seconds=seconds)
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} host sshd[1]: {msg}"


class ParserTests(unittest.TestCase):
    def test_ssh_formats(self):
        lines = [
            "Oct 27 03:14:07 web sshd[42]: Failed password for root from 203.0.113.5 port 5000 ssh2",
            "Oct 27 03:14:09 web sshd[42]: Failed password for invalid user bob from 203.0.113.5 port 5000 ssh2",
            "2026-10-27T03:14:10.123456+00:00 web sshd[43]: Accepted publickey for alice from 192.168.1.2 port 22 ssh2",
            "Oct 27 03:14:11 web sshd[44]: Invalid user admin from 203.0.113.5 port 5001",
            "Oct 27 03:14:12 web CRON[9]: session opened",
        ]
        events, skipped = parse_lines(lines, year=2026)
        self.assertEqual([(e.kind, e.user, e.ip) for e in events], [
            ("ssh_fail", "root", "203.0.113.5"), ("ssh_fail", "bob", "203.0.113.5"),
            ("ssh_ok", "alice", "192.168.1.2"), ("ssh_invalid_user", "admin", "203.0.113.5")])
        self.assertEqual(skipped, 1)
        self.assertEqual(events[0].time, datetime(2026, 10, 27, 3, 14, 7))

    def test_web_and_firewall(self):
        web = '203.0.113.9 - - [27/Oct/2026:14:21:15 +0000] "GET /.env HTTP/1.1" 200 19 "-" "curl/8.4.0"'
        fw = ("Oct 27 01:58:00 web kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.12 DST=10.0.0.1 "
              "LEN=44 PROTO=TCP SPT=1234 DPT=22 WINDOW=1024")
        (w, f), skipped = parse_lines([web, fw], year=2026)
        self.assertEqual((w.kind, w.ip, w.path, w.status, w.agent), ("web", "203.0.113.9", "/.env", 200, "curl/8.4.0"))
        self.assertEqual((f.kind, f.ip, f.port), (FW_BLOCK, "203.0.113.12", 22))
        self.assertEqual(skipped, 0)


class ParserRobustnessTests(unittest.TestCase):
    def test_forged_ip_in_username_is_ignored(self):
        line = "Oct 27 03:14:07 web sshd[1]: Failed password for invalid user root from 10.0.0.1 port 22 from 203.0.113.5 port 5000 ssh2"
        (e,), _ = parse_lines([line], year=2026)
        self.assertEqual(e.ip, "203.0.113.5")
        self.assertEqual(e.user, "root from 10.0.0.1 port 22")

    def test_impossible_dates_are_skipped_not_fatal(self):
        events, skipped = parse_lines(["2026-13-45T00:00:00 host sshd[1]: x", "Feb 30 00:00:00 h sshd[1]: x"], year=2026)
        self.assertEqual((events, skipped), ([], 2))

    def test_repeated_message_expands(self):
        line = "Oct 27 03:14:07 web sshd[1]: message repeated 50 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]"
        events, _ = parse_lines([line], year=2026)
        self.assertEqual(len(events), 50)
        self.assertEqual({(e.kind, e.ip) for e in events}, {(SSH_FAIL, "203.0.113.5")})

    def test_year_rollover(self):
        lines = ["Dec 31 23:59:00 h sshd[1]: Invalid user a from 203.0.113.1 port 1",
                 "Jan  1 00:01:00 h sshd[1]: Invalid user b from 203.0.113.1 port 1"]
        dec, jan = parse_lines(lines, now=datetime(2027, 1, 1, 9, 0))[0]
        self.assertEqual((dec.time.year, jan.time.year), (2026, 2027))
        self.assertLess(dec.time, jan.time)
        (feb29,), _ = parse_lines(["Feb 29 10:00:00 h sshd[1]: Invalid user a from 203.0.113.1 port 1"], year=2025)
        self.assertEqual(feb29.time.year, 2024)

    def test_times_kept_as_the_server_wrote_them(self):
        web = '203.0.113.9 - - [27/Oct/2026:14:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "x"'
        iso = "2026-10-27T14:00:05Z host sshd[1]: Invalid user a from 203.0.113.9 port 1"
        plain = "Oct 27 14:00:10 host sshd[1]: Invalid user b from 203.0.113.9 port 1"
        (w, i, p), _ = parse_lines([web, iso, plain], year=2026)
        self.assertEqual([e.time.strftime("%H:%M:%S") for e in (w, i, p)], ["14:00:00", "14:00:05", "14:00:10"])

    def test_folder_skips_binaries_and_duplicates(self):
        from logwatch.__main__ import collect
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "auth.log").write_text("x\n")
            (Path(d) / "auth.log.1").write_text("x\n")
            (Path(d) / "lastlog").write_bytes(b"\x00" * 100)
            (Path(d) / "wtmp.log").write_bytes(b"\x00binary")
            names = [p.name for p in collect([Path(d), Path(d) / "auth.log"])]
        self.assertEqual(names, ["auth.log", "auth.log.1"])


class SshDetectionTests(unittest.TestCase):
    def alerts(self, lines, **settings):
        events, _ = parse_lines(lines, year=2026)
        return detect(events, Settings(**settings))

    def test_brute_force_threshold(self):
        lines = [ssh_line(i, f"Failed password for root from 203.0.113.1 port {i} ssh2") for i in range(10)]
        self.assertEqual([a.rule for a in self.alerts(lines)], ["ssh-brute-force"])
        self.assertEqual(self.alerts(lines[:9]), [])

    def test_slow_failures_outside_window_are_not_brute_force(self):
        lines = [ssh_line(i * 600, f"Failed password for root from 203.0.113.1 port {i} ssh2") for i in range(12)]
        self.assertNotIn("ssh-brute-force", [a.rule for a in self.alerts(lines)])

    def test_login_after_failures_is_critical(self):
        lines = [ssh_line(i * 60, f"Failed password for deploy from 203.0.113.2 port {i} ssh2") for i in range(5)]
        lines.append(ssh_line(400, "Accepted password for deploy from 203.0.113.2 port 9 ssh2"))
        alerts = self.alerts(lines)
        self.assertEqual(alerts[0].rule, "ssh-login-after-failures")
        self.assertEqual(alerts[0].severity, "critical")

    def test_old_typos_do_not_make_later_logins_critical(self):
        lines = [ssh_line(i * 86400, f"Failed password for admin from 192.168.1.5 port {i} ssh2") for i in range(5)]
        lines += [ssh_line(5 * 86400 + i * 3600, "Accepted password for admin from 192.168.1.5 port 9 ssh2") for i in range(10)]
        self.assertEqual(self.alerts(lines), [])

    def test_one_alert_per_burst(self):
        lines = [ssh_line(i, f"Failed password for x from 203.0.113.2 port {i} ssh2") for i in range(6)]
        lines += [ssh_line(100 + i * 60, "Accepted password for x from 203.0.113.2 port 9 ssh2") for i in range(3)]
        self.assertEqual([a.rule for a in self.alerts(lines)], ["ssh-login-after-failures"])

    def test_honest_typo_is_not_an_alert(self):
        lines = [ssh_line(0, "Failed password for bob from 192.168.1.35 port 1 ssh2"),
                 ssh_line(5, "Accepted password for bob from 192.168.1.35 port 1 ssh2")]
        self.assertEqual(self.alerts(lines), [])

    def test_invalid_user_lines_counted_once(self):
        lines = []
        for i, user in enumerate(["a", "b", "c", "d", "e"]):
            lines.append(ssh_line(i * 10, f"Invalid user {user} from 203.0.113.3 port 1"))
            lines.append(ssh_line(i * 10 + 1, f"Failed password for invalid user {user} from 203.0.113.3 port 1 ssh2"))
        alerts = self.alerts(lines)
        self.assertEqual([a.rule for a in alerts], ["ssh-user-guessing"])
        self.assertEqual(alerts[0].count, 5)


class WebAndFirewallTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_request("/dl?f=..%2F..%2Fetc%2Fpasswd"), ["path traversal", "sensitive file probe"])
        self.assertEqual(classify_request("/p?id=1%20UNION%20SELECT%201,2"), ["SQL injection"])
        self.assertEqual(classify_request("/q?x=%3Cscript%3E"), ["cross-site scripting"])
        self.assertEqual(classify_request("/blog/hello-world?page=2"), [])
        self.assertEqual(classify_request("/static/app.js"), [])

    def test_successful_attack_is_high(self):
        events = [Event(T0, "web", "203.0.113.4", path="/.env", status=200, raw="x"),
                  Event(T0, "web", "203.0.113.5", path="/.env", status=404, raw="x")]
        sev = {a.ip: a.severity for a in detect(events) if a.rule == "web-attack"}
        self.assertEqual(sev, {"203.0.113.4": "high", "203.0.113.5": "medium"})

    def test_port_scan_needs_distinct_ports_quickly(self):
        many = [Event(T0 + timedelta(seconds=i), FW_BLOCK, "203.0.113.6", port=1000 + i) for i in range(10)]
        same = [Event(T0 + timedelta(seconds=i), FW_BLOCK, "203.0.113.7", port=23) for i in range(30)]
        self.assertEqual([a.ip for a in detect(many + same)], ["203.0.113.6"])

    def test_icmp_does_not_count_as_a_port(self):
        nine = [Event(T0 + timedelta(seconds=i), FW_BLOCK, "203.0.113.8", port=2000 + i) for i in range(9)]
        icmp = [Event(T0, FW_BLOCK, "203.0.113.8", port=0)]
        self.assertEqual(detect(nine + icmp), [])


class EndToEndTests(unittest.TestCase):
    def test_samples(self):
        code, out = run([str(SAMPLES), "--json"])
        self.assertEqual(code, 3)
        alerts = json.loads(out)["alerts"]
        rules = sorted((a["rule"], a["ip"]) for a in alerts)
        self.assertEqual(rules, [
            ("port-scan", "203.0.113.12"),
            ("ssh-brute-force", "198.51.100.23"),
            ("ssh-brute-force", "203.0.113.50"),
            ("ssh-login-after-failures", "203.0.113.99"),
            ("ssh-user-guessing", "198.51.100.23"),
            ("web-attack", "203.0.113.66"),
            ("web-scanner", "203.0.113.12"),
        ])
        # Normal visitors, the admin and the honest typo are never flagged.
        self.assertFalse([a for a in alerts if a["ip"].startswith("192.168.1.")])
        # Alert times match the evidence lines, whatever time zone this computer is in.
        first = {a["rule"]: a["first"] for a in alerts}
        self.assertEqual(first["web-scanner"], "2026-10-27 02:00:00")
        self.assertEqual(first["web-attack"], "2026-10-27 14:20:00")
        self.assertEqual(first["port-scan"], "2026-10-27 01:58:00")

    def test_gzip_and_clean_logs(self):
        with tempfile.TemporaryDirectory() as d:
            with gzip.open(Path(d) / "auth.log.gz", "wt") as f:
                f.write(ssh_line(0, "Accepted publickey for alice from 192.168.1.20 port 1 ssh2") + "\n")
            code, out = run([d])
        self.assertEqual(code, 0)
        self.assertIn("No signs of attacks found", out)

    def test_errors(self):
        self.assertEqual(run([])[0], 2)
        self.assertEqual(run(["/nonexistent/file.log"])[0], 1)
        self.assertEqual(run([str(SAMPLES), "--brute-force", "0"])[0], 2)
        self.assertEqual(run([str(SAMPLES), "--timeline", "203.0.113.99", "--json"])[0], 2)
        self.assertEqual(run([str(SAMPLES), "--html", "/nonexistent/dir/r.html"])[0], 1)

    def test_hostile_log_content_is_escaped(self):
        evil = '203.0.113.8 - - [27/Oct/2026:14:21:15 +0000] "GET /<script>x</script>/.env HTTP/1.1" 200 1 "-" "\x1b[2Jcurl"'
        events, _ = parse_lines([evil], year=2026)
        page = render_html(detect(events), "stats")
        self.assertNotIn("<script>x", page)
        self.assertNotIn("\x1b", clean(evil))


if __name__ == "__main__":
    unittest.main()
