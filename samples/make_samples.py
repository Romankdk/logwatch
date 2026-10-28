"""Generate the example logs in this folder. All data is fake.

Attacker addresses use 203.0.113.0/24 and 198.51.100.0/24, ranges reserved for documentation,
so they never belong to anyone real. Run: python3 samples/make_samples.py
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
rng = random.Random(42)
START = datetime(2026, 10, 27, 0, 0, 0)


def syslog(ts: datetime, prog: str, msg: str) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} webserver {prog}: {msg}"


def auth_log():
    lines = []
    pid = 1000

    def sshd(ts, msg):
        nonlocal pid
        pid += 1
        lines.append((ts, syslog(ts, f"sshd[{pid}]", msg)))

    # Normal day: the admin logs in with a key from the office network a few times.
    for hour in (8, 12, 17):
        ts = START + timedelta(hours=hour, minutes=rng.randint(0, 50))
        sshd(ts, f"Accepted publickey for alice from 192.168.1.20 port {rng.randint(40000, 60000)} ssh2")
    # One honest typo, then success.
    ts = START + timedelta(hours=9, minutes=3)
    sshd(ts, "Failed password for bob from 192.168.1.35 port 51522 ssh2")
    sshd(ts + timedelta(seconds=6), "Accepted password for bob from 192.168.1.35 port 51522 ssh2")

    # Brute force: a bot hammers root/admin for a few minutes.
    ts = START + timedelta(hours=3, minutes=14)
    for i in range(60):
        user = rng.choice(["root", "root", "admin"])
        sshd(ts + timedelta(seconds=i * 3), f"Failed password for {user} from 203.0.113.50 port {rng.randint(30000, 65000)} ssh2")

    # Username guessing: many accounts that don't exist.
    ts = START + timedelta(hours=5, minutes=40)
    for i, user in enumerate(["test", "oracle", "postgres", "ubuntu", "git", "ftpuser", "guest", "pi", "support", "user"] * 2):
        sshd(ts + timedelta(seconds=i * 20), f"Invalid user {user} from 198.51.100.23 port {rng.randint(30000, 65000)}")
        sshd(ts + timedelta(seconds=i * 20 + 1), f"Failed password for invalid user {user} from 198.51.100.23 port {rng.randint(30000, 65000)} ssh2")

    # The scary one: slow guessing against "deploy", then it works.
    ts = START + timedelta(hours=22, minutes=5)
    for i in range(15):
        sshd(ts + timedelta(seconds=i * 40), f"Failed password for deploy from 203.0.113.99 port {rng.randint(30000, 65000)} ssh2")
    sshd(ts + timedelta(seconds=15 * 40 + 12), "Accepted password for deploy from 203.0.113.99 port 48812 ssh2")

    # Noise the parser should skip.
    lines.append((START + timedelta(hours=1), syslog(START + timedelta(hours=1), "CRON[2201]", "pam_unix(cron:session): session opened for user root")))
    return [line for _, line in sorted(lines)]


def access_log():
    lines = []
    pages = ["/", "/about", "/blog", "/blog/hello-world", "/contact", "/static/site.css", "/static/app.js", "/favicon.ico"]
    browser = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"

    def req(ts, ip, method, path, status, agent=browser, size=None):
        size = size if size is not None else rng.randint(300, 9000)
        lines.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'))

    # Ordinary visitors.
    for _ in range(150):
        ts = START + timedelta(seconds=rng.randint(0, 86000))
        req(ts, f"192.168.1.{rng.randint(40, 90)}", "GET", rng.choice(pages), 200)
    for _ in range(6):  # a few honest broken links
        ts = START + timedelta(seconds=rng.randint(0, 86000))
        req(ts, f"192.168.1.{rng.randint(40, 90)}", "GET", "/old-page", 404)

    # A vulnerability scanner that announces itself and hits lots of missing pages.
    ts = START + timedelta(hours=2)
    probes = ["/admin", "/phpmyadmin/", "/wp-login.php", "/backup.zip", "/config.php", "/test.php", "/cgi-bin/",
              "/server-info", "/.DS_Store", "/console", "/manager/html", "/api/v1/debug", "/old/", "/db/", "/install.php",
              "/shell.php", "/upload/", "/tmp/", "/logs/", "/private/", "/xmlrpc.php", "/actuator/health"]
    for i, path in enumerate(probes):
        req(ts + timedelta(seconds=i * 2), "203.0.113.12", "GET", path, 404, "Mozilla/5.00 (Nikto/2.5.0)", 0)

    # Someone trying classic attacks by hand. One request for .env is answered with 200: a real leak.
    ts = START + timedelta(hours=14, minutes=20)
    attacks = [
        ("GET", "/download?file=../../../../etc/passwd", 400),
        ("GET", "/search?q=%27%20OR%20%271%27%3D%271", 500),
        ("GET", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users", 500),
        ("GET", "/comment?text=%3Cscript%3Ealert(1)%3C/script%3E", 400),
        ("GET", "/.git/config", 403),
        ("GET", "/.env", 200),
    ]
    for i, (method, path, status) in enumerate(attacks):
        req(ts + timedelta(seconds=i * 15), "203.0.113.66", method, path, status, "curl/8.4.0")
    return [line for _, line in sorted(lines)]


def ufw_log():
    lines = []

    def block(ts, src, port, proto="TCP"):
        msg = (f"[{rng.randint(10000, 99999)}.{rng.randint(100000, 999999)}] [UFW BLOCK] IN=eth0 OUT= "
               f"MAC=00:00:00:00:00:00 SRC={src} DST=192.168.1.10 LEN=44 TOS=0x00 PREC=0x00 TTL=50 ID=0 "
               f"PROTO={proto} SPT={rng.randint(30000, 65000)} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0")
        lines.append((ts, syslog(ts, "kernel", msg)))

    # Background noise: random single blocked connections.
    for _ in range(25):
        ts = START + timedelta(seconds=rng.randint(0, 86000))
        block(ts, f"198.51.100.{rng.randint(1, 254)}", rng.choice([23, 445, 3389, 8080]))
    # A port scan: the same scanner from the web log maps the server's ports in a few seconds.
    ts = START + timedelta(hours=1, minutes=58)
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306,
             3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]
    for i, port in enumerate(ports):
        block(ts + timedelta(milliseconds=i * 150), "203.0.113.12", port)
    return [line for _, line in sorted(lines)]


if __name__ == "__main__":
    for name, make in (("auth.log", auth_log), ("access.log", access_log), ("ufw.log", ufw_log)):
        (HERE / name).write_text("\n".join(make()) + "\n")
        print(f"wrote samples/{name}")
