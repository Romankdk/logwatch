# logwatch

A log-based intrusion detector written in pure Python (standard library only, Python 3.9+).

It reads SSH, web server and firewall logs, and turns thousands of lines into a short list of
alerts a person can act on: who attacked, how, when, whether it worked, and what to do next.

It's the defensive companion to [port-scanner](https://github.com/Romankdk/port-scanner):
the scanner shows **which doors are open**; logwatch shows **who is knocking on them**.

## Try it

```bash
git clone https://github.com/Romankdk/logwatch.git
cd logwatch
python3 -m logwatch samples/
```

The `samples/` folder contains a fake day of logs from a small web server with several attacks
hidden among normal traffic. All addresses are from ranges reserved for documentation.

```
[CRITICAL] ssh-login-after-failures from 203.0.113.99
  Logged in as 'deploy' (password) after 15 failed attempts
  When: 2026-10-27 22:05:00 -> 22:15:12
  What to do: Treat the 'deploy' account as compromised: change its password, check what it did,
  and look for new SSH keys or users.
```

## What it detects

| Alert | Severity | Meaning |
|---|---|---|
| `ssh-login-after-failures` | critical | Many failed logins, then a success from the same IP: a likely break-in |
| `ssh-brute-force` | high | Many failed logins from one IP in a short time |
| `ssh-user-guessing` | medium | One IP trying many different usernames |
| `web-attack` | high / medium | Requests that look like path traversal, SQL injection, XSS, command injection or probing for secret files; **high** if any got a success response |
| `web-scanner` | medium | Automated vulnerability scanners (by user agent or bursts of "not found" pages) |
| `port-scan` | medium | One IP blocked by the firewall on many different ports within a minute |

## Supported logs

| Log | Typical location |
|---|---|
| SSH (OpenSSH) | `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/Fedora) |
| Web servers (Apache/Nginx combined format) | `/var/log/nginx/access.log`, `/var/log/apache2/access.log` |
| Firewall (UFW / iptables) | `/var/log/ufw.log`, `/var/log/kern.log` |

The format of each line is detected automatically; `.gz` rotated logs are read too.

## Usage

```bash
python3 -m logwatch samples/                              # a folder of logs
python3 -m logwatch auth.log access.log --html report.html
python3 -m logwatch samples/ --timeline 203.0.113.99      # everything one IP did
python3 -m logwatch samples/ --min-severity high          # only serious alerts
python3 -m logwatch samples/ --json                       # for other tools
sudo python3 -m logwatch --system                         # standard Linux log locations
```

To analyse another computer, either run logwatch on it or copy its log files to yours.
Syslog lines don't include the year; use `--year 2025` for older logs.

Exit codes: `0` no alerts, `1` error, `2` bad arguments, `3` alerts found.

## How it works

```
log files -> parsers.py  -> events (time, kind, ip, user, path, ...)
          -> detect.py   -> rules group events by IP and look for patterns in time windows
          -> report.py   -> terminal, JSON or HTML
```

Thresholds can be tuned with `--brute-force N` and `--scan-ports N`.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 samples/make_samples.py   # regenerate the sample logs
```

## Limits

- Pattern-based: it finds common, noisy attacks, not careful ones that blend in.
- Timestamps with a time zone (web logs, ISO syslog) are converted to this computer's local time; classic
  syslog lines have no zone and are assumed to already be local.
- Syslog lines have no year: they are assumed to be from the last 12 months unless you pass `--year`.
- Windows Event Logs and the macOS unified log are not supported yet.
