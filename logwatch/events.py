"""The structured facts we pull out of log lines."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

# Event kinds
SSH_FAIL = "ssh_fail"  # wrong password
SSH_INVALID = "ssh_invalid_user"  # username doesn't exist
SSH_OK = "ssh_ok"  # successful login
WEB = "web"  # one HTTP request
FW_BLOCK = "fw_block"  # firewall dropped a connection


@dataclass
class Event:
    time: datetime
    kind: str
    ip: str
    source: str = ""  # file:line it came from
    user: str = ""
    method: str = ""  # password / publickey for SSH, GET / POST for web
    path: str = ""
    status: int = 0
    agent: str = ""
    port: int = 0
    raw: str = ""
