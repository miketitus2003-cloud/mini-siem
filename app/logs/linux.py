"""
mini-siem.app.logs.linux
~~~~~~~~~~~~~~~~~~~~~~~~
Ingest and normalize Linux syslog / auth log data.

Supported formats
-----------------
* **RFC 3164** (BSD syslog) – the traditional format found in
  ``/var/log/syslog`` and ``/var/log/auth.log``.
* **RFC 5424** – structured syslog with explicit priority, version, and
  structured data elements.

The parser auto-detects the format on a per-line basis.

Security-relevant patterns (failed SSH, sudo, useradd, etc.) are
classified with specific ``event_type`` values so the alert engine can
match on them.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database import insert_raw_log, insert_normalized_event

logger = logging.getLogger("mini-siem.linux")

# ──────────────────────────────────────────────
# Severity mapping (syslog priority → SIEM severity)
# ──────────────────────────────────────────────

_SYSLOG_SEV = {
    0: "critical",  # emerg
    1: "critical",  # alert
    2: "critical",  # crit
    3: "high",      # err
    4: "medium",    # warning
    5: "low",       # notice
    6: "low",       # info
    7: "low",       # debug
}

# Facility names (for metadata)
_FACILITY = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

# ──────────────────────────────────────────────
# Regex patterns for syslog formats
# ──────────────────────────────────────────────

# RFC 3164: "Jun 15 08:23:11 host process[pid]: message"
_RFC3164 = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# RFC 5424: "<PRI>VERSION TIMESTAMP HOST APP PID MSGID SD MSG"
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:\[.*?\]|-)\s*"
    r"(?P<message>.*)$"
)

# ──────────────────────────────────────────────
# Security pattern classification
# ──────────────────────────────────────────────

_SECURITY_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": re.compile(r"Failed password for(?: invalid user)?\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE),
        "event_type": "login_failure",
        "severity": "high",
        "extract": lambda m: {"user": m.group(1), "source_ip": m.group(2)},
    },
    {
        "pattern": re.compile(r"Accepted (?:password|publickey) for\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE),
        "event_type": "login_success",
        "severity": "low",
        "extract": lambda m: {"user": m.group(1), "source_ip": m.group(2)},
    },
    {
        "pattern": re.compile(r"session opened for user\s+(\S+)", re.IGNORECASE),
        "event_type": "session_opened",
        "severity": "low",
        "extract": lambda m: {"user": m.group(1)},
    },
    {
        "pattern": re.compile(r"session closed for user\s+(\S+)", re.IGNORECASE),
        "event_type": "session_closed",
        "severity": "low",
        "extract": lambda m: {"user": m.group(1)},
    },
    {
        "pattern": re.compile(
            r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)",
            re.IGNORECASE,
        ),
        "event_type": "sudo_command",
        "severity": "medium",
        "extract": lambda m: {
            "user": m.group("user"),
            "target_user": m.group("target"),
            "command": m.group("cmd"),
        },
    },
    {
        "pattern": re.compile(r"authentication failure.*user=(\S+)", re.IGNORECASE),
        "event_type": "login_failure",
        "severity": "high",
        "extract": lambda m: {"user": m.group(1)},
    },
    {
        "pattern": re.compile(r"new user:.*name=(\S+?)(?:,|$)", re.IGNORECASE),
        "event_type": "account_created",
        "severity": "medium",
        "extract": lambda m: {"user": m.group(1)},
    },
    {
        "pattern": re.compile(r"delete user '(\S+)'", re.IGNORECASE),
        "event_type": "account_deleted",
        "severity": "medium",
        "extract": lambda m: {"user": m.group(1)},
    },
    {
        "pattern": re.compile(r"add '(\S+)' to group '(\S+)'", re.IGNORECASE),
        "event_type": "group_member_added",
        "severity": "medium",
        "extract": lambda m: {"user": m.group(1), "group": m.group(2)},
    },
    {
        "pattern": re.compile(r"COMMAND=.*(?:passwd|shadow|sudoers)", re.IGNORECASE),
        "event_type": "sensitive_file_access",
        "severity": "high",
        "extract": lambda m: {},
    },
    {
        "pattern": re.compile(r"Unauthorized|permission denied|access denied", re.IGNORECASE),
        "event_type": "access_denied",
        "severity": "medium",
        "extract": lambda m: {},
    },
]

# ──────────────────────────────────────────────
# Parsing helpers
# ──────────────────────────────────────────────

def _parse_rfc3164_timestamp(ts_str: str, year: Optional[int] = None) -> str:
    """Convert BSD syslog timestamp to ISO-8601.

    BSD timestamps lack a year, so we default to the current year.
    """
    year = year or datetime.now(timezone.utc).year
    try:
        dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def _classify_message(message: str, process: str) -> Dict[str, Any]:
    """Run message through security patterns and return classification."""
    for rule in _SECURITY_PATTERNS:
        match = rule["pattern"].search(message)
        if match:
            extra = rule["extract"](match)
            return {
                "event_type": rule["event_type"],
                "severity": rule["severity"],
                "extra": extra,
            }

    # Fallback classification by process name
    proc_lower = process.lower()
    if "sshd" in proc_lower:
        return {"event_type": "ssh_event", "severity": "low", "extra": {}}
    if "sudo" in proc_lower:
        return {"event_type": "sudo_event", "severity": "medium", "extra": {}}
    if "cron" in proc_lower:
        return {"event_type": "cron_event", "severity": "low", "extra": {}}
    if "kernel" in proc_lower or "systemd" in proc_lower:
        return {"event_type": "system_event", "severity": "low", "extra": {}}

    return {"event_type": "linux_generic", "severity": "low", "extra": {}}


def parse_syslog_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single syslog line into a normalized event dict.

    Tries RFC 5424 first, then falls back to RFC 3164.
    """
    line = line.strip()
    if not line:
        return None

    # Try RFC 5424
    m = _RFC5424.match(line)
    if m:
        pri = int(m.group("pri"))
        facility = pri >> 3
        sev_num = pri & 0x07
        ts_raw = m.group("timestamp")
        try:
            timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).isoformat()
        except ValueError:
            timestamp = datetime.now(timezone.utc).isoformat()

        host = m.group("host")
        process = m.group("app")
        message = m.group("message") or ""

        classification = _classify_message(message, process)
        extra = classification["extra"]

        return {
            "timestamp": timestamp,
            "source": "linux",
            "event_type": classification["event_type"],
            "severity": classification["severity"],
            "host": host,
            "user": extra.get("user", ""),
            "process": process,
            "message": message[:2000],
            "metadata_json": json.dumps({
                "facility": _FACILITY.get(facility, str(facility)),
                "syslog_severity": sev_num,
                "pid": m.group("pid"),
                "msgid": m.group("msgid"),
                "extra": extra,
            }),
        }

    # Try RFC 3164
    m = _RFC3164.match(line)
    if m:
        timestamp = _parse_rfc3164_timestamp(m.group("timestamp"))
        host = m.group("host")
        process = m.group("process")
        message = m.group("message")
        pid = m.group("pid") or ""

        classification = _classify_message(message, process)
        extra = classification["extra"]

        return {
            "timestamp": timestamp,
            "source": "linux",
            "event_type": classification["event_type"],
            "severity": classification["severity"],
            "host": host,
            "user": extra.get("user", ""),
            "process": process,
            "message": message[:2000],
            "metadata_json": json.dumps({
                "facility": "unknown",
                "pid": pid,
                "extra": extra,
            }),
        }

    logger.debug("Unrecognized syslog format: %s", line[:120])
    return None


# ──────────────────────────────────────────────
# Ingestion entry points
# ──────────────────────────────────────────────

def ingest_syslog_lines(lines: List[str], db_path: Optional[str] = None) -> List[int]:
    """Parse and store a batch of syslog lines.

    Returns a list of ``normalized_events`` row IDs.
    """
    event_ids: List[int] = []
    for line in lines:
        if not line.strip():
            continue
        raw_id = insert_raw_log("linux", line.strip(), db_path=db_path)
        parsed = parse_syslog_line(line)
        if parsed is None:
            continue
        parsed["raw_log_id"] = raw_id
        eid = insert_normalized_event(parsed, db_path=db_path)
        event_ids.append(eid)
    logger.info("Ingested %d Linux syslog events", len(event_ids))
    return event_ids


def ingest_syslog_file(
    path: str,
    max_lines: int = 10_000,
    db_path: Optional[str] = None,
) -> List[int]:
    """Read a syslog file from disk and ingest up to *max_lines* entries."""
    if not os.path.isfile(path):
        logger.warning("Syslog file not found: %s", path)
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = []
        for i, raw_line in enumerate(fh):
            if i >= max_lines:
                break
            lines.append(raw_line)
    return ingest_syslog_lines(lines, db_path=db_path)


def tail_syslog(
    path: str = "/var/log/syslog",
    num_lines: int = 100,
    db_path: Optional[str] = None,
) -> List[int]:
    """Read the last *num_lines* of a syslog file and ingest them.

    Useful for periodic polling on a live system.
    """
    if not os.path.isfile(path):
        logger.info("Cannot tail %s — file does not exist", path)
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        all_lines = fh.readlines()
    tail = all_lines[-num_lines:]
    return ingest_syslog_lines(tail, db_path=db_path)


# ──────────────────────────────────────────────
# Demo / sample data generator
# ──────────────────────────────────────────────

_SAMPLE_SYSLOG = [
    "Jun 15 08:20:01 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
    "Jun 15 08:20:03 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54322 ssh2",
    "Jun 15 08:20:05 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54323 ssh2",
    "Jun 15 08:20:07 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54324 ssh2",
    "Jun 15 08:20:09 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54325 ssh2",
    "Jun 15 08:20:11 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54326 ssh2",
    "Jun 15 08:21:00 web01 sshd[12346]: Accepted publickey for deploy from 10.0.0.5 port 40022 ssh2",
    "Jun 15 08:21:01 web01 systemd-logind[800]: session opened for user deploy by (uid=0)",
    "Jun 15 08:22:15 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx",
    "Jun 15 08:23:00 web01 useradd[13000]: new user: name=backdoor_user, UID=1050, GID=1050, home=/home/backdoor_user, shell=/bin/bash",
    "Jun 15 08:24:00 web01 usermod[13001]: add 'backdoor_user' to group 'sudo'",
    "Jun 15 08:25:00 db01 sshd[14000]: Accepted password for dbadmin from 10.0.0.10 port 22 ssh2",
    "Jun 15 08:25:01 db01 sudo: dbadmin : TTY=pts/1 ; PWD=/var/lib/mysql ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
    "Jun 15 08:30:00 web01 CRON[15000]: (root) CMD (/usr/local/bin/backup.sh)",
    "Jun 15 09:00:00 web01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:xx SRC=203.0.113.50 DST=10.0.0.1 PROTO=TCP DPT=22 SPT=12345",
    "Jun 15 09:05:00 web01 sshd[16000]: Failed password for root from 203.0.113.50 port 55555 ssh2",
    "Jun 15 09:05:02 web01 sshd[16000]: Failed password for root from 203.0.113.50 port 55556 ssh2",
    "Jun 15 09:05:04 web01 sshd[16000]: Failed password for root from 203.0.113.50 port 55557 ssh2",
]


def load_sample_data(db_path: Optional[str] = None) -> List[int]:
    """Insert realistic sample Linux syslog events for demonstration."""
    return ingest_syslog_lines(_SAMPLE_SYSLOG, db_path=db_path)
