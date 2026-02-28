"""
mini-siem.app.logs.firewall
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Ingest and normalize firewall/perimeter log data.

Supports a simple key=value syslog-style format produced by most
commercial and open-source firewalls (pfSense, iptables, Fortinet, etc.).

Example line::

    Jan 15 08:22:11 fw01 pf: rule 5/0(match): block in on em0: \
        10.0.0.55.52341 > 192.168.1.1.22: tcp

Normalized fields
-----------------
event_type  One of: connection_blocked, connection_allowed, port_scan,
            dns_query, traffic_spike
severity    Derived from action (block→high, allow→low) and port
host        Firewall hostname
user        n/a (empty)
process     Firewall process/daemon name
message     Human-readable summary
metadata    src_ip, dst_ip, src_port, dst_port, proto, action, rule
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database import insert_raw_log, insert_normalized_event

logger = logging.getLogger("mini-siem.firewall")

# Sensitive ports that elevate severity
_HIGH_RISK_PORTS = {22, 23, 3389, 445, 139, 1433, 3306, 5432, 6379, 27017}

# Regex for a generic firewall CSV / KV line
# Handles both "key=value" and positional formats.
_KV_RE = re.compile(r'(\w+)=(\"[^\"]*\"|[^\s,]+)')

# Syslog-style header: Month Day HH:MM:SS hostname process
_SYSLOG_HDR = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?):\s+(?P<rest>.*)$"
)


def _derive_event_type(action: str, dst_port: int) -> str:
    action_lower = action.lower()
    if "block" in action_lower or "deny" in action_lower or "drop" in action_lower:
        return "connection_blocked"
    if dst_port in _HIGH_RISK_PORTS:
        return "connection_allowed"
    return "connection_allowed"


def _derive_severity(event_type: str, dst_port: int, action: str) -> str:
    if event_type == "connection_blocked" and dst_port in _HIGH_RISK_PORTS:
        return "high"
    if event_type == "connection_blocked":
        return "medium"
    if dst_port in _HIGH_RISK_PORTS:
        return "medium"
    return "low"


def parse_firewall_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one firewall log line into a normalized event dict."""
    line = line.strip()
    if not line:
        return None

    host = "firewall"
    proc = "fw"
    rest = line
    timestamp = datetime.now(timezone.utc).isoformat()

    m = _SYSLOG_HDR.match(line)
    if m:
        host = m.group("host")
        proc = m.group("proc").rstrip("[]0123456789")
        rest = m.group("rest")
        # Build a best-effort timestamp (no year in syslog)
        year = datetime.now(timezone.utc).year
        try:
            ts_str = f"{m.group('month')} {m.group('day')} {year} {m.group('time')} +0000"
            timestamp = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S %z").isoformat()
        except ValueError:
            pass

    # Extract key=value pairs
    kv = {k: v.strip('"') for k, v in _KV_RE.findall(rest)}

    src_ip = kv.get("src", kv.get("src_ip", kv.get("SRC", "")))
    dst_ip = kv.get("dst", kv.get("dst_ip", kv.get("DST", "")))
    src_port_s = kv.get("spt", kv.get("src_port", kv.get("SPT", "0")))
    dst_port_s = kv.get("dpt", kv.get("dst_port", kv.get("DPT", "0")))
    proto = kv.get("proto", kv.get("PROTO", "tcp")).upper()
    action = kv.get("action", kv.get("ACTION", ""))

    # Fallback: try to infer action from keywords
    rest_lower = rest.lower()
    if not action:
        if any(w in rest_lower for w in ("block", "deny", "drop", "reject")):
            action = "block"
        elif any(w in rest_lower for w in ("accept", "allow", "pass")):
            action = "allow"
        else:
            action = "allow"

    # Fallback: try to parse pf/iptables inline format
    # e.g. "10.0.0.55.52341 > 192.168.1.1.22"
    if not src_ip:
        inline = re.search(
            r"([\d.]+)\.(\d+)\s*[>→]\s*([\d.]+)\.(\d+)",
            rest,
        )
        if inline:
            src_ip = inline.group(1)
            src_port_s = inline.group(2)
            dst_ip = inline.group(3)
            dst_port_s = inline.group(4)

    try:
        dst_port = int(dst_port_s)
    except (ValueError, TypeError):
        dst_port = 0
    try:
        src_port = int(src_port_s)
    except (ValueError, TypeError):
        src_port = 0

    event_type = _derive_event_type(action, dst_port)
    severity = _derive_severity(event_type, dst_port, action)

    msg_parts = [f"Action={action.upper()}"]
    if src_ip:
        msg_parts.append(f"Src={src_ip}:{src_port}")
    if dst_ip:
        msg_parts.append(f"Dst={dst_ip}:{dst_port}")
    if proto:
        msg_parts.append(f"Proto={proto}")

    return {
        "timestamp": timestamp,
        "source": "firewall",
        "event_type": event_type,
        "severity": severity,
        "host": host,
        "user": "",
        "process": proc,
        "message": " | ".join(msg_parts),
        "metadata_json": json.dumps({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "action": action,
            "ip": src_ip,  # top-level for top_ips query
        }),
    }


def ingest_firewall_lines(lines: List[str], db_path: Optional[str] = None) -> List[int]:
    """Ingest a list of raw firewall log lines. Returns normalized event IDs."""
    event_ids: List[int] = []
    for line in lines:
        if not line.strip():
            continue
        raw_id = insert_raw_log("firewall", line, db_path=db_path)
        parsed = parse_firewall_line(line)
        if parsed is None:
            continue
        parsed["raw_log_id"] = raw_id
        eid = insert_normalized_event(parsed, db_path=db_path)
        event_ids.append(eid)
    logger.info("Ingested %d firewall events", len(event_ids))
    return event_ids


# ──────────────────────────────────────────────
# Sample data
# ──────────────────────────────────────────────

_SAMPLE_LINES = [
    "Jan 15 08:22:11 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:12 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:14 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:15 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:16 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:18 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:19 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:22:20 fw01 pf: action=block src=10.0.0.55 dst=192.168.1.1 dpt=22 proto=TCP",
    "Jan 15 08:30:00 fw01 pf: action=allow src=172.16.0.10 dst=8.8.8.8 dpt=443 proto=TCP",
    "Jan 15 08:31:05 fw01 pf: action=allow src=172.16.0.11 dst=8.8.8.8 dpt=80 proto=TCP",
    "Jan 15 08:35:22 fw01 pf: action=block src=203.0.113.5 dst=192.168.1.10 dpt=3389 proto=TCP",
    "Jan 15 08:35:23 fw01 pf: action=block src=203.0.113.5 dst=192.168.1.10 dpt=3389 proto=TCP",
    "Jan 15 08:35:24 fw01 pf: action=block src=203.0.113.5 dst=192.168.1.10 dpt=3389 proto=TCP",
    "Jan 15 09:00:00 fw01 pf: action=allow src=192.168.1.50 dst=10.0.0.1 dpt=8080 proto=TCP",
    "Jan 15 09:10:11 fw01 pf: action=block src=198.51.100.9 dst=192.168.1.5 dpt=445 proto=TCP",
    "Jan 15 09:10:12 fw01 pf: action=block src=198.51.100.9 dst=192.168.1.6 dpt=445 proto=TCP",
    "Jan 15 09:10:13 fw01 pf: action=block src=198.51.100.9 dst=192.168.1.7 dpt=445 proto=TCP",
    "Jan 15 10:00:00 fw01 pf: action=allow src=172.16.0.20 dst=172.16.10.5 dpt=5432 proto=TCP",
]


def load_sample_data(db_path: Optional[str] = None) -> List[int]:
    """Insert realistic sample firewall events for demonstration."""
    return ingest_firewall_lines(_SAMPLE_LINES, db_path=db_path)
