"""
mini-siem.app.logs.windows
~~~~~~~~~~~~~~~~~~~~~~~~~~
Ingest and normalize Windows Event Log data.

Supports two ingestion paths:

1. **Live collection** (Windows hosts only) – uses the ``pywin32`` library
   to read directly from the Windows Event Log API.
2. **EVTX / XML import** – parses exported ``.evtx`` XML fragments so
   the SIEM can be demonstrated on any platform.

Normalized fields
-----------------
event_type   One of the canonical types defined in ``EVENT_TYPE_MAP``.
severity     Derived from the Windows *Level* keyword.
host         Machine that generated the event.
user         Account associated with the event.
process      Originating process or provider name.
message      Human-readable description.
metadata     ``EventID``, ``Channel``, ``Keywords`` preserved verbatim.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database import insert_raw_log, insert_normalized_event

logger = logging.getLogger("mini-siem.windows")

# ──────────────────────────────────────────────
# Windows Event ID → canonical event type mapping
# ──────────────────────────────────────────────

EVENT_TYPE_MAP: Dict[int, str] = {
    # Authentication
    4624: "login_success",
    4625: "login_failure",
    4634: "logoff",
    4648: "explicit_credential_use",
    4672: "privilege_assigned",
    # Account management
    4720: "account_created",
    4722: "account_enabled",
    4725: "account_disabled",
    4726: "account_deleted",
    4740: "account_lockout",
    # Privilege escalation
    4732: "group_member_added",
    4756: "group_member_added",
    # Process execution
    4688: "process_created",
    4689: "process_terminated",
    # Object access & policy
    4663: "object_access",
    4719: "audit_policy_changed",
    # Log management
    1102: "log_cleared",
    104:  "log_cleared",
}

# Windows severity levels
LEVEL_SEVERITY: Dict[str, str] = {
    "0": "low",        # LogAlways
    "1": "critical",   # Critical
    "2": "high",       # Error
    "3": "medium",     # Warning
    "4": "low",        # Information
    "5": "low",        # Verbose
}

# ──────────────────────────────────────────────
# XML namespace used in Windows Event XML
# ──────────────────────────────────────────────

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


# ──────────────────────────────────────────────
# Parsing helpers
# ──────────────────────────────────────────────

def _text(element: Optional[ET.Element], default: str = "") -> str:
    if element is not None and element.text:
        return element.text.strip()
    return default


def parse_event_xml(xml_str: str) -> Optional[Dict[str, Any]]:
    """Parse a single ``<Event>`` XML element into a normalized dict.

    Returns ``None`` if the XML is malformed or missing critical fields.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        logger.warning("Malformed Windows event XML — skipped")
        return None

    # NOTE: Element.__bool__ returns False when the element has no children,
    # so we must use ``is None`` checks instead of ``or`` for fallback lookups.
    system = root.find("e:System", _NS)
    if system is None:
        system = root.find("System")
    if system is None:
        logger.warning("Missing <System> element in event XML")
        return None

    event_id_el = system.find("e:EventID", _NS)
    if event_id_el is None:
        event_id_el = system.find("EventID")
    event_id = int(_text(event_id_el, "0"))

    provider_el = system.find("e:Provider", _NS)
    if provider_el is None:
        provider_el = system.find("Provider")
    provider = (
        provider_el.attrib.get("Name", "Unknown") if provider_el is not None else "Unknown"
    )

    time_el = system.find("e:TimeCreated", _NS)
    if time_el is None:
        time_el = system.find("TimeCreated")
    time_str = (
        time_el.attrib.get("SystemTime", "") if time_el is not None else ""
    )
    try:
        timestamp = datetime.fromisoformat(time_str.replace("Z", "+00:00")).isoformat()
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc).isoformat()

    computer_el = system.find("e:Computer", _NS)
    if computer_el is None:
        computer_el = system.find("Computer")
    computer = _text(computer_el, "unknown-host")

    level_el = system.find("e:Level", _NS)
    if level_el is None:
        level_el = system.find("Level")
    level_val = _text(level_el, "4")

    channel_el = system.find("e:Channel", _NS)
    if channel_el is None:
        channel_el = system.find("Channel")
    channel = _text(channel_el, "Unknown")

    keywords_el = system.find("e:Keywords", _NS)
    if keywords_el is None:
        keywords_el = system.find("Keywords")
    keywords = _text(keywords_el)

    # Extract EventData or UserData for the message body
    event_data = root.find("e:EventData", _NS)
    if event_data is None:
        event_data = root.find("EventData")
    data_pairs: Dict[str, str] = {}
    if event_data is not None:
        for data_el in event_data:
            name = data_el.attrib.get("Name", data_el.tag)
            data_pairs[name] = _text(data_el)

    user_name = data_pairs.get("TargetUserName") or data_pairs.get("SubjectUserName", "")
    process_name = data_pairs.get("NewProcessName") or data_pairs.get("ProcessName", "")

    event_type = EVENT_TYPE_MAP.get(event_id, f"windows_{event_id}")
    severity = LEVEL_SEVERITY.get(level_val, "low")

    # Promote severity for security-critical event IDs
    if event_id in (4625, 4740, 1102, 104):
        severity = "high"
    if event_id == 4672:
        severity = "medium"

    message_parts = [f"EventID={event_id}", f"Channel={channel}", f"Provider={provider}"]
    if user_name:
        message_parts.append(f"User={user_name}")
    if process_name:
        message_parts.append(f"Process={process_name}")
    if data_pairs:
        extra = "; ".join(f"{k}={v}" for k, v in data_pairs.items() if k not in ("TargetUserName", "SubjectUserName", "NewProcessName", "ProcessName"))
        if extra:
            message_parts.append(extra)
    message = " | ".join(message_parts)

    return {
        "timestamp": timestamp,
        "source": "windows",
        "event_type": event_type,
        "severity": severity,
        "host": computer,
        "user": user_name,
        "process": process_name or provider,
        "message": message,
        "metadata_json": json.dumps({
            "event_id": event_id,
            "channel": channel,
            "keywords": keywords,
            "provider": provider,
            "event_data": data_pairs,
        }),
    }


# ──────────────────────────────────────────────
# Ingestion entry points
# ──────────────────────────────────────────────

def ingest_evtx_xml(xml_str: str, db_path: Optional[str] = None) -> List[int]:
    """Ingest one or more ``<Event>`` elements from an XML string.

    Returns a list of ``normalized_events`` row IDs that were inserted.
    """
    event_ids: List[int] = []

    # Handle multiple events wrapped in a root element or standalone
    if not xml_str.strip().startswith("<Events"):
        xml_str = f"<Events>{xml_str}</Events>"

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        logger.error("Cannot parse EVTX XML payload")
        return event_ids

    for event_el in root:
        raw_xml = ET.tostring(event_el, encoding="unicode")
        raw_id = insert_raw_log("windows", raw_xml, db_path=db_path)

        parsed = parse_event_xml(raw_xml)
        if parsed is None:
            continue
        parsed["raw_log_id"] = raw_id
        eid = insert_normalized_event(parsed, db_path=db_path)
        event_ids.append(eid)

    logger.info("Ingested %d Windows events", len(event_ids))
    return event_ids


def ingest_evtx_file(path: str, db_path: Optional[str] = None) -> List[int]:
    """Read an XML file containing exported Windows events and ingest them."""
    with open(path, "r", encoding="utf-8-sig") as fh:
        return ingest_evtx_xml(fh.read(), db_path=db_path)


# ──────────────────────────────────────────────
# Live collection (Windows-only, best-effort)
# ──────────────────────────────────────────────

def collect_live_events(
    log_type: str = "Security",
    server: str = "localhost",
    max_events: int = 50,
    db_path: Optional[str] = None,
) -> List[int]:
    """Pull recent events from the Windows Event Log API via pywin32.

    Gracefully returns an empty list when not running on Windows or
    when pywin32 is not installed.
    """
    try:
        import win32evtlog  # type: ignore[import-not-found]
        import win32evtlogutil  # type: ignore[import-not-found]
    except ImportError:
        logger.info("pywin32 not available — skipping live Windows collection")
        return []

    event_ids: List[int] = []
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    handle = win32evtlog.OpenEventLog(server, log_type)

    try:
        collected = 0
        while collected < max_events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break
            for ev in events:
                if collected >= max_events:
                    break
                raw_text = (
                    f"EventID={ev.EventID & 0xFFFF} "
                    f"Source={ev.SourceName} "
                    f"Time={ev.TimeGenerated.isoformat()} "
                    f"Computer={ev.ComputerName} "
                    f"Type={ev.EventType} "
                    f"Category={ev.EventCategory} "
                    f"SID={ev.Sid}"
                )
                raw_id = insert_raw_log("windows", raw_text, db_path=db_path)

                eid_num = ev.EventID & 0xFFFF
                event_type = EVENT_TYPE_MAP.get(eid_num, f"windows_{eid_num}")

                # Map Windows event type constants to severity
                type_map = {0: "low", 1: "high", 2: "medium", 4: "low", 8: "low"}
                severity = type_map.get(ev.EventType, "low")
                if eid_num in (4625, 4740, 1102):
                    severity = "high"

                try:
                    message = win32evtlogutil.SafeFormatMessage(ev, log_type)
                except Exception:
                    message = raw_text

                normalized = {
                    "raw_log_id": raw_id,
                    "timestamp": ev.TimeGenerated.isoformat(),
                    "source": "windows",
                    "event_type": event_type,
                    "severity": severity,
                    "host": ev.ComputerName,
                    "user": str(ev.Sid) if ev.Sid else "",
                    "process": ev.SourceName,
                    "message": message[:2000],
                    "metadata_json": json.dumps({
                        "event_id": eid_num,
                        "channel": log_type,
                        "category": ev.EventCategory,
                    }),
                }
                norm_id = insert_normalized_event(normalized, db_path=db_path)
                event_ids.append(norm_id)
                collected += 1
    finally:
        win32evtlog.CloseEventLog(handle)

    logger.info("Collected %d live Windows events from %s/%s", len(event_ids), server, log_type)
    return event_ids


# ──────────────────────────────────────────────
# Demo / sample data generator
# ──────────────────────────────────────────────

_SAMPLE_EVENTS_XML = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T08:23:11Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.0.0.55</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T08:23:14Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.0.0.55</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T08:23:18Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.0.0.55</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T08:23:22Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.0.0.55</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T08:23:26Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">10.0.0.55</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T09:01:05Z"/>
    <Computer>WS-PC14.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8020000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="IpAddress">-</Data>
    <Data Name="WorkstationName">WS-PC14</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4672</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T09:01:06Z"/>
    <Computer>WS-PC14.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8020000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jdoe</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="PrivilegeList">SeDebugPrivilege SeImpersonatePrivilege</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T09:05:33Z"/>
    <Computer>WS-PC14.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8020000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jdoe</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>1102</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T10:44:00Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x4020000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="SubjectUserName">svc_backup</Data>
    <Data Name="SubjectDomainName">CORP</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4740</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2025-06-15T08:25:00Z"/>
    <Computer>DC01.corp.local</Computer>
    <Channel>Security</Channel>
    <Keywords>0x8010000000000000</Keywords>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
  </EventData>
</Event>
</Events>"""


def load_sample_data(db_path: Optional[str] = None) -> List[int]:
    """Insert realistic sample Windows events for demonstration."""
    return ingest_evtx_xml(_SAMPLE_EVENTS_XML, db_path=db_path)
