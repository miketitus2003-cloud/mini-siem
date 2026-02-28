"""
mini-siem.app.alerts.engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rule-based detection engine for the Mini SIEM.

Architecture
------------
The engine evaluates **alert rules** stored in the ``alert_rules`` table
against the stream of ``normalized_events``.  Two evaluation modes:

1. **Threshold rules** – fire when *N* or more events of a given type
   appear within a sliding time window (e.g., 5 failed logins in 60 s).
2. **Single-event rules** – fire on any single event that matches the
   rule's ``event_type`` and optional field constraints.

Each rule's logic is stored as a JSON document in ``condition_json``::

    # Threshold rule
    {
        "mode": "threshold",
        "threshold": 5,
        "window_seconds": 300,
        "group_by": "user",        # optional
        "field_filters": {          # optional extra equality checks
            "source": "windows"
        }
    }

    # Single-event rule
    {
        "mode": "single",
        "field_filters": {
            "severity": "critical"
        }
    }

The engine is intentionally pull-based (``evaluate_all`` is called on a
schedule or after each ingestion batch) so it stays easy to test and
does not require background threads.
"""

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.database import (
    get_alert_rules,
    get_events_in_window,
    insert_alert,
    insert_alert_rule,
    query_events,
)

logger = logging.getLogger("mini-siem.alerts")


# ──────────────────────────────────────────────
# Built-in detection rules (seeded on first run)
# ──────────────────────────────────────────────

DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "name": "Brute-Force Login (Windows)",
        "description": (
            "Detects 5 or more failed Windows logon attempts (Event ID 4625) "
            "for the same user within a 5-minute window."
        ),
        "severity": "high",
        "event_type": "login_failure",
        "condition_json": json.dumps({
            "mode": "threshold",
            "threshold": 5,
            "window_seconds": 300,
            "group_by": "user",
            "field_filters": {"source": "windows"},
        }),
    },
    {
        "name": "Brute-Force Login (Linux SSH)",
        "description": (
            "Detects 5 or more failed SSH authentication attempts for the "
            "same user within a 5-minute window."
        ),
        "severity": "high",
        "event_type": "login_failure",
        "condition_json": json.dumps({
            "mode": "threshold",
            "threshold": 5,
            "window_seconds": 300,
            "group_by": "user",
            "field_filters": {"source": "linux"},
        }),
    },
    {
        "name": "Brute-Force Login (Azure AD)",
        "description": (
            "Detects 3 or more failed Azure AD sign-ins for the same user "
            "within a 10-minute window."
        ),
        "severity": "high",
        "event_type": "login_failure",
        "condition_json": json.dumps({
            "mode": "threshold",
            "threshold": 3,
            "window_seconds": 600,
            "group_by": "user",
            "field_filters": {"source": "azure"},
        }),
    },
    {
        "name": "Account Lockout",
        "description": "Fires on any account-lockout event across all sources.",
        "severity": "high",
        "event_type": "account_lockout",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {},
        }),
    },
    {
        "name": "Privilege Escalation – Special Privileges Assigned",
        "description": (
            "Fires when special privileges (Event ID 4672) are assigned to a "
            "new logon session."
        ),
        "severity": "medium",
        "event_type": "privilege_assigned",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {},
        }),
    },
    {
        "name": "Security Log Cleared",
        "description": (
            "Fires when a Windows Security event log is cleared (Event ID 1102/104), "
            "a common anti-forensics technique."
        ),
        "severity": "critical",
        "event_type": "log_cleared",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {},
        }),
    },
    {
        "name": "Suspicious Account Creation",
        "description": "Detects new user account creation across all sources.",
        "severity": "medium",
        "event_type": "account_created",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {},
        }),
    },
    {
        "name": "Sudo to Root – Sensitive Command",
        "description": (
            "Fires when a sudo command targets /etc/shadow, /etc/passwd, or "
            "sudoers files."
        ),
        "severity": "high",
        "event_type": "sensitive_file_access",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {"source": "linux"},
        }),
    },
    {
        "name": "Group Membership Change",
        "description": (
            "Detects when a user is added to a security-sensitive group."
        ),
        "severity": "medium",
        "event_type": "group_member_added",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {},
        }),
    },
    {
        "name": "Azure Conditional Access Block",
        "description": (
            "Fires when an Azure AD sign-in is blocked by Conditional Access, "
            "indicating a policy violation or risky sign-in."
        ),
        "severity": "high",
        "event_type": "login_failure",
        "condition_json": json.dumps({
            "mode": "single",
            "field_filters": {"source": "azure"},
        }),
    },
]


# ──────────────────────────────────────────────
# Rule seeding
# ──────────────────────────────────────────────

def seed_default_rules(db_path: Optional[str] = None) -> int:
    """Insert ``DEFAULT_RULES`` that do not already exist. Returns count inserted."""
    existing = {r["name"] for r in get_alert_rules(enabled_only=False, db_path=db_path)}
    inserted = 0
    for rule in DEFAULT_RULES:
        if rule["name"] not in existing:
            insert_alert_rule(rule, db_path=db_path)
            inserted += 1
    if inserted:
        logger.info("Seeded %d default alert rules", inserted)
    return inserted


# ──────────────────────────────────────────────
# Core evaluation logic
# ──────────────────────────────────────────────

def _evaluate_threshold_rule(
    rule: Dict[str, Any],
    condition: Dict[str, Any],
    now: datetime,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Evaluate a threshold-based rule. Returns list of alert dicts to insert."""
    window_sec = condition.get("window_seconds", 300)
    threshold = condition.get("threshold", 5)
    group_by = condition.get("group_by")
    field_filters = condition.get("field_filters", {})

    window_start = (now - timedelta(seconds=window_sec)).isoformat()
    window_end = now.isoformat()

    events = get_events_in_window(
        event_type=rule["event_type"],
        window_start=window_start,
        window_end=window_end,
        extra_filters=field_filters,
        db_path=db_path,
    )

    if not events:
        return []

    alerts_to_fire: List[Dict[str, Any]] = []

    if group_by:
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            key = ev.get(group_by, "__none__")
            groups[key].append(ev)

        for key, group_events in groups.items():
            if len(group_events) >= threshold:
                event_ids = [e["id"] for e in group_events]
                alerts_to_fire.append({
                    "rule_id": rule["id"],
                    "event_ids_json": json.dumps(event_ids),
                    "severity": rule["severity"],
                    "message": (
                        f"[{rule['name']}] {len(group_events)} events for "
                        f"{group_by}={key!r} in {window_sec}s window"
                    ),
                })
    else:
        if len(events) >= threshold:
            event_ids = [e["id"] for e in events]
            alerts_to_fire.append({
                "rule_id": rule["id"],
                "event_ids_json": json.dumps(event_ids),
                "severity": rule["severity"],
                "message": (
                    f"[{rule['name']}] {len(events)} events in {window_sec}s window"
                ),
            })

    return alerts_to_fire


def _evaluate_single_rule(
    rule: Dict[str, Any],
    condition: Dict[str, Any],
    recent_event_ids: Optional[List[int]] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Evaluate a single-event rule against recently ingested events."""
    field_filters = condition.get("field_filters", {})
    filters = {"event_type": rule["event_type"]}
    filters.update(field_filters)

    events = query_events(filters=filters, limit=500, db_path=db_path)

    if recent_event_ids is not None:
        id_set = set(recent_event_ids)
        events = [e for e in events if e["id"] in id_set]

    alerts_to_fire: List[Dict[str, Any]] = []
    for ev in events:
        alerts_to_fire.append({
            "rule_id": rule["id"],
            "event_ids_json": json.dumps([ev["id"]]),
            "severity": rule["severity"],
            "message": (
                f"[{rule['name']}] {ev.get('message', '')[:500]}"
            ),
        })

    return alerts_to_fire


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def evaluate_all(
    recent_event_ids: Optional[List[int]] = None,
    db_path: Optional[str] = None,
) -> List[int]:
    """Run every enabled alert rule and persist any resulting alerts.

    Parameters
    ----------
    recent_event_ids : list[int] | None
        If provided, single-event rules will only evaluate against these
        event IDs (efficiency optimisation after a batch ingest).
    db_path : str | None
        Override the default database path (used in tests).

    Returns
    -------
    list[int]
        Row IDs of newly created alerts.
    """
    rules = get_alert_rules(enabled_only=True, db_path=db_path)
    now = datetime.now(timezone.utc)
    alert_ids: List[int] = []

    for rule in rules:
        condition = json.loads(rule["condition_json"])
        mode = condition.get("mode", "single")

        if mode == "threshold":
            pending = _evaluate_threshold_rule(rule, condition, now, db_path=db_path)
        elif mode == "single":
            pending = _evaluate_single_rule(
                rule, condition, recent_event_ids=recent_event_ids, db_path=db_path
            )
        else:
            logger.warning("Unknown rule mode %r in rule %s", mode, rule["name"])
            continue

        for alert_data in pending:
            aid = insert_alert(alert_data, db_path=db_path)
            alert_ids.append(aid)
            logger.warning(
                "ALERT [%s] %s (alert id=%d)",
                alert_data["severity"].upper(),
                alert_data["message"][:200],
                aid,
            )

    if alert_ids:
        logger.info("Evaluation complete: %d new alerts fired", len(alert_ids))
    return alert_ids


def run_detection_cycle(
    recent_event_ids: Optional[List[int]] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience wrapper that returns a summary dict.

    Suitable for calling from the dashboard or a scheduler.
    """
    alert_ids = evaluate_all(recent_event_ids=recent_event_ids, db_path=db_path)
    return {
        "alerts_fired": len(alert_ids),
        "alert_ids": alert_ids,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }
