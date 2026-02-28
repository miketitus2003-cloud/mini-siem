"""
mini-siem.app.dashboard.routes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Flask blueprint that serves the SIEM dashboard UI and JSON API.

Routes
------
UI
    ``GET  /``                  – Dashboard overview
    ``GET  /events``            – Event explorer
    ``GET  /alerts``            – Alert viewer
    ``GET  /rules``             – Alert rule management

API (JSON)
    ``GET  /api/stats``         – Dashboard summary statistics
    ``GET  /api/events``        – Paginated event query
    ``GET  /api/alerts``        – Paginated alert query
    ``POST /api/alerts/<id>/ack`` – Acknowledge an alert
    ``POST /api/ingest``        – Manual log ingestion
    ``POST /api/detect``        – Trigger a detection cycle
    ``GET  /api/rules``         – List alert rules
    ``POST /api/rules/<id>/toggle`` – Enable / disable a rule
"""

import json
import logging
from typing import Optional

from flask import Blueprint, jsonify, render_template, request

from app.database import (
    acknowledge_alert,
    dashboard_stats,
    get_alerts,
    get_alert_rules,
    query_events,
    update_alert_rule,
)
from app.alerts.engine import evaluate_all, run_detection_cycle
from app.logs.windows import ingest_evtx_xml
from app.logs.linux import ingest_syslog_lines
from app.logs.azure import AzureMonitorStub, ingest_azure_logs

logger = logging.getLogger("mini-siem.dashboard")

bp = Blueprint(
    "dashboard",
    __name__,
    template_folder="templates",
)


# ──────────────────────────────────────────────
# UI routes
# ──────────────────────────────────────────────

@bp.route("/")
def index():
    stats = dashboard_stats()
    return render_template("index.html", stats=stats)


@bp.route("/events")
def events_page():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    source = request.args.get("source")
    severity = request.args.get("severity")
    event_type = request.args.get("event_type")

    filters = {}
    if source:
        filters["source"] = source
    if severity:
        filters["severity"] = severity
    if event_type:
        filters["event_type"] = event_type

    events = query_events(filters=filters, limit=per_page, offset=(page - 1) * per_page)
    return render_template("events.html", events=events, page=page, filters=filters)


@bp.route("/alerts")
def alerts_page():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    show = request.args.get("show", "unacknowledged")

    acknowledged = None
    if show == "unacknowledged":
        acknowledged = False
    elif show == "acknowledged":
        acknowledged = True

    alerts = get_alerts(acknowledged=acknowledged, limit=per_page, offset=(page - 1) * per_page)
    return render_template("alerts.html", alerts=alerts, page=page, show=show)


@bp.route("/rules")
def rules_page():
    rules = get_alert_rules(enabled_only=False)
    return render_template("rules.html", rules=rules)


# ──────────────────────────────────────────────
# JSON API routes
# ──────────────────────────────────────────────

@bp.route("/api/stats")
def api_stats():
    return jsonify(dashboard_stats())


@bp.route("/api/events")
def api_events():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    per_page = min(per_page, 500)

    filters = {}
    for key in ("source", "severity", "event_type", "host", "user"):
        val = request.args.get(key)
        if val:
            filters[key] = val

    events = query_events(filters=filters, limit=per_page, offset=(page - 1) * per_page)
    return jsonify({"events": events, "page": page, "per_page": per_page})


@bp.route("/api/alerts")
def api_alerts():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    ack = request.args.get("acknowledged")
    acknowledged = None
    if ack == "true":
        acknowledged = True
    elif ack == "false":
        acknowledged = False

    alerts = get_alerts(acknowledged=acknowledged, limit=per_page, offset=(page - 1) * per_page)
    return jsonify({"alerts": alerts, "page": page, "per_page": per_page})


@bp.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
def api_ack_alert(alert_id: int):
    acknowledge_alert(alert_id)
    return jsonify({"status": "acknowledged", "alert_id": alert_id})


@bp.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Accept log data for ingestion.

    Expected JSON payload::

        {
            "source": "windows" | "linux" | "azure",
            "data": "<xml string>" | ["syslog line", ...] | [{ azure obj }, ...]
        }
    """
    body = request.get_json(force=True)
    source = body.get("source")
    data = body.get("data")

    if source not in ("windows", "linux", "azure"):
        return jsonify({"error": "source must be windows, linux, or azure"}), 400
    if not data:
        return jsonify({"error": "data is required"}), 400

    event_ids = []
    if source == "windows":
        if not isinstance(data, str):
            return jsonify({"error": "Windows data must be an XML string"}), 400
        event_ids = ingest_evtx_xml(data)
    elif source == "linux":
        if isinstance(data, str):
            data = data.strip().split("\n")
        event_ids = ingest_syslog_lines(data)
    elif source == "azure":
        if not isinstance(data, list):
            return jsonify({"error": "Azure data must be a list of objects"}), 400
        category = body.get("category", "SignInLogs")
        event_ids = ingest_azure_logs(data, category=category)

    # Auto-run detection after ingest
    alert_result = run_detection_cycle(recent_event_ids=event_ids)

    return jsonify({
        "status": "ingested",
        "events_created": len(event_ids),
        "event_ids": event_ids,
        "detection": alert_result,
    })


@bp.route("/api/detect", methods=["POST"])
def api_detect():
    """Manually trigger a detection cycle."""
    result = run_detection_cycle()
    return jsonify(result)


@bp.route("/api/rules")
def api_rules():
    rules = get_alert_rules(enabled_only=False)
    return jsonify({"rules": rules})


@bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id: int):
    body = request.get_json(force=True) if request.data else {}
    enabled = body.get("enabled")
    if enabled is None:
        # Toggle: fetch current, flip it
        rules = get_alert_rules(enabled_only=False)
        current = next((r for r in rules if r["id"] == rule_id), None)
        if current is None:
            return jsonify({"error": "Rule not found"}), 404
        enabled = not bool(current["enabled"])
    update_alert_rule(rule_id, {"enabled": int(bool(enabled))})
    return jsonify({"rule_id": rule_id, "enabled": bool(enabled)})
