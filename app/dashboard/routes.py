"""
mini-siem.app.dashboard.routes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Flask blueprint — UI and JSON API.
"""

import json
import logging
from datetime import datetime, timezone, timedelta

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
    flash,
)
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import check_password_hash

from app.database import (
    acknowledge_alert,
    add_alert_note,
    dashboard_stats,
    events_per_hour_last_24h,
    get_alerts,
    get_alert_rules,
    get_user_by_username,
    query_events,
    query_events_with_time_range,
    top_ips,
    update_alert_rule,
)
from app.alerts.engine import evaluate_all, run_detection_cycle
from app.logs.windows import ingest_evtx_xml, load_sample_data as win_samples
from app.logs.linux import ingest_syslog_lines, load_sample_data as linux_samples
from app.logs.azure import ingest_azure_logs, load_sample_data as azure_samples

logger = logging.getLogger("mini-siem.routes")

bp = Blueprint("dashboard", __name__)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _require_admin():
    if not current_user.is_admin:
        return jsonify({"error": "Admin role required"}), 403
    return None


def _extract_ip(metadata_json: str) -> str:
    try:
        meta = json.loads(metadata_json or "{}")
        return (
            meta.get("ip")
            or meta.get("source_ip")
            or meta.get("IpAddress")
            or ""
        )
    except (json.JSONDecodeError, TypeError):
        return ""


# ──────────────────────────────────────────────
# Auth routes (unprotected)
# ──────────────────────────────────────────────

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_user_by_username(username)
        if row and check_password_hash(row["password_hash"], password):
            from app import SIEMUser
            user = SIEMUser(row)
            login_user(user)
            next_page = request.args.get("next") or url_for("dashboard.index")
            if next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("dashboard.login"))


# ──────────────────────────────────────────────
# UI routes (protected)
# ──────────────────────────────────────────────

@bp.route("/")
@login_required
def index():
    stats = dashboard_stats()
    hourly = events_per_hour_last_24h()
    top5_ips = top_ips(limit=5)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return render_template(
        "index.html",
        stats=stats,
        hourly=hourly,
        top5_ips=top5_ips,
        last_refreshed=now_utc,
    )


@bp.route("/events")
@login_required
def events_page():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    source = request.args.get("source", "")
    severity = request.args.get("severity", "")
    event_type = request.args.get("event_type", "")
    time_range = request.args.get("time_range", "")

    filters = {}
    if source:
        filters["source"] = source
    if severity:
        filters["severity"] = severity
    if event_type:
        filters["event_type"] = event_type

    events = query_events_with_time_range(
        filters=filters,
        time_range=time_range or None,
        limit=per_page,
        offset=offset,
    )

    for ev in events:
        ev["ip"] = _extract_ip(ev.get("metadata_json", "{}"))

    return render_template(
        "events.html",
        events=events,
        page=page,
        per_page=per_page,
        source=source,
        severity=severity,
        event_type=event_type,
        time_range=time_range,
    )


@bp.route("/alerts")
@login_required
def alerts_page():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    show = request.args.get("show", "open")

    if show == "open":
        ack_filter = False
    elif show == "ack":
        ack_filter = True
    else:
        ack_filter = None

    alerts = get_alerts(acknowledged=ack_filter, limit=per_page, offset=offset)
    return render_template(
        "alerts.html",
        alerts=alerts,
        page=page,
        per_page=per_page,
        show=show,
    )


@bp.route("/rules")
@login_required
def rules_page():
    rules = get_alert_rules(enabled_only=False)
    return render_template("rules.html", rules=rules)


@bp.route("/ingest")
@login_required
def ingest_page():
    err = _require_admin()
    if err:
        flash("Admin access required to ingest logs.", "danger")
        return redirect(url_for("dashboard.index"))
    return render_template("ingest.html")


# ──────────────────────────────────────────────
# JSON API
# ──────────────────────────────────────────────

@bp.route("/api/stats")
@login_required
def api_stats():
    return jsonify(dashboard_stats())


@bp.route("/api/events")
@login_required
def api_events():
    limit = min(request.args.get("limit", 100, type=int), 500)
    offset = request.args.get("offset", 0, type=int)
    filters = {}
    for key in ("source", "severity", "event_type", "host", "user"):
        val = request.args.get(key)
        if val:
            filters[key] = val
    events = query_events(filters=filters, limit=limit, offset=offset)
    return jsonify(events)


@bp.route("/api/alerts")
@login_required
def api_alerts():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    ack = request.args.get("acknowledged")
    if ack == "true":
        ack_filter = True
    elif ack == "false":
        ack_filter = False
    else:
        ack_filter = None
    return jsonify(get_alerts(acknowledged=ack_filter, limit=limit, offset=offset))


@bp.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
def api_ack_alert(alert_id: int):
    acknowledge_alert(alert_id)
    return jsonify({"ok": True})


@bp.route("/api/alerts/<int:alert_id>/note", methods=["POST"])
@login_required
def api_alert_note(alert_id: int):
    data = request.get_json(silent=True) or {}
    note = str(data.get("note", "")).strip()
    add_alert_note(alert_id, note)
    return jsonify({"ok": True})


@bp.route("/api/ingest", methods=["POST"])
@login_required
def api_ingest():
    err = _require_admin()
    if err:
        return err

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "JSON body required"}), 400

    source = payload.get("source", "").lower()
    data = payload.get("data")
    if source not in ("windows", "linux", "azure"):
        return jsonify({"error": "source must be windows, linux, or azure"}), 400
    if not data:
        return jsonify({"error": "data field required"}), 400

    try:
        if source == "windows":
            event_ids = ingest_evtx_xml(data)
        elif source == "linux":
            lines = data if isinstance(data, list) else data.splitlines()
            event_ids = ingest_syslog_lines(lines)
        else:
            event_ids = ingest_azure_logs(data if isinstance(data, list) else [data])
    except Exception as exc:
        logger.exception("Ingestion error")
        return jsonify({"error": str(exc)}), 500

    alerts = evaluate_all(recent_event_ids=event_ids)
    return jsonify({"events_created": len(event_ids), "alerts_fired": len(alerts)})


@bp.route("/api/ingest/sample", methods=["POST"])
@login_required
def api_ingest_sample():
    err = _require_admin()
    if err:
        return err

    payload = request.get_json(silent=True) or {}
    source = payload.get("source", "all").lower()

    event_ids = []
    if source in ("windows", "all"):
        event_ids += win_samples()
    if source in ("linux", "all"):
        event_ids += linux_samples()
    if source in ("azure", "all"):
        event_ids += azure_samples()

    if not event_ids:
        return jsonify({"error": f"Unknown source: {source}"}), 400

    alerts = evaluate_all(recent_event_ids=event_ids)
    return jsonify({"events_created": len(event_ids), "alerts_fired": len(alerts)})


@bp.route("/api/detect", methods=["POST"])
@login_required
def api_detect():
    result = run_detection_cycle()
    return jsonify(result)


@bp.route("/api/rules")
@login_required
def api_rules():
    return jsonify(get_alert_rules(enabled_only=False))


@bp.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def api_toggle_rule(rule_id: int):
    err = _require_admin()
    if err:
        return err

    payload = request.get_json(silent=True) or {}
    if "enabled" in payload:
        new_state = int(bool(payload["enabled"]))
    else:
        rules = get_alert_rules(enabled_only=False)
        current = next((r for r in rules if r["id"] == rule_id), None)
        if current is None:
            return jsonify({"error": "Rule not found"}), 404
        new_state = 0 if current["enabled"] else 1

    update_alert_rule(rule_id, {"enabled": new_state})
    return jsonify({"ok": True, "enabled": bool(new_state)})
