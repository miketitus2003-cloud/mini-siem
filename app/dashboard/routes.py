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
    create_incident,
    dashboard_stats,
    delete_user,
    events_per_hour_last_24h,
    get_alert_rules,
    get_alerts,
    get_all_users,
    get_audit_log,
    get_incident,
    get_incident_alerts,
    get_incidents,
    get_log_sources,
    get_user_by_username,
    link_alert_to_incident,
    query_events,
    query_events_with_time_range,
    search_events,
    top_ips,
    update_alert_rule,
    update_incident,
    update_user_role,
    write_audit,
)
from app.alerts.engine import evaluate_all, run_detection_cycle
from app.logs.windows import ingest_evtx_xml, load_sample_data as win_samples
from app.logs.linux import ingest_syslog_lines, load_sample_data as linux_samples
from app.logs.azure import ingest_azure_logs, load_sample_data as azure_samples
from app.logs.firewall import ingest_firewall_lines, load_sample_data as fw_samples
from app.logs.endpoint import ingest_endpoint_events, load_sample_data as ep_samples

logger = logging.getLogger("mini-siem.routes")

bp = Blueprint("dashboard", __name__)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _require_admin():
    if not current_user.is_admin:
        return jsonify({"error": "Admin role required"}), 403
    return None


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


def _audit(action: str, target_type: str = "", target_id: str = "", detail: str = ""):
    """Write one audit record for the currently authenticated user."""
    username = getattr(current_user, "username", "anonymous")
    write_audit(
        username=username,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        detail=detail,
        ip_address=_client_ip(),
    )


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
            write_audit(username=username, action="login",
                        detail="successful login", ip_address=_client_ip())
            next_page = request.args.get("next") or url_for("dashboard.index")
            if next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard.index"))
        write_audit(
            username=username or "unknown", action="login_failed",
            detail="invalid credentials", ip_address=_client_ip(),
        )
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    _audit("logout")
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
    open_incidents = len(get_incidents(status="open", limit=500))
    return render_template(
        "index.html",
        stats=stats,
        hourly=hourly,
        top5_ips=top5_ips,
        last_refreshed=now_utc,
        open_incidents=open_incidents,
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
    search_q = request.args.get("q", "").strip()

    filters = {}
    if source:
        filters["source"] = source
    if severity:
        filters["severity"] = severity
    if event_type:
        filters["event_type"] = event_type

    if search_q:
        events = search_events(
            query=search_q,
            filters=filters,
            time_range=time_range or None,
            limit=per_page,
            offset=offset,
        )
    else:
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
        search_q=search_q,
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
    if current_user.is_viewer:
        return jsonify({"error": "Read-only role cannot acknowledge alerts"}), 403
    acknowledge_alert(alert_id)
    _audit("alert_ack", target_type="alert", target_id=alert_id)
    return jsonify({"ok": True})


@bp.route("/api/alerts/<int:alert_id>/note", methods=["POST"])
@login_required
def api_alert_note(alert_id: int):
    if current_user.is_viewer:
        return jsonify({"error": "Read-only role cannot add notes"}), 403
    data = request.get_json(silent=True) or {}
    note = str(data.get("note", "")).strip()
    add_alert_note(alert_id, note)
    _audit("alert_note", target_type="alert", target_id=alert_id,
           detail=note[:120])
    return jsonify({"ok": True})


_MAX_INGEST_BYTES = 2 * 1024 * 1024   # 2 MB hard limit
_MAX_INGEST_LINES = 5_000             # line-based sources
_MAX_INGEST_RECORDS = 1_000           # JSON array sources
_VALID_SOURCES = frozenset(("windows", "linux", "azure", "firewall", "endpoint"))


@bp.route("/api/ingest", methods=["POST"])
@login_required
def api_ingest():
    err = _require_admin()
    if err:
        return err

    # Size guard — reject before parsing
    if request.content_length and request.content_length > _MAX_INGEST_BYTES:
        return jsonify({"error": "Payload too large (max 2 MB)"}), 413

    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "JSON object body required"}), 400

    source = str(payload.get("source", "")).lower().strip()
    data = payload.get("data")

    if source not in _VALID_SOURCES:
        return jsonify({
            "error": "source must be one of: windows, linux, azure, firewall, endpoint"
        }), 400
    if data is None or data == "" or data == []:
        return jsonify({"error": "data field required and must not be empty"}), 400

    # Per-source data type validation
    if source == "windows":
        if not isinstance(data, str):
            return jsonify({"error": "windows source expects a string (XML)"}), 400
        if len(data) > _MAX_INGEST_BYTES:
            return jsonify({"error": "Payload too large"}), 413
    elif source in ("linux", "firewall"):
        if isinstance(data, str):
            lines = data.splitlines()
        elif isinstance(data, list):
            lines = [str(x) for x in data]
        else:
            return jsonify({"error": f"{source} source expects a string or list of strings"}), 400
        if len(lines) > _MAX_INGEST_LINES:
            return jsonify({"error": f"Too many lines (max {_MAX_INGEST_LINES})"}), 413
    elif source == "azure":
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = [data]
        else:
            return jsonify({"error": "azure source expects a JSON array or object"}), 400
        if len(records) > _MAX_INGEST_RECORDS:
            return jsonify({"error": f"Too many records (max {_MAX_INGEST_RECORDS})"}), 413
    elif source == "endpoint":
        if isinstance(data, str):
            pass  # NDJSON string — validated inside ingest_endpoint_events
        elif not isinstance(data, (list, dict)):
            return jsonify({"error": "endpoint source expects JSON object, array, or NDJSON string"}), 400

    try:
        if source == "windows":
            event_ids = ingest_evtx_xml(data)
        elif source == "linux":
            event_ids = ingest_syslog_lines(lines)
        elif source == "azure":
            event_ids = ingest_azure_logs(records)
        elif source == "firewall":
            event_ids = ingest_firewall_lines(lines)
        else:  # endpoint
            event_ids = ingest_endpoint_events(data)
    except Exception:
        logger.exception("Ingestion error for source=%s", source)
        return jsonify({"error": "Ingestion failed — check server logs for details"}), 500

    alerts = evaluate_all(recent_event_ids=event_ids)
    _audit("ingest", target_type="source", target_id=source,
           detail=f"events={len(event_ids)} alerts={len(alerts)}")
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
    if source in ("firewall", "all"):
        event_ids += fw_samples()
    if source in ("endpoint", "all"):
        event_ids += ep_samples()

    if not event_ids:
        return jsonify({"error": f"Unknown source: {source}"}), 400

    alerts = evaluate_all(recent_event_ids=event_ids)
    _audit("ingest_sample", target_type="source", target_id=source,
           detail=f"events={len(event_ids)} alerts={len(alerts)}")
    return jsonify({"events_created": len(event_ids), "alerts_fired": len(alerts)})


@bp.route("/api/detect", methods=["POST"])
@login_required
def api_detect():
    if current_user.is_viewer:
        return jsonify({"error": "Read-only role"}), 403
    result = run_detection_cycle()
    _audit("detect_cycle", detail=f"alerts_fired={result.get('alerts_fired', 0)}")
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
    _audit("rule_toggle", target_type="rule", target_id=rule_id,
           detail=f"enabled={bool(new_state)}")
    return jsonify({"ok": True, "enabled": bool(new_state)})


# ──────────────────────────────────────────────
# Log Sources page
# ──────────────────────────────────────────────

@bp.route("/sources")
@login_required
def sources_page():
    sources = get_log_sources()
    return render_template("sources.html", sources=sources)


# ──────────────────────────────────────────────
# Incidents / Case Management
# ──────────────────────────────────────────────

@bp.route("/incidents")
@login_required
def incidents_page():
    status_filter = request.args.get("status", "")
    page = request.args.get("page", 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    incidents = get_incidents(status=status_filter or None, limit=per_page, offset=offset)
    return render_template(
        "incidents.html",
        incidents=incidents,
        status_filter=status_filter,
        page=page,
        per_page=per_page,
    )


@bp.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id: int):
    inc = get_incident(incident_id)
    if inc is None:
        flash("Incident not found.", "danger")
        return redirect(url_for("dashboard.incidents_page"))
    linked_alerts = get_incident_alerts(incident_id)
    open_alerts = [a for a in get_alerts(acknowledged=False, limit=200) if a["id"] not in {la["id"] for la in linked_alerts}]
    return render_template(
        "incident_detail.html",
        incident=inc,
        linked_alerts=linked_alerts,
        open_alerts=open_alerts,
    )


@bp.route("/api/incidents", methods=["POST"])
@login_required
def api_create_incident():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    severity = data.get("severity", "medium")
    assigned_to = str(data.get("assigned_to", "")).strip()

    if not title:
        return jsonify({"error": "title required"}), 400
    if severity not in ("low", "medium", "high", "critical"):
        return jsonify({"error": "invalid severity"}), 400

    if current_user.is_viewer:
        return jsonify({"error": "Read-only role"}), 403
    inc_id = create_incident(title, description, severity, assigned_to)
    # Link alert IDs if provided
    for alert_id in data.get("alert_ids", []):
        try:
            link_alert_to_incident(inc_id, int(alert_id))
        except Exception:
            pass
    _audit("incident_create", target_type="incident", target_id=inc_id,
           detail=f"title={title[:80]} severity={severity}")
    return jsonify({"ok": True, "incident_id": inc_id})


@bp.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
@login_required
def api_update_incident(incident_id: int):
    data = request.get_json(silent=True) or {}
    allowed = {"title", "description", "severity", "status", "assigned_to"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": "no valid fields"}), 400
    if current_user.is_viewer:
        return jsonify({"error": "Read-only role"}), 403
    update_incident(incident_id, updates)
    _audit("incident_update", target_type="incident", target_id=incident_id,
           detail=str(list(updates.keys())))
    return jsonify({"ok": True})


@bp.route("/api/incidents/<int:incident_id>/alerts", methods=["POST"])
@login_required
def api_link_alert(incident_id: int):
    if current_user.is_viewer:
        return jsonify({"error": "Read-only role"}), 403
    data = request.get_json(silent=True) or {}
    alert_id = data.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id required"}), 400
    link_alert_to_incident(incident_id, int(alert_id))
    _audit("incident_link_alert", target_type="incident", target_id=incident_id,
           detail=f"alert_id={alert_id}")
    return jsonify({"ok": True})


# ──────────────────────────────────────────────
# User Management (admin only)
# ──────────────────────────────────────────────

@bp.route("/users")
@login_required
def users_page():
    err = _require_admin()
    if err:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))
    from werkzeug.security import generate_password_hash
    from app.database import create_user as db_create_user
    users = get_all_users()
    return render_template("users.html", users=users)


@bp.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    err = _require_admin()
    if err:
        return err
    from werkzeug.security import generate_password_hash
    from app.database import create_user as db_create_user
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    role = data.get("role", "analyst")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "role must be admin, analyst, or viewer"}), 400
    if get_user_by_username(username):
        return jsonify({"error": "username already exists"}), 409
    uid = db_create_user(username, generate_password_hash(password), role=role)
    _audit("user_create", target_type="user", target_id=uid,
           detail=f"username={username} role={role}")
    return jsonify({"ok": True, "user_id": uid})


@bp.route("/api/users/<int:user_id>/role", methods=["PATCH"])
@login_required
def api_update_user_role(user_id: int):
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    role = data.get("role", "")
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "role must be admin, analyst, or viewer"}), 400
    update_user_role(user_id, role)
    _audit("user_role_change", target_type="user", target_id=user_id,
           detail=f"new_role={role}")
    return jsonify({"ok": True})


@bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_delete_user(user_id: int):
    err = _require_admin()
    if err:
        return err
    if str(user_id) == current_user.id:
        return jsonify({"error": "Cannot delete your own account"}), 400
    delete_user(user_id)
    _audit("user_delete", target_type="user", target_id=user_id)
    return jsonify({"ok": True})


# ──────────────────────────────────────────────
# Audit Log page (admin only)
# ──────────────────────────────────────────────

@bp.route("/audit")
@login_required
def audit_page():
    err = _require_admin()
    if err:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))
    page = request.args.get("page", 1, type=int)
    per_page = 100
    offset = (page - 1) * per_page
    username_filter = request.args.get("username", "")
    action_filter = request.args.get("action", "")
    entries = get_audit_log(
        username=username_filter or None,
        action=action_filter or None,
        limit=per_page,
        offset=offset,
    )
    return render_template(
        "audit.html",
        entries=entries,
        page=page,
        per_page=per_page,
        username_filter=username_filter,
        action_filter=action_filter,
    )
