"""
mini-siem.app.database
~~~~~~~~~~~~~~~~~~~~~~
SQLite persistence layer for the Mini SIEM.

Tables
------
raw_logs            – verbatim log text with source metadata
normalized_events   – parsed, schema-aligned event records
alert_rules         – detection rule definitions
alerts              – fired alert instances linked to triggering events

All timestamps are stored as ISO-8601 UTC strings.
"""

import json
import sqlite3
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
DB_PATH = os.path.join(DB_DIR, "siem.db")

_local = threading.local()

SCHEMA_VERSION = 3

# ──────────────────────────────────────────────
# Schema DDL
# ──────────────────────────────────────────────

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS log_sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    source_type TEXT    NOT NULL CHECK(source_type IN ('network','identity','application','host','cloud')),
    description TEXT    DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT    NOT NULL,
    ingested_at TEXT    NOT NULL,
    raw_text    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_log_id      INTEGER REFERENCES raw_logs(id),
    timestamp       TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    host            TEXT,
    user            TEXT,
    process         TEXT,
    message         TEXT    NOT NULL,
    metadata_json   TEXT    DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT,
    severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    event_type      TEXT    NOT NULL,
    condition_json  TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id         INTEGER NOT NULL REFERENCES alert_rules(id),
    event_ids_json  TEXT    NOT NULL,
    fired_at        TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    message         TEXT    NOT NULL,
    acknowledged    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_norm_events_ts      ON normalized_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_norm_events_type    ON normalized_events(event_type);
CREATE INDEX IF NOT EXISTS idx_norm_events_source  ON normalized_events(source);
CREATE INDEX IF NOT EXISTS idx_norm_events_sev     ON normalized_events(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_fired        ON alerts(fired_at);
CREATE INDEX IF NOT EXISTS idx_alerts_ack          ON alerts(acknowledged);

CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT    NOT NULL,
    description     TEXT    DEFAULT '',
    severity        TEXT    NOT NULL CHECK(severity IN ('low','medium','high','critical')),
    status          TEXT    NOT NULL DEFAULT 'open'
                            CHECK(status IN ('open','investigating','resolved','closed')),
    assigned_to     TEXT    DEFAULT '',
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'analyst'
                          CHECK(role IN ('admin', 'analyst', 'viewer')),
    created_at    TEXT    NOT NULL
);
"""

# ──────────────────────────────────────────────
# Connection helpers
# ──────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return a thread-local SQLite connection with row-factory enabled."""
    path = db_path or DB_PATH
    conn = getattr(_local, "connection", None)
    if conn is None or conn is not None and _path_of(conn) != path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _local.connection = conn
    return conn


def _path_of(conn: sqlite3.Connection) -> str:
    """Retrieve the file path backing a connection."""
    row = conn.execute("PRAGMA database_list").fetchone()
    return row[2] if row else ""


@contextmanager
def transaction(db_path: Optional[str] = None):
    """Context manager that commits on success, rolls back on error."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def close_connection():
    conn = getattr(_local, "connection", None)
    if conn is not None:
        conn.close()
        _local.connection = None


# ──────────────────────────────────────────────
# Bootstrap
# ──────────────────────────────────────────────

def _migrate(conn: sqlite3.Connection) -> None:
    """Apply incremental schema migrations to existing databases."""
    # v1 → v2: add notes to alerts
    cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "notes" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN notes TEXT DEFAULT ''")
        conn.commit()

    # v2 → v3: log_sources, incidents, incident_alerts; viewer role; fts index
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "log_sources" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS log_sources (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL UNIQUE,
                source_type TEXT    NOT NULL,
                description TEXT    DEFAULT '',
                enabled     INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT    NOT NULL,
                description     TEXT    DEFAULT '',
                severity        TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'open',
                assigned_to     TEXT    DEFAULT '',
                created_at      TEXT    NOT NULL,
                updated_at      TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                alert_id        INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                PRIMARY KEY (incident_id, alert_id)
            );
        """)
        conn.commit()

    # Widen the users role CHECK constraint (SQLite can't ALTER CHECK, recreate if needed)
    # We just ensure viewer is allowed by not enforcing via the app layer for older DBs.
    # New DBs get the full CHECK from _SCHEMA_SQL above.


def init_db(db_path: Optional[str] = None):
    """Create tables and indexes if they do not exist."""
    conn = get_connection(db_path)
    conn.executescript(_SCHEMA_SQL)
    _migrate(conn)
    # Track schema version
    existing = conn.execute("SELECT version FROM schema_version").fetchone()
    if existing is None:
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
    conn.commit()


# ──────────────────────────────────────────────
# Raw log operations
# ──────────────────────────────────────────────

def insert_raw_log(source: str, raw_text: str, db_path: Optional[str] = None) -> int:
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO raw_logs (source, ingested_at, raw_text) VALUES (?, ?, ?)",
            (source, _utcnow(), raw_text),
        )
        return cur.lastrowid


def get_raw_logs(
    source: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    if source:
        rows = conn.execute(
            "SELECT * FROM raw_logs WHERE source = ? ORDER BY id DESC LIMIT ? OFFSET ?",
            (source, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM raw_logs ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────
# Normalized event operations
# ──────────────────────────────────────────────

def insert_normalized_event(event: Dict[str, Any], db_path: Optional[str] = None) -> int:
    fields = (
        "raw_log_id", "timestamp", "source", "event_type",
        "severity", "host", "user", "process", "message", "metadata_json",
    )
    values = tuple(event.get(f) for f in fields)
    placeholders = ", ".join("?" for _ in fields)
    col_names = ", ".join(fields)
    with transaction(db_path) as conn:
        cur = conn.execute(
            f"INSERT INTO normalized_events ({col_names}) VALUES ({placeholders})",
            values,
        )
        return cur.lastrowid


def query_events(
    filters: Optional[Dict[str, Any]] = None,
    limit: int = 200,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flexible event query with optional equality filters."""
    conn = get_connection(db_path)
    clauses: List[str] = []
    params: List[Any] = []
    allowed = {
        "source", "event_type", "severity", "host", "user", "process",
    }
    for key, val in (filters or {}).items():
        if key in allowed:
            clauses.append(f"{key} = ?")
            params.append(val)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    sql = f"SELECT * FROM normalized_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_events_by(column: str, db_path: Optional[str] = None) -> List[Tuple[str, int]]:
    """Return (value, count) pairs grouped by *column*."""
    allowed = {"source", "event_type", "severity", "host"}
    if column not in allowed:
        raise ValueError(f"Cannot group by {column!r}")
    conn = get_connection(db_path)
    rows = conn.execute(
        f"SELECT {column}, COUNT(*) as cnt FROM normalized_events GROUP BY {column} ORDER BY cnt DESC"
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def get_events_in_window(
    event_type: str,
    window_start: str,
    window_end: str,
    extra_filters: Optional[Dict[str, str]] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return events of *event_type* within a time window (ISO-8601 strings)."""
    conn = get_connection(db_path)
    clauses = ["event_type = ?", "timestamp >= ?", "timestamp <= ?"]
    params: list = [event_type, window_start, window_end]
    for k, v in (extra_filters or {}).items():
        clauses.append(f"{k} = ?")
        params.append(v)
    sql = (
        "SELECT * FROM normalized_events WHERE "
        + " AND ".join(clauses)
        + " ORDER BY timestamp ASC"
    )
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────
# Alert rule operations
# ──────────────────────────────────────────────

def insert_alert_rule(rule: Dict[str, Any], db_path: Optional[str] = None) -> int:
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO alert_rules (name, description, severity, event_type, condition_json, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                rule["name"],
                rule.get("description", ""),
                rule["severity"],
                rule["event_type"],
                rule["condition_json"],
                rule.get("enabled", 1),
                _utcnow(),
            ),
        )
        return cur.lastrowid


def get_alert_rules(enabled_only: bool = True, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    if enabled_only:
        rows = conn.execute("SELECT * FROM alert_rules WHERE enabled = 1").fetchall()
    else:
        rows = conn.execute("SELECT * FROM alert_rules").fetchall()
    return [dict(r) for r in rows]


def update_alert_rule(rule_id: int, updates: Dict[str, Any], db_path: Optional[str] = None):
    allowed = {"name", "description", "severity", "event_type", "condition_json", "enabled"}
    sets = []
    params = []
    for k, v in updates.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return
    params.append(rule_id)
    with transaction(db_path) as conn:
        conn.execute(
            f"UPDATE alert_rules SET {', '.join(sets)} WHERE id = ?",
            params,
        )


# ──────────────────────────────────────────────
# Alert operations
# ──────────────────────────────────────────────

def insert_alert(alert: Dict[str, Any], db_path: Optional[str] = None) -> int:
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO alerts (rule_id, event_ids_json, fired_at, severity, message, acknowledged) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                alert["rule_id"],
                alert["event_ids_json"],
                _utcnow(),
                alert["severity"],
                alert["message"],
                0,
            ),
        )
        return cur.lastrowid


def get_alerts(
    acknowledged: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    if acknowledged is not None:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE acknowledged = ? ORDER BY fired_at DESC LIMIT ? OFFSET ?",
            (int(acknowledged), limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY fired_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int, db_path: Optional[str] = None):
    with transaction(db_path) as conn:
        conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))


# ──────────────────────────────────────────────
# Statistics helpers (used by dashboard)
# ──────────────────────────────────────────────

def dashboard_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Aggregate numbers for the dashboard overview."""
    conn = get_connection(db_path)
    total_events = conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
    total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    unack_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
    severity_dist = dict(
        conn.execute(
            "SELECT severity, COUNT(*) FROM normalized_events GROUP BY severity"
        ).fetchall()
    )
    source_dist = dict(
        conn.execute(
            "SELECT source, COUNT(*) FROM normalized_events GROUP BY source"
        ).fetchall()
    )
    recent_alerts = get_alerts(limit=10, db_path=db_path)
    recent_events = query_events(limit=20, db_path=db_path)
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "unacknowledged_alerts": unack_alerts,
        "severity_distribution": severity_dist,
        "source_distribution": source_dist,
        "recent_alerts": recent_alerts,
        "recent_events": recent_events,
    }


def events_per_hour_last_24h(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return event counts bucketed by hour for the last 24 hours."""
    conn = get_connection(db_path)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    rows = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:00', timestamp) as hour, COUNT(*) as cnt "
        "FROM normalized_events WHERE timestamp >= ? "
        "GROUP BY hour ORDER BY hour ASC",
        (since,),
    ).fetchall()
    return [{"hour": r[0], "count": r[1]} for r in rows]


def top_ips(limit: int = 5, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return the top source IPs extracted from metadata_json."""
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT metadata_json FROM normalized_events WHERE metadata_json IS NOT NULL AND metadata_json != '{}'"
    ).fetchall()
    ip_counts: Dict[str, int] = {}
    for row in rows:
        try:
            meta = json.loads(row[0])
            ip = meta.get("ip") or meta.get("source_ip") or meta.get("IpAddress")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except (json.JSONDecodeError, TypeError):
            pass
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"ip": ip, "count": cnt} for ip, cnt in sorted_ips]


def query_events_with_time_range(
    filters: Optional[Dict[str, Any]] = None,
    time_range: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Query events with optional time range (last_hour, last_24h, last_7d)."""
    conn = get_connection(db_path)
    clauses: List[str] = []
    params: List[Any] = []
    allowed = {"source", "event_type", "severity", "host", "user", "process"}
    for key, val in (filters or {}).items():
        if key in allowed and val:
            clauses.append(f"{key} = ?")
            params.append(val)
    if time_range == "last_hour":
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(since)
    elif time_range == "last_24h":
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(since)
    elif time_range == "last_7d":
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(since)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    sql = f"SELECT * FROM normalized_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def add_alert_note(alert_id: int, note: str, db_path: Optional[str] = None):
    with transaction(db_path) as conn:
        conn.execute("UPDATE alerts SET notes = ? WHERE id = ?", (note, alert_id))


# ──────────────────────────────────────────────
# User operations
# ──────────────────────────────────────────────

def create_user(
    username: str,
    password_hash: str,
    role: str = "analyst",
    db_path: Optional[str] = None,
) -> int:
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, _utcnow()),
        )
        return cur.lastrowid


def get_user_by_username(
    username: str, db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return dict(row) if row else None


def get_user_by_id(
    user_id: int, db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return dict(row) if row else None


def get_all_users(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def update_user_role(user_id: int, role: str, db_path: Optional[str] = None):
    with transaction(db_path) as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))


def delete_user(user_id: int, db_path: Optional[str] = None):
    with transaction(db_path) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ──────────────────────────────────────────────
# Log source operations
# ──────────────────────────────────────────────

_DEFAULT_SOURCES = [
    ("windows",  "host",     "Windows Event Logs (Security, System, Application)"),
    ("linux",    "host",     "Linux Syslog / auth.log / kern.log"),
    ("azure",    "cloud",    "Azure AD Sign-in & Audit Logs"),
    ("firewall", "network",  "Firewall / perimeter traffic logs"),
    ("endpoint", "host",     "EDR / endpoint telemetry"),
]


def seed_log_sources(db_path: Optional[str] = None) -> int:
    """Insert default log source definitions if they don't exist yet."""
    conn = get_connection(db_path)
    existing = {r[0] for r in conn.execute("SELECT name FROM log_sources").fetchall()}
    inserted = 0
    for name, stype, desc in _DEFAULT_SOURCES:
        if name not in existing:
            with transaction(db_path) as c:
                c.execute(
                    "INSERT INTO log_sources (name, source_type, description, enabled, created_at) "
                    "VALUES (?, ?, ?, 1, ?)",
                    (name, stype, desc, _utcnow()),
                )
            inserted += 1
    return inserted


def get_log_sources(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    rows = conn.execute("SELECT * FROM log_sources ORDER BY id").fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────
# Full-text event search
# ──────────────────────────────────────────────

def search_events(
    query: str,
    filters: Optional[Dict[str, Any]] = None,
    time_range: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search events by free-text across message, host, user, process, and IP."""
    conn = get_connection(db_path)
    clauses: List[str] = []
    params: List[Any] = []
    allowed = {"source", "event_type", "severity", "host", "user", "process"}
    for key, val in (filters or {}).items():
        if key in allowed and val:
            clauses.append(f"{key} = ?")
            params.append(val)
    if time_range == "last_hour":
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(since)
    elif time_range == "last_24h":
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(since)
    elif time_range == "last_7d":
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        clauses.append("timestamp >= ?")
        params.append(since)
    if query:
        like = f"%{query}%"
        clauses.append(
            "(message LIKE ? OR host LIKE ? OR \"user\" LIKE ? OR process LIKE ? OR metadata_json LIKE ?)"
        )
        params.extend([like, like, like, like, like])
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    sql = f"SELECT * FROM normalized_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────
# Incident / Case management
# ──────────────────────────────────────────────

def create_incident(
    title: str,
    description: str,
    severity: str,
    assigned_to: str = "",
    db_path: Optional[str] = None,
) -> int:
    now = _utcnow()
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO incidents (title, description, severity, status, assigned_to, created_at, updated_at) "
            "VALUES (?, ?, ?, 'open', ?, ?, ?)",
            (title, description, severity, assigned_to, now, now),
        )
        return cur.lastrowid


def get_incidents(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    if status:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (status, limit, offset),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def get_incident(incident_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return dict(row) if row else None


def update_incident(incident_id: int, updates: Dict[str, Any], db_path: Optional[str] = None):
    allowed = {"title", "description", "severity", "status", "assigned_to"}
    sets = []
    params = []
    for k, v in updates.items():
        if k in allowed:
            sets.append(f"{k} = ?")
            params.append(v)
    if not sets:
        return
    sets.append("updated_at = ?")
    params.append(_utcnow())
    params.append(incident_id)
    with transaction(db_path) as conn:
        conn.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?", params)


def link_alert_to_incident(incident_id: int, alert_id: int, db_path: Optional[str] = None):
    with transaction(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
            (incident_id, alert_id),
        )
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (_utcnow(), incident_id))


def get_incident_alerts(incident_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT a.* FROM alerts a "
        "JOIN incident_alerts ia ON ia.alert_id = a.id "
        "WHERE ia.incident_id = ? ORDER BY a.fired_at DESC",
        (incident_id,),
    ).fetchall()
    return [dict(r) for r in rows]
