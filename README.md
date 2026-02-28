# Mini SIEM

A fully functional Security Information and Event Management (SIEM) system built in Python/Flask — designed as a portfolio project demonstrating real SOC tooling concepts.

Ingests, normalises, and correlates security events from **five log sources**, applies rule-based detection including correlation rules, and serves a real-time analyst dashboard with case management, RBAC, and a complete audit trail.

---

## Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Windows     │  │  Linux       │  │  Azure AD    │  │  Firewall    │  │  Endpoint    │
│  Event Logs  │  │  Syslog      │  │  Sign-in /   │  │  (key=value  │  │  EDR / JSON  │
│  (XML/EVTX)  │  │  (auth.log)  │  │  Audit Logs  │  │  syslog)     │  │  telemetry)  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │                 │                 │
       ▼                 ▼                 ▼                 ▼                 ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                            Normalisation Layer                                          │
│             Source parsers → canonical schema (timestamp, source, event_type,           │
│             severity, host, user, process, message, metadata_json)                      │
└────────────────────────────────────┬───────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SQLite Database (WAL mode)                                 │
│  raw_logs │ normalized_events │ alert_rules │ alerts │ incidents │ audit_log │ users    │
└────────────────────────────────────┬───────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Detection Engine                                           │
│  Single-event rules   │   Threshold rules (N events / window)   │   Correlation rules  │
│  (immediate match)    │   (brute-force, port scan)               │   (failures→success) │
└────────────────────────────────────┬───────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              Flask Dashboard                                            │
│  Overview │ Event Explorer │ Alert Triage │ Incident Management │ Rule Manager │        │
│  Log Sources │ User Management │ Audit Log                                             │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Features

### Log Ingestion — 5 Sources

| Source | Format | Module |
|--------|--------|--------|
| Windows | Event Log XML / EVTX export, live `pywin32` collection | `app/logs/windows.py` |
| Linux | RFC 3164/5424 syslog (auth.log, syslog, kern.log) | `app/logs/linux.py` |
| Azure AD | Sign-in Logs, Audit Logs, Activity Logs (stub + JSON) | `app/logs/azure.py` |
| Firewall | key=value syslog (pfSense, iptables, Fortinet) | `app/logs/firewall.py` |
| Endpoint | EDR/NDJSON telemetry (CrowdStrike/SentinelOne schema) | `app/logs/endpoint.py` |

All raw logs are preserved verbatim (`raw_logs` table). Parsed records share a common normalised schema.

### Detection Rules — 15 Built-In

Three rule modes:

| Mode | Description |
|------|-------------|
| **Single** | Fires immediately on any matching event |
| **Threshold** | Fires when N events of the same type occur within a sliding time window |
| **Correlation** | Joins two event types — e.g., 3+ failures then 1 success = likely compromise |

Built-in rules cover MITRE ATT&CK-aligned scenarios:

| Rule | Mode | Trigger |
|------|------|---------|
| Brute-Force Login (Windows) | Threshold | 5+ failed logons (4625) per user in 5 min |
| Brute-Force Login (Linux SSH) | Threshold | 5+ failed SSH attempts per user in 5 min |
| Brute-Force Login (Azure AD) | Threshold | 3+ failed sign-ins per user in 10 min |
| **Brute-Force Success – Likely Compromise** | **Correlation** | 3+ failures then 1 success → auto-creates incident |
| Account Lockout | Single | Any account lockout event |
| Privilege Escalation | Single | Special privileges assigned (4672) |
| Security Log Cleared | Single | Event ID 1102/104 — anti-forensics |
| Suspicious Account Creation | Single | New user account created |
| Sudo to Root – Sensitive File | Single | `/etc/shadow`, `/etc/passwd`, `sudoers` access |
| Group Membership Change | Single | User added to security-sensitive group |
| Azure Conditional Access Block | Single | Sign-in blocked by Conditional Access |
| Port Scan Detected | Threshold | 8+ firewall blocks from same IP in 2 min |
| RDP/SMB Attack from Internet | Single | Any blocked RDP (3389) or SMB (445) connection |
| Suspicious Process Execution | Single | High-severity EDR process creation |
| LSASS Memory Access | Single | Process access to lsass.exe (credential dumping) |

### Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| Overview | `/` | Stat cards, hourly bar chart, severity donut, source pie, recent alerts/events |
| Event Explorer | `/events` | Full-text search (IP, user, host, message) + filter by source/severity/time |
| Alert Viewer | `/alerts` | Open/acknowledged tabs, acknowledge, add analyst notes |
| Incidents | `/incidents` | Case management — create, assign, update status, link alerts |
| Rules | `/rules` | View all rules, toggle enable/disable (admin) |
| Log Sources | `/sources` | Registered sources with type category and sample data loading |
| Ingest | `/ingest` | Load sample data or paste raw logs (admin) |
| Users | `/users` | Create/edit/delete accounts with role assignment (admin) |
| Audit Log | `/audit` | Filterable record of all write actions by all users (admin) |

### Security Features

- **Password hashing** — Werkzeug PBKDF2-SHA256 (no plaintext passwords stored)
- **RBAC** — Three roles with least-privilege enforcement:
  - `admin` — full access including ingest, user management, rule toggle, audit log
  - `analyst` — triage access (acknowledge alerts, manage incidents, add notes)
  - `viewer` — read-only (dashboard, events, alerts, incidents)
- **Audit logging** — every write action logged with username, action, target, detail, IP address
- **Input validation** — size limits (2 MB / 5,000 lines / 1,000 records), type checking, source allowlist
- **Error handling** — safe error pages/responses without stack traces exposed to clients
- **Session management** — Flask-Login with secure cookie sessions

### REST API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/stats` | any | Dashboard statistics |
| `GET` | `/api/events` | any | Query events (source, severity, event_type, host, user) |
| `GET` | `/api/alerts` | any | Query alerts (acknowledged filter) |
| `POST` | `/api/alerts/<id>/ack` | analyst+ | Acknowledge an alert |
| `POST` | `/api/alerts/<id>/note` | analyst+ | Add analyst note |
| `POST` | `/api/ingest` | admin | Submit logs (XML, syslog, JSON, key=value, NDJSON) |
| `POST` | `/api/ingest/sample` | admin | Load built-in sample data |
| `POST` | `/api/detect` | analyst+ | Trigger detection cycle |
| `GET` | `/api/rules` | any | List alert rules |
| `POST` | `/api/rules/<id>/toggle` | admin | Enable/disable a rule |
| `POST` | `/api/incidents` | analyst+ | Create incident |
| `PATCH` | `/api/incidents/<id>` | analyst+ | Update incident status/assignment |
| `POST` | `/api/incidents/<id>/alerts` | analyst+ | Link alert to incident |
| `POST` | `/api/users` | admin | Create user account |
| `PATCH` | `/api/users/<id>/role` | admin | Change user role |
| `DELETE` | `/api/users/<id>` | admin | Delete user account |

---

## Quick Start

```bash
# Clone and enter the project
cd mini-siem

# Install dependencies
pip install -r requirements.txt

# Start with sample data pre-loaded (recommended for demo)
python run.py --demo

# Open in browser
open http://127.0.0.1:5000
# Login: admin / admin   (change this in production via the Users page)
```

### CLI Options

```
python run.py [OPTIONS]

  --host HOST    Bind address (default: 127.0.0.1)
  --port PORT    Port (default: 5000)
  --debug        Enable Flask debug/reload
  --demo         Load sample events from all sources on startup
```

### Log Forwarder (Live Simulation)

Continuously generates realistic security events and POSTs them to the SIEM — watch the dashboard fill up in real time:

```bash
# Default: all sources, every 5 seconds
python scripts/log_forwarder.py

# Custom: firewall logs every 2 seconds
python scripts/log_forwarder.py --source firewall --interval 2 --count 10

# One-shot batch of Windows events
python scripts/log_forwarder.py --once --source windows --count 20

# Options
python scripts/log_forwarder.py --help
```

The forwarder uses only Python stdlib — no extra dependencies.

---

## Running Tests

```bash
python -m pytest tests/ -v
# 56 tests, all passing
```

Tests use temporary per-test SQLite databases — no cleanup needed.

---

## Project Structure

```
mini-siem/
├── app/
│   ├── __init__.py              # Flask app factory, RBAC user model, error handlers
│   ├── database.py              # SQLite schema (v4), connection pool, all CRUD + audit ops
│   ├── logs/
│   │   ├── windows.py           # Windows Event Log XML parser + live pywin32 collection
│   │   ├── linux.py             # Syslog RFC 3164/5424 parser
│   │   ├── azure.py             # Azure AD stub + JSON normalisation
│   │   ├── firewall.py          # Firewall key=value syslog parser
│   │   └── endpoint.py          # EDR NDJSON/JSON parser
│   ├── alerts/
│   │   └── engine.py            # Detection engine: single / threshold / correlation rules
│   └── dashboard/
│       ├── routes.py             # Flask blueprint (UI routes + JSON API + audit hooks)
│       └── templates/
│           ├── base.html         # Dark Bootstrap 5 layout + navbar
│           ├── index.html        # Dashboard overview + Chart.js charts
│           ├── events.html       # Event explorer with full-text search
│           ├── alerts.html       # Alert triage (ack, notes)
│           ├── incidents.html    # Incident list + create
│           ├── incident_detail.html  # Case detail, status, assign, link alerts
│           ├── rules.html        # Rule manager
│           ├── sources.html      # Log source registry
│           ├── ingest.html       # Sample data loader + paste interface
│           ├── users.html        # User management (RBAC)
│           ├── audit.html        # Audit log viewer
│           ├── login.html        # Authentication
│           └── error.html        # Safe error pages (no stack traces)
├── scripts/
│   └── log_forwarder.py         # Standalone log simulator (stdlib only)
├── tests/
│   ├── test_logs.py              # Parser + ingestion tests (39 tests)
│   └── test_alerts.py            # Detection engine tests (17 tests)
├── run.py                        # CLI entry point
└── requirements.txt              # Flask, Flask-Login, Werkzeug, gunicorn
```

---

## Database Schema (v4)

```
raw_logs            — verbatim log text, source tag, ingestion timestamp
normalized_events   — parsed events with canonical schema + indexes
alert_rules         — rule definitions (single / threshold / correlation)
alerts              — fired alert instances, ack status, analyst notes
incidents           — security cases (open/investigating/resolved/closed)
incident_alerts     — many-to-many alert→incident links
log_sources         — source registry with type metadata
users               — accounts with hashed passwords and roles
audit_log           — immutable record of all write actions
```

---

## Security Concepts Demonstrated

Aligned with **CompTIA Security+** and industry SOC practices:

| Concept | Where |
|---------|-------|
| Log management & normalisation | 5-source ingestion pipeline |
| Threshold-based detection | Brute-force, port scan rules |
| Correlation rules | Failure→success = compromise pattern |
| MITRE ATT&CK alignment | Rule descriptions reference techniques |
| Least privilege / RBAC | admin / analyst / viewer roles |
| Audit trail / accountability | Audit log table, `/audit` page |
| Chain of custody | Raw logs preserved alongside normalised records |
| Alert lifecycle | open → acknowledged workflow |
| Incident management | Cases with status, assignment, linked alerts |
| Defence in depth | Auth + RBAC + audit + input validation + error handling |

---

## Technology

- **Python 3.10+**
- **Flask 3** — web framework and REST API
- **Flask-Login** — session authentication
- **Werkzeug** — PBKDF2 password hashing
- **SQLite 3** (WAL mode) — embedded database with indexes
- **Bootstrap 5.3** — responsive dark-themed UI
- **Chart.js 4.4** — dashboard visualisation (bar, donut charts)
- **Gunicorn** — production WSGI server
