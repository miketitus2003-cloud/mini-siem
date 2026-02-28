# Mini SIEM

A security information and event management (SIEM) system built in Python.
Ingests, normalizes, and correlates security events from Windows, Linux, and Azure sources, applies rule-based detection, and serves a real-time dashboard.

---

## Architecture

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Windows     │  │  Linux       │  │  Azure       │
│  Event Logs  │  │  Syslog      │  │  Monitor     │
│  (XML/EVTX)  │  │  (RFC 3164/  │  │  (Stub /     │
│              │  │   5424)      │  │   REST API)  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       ▼                 ▼                 ▼
┌────────────────────────────────────────────────┐
│            Normalization Layer                  │
│  Source-specific parsers → canonical schema     │
└────────────────────┬───────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────┐
│            SQLite Database                      │
│  raw_logs │ normalized_events │ alert_rules │   │
│           │                   │ alerts      │   │
└────────────────────┬───────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────┐
│            Alert Engine                         │
│  Threshold rules (brute-force, flood)          │
│  Single-event rules (log cleared, escalation)  │
└────────────────────┬───────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────┐
│            Flask Dashboard                      │
│  Overview │ Event Explorer │ Alert Viewer │     │
│           │                │ Rule Manager │     │
└────────────────────────────────────────────────┘
```

## Features

### Log Ingestion

| Source | Format | Module |
|--------|--------|--------|
| Windows | Event Log XML / EVTX export, live `pywin32` collection | `app/logs/windows.py` |
| Linux | RFC 3164 (BSD syslog), RFC 5424 | `app/logs/linux.py` |
| Azure | Simulated Azure AD Sign-in, Audit, and Activity logs | `app/logs/azure.py` |

Every raw log is preserved verbatim in the `raw_logs` table. Parsed events are stored in `normalized_events` with a common schema:

```
timestamp | source | event_type | severity | host | user | process | message | metadata_json
```

### Detection Rules

10 built-in rules covering MITRE ATT&CK-aligned scenarios:

| Rule | Mode | Description |
|------|------|-------------|
| Brute-Force Login (Windows) | Threshold | 5+ failed logons (4625) per user in 5 min |
| Brute-Force Login (Linux SSH) | Threshold | 5+ failed SSH attempts per user in 5 min |
| Brute-Force Login (Azure AD) | Threshold | 3+ failed sign-ins per user in 10 min |
| Account Lockout | Single | Any account lockout event |
| Privilege Escalation | Single | Special privileges assigned (4672) |
| Security Log Cleared | Single | Event ID 1102/104 — anti-forensics indicator |
| Suspicious Account Creation | Single | New user account created |
| Sudo to Root – Sensitive Command | Single | Access to /etc/shadow, sudoers |
| Group Membership Change | Single | User added to security group |
| Azure Conditional Access Block | Single | Sign-in blocked by policy |

Rules are stored in the database and can be enabled/disabled at runtime.

### Dashboard

Dark-themed Bootstrap 5 interface with four views:

- **Overview** — event/alert totals, severity distribution, source breakdown, recent activity
- **Event Explorer** — filterable table (source, severity, event type) with pagination
- **Alert Viewer** — open/acknowledged/all tabs, one-click acknowledgement
- **Rule Manager** — view all rules, toggle enable/disable

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/events?source=&severity=&page=` | Query events |
| `GET` | `/api/alerts?acknowledged=true/false` | Query alerts |
| `POST` | `/api/alerts/<id>/ack` | Acknowledge an alert |
| `POST` | `/api/ingest` | Submit logs (Windows XML, syslog lines, Azure JSON) |
| `POST` | `/api/detect` | Trigger detection cycle |
| `GET` | `/api/rules` | List alert rules |
| `POST` | `/api/rules/<id>/toggle` | Enable/disable a rule |

## Quick Start

```bash
# Clone and enter the project
cd mini-siem

# Install dependencies
pip install -r requirements.txt

# Start with sample data (recommended for demo)
python run.py --demo

# Open in browser
open http://127.0.0.1:5000
```

### CLI Options

```
python run.py [OPTIONS]

  --host HOST    Bind address (default: 127.0.0.1)
  --port PORT    Port (default: 5000)
  --debug        Enable Flask debug/reload
  --demo         Load sample events from all sources on startup
```

## Running Tests

```bash
python -m pytest tests/ -v
```

Tests use temporary SQLite databases that are created and destroyed per test case — no cleanup needed.

## Project Structure

```
mini-siem/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── database.py          # SQLite schema, connection pool, CRUD
│   ├── logs/
│   │   ├── windows.py       # Windows Event Log parser & ingestion
│   │   ├── linux.py         # Syslog (RFC 3164/5424) parser & ingestion
│   │   └── azure.py         # Azure Monitor stub & normalization
│   ├── alerts/
│   │   └── engine.py        # Rule-based detection engine
│   └── dashboard/
│       ├── routes.py         # Flask blueprint (UI + JSON API)
│       └── templates/        # Jinja2 HTML templates
├── tests/
│   ├── test_logs.py          # Ingestion & normalization tests
│   └── test_alerts.py        # Detection engine tests
├── run.py                    # CLI entry point
├── requirements.txt
└── README.md
```

## Security Concepts Demonstrated

- **Log normalization** — heterogeneous sources mapped to a unified event schema
- **Correlation** — threshold-based rules detect patterns across event streams
- **MITRE ATT&CK alignment** — rules target Initial Access, Persistence, Privilege Escalation, Defense Evasion
- **Chain of custody** — raw logs preserved alongside normalized records
- **Alert lifecycle** — open → acknowledged workflow

## Technology

- **Python 3.10+**
- **Flask** — web framework and REST API
- **SQLite** (WAL mode) — embedded database with full-text indexes
- **Jinja2** — server-side HTML templates
- **Bootstrap 5** — responsive dark-themed dashboard
