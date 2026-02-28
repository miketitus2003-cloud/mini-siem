"""
mini-siem.app
~~~~~~~~~~~~~
Application factory for the Mini SIEM Flask application.

Usage::

    from app import create_app
    app = create_app()
    app.run()
"""

import logging
import os
from typing import Optional

from flask import Flask
from flask_login import LoginManager, UserMixin
from werkzeug.security import generate_password_hash

from app.database import (
    close_connection,
    create_user,
    get_user_by_id,
    get_user_by_username,
    init_db,
)
from app.alerts.engine import seed_default_rules


# ── Flask-Login User model ────────────────────
# Lives here (not database.py) to keep the DB layer free of Flask imports.

class SIEMUser(UserMixin):
    """Thin wrapper around a users dict row for Flask-Login."""

    def __init__(self, row: dict):
        self.id = str(row["id"])
        self.username = row["username"]
        self.password_hash = row["password_hash"]
        self.role = row["role"]

    def get_id(self) -> str:
        return self.id

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def create_app(db_path: Optional[str] = None, load_samples: bool = False) -> Flask:
    """Create and configure the Flask application.

    Parameters
    ----------
    db_path : str | None
        Override the default SQLite database path (useful for testing).
    load_samples : bool
        If ``True``, insert sample data from every log source on startup.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "dashboard", "templates"),
    )

    # ── Secret key (required for sessions) ───
    app.config["SECRET_KEY"] = os.environ.get("SIEM_SECRET_KEY", "change-me-in-production")

    # ── Logging ──────────────────────────────
    log_level = os.environ.get("SIEM_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger("mini-siem")

    # ── Database ─────────────────────────────
    init_db(db_path)
    logger.info("Database initialised")

    # ── Alert rules ──────────────────────────
    seeded = seed_default_rules(db_path)
    if seeded:
        logger.info("Seeded %d default detection rules", seeded)

    # ── Default admin account ─────────────────
    _seed_admin(db_path, logger)

    # ── Flask-Login ───────────────────────────
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "dashboard.login"
    login_manager.login_message = "Please log in to access the SIEM."
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id: str):
        row = get_user_by_id(int(user_id), db_path=db_path)
        return SIEMUser(row) if row else None

    # ── Optional sample data ─────────────────
    if load_samples:
        _load_all_samples(db_path, logger)

    # ── Blueprints ───────────────────────────
    from app.dashboard.routes import bp as dashboard_bp
    app.register_blueprint(dashboard_bp)

    # ── Teardown ─────────────────────────────
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        close_connection()

    logger.info("Mini SIEM application ready")
    return app


def _seed_admin(db_path, logger):
    """Create the default admin account if no users exist yet."""
    existing = get_user_by_username("admin", db_path=db_path)
    if existing is None:
        pw_hash = generate_password_hash("admin")
        create_user("admin", pw_hash, role="admin", db_path=db_path)
        logger.info("Seeded default admin account (username: admin, password: admin)")


def _load_all_samples(db_path, logger):
    """Import sample data from every log source module."""
    from app.logs.windows import load_sample_data as win_samples
    from app.logs.linux import load_sample_data as linux_samples
    from app.logs.azure import load_sample_data as azure_samples
    from app.alerts.engine import evaluate_all

    w = win_samples(db_path=db_path)
    logger.info("Loaded %d Windows sample events", len(w))

    l = linux_samples(db_path=db_path)
    logger.info("Loaded %d Linux sample events", len(l))

    a = azure_samples(db_path=db_path)
    logger.info("Loaded %d Azure sample events", len(a))

    all_ids = w + l + a
    alerts = evaluate_all(recent_event_ids=all_ids, db_path=db_path)
    logger.info("Detection cycle on sample data produced %d alerts", len(alerts))
