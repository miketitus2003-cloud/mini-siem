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

from app.database import close_connection, init_db
from app.alerts.engine import seed_default_rules


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
