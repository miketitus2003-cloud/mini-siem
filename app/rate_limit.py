"""
mini-siem.app.rate_limit
~~~~~~~~~~~~~~~~~~~~~~~~
In-memory IP-based rate limiter for the login endpoint.

State resets on process restart — acceptable for a single-process deployment.
Uses threading.Lock for safety under Gunicorn sync workers.
"""

import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List

_lock = threading.Lock()
_failed_attempts: Dict[str, List[datetime]] = {}

MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300    # 5 minutes — window to count failures
LOCKOUT_SECONDS = 900   # 15 minutes — lockout after threshold hit


def _now() -> datetime:
    return datetime.now(timezone.utc)


def record_failure(ip: str) -> None:
    """Record one failed login attempt for the given IP."""
    with _lock:
        _failed_attempts.setdefault(ip, []).append(_now())


def clear_failures(ip: str) -> None:
    """Clear the failure history for an IP (called on successful login)."""
    with _lock:
        _failed_attempts.pop(ip, None)


def is_rate_limited(ip: str) -> bool:
    """
    Return True if this IP has >= MAX_ATTEMPTS failures within WINDOW_SECONDS
    and the most recent failure is within LOCKOUT_SECONDS.
    Prunes stale entries atomically.
    """
    with _lock:
        bucket = _failed_attempts.get(ip, [])
        now = _now()
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)
        recent = [ts for ts in bucket if ts >= cutoff]
        _failed_attempts[ip] = recent  # prune in-place

        if len(recent) < MAX_ATTEMPTS:
            return False

        lockout_cutoff = now - timedelta(seconds=LOCKOUT_SECONDS)
        return recent[-1] >= lockout_cutoff
