"""
Tests for the in-memory IP rate limiter (app/rate_limit.py).
"""

import unittest
from datetime import datetime, timezone, timedelta


class TestRateLimiter(unittest.TestCase):

    def setUp(self):
        import app.rate_limit as rl
        rl._failed_attempts.clear()
        self.rl = rl

    def test_new_ip_not_rate_limited(self):
        self.assertFalse(self.rl.is_rate_limited("1.2.3.4"))

    def test_below_threshold_not_blocked(self):
        for _ in range(self.rl.MAX_ATTEMPTS - 1):
            self.rl.record_failure("1.2.3.4")
        self.assertFalse(self.rl.is_rate_limited("1.2.3.4"))

    def test_at_threshold_is_blocked(self):
        for _ in range(self.rl.MAX_ATTEMPTS):
            self.rl.record_failure("1.2.3.4")
        self.assertTrue(self.rl.is_rate_limited("1.2.3.4"))

    def test_above_threshold_is_blocked(self):
        for _ in range(self.rl.MAX_ATTEMPTS + 3):
            self.rl.record_failure("1.2.3.4")
        self.assertTrue(self.rl.is_rate_limited("1.2.3.4"))

    def test_clear_failures_unblocks_ip(self):
        for _ in range(self.rl.MAX_ATTEMPTS):
            self.rl.record_failure("1.2.3.4")
        self.assertTrue(self.rl.is_rate_limited("1.2.3.4"))
        self.rl.clear_failures("1.2.3.4")
        self.assertFalse(self.rl.is_rate_limited("1.2.3.4"))

    def test_different_ips_are_isolated(self):
        for _ in range(self.rl.MAX_ATTEMPTS):
            self.rl.record_failure("1.2.3.4")
        self.assertFalse(self.rl.is_rate_limited("5.6.7.8"))

    def test_clear_nonexistent_ip_is_safe(self):
        self.rl.clear_failures("9.9.9.9")  # should not raise
        self.assertFalse(self.rl.is_rate_limited("9.9.9.9"))

    def test_stale_failures_outside_window_not_counted(self):
        """Failures older than WINDOW_SECONDS should be pruned and not trigger block."""
        old_time = datetime.now(timezone.utc) - timedelta(seconds=self.rl.WINDOW_SECONDS + 60)
        import app.rate_limit as rl
        with rl._lock:
            rl._failed_attempts["2.2.2.2"] = [old_time] * (self.rl.MAX_ATTEMPTS + 5)
        # All entries are stale — should not be rate limited
        self.assertFalse(self.rl.is_rate_limited("2.2.2.2"))

    def test_mix_of_old_and_recent_failures(self):
        """Only recent failures count toward the threshold."""
        old_time = datetime.now(timezone.utc) - timedelta(seconds=self.rl.WINDOW_SECONDS + 60)
        import app.rate_limit as rl
        with rl._lock:
            # 4 old + 4 recent = 4 recent (below threshold of 5)
            rl._failed_attempts["3.3.3.3"] = [old_time] * 4
        for _ in range(4):
            self.rl.record_failure("3.3.3.3")
        self.assertFalse(self.rl.is_rate_limited("3.3.3.3"))
        # One more recent failure pushes to threshold
        self.rl.record_failure("3.3.3.3")
        self.assertTrue(self.rl.is_rate_limited("3.3.3.3"))


if __name__ == "__main__":
    unittest.main()
