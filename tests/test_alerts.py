"""
tests.test_alerts
~~~~~~~~~~~~~~~~~
Test suite for the alert engine and detection rules.

Covers:
    - Default rule seeding
    - Threshold rule evaluation (brute-force detection)
    - Single-event rule evaluation
    - Alert creation and acknowledgement
    - Detection cycle integration
    - Edge cases: no events, disabled rules, duplicate seeding
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import (
    init_db,
    close_connection,
    insert_normalized_event,
    get_alerts,
    get_alert_rules,
    acknowledge_alert,
    update_alert_rule,
)
from app.alerts.engine import (
    DEFAULT_RULES,
    seed_default_rules,
    evaluate_all,
    run_detection_cycle,
)


class _DBTestCase(unittest.TestCase):
    """Provides a fresh temporary database for each test."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self._tmp.name
        self._tmp.close()
        init_db(self.db_path)

    def tearDown(self):
        close_connection()
        os.unlink(self.db_path)


# ══════════════════════════════════════════════
# Rule seeding tests
# ══════════════════════════════════════════════

class TestRuleSeeding(_DBTestCase):

    def test_seed_creates_default_rules(self):
        count = seed_default_rules(db_path=self.db_path)
        self.assertEqual(count, len(DEFAULT_RULES))

        rules = get_alert_rules(enabled_only=False, db_path=self.db_path)
        self.assertEqual(len(rules), len(DEFAULT_RULES))

    def test_seed_is_idempotent(self):
        seed_default_rules(db_path=self.db_path)
        second = seed_default_rules(db_path=self.db_path)
        self.assertEqual(second, 0)

        rules = get_alert_rules(enabled_only=False, db_path=self.db_path)
        self.assertEqual(len(rules), len(DEFAULT_RULES))

    def test_all_rules_enabled_by_default(self):
        seed_default_rules(db_path=self.db_path)
        rules = get_alert_rules(enabled_only=True, db_path=self.db_path)
        self.assertEqual(len(rules), len(DEFAULT_RULES))

    def test_rule_has_valid_condition_json(self):
        seed_default_rules(db_path=self.db_path)
        rules = get_alert_rules(enabled_only=False, db_path=self.db_path)
        for rule in rules:
            cond = json.loads(rule["condition_json"])
            self.assertIn("mode", cond)
            self.assertIn(cond["mode"], ("single", "threshold"))


# ══════════════════════════════════════════════
# Threshold rule tests
# ══════════════════════════════════════════════

class TestThresholdDetection(_DBTestCase):

    def setUp(self):
        super().setUp()
        seed_default_rules(db_path=self.db_path)

    def _insert_failed_logins(self, count, source="windows", user="admin", minutes_ago=2):
        """Helper: insert a batch of failed login events within a recent time window."""
        base_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
        ids = []
        for i in range(count):
            ts = (base_time + timedelta(seconds=i * 5)).isoformat()
            eid = insert_normalized_event({
                "raw_log_id": None,
                "timestamp": ts,
                "source": source,
                "event_type": "login_failure",
                "severity": "high",
                "host": "DC01",
                "user": user,
                "process": "sshd" if source == "linux" else "Security-Auditing",
                "message": f"Failed login #{i+1} for {user}",
                "metadata_json": "{}",
            }, db_path=self.db_path)
            ids.append(eid)
        return ids

    def test_brute_force_fires_at_threshold(self):
        """Five failed logins for the same user should trigger the brute-force rule."""
        event_ids = self._insert_failed_logins(5, source="windows", user="admin")
        alert_ids = evaluate_all(recent_event_ids=event_ids, db_path=self.db_path)

        # Should fire at least the Windows brute-force rule
        alerts = get_alerts(db_path=self.db_path)
        brute_alerts = [a for a in alerts if "Brute" in a["message"] and "Windows" in a["message"]]
        self.assertGreater(len(brute_alerts), 0)

    def test_brute_force_does_not_fire_below_threshold(self):
        """Three failed logins should NOT trigger the 5-event threshold rule."""
        event_ids = self._insert_failed_logins(3, source="windows", user="admin")
        alert_ids = evaluate_all(recent_event_ids=event_ids, db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        brute_alerts = [a for a in alerts if "Brute-Force Login (Windows)" in a["message"]]
        self.assertEqual(len(brute_alerts), 0)

    def test_brute_force_groups_by_user(self):
        """Separate users should be evaluated independently."""
        self._insert_failed_logins(5, source="linux", user="root")
        self._insert_failed_logins(2, source="linux", user="deploy")
        evaluate_all(db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        root_alerts = [a for a in alerts if "root" in a["message"] and "Brute" in a["message"]]
        deploy_alerts = [a for a in alerts if "deploy" in a["message"] and "Brute" in a["message"]]

        self.assertGreater(len(root_alerts), 0)
        self.assertEqual(len(deploy_alerts), 0)

    def test_old_events_outside_window_ignored(self):
        """Events older than the window should not be counted."""
        # Insert events from 20 minutes ago (outside the 5-min window)
        event_ids = self._insert_failed_logins(10, source="windows", user="admin", minutes_ago=20)
        alert_ids = evaluate_all(recent_event_ids=event_ids, db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        brute_alerts = [a for a in alerts if "Brute-Force Login (Windows)" in a["message"]]
        self.assertEqual(len(brute_alerts), 0)


# ══════════════════════════════════════════════
# Single-event rule tests
# ══════════════════════════════════════════════

class TestSingleEventDetection(_DBTestCase):

    def setUp(self):
        super().setUp()
        seed_default_rules(db_path=self.db_path)

    def _insert_event(self, event_type, severity="high", source="windows", **kwargs):
        base = {
            "raw_log_id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "host": "DC01",
            "user": "admin",
            "process": "test",
            "message": f"Test event: {event_type}",
            "metadata_json": "{}",
        }
        base.update(kwargs)
        return insert_normalized_event(base, db_path=self.db_path)

    def test_log_cleared_fires_alert(self):
        eid = self._insert_event("log_cleared")
        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        log_clear_alerts = [a for a in alerts if "Log Cleared" in a["message"]]
        self.assertGreater(len(log_clear_alerts), 0)
        self.assertEqual(log_clear_alerts[0]["severity"], "critical")

    def test_account_lockout_fires_alert(self):
        eid = self._insert_event("account_lockout")
        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        lockout_alerts = [a for a in alerts if "Lockout" in a["message"]]
        self.assertGreater(len(lockout_alerts), 0)

    def test_account_created_fires_alert(self):
        eid = self._insert_event("account_created", severity="medium")
        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        acct_alerts = [a for a in alerts if "Account Creation" in a["message"]]
        self.assertGreater(len(acct_alerts), 0)

    def test_group_member_added_fires_alert(self):
        eid = self._insert_event("group_member_added", severity="medium")
        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        group_alerts = [a for a in alerts if "Group" in a["message"]]
        self.assertGreater(len(group_alerts), 0)

    def test_sensitive_file_access_fires_alert(self):
        eid = self._insert_event("sensitive_file_access", source="linux")
        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)

        alerts = get_alerts(db_path=self.db_path)
        sens_alerts = [a for a in alerts if "Sensitive" in a["message"] or "sudo" in a["message"].lower()]
        self.assertGreater(len(sens_alerts), 0)


# ══════════════════════════════════════════════
# Alert management tests
# ══════════════════════════════════════════════

class TestAlertManagement(_DBTestCase):

    def setUp(self):
        super().setUp()
        seed_default_rules(db_path=self.db_path)

    def test_acknowledge_alert(self):
        eid = insert_normalized_event({
            "raw_log_id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "windows",
            "event_type": "log_cleared",
            "severity": "critical",
            "host": "DC01",
            "user": "attacker",
            "process": "test",
            "message": "Log cleared",
            "metadata_json": "{}",
        }, db_path=self.db_path)

        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)

        open_alerts = get_alerts(acknowledged=False, db_path=self.db_path)
        self.assertGreater(len(open_alerts), 0)

        alert_id = open_alerts[0]["id"]
        acknowledge_alert(alert_id, db_path=self.db_path)

        acked = get_alerts(acknowledged=True, db_path=self.db_path)
        self.assertTrue(any(a["id"] == alert_id for a in acked))

    def test_disabled_rule_does_not_fire(self):
        rules = get_alert_rules(enabled_only=False, db_path=self.db_path)
        log_clear_rule = next(r for r in rules if "Log Cleared" in r["name"])

        update_alert_rule(log_clear_rule["id"], {"enabled": 0}, db_path=self.db_path)

        eid = insert_normalized_event({
            "raw_log_id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "windows",
            "event_type": "log_cleared",
            "severity": "critical",
            "host": "DC01",
            "user": "admin",
            "process": "test",
            "message": "Log cleared",
            "metadata_json": "{}",
        }, db_path=self.db_path)

        evaluate_all(recent_event_ids=[eid], db_path=self.db_path)
        alerts = get_alerts(db_path=self.db_path)
        log_alerts = [a for a in alerts if "Log Cleared" in a["message"]]
        self.assertEqual(len(log_alerts), 0)


# ══════════════════════════════════════════════
# Detection cycle integration test
# ══════════════════════════════════════════════

class TestDetectionCycle(_DBTestCase):

    def test_run_detection_cycle_returns_summary(self):
        seed_default_rules(db_path=self.db_path)

        eid = insert_normalized_event({
            "raw_log_id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "windows",
            "event_type": "log_cleared",
            "severity": "critical",
            "host": "DC01",
            "user": "admin",
            "process": "test",
            "message": "Log cleared event",
            "metadata_json": "{}",
        }, db_path=self.db_path)

        result = run_detection_cycle(recent_event_ids=[eid], db_path=self.db_path)
        self.assertIn("alerts_fired", result)
        self.assertIn("alert_ids", result)
        self.assertIn("evaluated_at", result)
        self.assertGreater(result["alerts_fired"], 0)

    def test_no_events_no_alerts(self):
        seed_default_rules(db_path=self.db_path)
        result = run_detection_cycle(db_path=self.db_path)
        self.assertEqual(result["alerts_fired"], 0)

    def test_full_pipeline_with_sample_data(self):
        """End-to-end: load samples from all sources, run detection, verify alerts."""
        seed_default_rules(db_path=self.db_path)

        from app.logs.windows import load_sample_data as win_samples
        from app.logs.linux import load_sample_data as linux_samples
        from app.logs.azure import load_sample_data as azure_samples

        w_ids = win_samples(db_path=self.db_path)
        l_ids = linux_samples(db_path=self.db_path)
        a_ids = azure_samples(db_path=self.db_path)

        all_ids = w_ids + l_ids + a_ids
        result = run_detection_cycle(recent_event_ids=all_ids, db_path=self.db_path)

        self.assertGreater(result["alerts_fired"], 0, "Sample data should trigger at least one alert")

        alerts = get_alerts(db_path=self.db_path)
        severities = {a["severity"] for a in alerts}
        self.assertTrue(
            severities & {"high", "critical"},
            "Expected at least one high/critical alert from sample data",
        )


if __name__ == "__main__":
    unittest.main()
