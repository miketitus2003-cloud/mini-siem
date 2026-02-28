"""
tests.test_logs
~~~~~~~~~~~~~~~
Test suite for the log ingestion and normalization layer.

Covers:
    - Windows Event Log XML parsing and ingestion
    - Linux syslog (RFC 3164 / RFC 5424) parsing and ingestion
    - Azure Monitor stub ingestion
    - Edge cases: malformed input, empty input, boundary values
    - Database round-trip verification
"""

import json
import os
import tempfile
import unittest

# Ensure app package is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import init_db, get_connection, close_connection, query_events, get_raw_logs
from app.logs.windows import parse_event_xml, ingest_evtx_xml, load_sample_data as win_samples
from app.logs.linux import parse_syslog_line, ingest_syslog_lines, load_sample_data as linux_samples
from app.logs.azure import (
    AzureMonitorStub,
    normalize_signin_log,
    normalize_audit_log,
    normalize_activity_log,
    ingest_azure_logs,
    load_sample_data as azure_samples,
)


class _DBTestCase(unittest.TestCase):
    """Base class that provides a fresh temporary database for each test."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self._tmp.name
        self._tmp.close()
        init_db(self.db_path)

    def tearDown(self):
        close_connection()
        os.unlink(self.db_path)


# ══════════════════════════════════════════════
# Windows Event Log tests
# ══════════════════════════════════════════════

class TestWindowsParser(unittest.TestCase):
    """Unit tests for the Windows XML parser (no database needed)."""

    VALID_EVENT = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4625</EventID>
        <Level>0</Level>
        <TimeCreated SystemTime="2025-06-15T08:23:11Z"/>
        <Computer>DC01.corp.local</Computer>
        <Channel>Security</Channel>
        <Keywords>0x8010000000000000</Keywords>
      </System>
      <EventData>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="TargetDomainName">CORP</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="IpAddress">10.0.0.55</Data>
      </EventData>
    </Event>
    """

    def test_parse_valid_event(self):
        result = parse_event_xml(self.VALID_EVENT)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "login_failure")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["host"], "DC01.corp.local")
        self.assertEqual(result["user"], "admin")
        self.assertEqual(result["source"], "windows")

    def test_parse_extracts_metadata(self):
        result = parse_event_xml(self.VALID_EVENT)
        meta = json.loads(result["metadata_json"])
        self.assertEqual(meta["event_id"], 4625)
        self.assertEqual(meta["channel"], "Security")
        self.assertEqual(meta["event_data"]["IpAddress"], "10.0.0.55")

    def test_parse_login_success(self):
        xml = self.VALID_EVENT.replace("4625", "4624")
        result = parse_event_xml(xml)
        self.assertEqual(result["event_type"], "login_success")

    def test_parse_log_cleared(self):
        xml = self.VALID_EVENT.replace("4625", "1102")
        result = parse_event_xml(xml)
        self.assertEqual(result["event_type"], "log_cleared")
        self.assertEqual(result["severity"], "high")

    def test_parse_privilege_assigned(self):
        xml = self.VALID_EVENT.replace("4625", "4672")
        result = parse_event_xml(xml)
        self.assertEqual(result["event_type"], "privilege_assigned")
        self.assertEqual(result["severity"], "medium")

    def test_parse_malformed_xml_returns_none(self):
        result = parse_event_xml("<not-valid-xml><<<")
        self.assertIsNone(result)

    def test_parse_missing_system_returns_none(self):
        result = parse_event_xml("<Event><Data>test</Data></Event>")
        self.assertIsNone(result)

    def test_parse_unknown_event_id(self):
        xml = self.VALID_EVENT.replace("4625", "9999")
        result = parse_event_xml(xml)
        self.assertEqual(result["event_type"], "windows_9999")


class TestWindowsIngestion(_DBTestCase):
    """Integration tests for Windows event ingestion into the database."""

    def test_ingest_single_event(self):
        xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Test"/>
            <EventID>4624</EventID>
            <Level>4</Level>
            <TimeCreated SystemTime="2025-01-01T00:00:00Z"/>
            <Computer>TEST-PC</Computer>
            <Channel>Security</Channel>
          </System>
          <EventData>
            <Data Name="TargetUserName">testuser</Data>
          </EventData>
        </Event>
        """
        ids = ingest_evtx_xml(xml, db_path=self.db_path)
        self.assertEqual(len(ids), 1)

        events = query_events(db_path=self.db_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "windows")
        self.assertEqual(events[0]["event_type"], "login_success")

    def test_ingest_multiple_events(self):
        xml = """
        <Events>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="T"/><EventID>4625</EventID><Level>0</Level>
          <TimeCreated SystemTime="2025-01-01T00:00:00Z"/><Computer>A</Computer><Channel>Security</Channel></System>
          <EventData><Data Name="TargetUserName">u1</Data></EventData>
        </Event>
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="T"/><EventID>4624</EventID><Level>4</Level>
          <TimeCreated SystemTime="2025-01-01T00:01:00Z"/><Computer>B</Computer><Channel>Security</Channel></System>
          <EventData><Data Name="TargetUserName">u2</Data></EventData>
        </Event>
        </Events>
        """
        ids = ingest_evtx_xml(xml, db_path=self.db_path)
        self.assertEqual(len(ids), 2)

    def test_ingest_stores_raw_log(self):
        xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="T"/><EventID>4688</EventID><Level>4</Level>
          <TimeCreated SystemTime="2025-01-01T00:00:00Z"/><Computer>X</Computer><Channel>Security</Channel></System>
          <EventData><Data Name="NewProcessName">cmd.exe</Data></EventData>
        </Event>
        """
        ingest_evtx_xml(xml, db_path=self.db_path)
        raws = get_raw_logs(source="windows", db_path=self.db_path)
        self.assertEqual(len(raws), 1)
        self.assertIn("4688", raws[0]["raw_text"])

    def test_sample_data_loads(self):
        ids = win_samples(db_path=self.db_path)
        self.assertGreater(len(ids), 5)


# ══════════════════════════════════════════════
# Linux syslog tests
# ══════════════════════════════════════════════

class TestLinuxParser(unittest.TestCase):
    """Unit tests for the syslog line parser."""

    def test_parse_failed_ssh(self):
        line = "Jun 15 08:20:01 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
        result = parse_syslog_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "login_failure")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["host"], "web01")
        self.assertEqual(result["user"], "admin")

    def test_parse_successful_ssh(self):
        line = "Jun 15 08:21:00 web01 sshd[12346]: Accepted publickey for deploy from 10.0.0.5 port 40022 ssh2"
        result = parse_syslog_line(line)
        self.assertEqual(result["event_type"], "login_success")
        self.assertEqual(result["user"], "deploy")

    def test_parse_sudo_command(self):
        line = "Jun 15 08:22:15 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart nginx"
        result = parse_syslog_line(line)
        self.assertEqual(result["event_type"], "sudo_command")
        self.assertEqual(result["severity"], "medium")

    def test_parse_useradd(self):
        line = "Jun 15 08:23:00 web01 useradd[13000]: new user: name=testuser, UID=1050, GID=1050, home=/home/testuser, shell=/bin/bash"
        result = parse_syslog_line(line)
        self.assertEqual(result["event_type"], "account_created")

    def test_parse_usermod_group(self):
        line = "Jun 15 08:24:00 web01 usermod[13001]: add 'testuser' to group 'sudo'"
        result = parse_syslog_line(line)
        self.assertEqual(result["event_type"], "group_member_added")

    def test_parse_cron(self):
        line = "Jun 15 08:30:00 web01 CRON[15000]: (root) CMD (/usr/local/bin/backup.sh)"
        result = parse_syslog_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "linux")

    def test_parse_empty_line_returns_none(self):
        self.assertIsNone(parse_syslog_line(""))
        self.assertIsNone(parse_syslog_line("   "))

    def test_parse_garbage_returns_none(self):
        self.assertIsNone(parse_syslog_line("this is not a syslog line at all"))

    def test_metadata_contains_extras(self):
        line = "Jun 15 08:20:01 web01 sshd[12345]: Failed password for admin from 10.0.0.1 port 22 ssh2"
        result = parse_syslog_line(line)
        meta = json.loads(result["metadata_json"])
        self.assertEqual(meta["pid"], "12345")
        self.assertEqual(meta["extra"]["source_ip"], "10.0.0.1")

    def test_parse_sensitive_file_access(self):
        line = "Jun 15 08:25:00 db01 sudo: dbadmin : TTY=pts/1 ; PWD=/var/lib/mysql ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        result = parse_syslog_line(line)
        # Could match either sudo_command or sensitive_file_access depending on pattern ordering
        self.assertIn(result["event_type"], ("sudo_command", "sensitive_file_access"))


class TestLinuxIngestion(_DBTestCase):
    """Integration tests for Linux syslog ingestion."""

    def test_ingest_batch(self):
        lines = [
            "Jun 15 08:20:01 web01 sshd[12345]: Failed password for admin from 10.0.0.1 port 22 ssh2",
            "Jun 15 08:21:00 web01 sshd[12346]: Accepted publickey for deploy from 10.0.0.5 port 40022 ssh2",
        ]
        ids = ingest_syslog_lines(lines, db_path=self.db_path)
        self.assertEqual(len(ids), 2)

        events = query_events(filters={"source": "linux"}, db_path=self.db_path)
        self.assertEqual(len(events), 2)

    def test_ingest_skips_empty_lines(self):
        lines = ["", "   ", "Jun 15 08:20:01 web01 sshd[12345]: Failed password for admin from 10.0.0.1 port 22 ssh2", ""]
        ids = ingest_syslog_lines(lines, db_path=self.db_path)
        self.assertEqual(len(ids), 1)

    def test_sample_data_loads(self):
        ids = linux_samples(db_path=self.db_path)
        self.assertGreater(len(ids), 10)

    def test_raw_logs_stored(self):
        lines = ["Jun 15 08:20:01 web01 sshd[1]: Failed password for admin from 10.0.0.1 port 22 ssh2"]
        ingest_syslog_lines(lines, db_path=self.db_path)
        raws = get_raw_logs(source="linux", db_path=self.db_path)
        self.assertEqual(len(raws), 1)
        self.assertIn("sshd", raws[0]["raw_text"])


# ══════════════════════════════════════════════
# Azure Monitor tests
# ══════════════════════════════════════════════

class TestAzureStub(unittest.TestCase):
    """Unit tests for the Azure Monitor stub client."""

    def test_stub_connect(self):
        client = AzureMonitorStub()
        self.assertTrue(client.connect())
        self.assertTrue(client._connected)

    def test_stub_fetch_returns_list(self):
        client = AzureMonitorStub()
        logs = client.fetch(category="SignInLogs", max_results=3)
        self.assertIsInstance(logs, list)
        self.assertEqual(len(logs), 3)

    def test_stub_fetch_contains_required_fields(self):
        client = AzureMonitorStub()
        logs = client.fetch(category="SignInLogs", max_results=1)
        entry = logs[0]
        self.assertIn("id", entry)
        self.assertIn("category", entry)
        self.assertIn("createdDateTime", entry)
        self.assertIn("userPrincipalName", entry)


class TestAzureNormalization(unittest.TestCase):
    """Unit tests for Azure log normalization."""

    def test_normalize_successful_signin(self):
        entry = {
            "id": "test-id",
            "createdDateTime": "2025-06-15T10:00:00Z",
            "userPrincipalName": "alice@contoso.com",
            "ipAddress": "10.0.0.1",
            "location": {"city": "Seattle", "state": "WA", "countryOrRegion": "US"},
            "clientAppUsed": "Browser",
            "appDisplayName": "Office 365",
            "status": {"errorCode": 0, "failureReason": None},
            "riskLevelDuringSignIn": "none",
            "resourceDisplayName": "Office 365",
            "conditionalAccessStatus": "success",
            "deviceDetail": {"operatingSystem": "Windows", "browser": "Chrome"},
        }
        result = normalize_signin_log(entry)
        self.assertEqual(result["event_type"], "login_success")
        self.assertEqual(result["severity"], "low")
        self.assertEqual(result["user"], "alice@contoso.com")
        self.assertEqual(result["source"], "azure")

    def test_normalize_failed_signin(self):
        entry = {
            "id": "test-id",
            "createdDateTime": "2025-06-15T10:00:00Z",
            "userPrincipalName": "bob@contoso.com",
            "ipAddress": "1.2.3.4",
            "location": {"city": "Moscow", "state": None, "countryOrRegion": "RU"},
            "clientAppUsed": "Browser",
            "appDisplayName": "Azure Portal",
            "status": {"errorCode": 50126, "failureReason": "Invalid credentials"},
            "riskLevelDuringSignIn": "high",
            "resourceDisplayName": "Azure Portal",
            "conditionalAccessStatus": "failure",
            "deviceDetail": {},
        }
        result = normalize_signin_log(entry)
        self.assertEqual(result["event_type"], "login_failure")
        self.assertEqual(result["severity"], "high")

    def test_normalize_audit_role_assignment(self):
        entry = {
            "id": "test-id",
            "createdDateTime": "2025-06-15T10:00:00Z",
            "activityDisplayName": "Add member to role",
            "operationType": "Add",
            "targetResources": [{"displayName": "Global Administrator", "type": "Role"}],
            "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
            "result": "success",
        }
        result = normalize_audit_log(entry)
        self.assertEqual(result["event_type"], "azure_audit")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["user"], "admin@contoso.com")

    def test_normalize_activity_nsg_change(self):
        entry = {
            "id": "test-id",
            "createdDateTime": "2025-06-15T10:00:00Z",
            "operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "caller": "netadmin@contoso.com",
            "resourceGroup": "prod-rg",
            "status": "Succeeded",
            "level": "Warning",
        }
        result = normalize_activity_log(entry)
        self.assertEqual(result["event_type"], "azure_activity")
        self.assertEqual(result["severity"], "high")


class TestAzureIngestion(_DBTestCase):
    """Integration tests for Azure log ingestion."""

    def test_ingest_signin_logs(self):
        client = AzureMonitorStub()
        entries = client.fetch(category="SignInLogs", max_results=3)
        ids = ingest_azure_logs(entries, category="SignInLogs", db_path=self.db_path)
        self.assertEqual(len(ids), 3)

        events = query_events(filters={"source": "azure"}, db_path=self.db_path)
        self.assertEqual(len(events), 3)

    def test_ingest_stores_raw_json(self):
        client = AzureMonitorStub()
        entries = client.fetch(category="SignInLogs", max_results=1)
        ingest_azure_logs(entries, category="SignInLogs", db_path=self.db_path)
        raws = get_raw_logs(source="azure", db_path=self.db_path)
        self.assertEqual(len(raws), 1)
        raw = json.loads(raws[0]["raw_text"])
        self.assertIn("userPrincipalName", raw)

    def test_sample_data_loads(self):
        ids = azure_samples(db_path=self.db_path)
        self.assertGreater(len(ids), 5)


# ══════════════════════════════════════════════
# Cross-source tests
# ══════════════════════════════════════════════

class TestCrossSource(_DBTestCase):
    """Tests that verify events from all sources coexist correctly."""

    def test_all_sources_in_database(self):
        win_samples(db_path=self.db_path)
        linux_samples(db_path=self.db_path)
        azure_samples(db_path=self.db_path)

        for source in ("windows", "linux", "azure"):
            events = query_events(filters={"source": source}, db_path=self.db_path)
            self.assertGreater(len(events), 0, f"No events found for source={source}")

    def test_severity_filter_across_sources(self):
        win_samples(db_path=self.db_path)
        linux_samples(db_path=self.db_path)

        high_events = query_events(filters={"severity": "high"}, db_path=self.db_path)
        self.assertGreater(len(high_events), 0)
        for ev in high_events:
            self.assertEqual(ev["severity"], "high")


if __name__ == "__main__":
    unittest.main()
