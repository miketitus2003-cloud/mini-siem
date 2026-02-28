"""
mini-siem.app.logs.azure
~~~~~~~~~~~~~~~~~~~~~~~~~
Stub integration for Azure Monitor / Azure Active Directory logs.

In a production deployment this module would authenticate against the
Azure Monitor REST API (or use the ``azure-monitor-query`` SDK) to pull:

* **Azure AD Sign-in logs** – interactive, non-interactive, service
  principal, and managed identity sign-ins.
* **Azure AD Audit logs** – directory changes, app registrations, role
  assignments.
* **Azure Activity logs** – subscription-level control-plane operations.

Because this is a portfolio project that must run without cloud
credentials, the module provides:

1. A **simulated API client** that returns realistic JSON payloads.
2. A **normalizer** that maps Azure log schemas to the SIEM's canonical
   event format.
3. ``load_sample_data()`` for the demo workflow.

Replace ``_fetch_from_api`` with real HTTP calls when deploying against
a live Azure tenant.
"""

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from app.database import insert_raw_log, insert_normalized_event

logger = logging.getLogger("mini-siem.azure")

# ──────────────────────────────────────────────
# Azure log category → SIEM event type
# ──────────────────────────────────────────────

_CATEGORY_MAP: Dict[str, str] = {
    "SignInLogs": "login_success",
    "NonInteractiveUserSignInLogs": "login_success",
    "ServicePrincipalSignInLogs": "service_principal_signin",
    "ManagedIdentitySignInLogs": "managed_identity_signin",
    "AuditLogs": "azure_audit",
    "ActivityLogs": "azure_activity",
}

_RESULT_TYPE_SEVERITY: Dict[str, str] = {
    "0": "low",      # Success
    "50126": "high",  # Invalid credentials
    "50053": "high",  # Account locked
    "50057": "high",  # Disabled account
    "50076": "medium",  # MFA required
    "50074": "medium",  # Strong auth required
    "700016": "medium",  # App not found
    "530003": "high",  # Conditional Access block
}

# ──────────────────────────────────────────────
# Simulated API client
# ──────────────────────────────────────────────

class AzureMonitorStub:
    """Simulated Azure Monitor client.

    Replace the ``fetch`` method body with real API calls when
    connecting to an Azure tenant::

        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient

        credential = DefaultAzureCredential()
        client = LogsQueryClient(credential)
        ...
    """

    def __init__(self, tenant_id: str = "00000000-0000-0000-0000-000000000000"):
        self.tenant_id = tenant_id
        self._connected = False

    def connect(self) -> bool:
        """Simulate authentication handshake."""
        logger.info(
            "Azure Monitor stub: simulating OAuth2 token acquisition for tenant %s",
            self.tenant_id,
        )
        self._connected = True
        return True

    def fetch(self, category: str = "SignInLogs", max_results: int = 50) -> List[Dict[str, Any]]:
        """Return simulated log entries.

        In production this would call the Log Analytics REST API:
        ``POST https://api.loganalytics.io/v1/workspaces/{id}/query``
        """
        if not self._connected:
            self.connect()
        logger.info("Azure Monitor stub: fetching %d %s entries (simulated)", max_results, category)
        return _generate_simulated_logs(category, max_results)


# ──────────────────────────────────────────────
# Simulated data generation
# ──────────────────────────────────────────────

def _generate_simulated_logs(category: str, count: int) -> List[Dict[str, Any]]:
    """Produce realistic Azure Monitor JSON records."""
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)
    logs: List[Dict[str, Any]] = []

    scenarios = _SCENARIOS.get(category, _SCENARIOS["SignInLogs"])
    for i in range(count):
        scenario = scenarios[i % len(scenarios)]
        ts = (base_time + timedelta(seconds=i * 15)).isoformat()
        entry = {
            "id": str(uuid.uuid4()),
            "category": category,
            "createdDateTime": ts,
            "correlationId": str(uuid.uuid4()),
            **scenario,
        }
        logs.append(entry)
    return logs


_SCENARIOS: Dict[str, List[Dict[str, Any]]] = {
    "SignInLogs": [
        {
            "userPrincipalName": "alice@contoso.com",
            "userDisplayName": "Alice Johnson",
            "ipAddress": "203.0.113.10",
            "location": {"city": "Seattle", "state": "WA", "countryOrRegion": "US"},
            "clientAppUsed": "Browser",
            "resourceDisplayName": "Microsoft Office 365",
            "status": {"errorCode": 0, "failureReason": None},
            "conditionalAccessStatus": "success",
            "riskLevelDuringSignIn": "none",
            "appDisplayName": "Office 365 Exchange Online",
            "deviceDetail": {"operatingSystem": "Windows 10", "browser": "Edge 125"},
        },
        {
            "userPrincipalName": "bob@contoso.com",
            "userDisplayName": "Bob Smith",
            "ipAddress": "198.51.100.44",
            "location": {"city": "Moscow", "state": None, "countryOrRegion": "RU"},
            "clientAppUsed": "Browser",
            "resourceDisplayName": "Azure Portal",
            "status": {"errorCode": 50126, "failureReason": "Invalid username or password."},
            "conditionalAccessStatus": "failure",
            "riskLevelDuringSignIn": "high",
            "appDisplayName": "Azure Portal",
            "deviceDetail": {"operatingSystem": "Linux", "browser": "Firefox 127"},
        },
        {
            "userPrincipalName": "bob@contoso.com",
            "userDisplayName": "Bob Smith",
            "ipAddress": "198.51.100.44",
            "location": {"city": "Moscow", "state": None, "countryOrRegion": "RU"},
            "clientAppUsed": "Browser",
            "resourceDisplayName": "Azure Portal",
            "status": {"errorCode": 50053, "failureReason": "Account is locked."},
            "conditionalAccessStatus": "failure",
            "riskLevelDuringSignIn": "high",
            "appDisplayName": "Azure Portal",
            "deviceDetail": {"operatingSystem": "Linux", "browser": "Firefox 127"},
        },
        {
            "userPrincipalName": "svc-pipeline@contoso.com",
            "userDisplayName": "CI/CD Pipeline",
            "ipAddress": "10.0.0.50",
            "location": {"city": "Redmond", "state": "WA", "countryOrRegion": "US"},
            "clientAppUsed": "Mobile App",
            "resourceDisplayName": "Azure DevOps",
            "status": {"errorCode": 0, "failureReason": None},
            "conditionalAccessStatus": "success",
            "riskLevelDuringSignIn": "none",
            "appDisplayName": "Azure DevOps",
            "deviceDetail": {"operatingSystem": "Android 14", "browser": "Mobile Safari"},
        },
        {
            "userPrincipalName": "carol@contoso.com",
            "userDisplayName": "Carol Lee",
            "ipAddress": "192.0.2.88",
            "location": {"city": "Beijing", "state": None, "countryOrRegion": "CN"},
            "clientAppUsed": "Exchange ActiveSync",
            "resourceDisplayName": "Microsoft Office 365",
            "status": {"errorCode": 530003, "failureReason": "Access has been blocked by Conditional Access policies."},
            "conditionalAccessStatus": "failure",
            "riskLevelDuringSignIn": "medium",
            "appDisplayName": "Office 365 Exchange Online",
            "deviceDetail": {"operatingSystem": "iOS 18", "browser": "Outlook Mobile"},
        },
    ],
    "AuditLogs": [
        {
            "activityDisplayName": "Add member to role",
            "operationType": "Add",
            "targetResources": [{"displayName": "Global Administrator", "type": "Role"}],
            "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
            "result": "success",
        },
        {
            "activityDisplayName": "Update application",
            "operationType": "Update",
            "targetResources": [{"displayName": "InternalApp", "type": "Application"}],
            "initiatedBy": {"user": {"userPrincipalName": "dev@contoso.com"}},
            "result": "success",
        },
        {
            "activityDisplayName": "Delete user",
            "operationType": "Delete",
            "targetResources": [{"displayName": "temp_contractor", "type": "User"}],
            "initiatedBy": {"user": {"userPrincipalName": "hr-admin@contoso.com"}},
            "result": "success",
        },
    ],
    "ActivityLogs": [
        {
            "operationName": "Microsoft.Compute/virtualMachines/deallocate/action",
            "caller": "ops@contoso.com",
            "resourceGroup": "prod-rg",
            "status": "Succeeded",
            "level": "Informational",
        },
        {
            "operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "caller": "netadmin@contoso.com",
            "resourceGroup": "prod-rg",
            "status": "Succeeded",
            "level": "Warning",
        },
    ],
}


# ──────────────────────────────────────────────
# Normalization
# ──────────────────────────────────────────────

def normalize_signin_log(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Map an Azure AD sign-in record to the SIEM schema."""
    error_code = str(entry.get("status", {}).get("errorCode", 0))
    severity = _RESULT_TYPE_SEVERITY.get(error_code, "low")
    risk = entry.get("riskLevelDuringSignIn", "none")
    if risk in ("high",):
        severity = "high"
    elif risk in ("medium",) and severity == "low":
        severity = "medium"

    event_type = "login_success" if error_code == "0" else "login_failure"

    location = entry.get("location", {})
    loc_str = ", ".join(
        filter(None, [location.get("city"), location.get("state"), location.get("countryOrRegion")])
    )

    failure = entry.get("status", {}).get("failureReason") or "None"
    message = (
        f"Azure AD sign-in: {entry.get('userPrincipalName', '?')} "
        f"from {entry.get('ipAddress', '?')} ({loc_str}) "
        f"to {entry.get('appDisplayName', '?')} — "
        f"{'Success' if error_code == '0' else f'Failed ({failure})'}"
    )

    return {
        "timestamp": entry.get("createdDateTime", datetime.now(timezone.utc).isoformat()),
        "source": "azure",
        "event_type": event_type,
        "severity": severity,
        "host": entry.get("appDisplayName", "Azure AD"),
        "user": entry.get("userPrincipalName", ""),
        "process": entry.get("clientAppUsed", ""),
        "message": message[:2000],
        "metadata_json": json.dumps({
            "azure_id": entry.get("id"),
            "correlation_id": entry.get("correlationId"),
            "error_code": error_code,
            "risk_level": risk,
            "conditional_access": entry.get("conditionalAccessStatus"),
            "ip_address": entry.get("ipAddress"),
            "location": location,
            "device": entry.get("deviceDetail"),
            "resource": entry.get("resourceDisplayName"),
        }),
    }


def normalize_audit_log(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Map an Azure AD audit record to the SIEM schema."""
    activity = entry.get("activityDisplayName", "Unknown")
    targets = entry.get("targetResources", [])
    target_name = targets[0].get("displayName", "?") if targets else "?"
    target_type = targets[0].get("type", "?") if targets else "?"
    initiator = (
        entry.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "system")
    )

    severity = "medium"
    if "role" in activity.lower() or "admin" in target_name.lower():
        severity = "high"
    if entry.get("operationType") == "Delete":
        severity = "high"

    message = (
        f"Azure AD audit: {activity} — "
        f"Target: {target_name} ({target_type}) — "
        f"By: {initiator} — "
        f"Result: {entry.get('result', '?')}"
    )

    return {
        "timestamp": entry.get("createdDateTime", datetime.now(timezone.utc).isoformat()),
        "source": "azure",
        "event_type": "azure_audit",
        "severity": severity,
        "host": "Azure AD",
        "user": initiator,
        "process": "AuditLog",
        "message": message[:2000],
        "metadata_json": json.dumps({
            "azure_id": entry.get("id"),
            "activity": activity,
            "operation_type": entry.get("operationType"),
            "target_resources": targets,
        }),
    }


def normalize_activity_log(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Map an Azure Activity log record to the SIEM schema."""
    op = entry.get("operationName", "Unknown")
    caller = entry.get("caller", "unknown")
    severity = "medium" if entry.get("level") == "Warning" else "low"

    # NSG rule changes are high-severity
    op_lower = op.lower()
    if "securityrules" in op_lower or "firewallrules" in op_lower:
        severity = "high"

    message = (
        f"Azure Activity: {op} — "
        f"Caller: {caller} — "
        f"RG: {entry.get('resourceGroup', '?')} — "
        f"Status: {entry.get('status', '?')}"
    )

    return {
        "timestamp": entry.get("createdDateTime", datetime.now(timezone.utc).isoformat()),
        "source": "azure",
        "event_type": "azure_activity",
        "severity": severity,
        "host": entry.get("resourceGroup", "Azure"),
        "user": caller,
        "process": "ActivityLog",
        "message": message[:2000],
        "metadata_json": json.dumps({
            "azure_id": entry.get("id"),
            "operation": op,
            "resource_group": entry.get("resourceGroup"),
            "status": entry.get("status"),
        }),
    }


_NORMALIZERS = {
    "SignInLogs": normalize_signin_log,
    "NonInteractiveUserSignInLogs": normalize_signin_log,
    "AuditLogs": normalize_audit_log,
    "ActivityLogs": normalize_activity_log,
}


# ──────────────────────────────────────────────
# Ingestion entry point
# ──────────────────────────────────────────────

def ingest_azure_logs(
    entries: List[Dict[str, Any]],
    category: str = "SignInLogs",
    db_path: Optional[str] = None,
) -> List[int]:
    """Normalize and store Azure log entries.

    Returns a list of ``normalized_events`` row IDs.
    """
    normalizer = _NORMALIZERS.get(category, normalize_signin_log)
    event_ids: List[int] = []

    for entry in entries:
        raw_json = json.dumps(entry)
        raw_id = insert_raw_log("azure", raw_json, db_path=db_path)

        normalized = normalizer(entry)
        normalized["raw_log_id"] = raw_id
        eid = insert_normalized_event(normalized, db_path=db_path)
        event_ids.append(eid)

    logger.info("Ingested %d Azure %s events", len(event_ids), category)
    return event_ids


# ──────────────────────────────────────────────
# Demo / sample data
# ──────────────────────────────────────────────

def load_sample_data(db_path: Optional[str] = None) -> List[int]:
    """Insert realistic simulated Azure logs for demonstration."""
    client = AzureMonitorStub()
    all_ids: List[int] = []

    for category in ("SignInLogs", "AuditLogs", "ActivityLogs"):
        entries = client.fetch(category=category, max_results=5)
        ids = ingest_azure_logs(entries, category=category, db_path=db_path)
        all_ids.extend(ids)

    return all_ids
