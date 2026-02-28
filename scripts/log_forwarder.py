#!/usr/bin/env python3
"""
mini-siem — Log Forwarder / Simulator
======================================
Continuously generates realistic security log events and POSTs them
to the Mini SIEM ingestion API.  Use this to simulate "live" data
flowing into the dashboard so you can watch alerts fire in real time.

Usage
-----
    # Default: send mixed logs every 5 seconds to localhost:5000
    python scripts/log_forwarder.py

    # Custom target, rate, and source type
    python scripts/log_forwarder.py --url http://localhost:5000 \
        --interval 3 --source all --count 5

    # One-shot batch (don't loop)
    python scripts/log_forwarder.py --once --source windows

Options
-------
  --url URL          SIEM base URL (default: http://localhost:5000)
  --interval SEC     Seconds between batches (default: 5)
  --source SOURCE    Log type: windows, linux, azure, firewall, endpoint, all
  --count N          Events per batch (default: 3)
  --username USER    SIEM username (default: admin)
  --password PASS    SIEM password (default: admin)
  --once             Send one batch and exit
  --verbose          Print each batch payload
"""

import argparse
import json
import random
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta


# ──────────────────────────────────────────────
# Event generators
# ──────────────────────────────────────────────

USERS  = ["jdoe", "alee", "msmith", "svc_backup", "administrator", "root", "ubuntu"]
HOSTS  = ["DC01.corp.local", "WS-PC14.corp.local", "SRV-FILE01.corp.local",
          "WS-PC22.corp.local", "web01.corp.local"]
IPS    = ["10.0.0.55", "192.168.1.100", "203.0.113.5", "198.51.100.9",
          "172.16.0.10", "10.10.10.20"]
PROCS  = ["powershell.exe", "cmd.exe", "mimikatz.exe", "net.exe",
          "certutil.exe", "lsass.exe", "svchost.exe", "chrome.exe"]


def _ts(offset_sec: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_sec)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _syslog_ts() -> str:
    return datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")


# ── Windows ──────────────────────────────────

_WIN_TEMPLATES = [
    lambda: f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID><Level>0</Level>
    <TimeCreated SystemTime="{_ts()}"/>
    <Computer>{random.choice(HOSTS)}</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">{random.choice(USERS)}</Data>
    <Data Name="IpAddress">{random.choice(IPS)}</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="Status">0xC000006D</Data>
  </EventData>
</Event>""",
    lambda: f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID><Level>0</Level>
    <TimeCreated SystemTime="{_ts()}"/>
    <Computer>{random.choice(HOSTS)}</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">{random.choice(USERS)}</Data>
    <Data Name="IpAddress">{random.choice(IPS)}</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>""",
    lambda: f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID><Level>0</Level>
    <TimeCreated SystemTime="{_ts()}"/>
    <Computer>{random.choice(HOSTS)}</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="SubjectUserName">{random.choice(USERS)}</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\{random.choice(PROCS)}</Data>
    <Data Name="CommandLine">{random.choice(PROCS)} /c whoami</Data>
  </EventData>
</Event>""",
    lambda: f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4740</EventID><Level>0</Level>
    <TimeCreated SystemTime="{_ts()}"/>
    <Computer>{random.choice(HOSTS)}</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">{random.choice(USERS)}</Data>
  </EventData>
</Event>""",
]


def gen_windows(n: int = 1) -> dict:
    events = "".join(random.choice(_WIN_TEMPLATES)() for _ in range(n))
    return {"source": "windows", "data": events}


# ── Linux ─────────────────────────────────────

_LINUX_TEMPLATES = [
    lambda: f"{_syslog_ts()} {random.choice(HOSTS).split('.')[0]} sshd[{random.randint(1000,9999)}]: Failed password for {random.choice(USERS)} from {random.choice(IPS)} port {random.randint(1024,65535)} ssh2",
    lambda: f"{_syslog_ts()} {random.choice(HOSTS).split('.')[0]} sshd[{random.randint(1000,9999)}]: Accepted password for {random.choice(USERS)} from {random.choice(IPS)} port {random.randint(1024,65535)} ssh2",
    lambda: f"{_syslog_ts()} {random.choice(HOSTS).split('.')[0]} sudo: {random.choice(USERS)} : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    lambda: f"{_syslog_ts()} {random.choice(HOSTS).split('.')[0]} useradd[{random.randint(1000,9999)}]: new user: name=hacker{random.randint(1,99)}, UID={random.randint(1000,9999)}, GID={random.randint(1000,9999)}, home=/home/hacker",
    lambda: f"{_syslog_ts()} {random.choice(HOSTS).split('.')[0]} kernel: Possible SYN flooding on port 22. Sending cookies.",
]


def gen_linux(n: int = 1) -> dict:
    lines = [random.choice(_LINUX_TEMPLATES)() for _ in range(n)]
    return {"source": "linux", "data": "\n".join(lines)}


# ── Azure ─────────────────────────────────────

_AZURE_ERROR_CODES = [50126, 50076, 50053, 0, 50158]


def gen_azure(n: int = 1) -> dict:
    records = []
    for _ in range(n):
        user = random.choice(USERS)
        code = random.choice(_AZURE_ERROR_CODES)
        records.append({
            "category": "SignInLogs",
            "userPrincipalName": f"{user}@corp.onmicrosoft.com",
            "ipAddress": random.choice(IPS),
            "status": {"errorCode": code},
            "createdDateTime": _ts(),
            "appDisplayName": random.choice(["Office 365", "Azure Portal", "Teams"]),
            "location": {"city": random.choice(["New York", "Moscow", "Beijing", "London"])},
        })
    return {"source": "azure", "data": records}


# ── Firewall ──────────────────────────────────

_ACTIONS  = ["block", "block", "block", "allow"]
_DST_PORTS = [22, 3389, 445, 80, 443, 8080, 3306, 1433]


def gen_firewall(n: int = 1) -> dict:
    lines = []
    for _ in range(n):
        action = random.choice(_ACTIONS)
        src = random.choice(IPS)
        dst = random.choice(IPS)
        dpt = random.choice(_DST_PORTS)
        lines.append(
            f"{_syslog_ts()} fw01 pf: action={action} src={src} dst={dst} "
            f"dpt={dpt} proto=TCP"
        )
    return {"source": "firewall", "data": "\n".join(lines)}


# ── Endpoint ──────────────────────────────────

_EP_TYPES = ["ProcessCreate", "ProcessCreate", "NetworkConnect", "FileCreate", "RegistrySet"]
_EP_SEVS  = ["low", "low", "medium", "high", "high", "critical"]


def gen_endpoint(n: int = 1) -> dict:
    records = []
    for _ in range(n):
        proc = random.choice(PROCS)
        user = random.choice(USERS)
        etype = random.choice(_EP_TYPES)
        sev = random.choice(_EP_SEVS)
        records.append({
            "timestamp": _ts(),
            "hostname": random.choice(HOSTS).split(".")[0],
            "username": user,
            "process_name": proc,
            "parent_process": random.choice(PROCS),
            "command_line": f"{proc} {'--encoded' if proc == 'powershell.exe' else '/c whoami'}",
            "event_type": etype,
            "severity": sev,
        })
    lines = [json.dumps(r) for r in records]
    return {"source": "endpoint", "data": "\n".join(lines)}


# ──────────────────────────────────────────────
# HTTP client (stdlib only, no requests needed)
# ──────────────────────────────────────────────

class SIEMClient:
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._cookie = ""

    def login(self) -> bool:
        url = f"{self.base_url}/login"
        data = urllib.parse.urlencode({
            "username": self.username,
            "password": self.password,
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req) as resp:
                # Store session cookie
                cookie_header = resp.headers.get("Set-Cookie", "")
                if cookie_header:
                    self._cookie = cookie_header.split(";")[0]
                return True
        except urllib.error.HTTPError as e:
            # Flask redirects on successful login; treat 302 as OK
            if e.code in (301, 302, 303):
                cookie_header = e.headers.get("Set-Cookie", "")
                if cookie_header:
                    self._cookie = cookie_header.split(";")[0]
                return True
            print(f"Login failed: {e.code} {e.reason}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            return False

    def ingest(self, payload: dict, verbose: bool = False) -> dict | None:
        url = f"{self.base_url}/api/ingest"
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        if self._cookie:
            req.add_header("Cookie", self._cookie)
        if verbose:
            print(f"  POST {url} source={payload['source']}", file=sys.stderr)
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read()
            print(f"  Ingest error {e.code}: {body[:200]}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"  Ingest error: {e}", file=sys.stderr)
            return None


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

_GENERATORS = {
    "windows":  gen_windows,
    "linux":    gen_linux,
    "azure":    gen_azure,
    "firewall": gen_firewall,
    "endpoint": gen_endpoint,
}


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM log forwarder / simulator")
    parser.add_argument("--url",      default="http://localhost:5000", help="SIEM base URL")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between batches")
    parser.add_argument("--source",   default="all",
                        choices=list(_GENERATORS) + ["all"],
                        help="Log source to simulate")
    parser.add_argument("--count",    type=int, default=3, help="Events per batch")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--once",     action="store_true", help="Send one batch and exit")
    parser.add_argument("--verbose",  action="store_true")
    args = parser.parse_args()

    client = SIEMClient(args.url, args.username, args.password)
    print(f"[forwarder] Logging in to {args.url} as {args.username}…")
    if not client.login():
        print("[forwarder] Login failed — check URL, username, and password")
        sys.exit(1)
    print(f"[forwarder] Authenticated. Sending {args.count} event(s) per batch "
          f"every {args.interval}s  (source={args.source})")

    if args.source == "all":
        sources = list(_GENERATORS.keys())
    else:
        sources = [args.source]

    batch = 0
    while True:
        batch += 1
        ts = datetime.now().strftime("%H:%M:%S")
        for src in sources:
            payload = _GENERATORS[src](args.count)
            result = client.ingest(payload, verbose=args.verbose)
            if result:
                print(
                    f"[{ts}] batch={batch} source={src:10s} "
                    f"events={result.get('events_created', '?'):3}  "
                    f"alerts={result.get('alerts_fired', '?')}"
                )
            else:
                print(f"[{ts}] batch={batch} source={src} — ingest failed (re-login?)")
                client.login()

        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
