
import json
import time
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LLM_EVENTS = os.path.join(BASE_DIR, "llm_events.json")
BEACON_EVENTS = os.path.join(BASE_DIR, "beacon_events.json")
CORRELATION_LOG = os.path.join(BASE_DIR, "correlation_events.json")
DB_FILE = os.path.join(BASE_DIR, "honeypot.db")


CORRELATION_WINDOW_MINUTES = 30

already_correlated = set()


def save_correlation(event):
    
    with open(CORRELATION_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")

    try:
        with sqlite3.connect(DB_FILE, check_same_thread=False) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS correlation_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    attacker_ip TEXT,
                    canary_files TEXT,
                    beacon_routes TEXT,
                    risk_level TEXT,
                    description TEXT
                )
            """)
            conn.execute(
                "INSERT INTO correlation_events (timestamp, attacker_ip, canary_files, beacon_routes, risk_level, description) VALUES (?,?,?,?,?,?)",
                (
                    event["timestamp"],
                    event["attacker_ip"],
                    event.get("canary_files_accessed", ""),
                    event.get("beacon_routes_accessed", ""),
                    event.get("risk_level", "unknown"),
                    event.get("description", ""),
                ),
            )
    except Exception as e:
        print(f"[correlator] DB error: {e}")


def load_events(filepath):
    events = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return events


def parse_timestamp(ts_str):
    """Parse ISO timestamp string to datetime."""
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def correlate():
    canary_by_ip = defaultdict(list)
    beacon_by_ip = defaultdict(list)

    
    for event in load_events(LLM_EVENTS):
        if event.get("event_type") == "canary_triggered":
            ip = event.get("client_ip")
            if ip:
                canary_by_ip[ip].append(event)

    
    for event in load_events(BEACON_EVENTS):
        if event.get("event_type") in ("beacon_triggered", "sql_injection", "web_terminal_accessed", "web_terminal_command"):
            ip = event.get("attacker_ip")
            if ip:
                beacon_by_ip[ip].append(event)

    
    for ip in canary_by_ip:
        if ip not in beacon_by_ip:
            continue

        canary_events = canary_by_ip[ip]
        beacon_events = beacon_by_ip[ip]

       
        correlated_canaries = set()
        correlated_beacons = set()

        for ce in canary_events:
            ce_time = parse_timestamp(ce.get("timestamp", ""))
            if not ce_time:
                continue
            for be in beacon_events:
                be_time = parse_timestamp(be.get("timestamp", ""))
                if not be_time:
                    continue
                diff = abs((be_time - ce_time).total_seconds())
                if diff <= CORRELATION_WINDOW_MINUTES * 60:
                    correlated_canaries.add(ce.get("canary_file", "unknown"))
                    correlated_beacons.add(be.get("route_accessed", "unknown"))

        if not correlated_canaries or not correlated_beacons:
            continue

        # Dedup key
        key = f"{ip}|{'|'.join(sorted(correlated_canaries))}|{'|'.join(sorted(correlated_beacons))}"
        if key in already_correlated:
            continue
        already_correlated.add(key)

        # Severity scoring
        has_sqli = any(e.get("event_type") == "sql_injection" for e in beacon_events)
        CREDENTIAL_CANARIES_CORR = {
            "passwords.txt", "aws_credentials.txt",
            "config.env", "vpn_config.ovpn"
        }
        sensitive_canaries = correlated_canaries & CREDENTIAL_CANARIES_CORR

        if has_sqli or len(sensitive_canaries) >= 2 or len(correlated_canaries) >= 3:
            risk = "critical"
        else:
            risk = "high"

        correlation_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "attack_correlation",
            "attacker_ip": ip,
            "canary_files_accessed": ", ".join(sorted(correlated_canaries)),
            "beacon_routes_accessed": ", ".join(sorted(correlated_beacons)),
            "canary_count": len(correlated_canaries),
            "beacon_count": len(correlated_beacons),
            "includes_sqli": has_sqli,
            "risk_level": risk,
            "description": (
                f"Attacker {ip} read {len(correlated_canaries)} sensitive file(s) via SSH "
                f"then accessed {len(correlated_beacons)} web beacon(s) within {CORRELATION_WINDOW_MINUTES}min window"
            ),
        }

        save_correlation(correlation_event)
        print(f"🔗 CORRELATION: {ip}")
        print(f"   Canaries: {sorted(correlated_canaries)}")
        print(f"   Beacons:  {sorted(correlated_beacons)}")
        print(f"   Risk:     {risk}")


if __name__ == "__main__":
    print(" Correlator running (checking every 10s)...")
    try:
        while True:
            correlate()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n[correlator] Stopped by user")