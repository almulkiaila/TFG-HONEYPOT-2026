

import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "honeypot.db")


def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_conn() as conn:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            session_id TEXT,
            ip TEXT,
            command TEXT,
            response TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS llm_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            session_id TEXT,
            ip TEXT,
            risk_level TEXT,
            final_intent TEXT,
            attack_path TEXT,
            mitigation TEXT,
            deception_recommendation TEXT,
            canaries_accessed TEXT,
            commands_summary TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS canary_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            session_id TEXT,
            ip TEXT,
            canary_file TEXT,
            access_count INTEGER,
            commands_before TEXT
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS beacon_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            token TEXT,
            route_accessed TEXT,
            attacker_ip TEXT,
            
            user_agent TEXT,
            risk_level TEXT
        )
        """)

        cursor.execute("""
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

       
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_commands_ip ON commands(ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_canary_ip ON canary_events(ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_beacon_ip ON beacon_events(attacker_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_llm_session ON llm_analysis(session_id)")

    print("[DB] Database initialized")


def save_command(event):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO commands (timestamp, session_id, ip, command, response)
               VALUES (?, ?, ?, ?, ?)""",
            (
                event.get("timestamp"),
                event.get("session_id"),
                event.get("client_ip"),
                event.get("command"),
                event.get("response"),
            ),
        )


def save_llm_analysis(event):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO llm_analysis
               (timestamp, session_id, ip, risk_level, final_intent, attack_path,
                mitigation, deception_recommendation, canaries_accessed, commands_summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.get("timestamp"),
                event.get("session_id"),
                event.get("client_ip"),
                event.get("risk_level"),
                event.get("final_intent"),
                event.get("attack_path"),
                event.get("mitigation"),
                event.get("deception_recommendation"),
                event.get("canaries_accessed"),
                event.get("commands"),
            ),
        )


def save_canary(event):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO canary_events
               (timestamp, session_id, ip, canary_file, access_count, commands_before)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event.get("timestamp"),
                event.get("session_id"),
                event.get("client_ip"),
                event.get("canary_file"),
                event.get("access_count"),
                event.get("commands_before"),
            ),
        )


def save_beacon_db(event):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO beacon_events
               (timestamp, token, route_accessed, attacker_ip, user_agent, risk_level)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event.get("timestamp"),
                event.get("token"),
                event.get("route_accessed"),
                event.get("attacker_ip"),
                event.get("user_agent"),
                event.get("risk_level"),
            ),
        )