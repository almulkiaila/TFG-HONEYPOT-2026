"""
insider_profiler.py — Insider Threat Profiling Engine

Behavioral profiling to distinguish between:
  - MALICIOUS insider: deliberate, methodical, knows what they're doing
  - NEGLIGENT insider: careless, untrained, stumbles into sensitive areas

Based on behavioral indicators from:
  - CERT/CMU Common Sense Guide to Mitigating Insider Threats (5th ed.)
  - Ponemon Institute: Cost of Insider Threats Global Report
  - CISA insider threat behavioral model
  - Syteca/Proofpoint behavioral indicator frameworks

Scoring dimensions:
  1. Command sophistication (do they know Linux well?)
  2. Navigation efficiency (do they go straight to targets?)
  3. Canary interaction pattern (accidental vs deliberate access)
  4. Time behavior (speed, hesitation patterns)
  5. Lateral movement (SSH → Web correlation)
  6. Historical behavior (repeat offender?)
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "honeypot.db")
PROFILE_LOG = os.path.join(BASE_DIR, "insider_profiles.json")

# ── Behavioral indicator definitions ─────────────────────────

# Commands that indicate technical knowledge (malicious indicator)
ADVANCED_COMMANDS = {
    "sudo", "cat /etc/shadow", "sudo -l", "sudo su", "sudo bash",
    "netstat", "ss -tlnp", "nmap", "ps aux", "env", "printenv",
    "id", "cat /etc/passwd", "history", "find", "grep", "chmod",
    "chown", "wget", "curl", "scp", "ssh", "nc", "python",
    "base64", "tar", "zip", "mysqldump", "pg_dump",
}

# Commands that indicate basic/naive user (negligent indicator)
BASIC_COMMANDS = {
    "whoami", "pwd", "ls", "cd", "help", "exit", "clear",
    "uname", "hostname", "date", "uptime",
}

# Canary files ordered by sensitivity (higher = more targeted)
CANARY_SENSITIVITY = {
    "config.env": 3,
    "passwords.txt": 5,
    "aws_credentials.txt": 5,
    "db_backup_2025.sql": 4,
    "users_dump.sql": 4,
    "salaries_2025.csv": 3,
    "vpn_config.ovpn": 3,
}

CREDENTIAL_CANARIES = {
    "config.env", "passwords.txt",
    "aws_credentials.txt", "vpn_config.ovpn"
}



BEHAVIOR_TAXONOMY = {
    # Negligent behaviors (no clear intent)
    "accidental_credential_exposure":
        "Accessed a credentials file without prior exploration, likely accidental",
    "exploring_unauthorized_directories":
        "Navigated to directories outside the user's expected role scope",
    "basic_recon_only":
        "Performed only basic discovery commands without exploitation",
    "single_sensitive_access":
        "Accessed one sensitive file without follow-up actions",

    # Intermediate behaviors (questionable)
    "accessing_files_outside_role":
        "Read files unrelated to job function (HR, finance data)",
    "ignoring_classification_labels":
        "Accessed multiple files marked as sensitive without business need",
    "extended_unauthorized_exploration":
        "Sustained navigation through restricted areas",

    # Advanced behaviors (intentional)
    "deliberate_privilege_escalation":
        "Used sudo or attempted privilege escalation deliberately",
    "credential_dumping_attempt":
        "Accessed /etc/shadow, /etc/passwd or credential stores",
    "data_exfiltration_pattern":
        "Read multiple sensitive files sequentially, consistent with exfiltration",
    "lateral_movement_attempt":
        "Followed internal URLs from sensitive files to other systems",
    "policy_violation_systematic":
        "Multiple deliberate accesses to explicitly restricted resources",

    # Historical/temporal behaviors (derived from comparing sessions)
    "recurring_same_pattern":
        "Repeated the same problematic behavior after previous training",
    "escalating_severity":
        "Each new incident is more severe than the previous one",
}


# ═══════════════════════════════════════════════════════════════
# TRAINING COURSES (enriched with topics and addressed behaviors)
# ═══════════════════════════════════════════════════════════════

TRAINING_COURSES = {
    1: {
        "name": "Security Awareness Fundamentals",
        "level": "basic",
        "duration_hours": 2,
        "topics": [
            "password_hygiene",
            "phishing_recognition",
            "data_classification_basics",
            "appropriate_use_of_resources",
        ],
        "addresses_behaviors": [
            "exploring_unauthorized_directories",
            "accidental_credential_exposure",
            "single_sensitive_access",
            "basic_recon_only",
        ],
    },
    2: {
        "name": "Data Handling and Access Control",
        "level": "intermediate",
        "duration_hours": 3,
        "topics": [
            "sensitive_file_handling",
            "least_privilege_principle",
            "incident_reporting_procedures",
            "role_based_access_understanding",
        ],
        "addresses_behaviors": [
            

            "accessing_files_outside_role",
            "ignoring_classification_labels",
            "extended_unauthorized_exploration",
        ],
    },
    3: {
        "name": "Advanced Security Policy Compliance",
        "level": "advanced",
        "duration_hours": 4,
        "topics": [
            "incident_response_protocols",
            "acceptable_use_policy_deep_dive",
            "legal_obligations_data_protection",
            "consequences_of_policy_violations",
        ],
        "addresses_behaviors": [
            "deliberate_privilege_escalation",
            "credential_dumping_attempt",
            "data_exfiltration_pattern",
            "lateral_movement_attempt",
            "policy_violation_systematic",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════
# TRUST SCORE PARAMETERS (calibratable hyperparameters)
# ═══════════════════════════════════════════════════════════════


INITIAL_TRUST_SCORE = 1.0

# Decision thresholds
TRUST_REVOCATION_THRESHOLD = 0.2   # below → recommend revocation
TRUST_WARNING_THRESHOLD = 0.4      # below → alert supervisor
TRUST_HEALTHY_THRESHOLD = 0.7      # above → normal monitoring

# How much trust drops per incident (multiplies the composite score)
# Example: composite 0.8 × 0.5 = trust drops by 0.4
TRUST_DECAY_RATE = 0.5


# Trust recovery over time without incidents
# Calibrated to ~70 days full recovery from a moderate incident
# Demo-friendly for dashboard visualization (weekly periods)
TRUST_RECOVERY_PER_PERIOD = 0.10
TRUST_RECOVERY_PERIOD_DAYS = 7
TRUST_MAX = 1.0
# Bonus for completing a training course after an incident
TRUST_COURSE_COMPLETION_BONUS = 0.10


# ═══════════════════════════════════════════════════════════════
# COURSE MATCHING PARAMETERS
# ═══════════════════════════════════════════════════════════════

# Minimum number of matching tags to assign a course
MIN_TAG_MATCH_THRESHOLD = 1

# If insider repeats the same pattern after training, repeat the course
REPEAT_COURSE_ON_PERSISTENT_PATTERN = True


# ═══════════════════════════════════════════════════════════════
# BEHAVIORAL TAGGING THRESHOLDS
# Used by the tagging function (Step 3) to convert scores into tags
# ═══════════════════════════════════════════════════════════════

SOPHISTICATION_DELIBERATE_THRESHOLD = 0.6
CANARY_INTENT_EXFILTRATION_THRESHOLD = 0.7
CANARY_COUNT_SYSTEMATIC = 4
EFFICIENCY_DIRECT_TARGETING_THRESHOLD = 0.5

# ═══════════════════════════════════════════════════════════════
# BEHAVIOURAL TAG GENERATION (taxonomy → tags → course matching)
# ═══════════════════════════════════════════════════════════════

def generate_behavior_tags(commands, canaries_touched,
                           sophistication, efficiency, canary_intent,
                           lateral, web_terminal_used, is_repeat):
    """
    Convert the deterministic behavioural scores into policy-level tags from
    BEHAVIOR_TAXONOMY. Pure function (no DB) so every tag is reproducible from
    the session evidence (NFR-07). The historical 'escalating_severity' tag is
    added in profile_insider(), where the previous composite score is available.
    """
    tags = []
    num_canaries = len(canaries_touched)
    cred_canaries = [c for c in canaries_touched if c["file"] in CREDENTIAL_CANARIES]
    cmd_text = " ".join(commands).lower()
    cd_count = sum(1 for c in commands if c.strip().startswith("cd "))

    # ── Advanced tier (deliberate intent) ──────────────────────
    if sophistication >= SOPHISTICATION_DELIBERATE_THRESHOLD and "sudo" in cmd_text:
        tags.append("deliberate_privilege_escalation")
    if "shadow" in cmd_text or "/etc/passwd" in cmd_text:
        tags.append("credential_dumping_attempt")
    if canary_intent >= CANARY_INTENT_EXFILTRATION_THRESHOLD or num_canaries >= 2:
        tags.append("data_exfiltration_pattern")
    if lateral or web_terminal_used:
        tags.append("lateral_movement_attempt")
    if num_canaries >= CANARY_COUNT_SYSTEMATIC:
        tags.append("policy_violation_systematic")

    # ── Intermediate tier (questionable) ───────────────────────
    if cred_canaries and efficiency >= EFFICIENCY_DIRECT_TARGETING_THRESHOLD:
        tags.append("accessing_files_outside_role")
    if num_canaries >= 2 and "data_exfiltration_pattern" not in tags:
        tags.append("ignoring_classification_labels")
    if efficiency <= 0.3 and len(commands) > 8 and num_canaries == 0:
        tags.append("extended_unauthorized_exploration")

    # ── Negligent tier (no clear intent) ───────────────────────
    if (cred_canaries and efficiency < EFFICIENCY_DIRECT_TARGETING_THRESHOLD
            and "deliberate_privilege_escalation" not in tags):
        tags.append("accidental_credential_exposure")
    if num_canaries == 1 and "data_exfiltration_pattern" not in tags:
        tags.append("single_sensitive_access")
    if num_canaries == 0 and sophistication < 0.3:
        tags.append("basic_recon_only")
    if num_canaries == 0 and cd_count >= 2:
        tags.append("exploring_unauthorized_directories")

    # ── Historical tier ────────────────────────────────────────
    if is_repeat:
        tags.append("recurring_same_pattern")

    # Deduplicate, preserve order
    seen, ordered = set(), []
    for t in tags:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def match_courses_from_tags(tags):
    """
    Map detected tags to the highest remedial course whose
    'addresses_behaviors' list they match, honouring MIN_TAG_MATCH_THRESHOLD.
    Returns 0 if no course matches (e.g. only historical tags).
    """
    if not tags:
        return 0
    tagset = set(tags)
    matched_level = 0
    for course_id, course in TRAINING_COURSES.items():
        addressed = set(course.get("addresses_behaviors", []))
        if len(addressed & tagset) >= MIN_TAG_MATCH_THRESHOLD:
            matched_level = max(matched_level, course_id)
    return matched_level


def save_behavior_observations(session_id, ip, tags, composite_score):
    """Persist one row per detected tag into the behavior_observations table."""
    if not tags:
        return
    try:
        now = datetime.now(timezone.utc).isoformat()
        with get_conn() as conn:
            for tag in tags:
                conn.execute(
                    """INSERT INTO behavior_observations
                       (timestamp, session_id, ip, behavior_tag,
                        tag_description, composite_score)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (now, session_id, ip, tag,
                     BEHAVIOR_TAXONOMY.get(tag, ""), composite_score),
                )
    except Exception as e:
        print(f"[PROFILER] behavior_observations error: {e}")

def get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)


def init_profiler_db():
    """Create insider profiler tables with trust system + timeline support."""
    with get_conn() as conn:
        # ── Profiles table (one row per session) ────────────────
        conn.execute("""
        CREATE TABLE IF NOT EXISTS insider_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            session_id TEXT,
            ip TEXT,
            profile_type TEXT,
            confidence REAL,
            sophistication_score REAL,
            efficiency_score REAL,
            canary_intent_score REAL,
            time_score REAL,
            lateral_movement INTEGER,
            is_repeat_offender INTEGER,
            previous_sessions INTEGER,
            training_level INTEGER DEFAULT 0,
            recommended_action TEXT,
            reasoning TEXT
        )
        """)

        # ── Training state (current state, one row per IP) ──────
        # Now includes trust system columns from the start
        conn.execute("""
        CREATE TABLE IF NOT EXISTS insider_training (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            employee_name TEXT DEFAULT 'unknown',
            training_level INTEGER DEFAULT 0,
            course_1_completed INTEGER DEFAULT 0,
            course_2_completed INTEGER DEFAULT 0,
            course_3_completed INTEGER DEFAULT 0,
            incidents_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT DEFAULT 'active',
            trust_score REAL DEFAULT 1.0,
            last_incident_at TEXT,
            last_course_completed_at TEXT,
            revocation_recommended INTEGER DEFAULT 0
        )
        """)

        # ── Training history (event log of course assignments) ──
        conn.execute("""
        CREATE TABLE IF NOT EXISTS training_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            session_id TEXT,
            course_id INTEGER,
            course_name TEXT,
            is_repeat INTEGER DEFAULT 0,
            triggered_by_behaviors TEXT,
            trust_score_before REAL,
            trust_score_after REAL,
            reasoning TEXT
        )
        """)

        # ── Behavior observations (one row per detected tag) ────
        conn.execute("""
        CREATE TABLE IF NOT EXISTS behavior_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            session_id TEXT,
            ip TEXT,
            behavior_tag TEXT,
            tag_description TEXT,
            composite_score REAL
        )
        """)

        # ── Trust score history (every change, any reason) ──────
        # Powers dashboard timeline views
        conn.execute("""
        CREATE TABLE IF NOT EXISTS trust_score_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            session_id TEXT,
            trust_before REAL,
            trust_after REAL,
            change_delta REAL,
            change_reason TEXT,
            composite_score REAL
        )
        """)

        # ── Indexes for query performance ──────────────────────
        conn.execute("CREATE INDEX IF NOT EXISTS idx_profile_ip ON insider_profiles(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_training_ip ON insider_training(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_history_ip ON training_history(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_ip ON behavior_observations(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_session ON behavior_observations(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trust_ip ON trust_score_history(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_trust_ts ON trust_score_history(timestamp)")

        print("[DB] Profiler tables ready (with trust system + timeline)")

def get_ip_history(ip):
    """Check how many previous sessions this IP has had."""
    with get_conn() as conn:
        cursor = conn.execute(
            "SELECT COUNT(DISTINCT session_id) FROM commands WHERE ip = ?", (ip,)
        )
        count = cursor.fetchone()[0]

        cursor = conn.execute(
            "SELECT COUNT(*) FROM canary_events WHERE ip = ?", (ip,)
        )
        canary_count = cursor.fetchone()[0]

        cursor = conn.execute(
            "SELECT COUNT(*) FROM beacon_events WHERE attacker_ip = ?", (ip,)
        )
        beacon_count = cursor.fetchone()[0]

    return {
        "previous_sessions": count,
        "total_canary_accesses": canary_count,
        "total_beacon_accesses": beacon_count,
        "is_repeat": count > 1,
    }


def get_training_record(ip):
    """Get or create training record for this IP."""
    with get_conn() as conn:
        cursor = conn.execute(
            "SELECT * FROM insider_training WHERE ip = ?", (ip,)
        )
        row = cursor.fetchone()

        if row is None:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT INTO insider_training
                   (ip, training_level, incidents_count, first_seen, last_seen, status)
                   VALUES (?, 0, 0, ?, ?, 'active')""",
                (ip, now, now),
            )
            return {
                "ip": ip,
                "training_level": 0,
                "course_1": False,
                "course_2": False,
                "course_3": False,
                "incidents_count": 0,
                "status": "active",
            }

        return {
            "ip": row[1],
            "employee_name": row[2],
            "training_level": row[3],
            "course_1": bool(row[4]),
            "course_2": bool(row[5]),
            "course_3": bool(row[6]),
            "incidents_count": row[7],
            "status": row[10],
        }


def increment_training(ip):
    """Advance the insider to the next training course."""
    with get_conn() as conn:
        record = get_training_record(ip)
        current_level = record["training_level"]
        new_level = min(current_level + 1, 3)
        now = datetime.now(timezone.utc).isoformat()

        course_field = f"course_{new_level}_completed"
        conn.execute(
            f"""UPDATE insider_training
                SET training_level = ?,
                    {course_field} = 1,
                    incidents_count = incidents_count + 1,
                    last_seen = ?
                WHERE ip = ?""",
            (new_level, now, ip),
        )
        return new_level


def flag_for_removal(ip):
    """Mark insider for removal after exhausting all training."""
    with get_conn() as conn:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """UPDATE insider_training
               SET status = 'flagged_removal',
                   incidents_count = incidents_count + 1,
                   last_seen = ?
               WHERE ip = ?""",
            (now, ip),
        )


# ── Behavioral scoring functions ─────────────────────────────

def score_sophistication(commands):
    """
    How technically skilled is this user?
    High score = malicious indicator (knows exactly what to do)
    Low score = negligent indicator (basic commands only)
    """
    if not commands:
        return 0.0

    advanced_count = 0
    basic_count = 0

    for cmd in commands:
        cmd_lower = cmd.lower().strip()
        base_cmd = cmd_lower.split()[0] if cmd_lower else ""

        if cmd_lower in ADVANCED_COMMANDS or base_cmd in {"sudo", "nmap", "netstat", "grep", "find", "wget", "curl", "ssh", "nc", "python", "mysqldump"}:
            advanced_count += 1
        elif cmd_lower in BASIC_COMMANDS or base_cmd in {"ls", "cd", "pwd", "whoami", "help", "clear"}:
            basic_count += 1

    total = advanced_count + basic_count
    if total == 0:
        return 0.5

    return round(advanced_count / total, 2)


def score_efficiency(commands, canaries_touched):
    """
    How directly does the user navigate to sensitive files?
    High score = malicious (goes straight to targets)
    Low score = negligent (wanders around, many ls/cd before finding anything)
    """
    if not commands:
        return 0.0

    if not canaries_touched:
        return 0.1  # didn't find anything sensitive

    # How many commands before first canary access?
    first_canary_idx = len(commands)
    for i, cmd in enumerate(commands):
        for cf in CANARY_SENSITIVITY:
            if cf in cmd:
                first_canary_idx = i
                break
        if first_canary_idx < len(commands):
            break

    # Fewer commands before canary = more efficient = more malicious
    ratio = first_canary_idx / len(commands) if len(commands) > 0 else 1.0

    # Invert: low ratio (found quickly) = high efficiency score
    efficiency = round(1.0 - ratio, 2)

    return max(0.0, min(1.0, efficiency))

def score_canary_intent(canaries_touched, commands):
    if not canaries_touched:
        return 0.0

    score = 0.0

    # Number of distinct canary files
    num_canaries = len(canaries_touched)
    score += min(num_canaries * 0.2, 0.6)

    # Sensitivity-weighted access
    for c in canaries_touched:
        sensitivity = CANARY_SENSITIVITY.get(c["file"], 1)
        score += sensitivity * 0.05
        # Credential-class files get a strong bonus
        # but only if there's navigation toward them (not first command)
        if c["file"] in CREDENTIAL_CANARIES:
            cmd_index = next(
                (i for i, cmd in enumerate(commands) if c["file"] in cmd),
                len(commands)
            )
            # if they navigated at least a few commands before accessing it
            if cmd_index > 2:
                score += 0.25
            else:
                # accessed very early — could be accidental
                score += 0.10

    # Repeated access to same file = deliberate
    for c in canaries_touched:
        if c["access_count"] > 1:
            score += 0.15

    return round(min(score, 1.0), 2)


def score_time_behavior(commands, duration_seconds):
    """
    How does time spent relate to behavior?
    Fast + targeted = malicious (knows what they want)
    Slow + wandering = negligent (exploring, confused)
    Very fast with many commands = automated tool (malicious)
    """
    if not commands or duration_seconds <= 0:
        return 0.5

    commands_per_minute = (len(commands) / duration_seconds) * 60

    # Automated tool detection (very high rate)
    if commands_per_minute > 30:
        return 1.0

    # Fast and efficient
    if commands_per_minute > 10:
        return 0.8

    # Normal pace
    if commands_per_minute > 3:
        return 0.5

    # Very slow (confused, exploring)
    return 0.2


def check_lateral_movement(ip):
    """
    Did this IP appear in both SSH and web beacons?
    Lateral movement is a strong malicious indicator.
    """
    try:
        beacon_file = os.path.join(BASE_DIR, "beacon_events.json")
        if not os.path.exists(beacon_file):
            return False

        with open(beacon_file, "r") as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    if event.get("attacker_ip") == ip and event.get("event_type") == "beacon_triggered":
                        return True
    except Exception:
        pass

    return False


# ── Main profiling function ──────────────────────────────────

def profile_insider(session, commands, canaries_touched, duration_seconds):
    """
    Compute behavioral scores for an insider session.
    
    This function ONLY computes scores — it does NOT decide the profile type,
    training action, or recommendation. That is the LLM's job.
    
    Returns a profile dict with all scores + context for the LLM.
    """
    ip = session["ip"]
    session_id = session["session_id"]

    # Calculate all behavioral scores
    sophistication = score_sophistication(commands)
    efficiency = score_efficiency(commands, canaries_touched)
    canary_intent = score_canary_intent(canaries_touched, commands)
    time_score = score_time_behavior(commands, duration_seconds)
    lateral = check_lateral_movement(ip) #binary
    history = get_ip_history(ip) 
    training = get_training_record(ip) 

    # Check if they accessed the web terminal (critical malicious signal)
    web_terminal_used = False
    try:
        beacon_file = os.path.join(BASE_DIR, "beacon_events.json")
        if os.path.exists(beacon_file):
            with open(beacon_file, "r") as f:
                for line in f:
                    if line.strip():
                        ev = json.loads(line)
                        if (ev.get("attacker_ip") == ip and 
                            ev.get("event_type") in ("web_terminal_accessed", "web_terminal_command")):
                            web_terminal_used = True
                            break
    except Exception:
        pass

    # Weighted composite score (0 = negligent, 1 = malicious)
    # Weights based on CERT/CMU behavioral indicator model
    composite = (
    sophistication * 0.15
    + efficiency * 0.10
    + canary_intent * 0.35      # ← was 0.15, now dominant signal
    + time_score * 0.05
    + (0.15 if lateral else 0)
    + (0.10 if history["is_repeat"] else 0)
    + (0.10 if web_terminal_used else 0)
    )
    composite = round(min(composite, 1.0), 2)

    current_level = training["training_level"]

    # Build reasoning text (factual observations, no decisions)
    #these oservations are sent to LLM
    reasoning_parts = []
    if sophistication >= 0.6:
        reasoning_parts.append(f"high command sophistication ({sophistication})")
    elif sophistication <= 0.3:
        reasoning_parts.append(f"low technical skill ({sophistication})")

    if efficiency >= 0.6:
        reasoning_parts.append("navigated directly to sensitive files")
    elif efficiency <= 0.3:
        reasoning_parts.append("wandered before reaching sensitive files")

    if canary_intent >= 0.5:
        reasoning_parts.append(f"accessed {len(canaries_touched)} sensitive files with intent")
    elif canaries_touched:
        reasoning_parts.append("minimal canary interaction")

    if lateral:
        reasoning_parts.append("LATERAL MOVEMENT: SSH to Web")

    if web_terminal_used:
        reasoning_parts.append("USED WEB TERMINAL (strong malicious signal)")

    if history["is_repeat"]:
        reasoning_parts.append(f"repeat offender ({history['previous_sessions']} prior sessions)")

    if current_level > 0:
        reasoning_parts.append(f"completed {current_level}/3 training courses already")

    reasoning = "; ".join(reasoning_parts) if reasoning_parts else "insufficient data for profiling"

    # Available training courses context (for LLM to reference)
    courses_info = []
    for cid, course in TRAINING_COURSES.items():
        status = "COMPLETED" if training.get(f"course_{cid}", False) else "NOT COMPLETED"
        courses_info.append(f"Course {cid}: '{course['name']}' ({course['level']}) — {status}")
    # ── Behavioural tag generation (taxonomy) ──────────────────
    behavior_tags = generate_behavior_tags(
        commands, canaries_touched,
        sophistication, efficiency, canary_intent,
        lateral, web_terminal_used, history["is_repeat"],
    )
    # Historical 'escalating_severity': compare with previous composite
    try:
        with get_conn() as conn:
            prev = conn.execute(
                "SELECT confidence FROM insider_profiles WHERE ip = ? ORDER BY id DESC LIMIT 1",
                (ip,),
            ).fetchone()
        if prev is not None and prev[0] is not None and composite > prev[0]:
            if "escalating_severity" not in behavior_tags:
                behavior_tags.append("escalating_severity")
    except Exception as e:
        print(f"[PROFILER] escalating_severity check error: {e}")
    # Build profile (scores only — no decisions)
    profile = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "insider_profile",
        "session_id": session_id,
        "ip": ip,
        "composite_score": composite,
        "sophistication_score": sophistication,
        "efficiency_score": efficiency,
        "canary_intent_score": canary_intent,
        "time_score": time_score,
        "lateral_movement": lateral,
        "web_terminal_used": web_terminal_used,
        "is_repeat_offender": history["is_repeat"],
        "previous_sessions": history["previous_sessions"],
        "total_canary_accesses": history["total_canary_accesses"],
        "total_beacon_accesses": history["total_beacon_accesses"],
        "training_level": current_level,
        "training_status": training["status"],
        "courses_info": "\n".join(courses_info),
        "reasoning": reasoning,
        "behavior_tags": behavior_tags,
        "duration_seconds": duration_seconds,
        "total_commands": len(commands),
    }

    # Save to DB (scores only)
    try:
        with get_conn() as conn:
            conn.execute(
                """INSERT INTO insider_profiles
                   (timestamp, session_id, ip, profile_type, confidence,
                    sophistication_score, efficiency_score, canary_intent_score,
                    time_score, lateral_movement, is_repeat_offender,
                    previous_sessions, training_level, recommended_action, reasoning)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    profile["timestamp"],
                    session_id,
                    ip,
                    "pending_llm",  # LLM decides
                    composite,
                    sophistication,
                    efficiency,
                    canary_intent,
                    time_score,
                    1 if lateral else 0,
                    1 if history["is_repeat"] else 0,
                    history["previous_sessions"],
                    current_level,
                    "pending_llm",  # LLM decides
                    reasoning,
                ),
            )
    except Exception as e:
        print(f"[PROFILER] DB error: {e}")

    # Persist behavioural tags for longitudinal analysis
    save_behavior_observations(session_id, ip, behavior_tags, composite)

    # Save to JSON log (for Wazuh)
    try:
        with open(PROFILE_LOG, "a") as f:
            f.write(json.dumps(profile) + "\n")
    except Exception as e:
        print(f"[PROFILER] log error: {e}")

    print(f"[PROFILER] {ip} → composite={composite}")
    print(f"[PROFILER] reasoning: {reasoning}")

    return profile


def update_profile_from_llm(session_id, ip, insider_type, recommended_action):
    """Called after LLM responds — updates the DB with the LLM's decisions."""
    try:
        with get_conn() as conn:
            conn.execute(
                """UPDATE insider_profiles
                   SET profile_type = ?, recommended_action = ?
                   WHERE session_id = ? AND ip = ?""",
                (insider_type, recommended_action, session_id, ip),
            )
    except Exception as e:
        print(f"[PROFILER] update error: {e}")


def update_training_from_llm(ip, new_level):
    """Called when LLM recommends advancing training level."""
    try:
        with get_conn() as conn:
            now = datetime.now(timezone.utc).isoformat()

            # Build SET clause to mark all courses up to new_level as completed
            course_updates = ", ".join(
                f"course_{i}_completed = 1" for i in range(1, new_level + 1)
            )

            conn.execute(
                f"""INSERT INTO insider_training (ip, training_level, incidents_count, first_seen, last_seen)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        training_level = MAX(training_level, ?),
                        {course_updates},
                        incidents_count = incidents_count + 1,
                        last_seen = ?""",
                (ip, new_level, now, now, new_level, now),
            )
    except Exception as e:
        print(f"[PROFILER] training update error: {e}")


# ═══════════════════════════════════════════════════════════════
# TRUST SCORE SYSTEM
# ═══════════════════════════════════════════════════════════════
# Trust is a persistent score per IP (0.0 to 1.0) that:
#   - Starts at 1.0 (full trust) for new IPs
#   - Decreases when an incident happens (decay proportional to composite)
#   - Recovers slowly over time when the IP behaves (lazy recovery)
#   - Gets a small bonus when a training course is assigned
#   - When trust hits 0, the IP is auto-flagged for access revocation
# ═══════════════════════════════════════════════════════════════


def _log_trust_change(conn, ip, session_id, before, after, reason, composite=None):
    """
    Record a trust change in two places:
      1. SQLite trust_score_history table (for the standalone DB queries)
      2. llm_events.json (for Wazuh — already monitored by filebeat/ossec)
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    delta = round(after - before, 3)

    # 1. SQLite (unchanged)
    conn.execute(
        """INSERT INTO trust_score_history
           (timestamp, ip, session_id, trust_before, trust_after,
            change_delta, change_reason, composite_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            timestamp,
            ip,
            session_id,
            round(before, 3),
            round(after, 3),
            delta,
            reason,
            composite,
        ),
    )

    # 2. JSON log for Wazuh ingestion
    # Compute the band so Wazuh visualisations can group by it directly
    if after < TRUST_REVOCATION_THRESHOLD:
        band = "revoke"
    elif after < TRUST_WARNING_THRESHOLD:
        band = "warn_supervisor"
    elif after < TRUST_HEALTHY_THRESHOLD:
        band = "assign_training"
    else:
        band = "normal_monitoring"

    event = {
        "timestamp": timestamp,
        "event_type": "trust_change",
        "client_ip": ip,
        "session_id": session_id,
        "trust_before": round(before, 3),
        "trust_after": round(after, 3),
        "change_delta": delta,
        "change_reason": reason,
        "trust_band": band,
        "composite_score": composite,
    }

    try:
        log_path = os.path.join(BASE_DIR, "llm_events.json")
        with open(log_path, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print(f"[TRUST] failed to write to llm_events.json: {e}")


def get_current_trust(ip, session_id=None):
    """
    Read trust for an IP and apply lazy time-based recovery first.
    Creates the training row if the IP is new (with INITIAL_TRUST_SCORE).
    Returns the up-to-date trust value (0.0 to 1.0).
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT trust_score, last_incident_at FROM insider_training WHERE ip = ?",
            (ip,),
        ).fetchone()

        # New IP → seed with full trust
        if row is None:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT INTO insider_training
                   (ip, training_level, incidents_count, first_seen, last_seen,
                    status, trust_score)
                   VALUES (?, 0, 0, ?, ?, 'active', ?)""",
                (ip, now, now, INITIAL_TRUST_SCORE),
            )
            return INITIAL_TRUST_SCORE

        current_trust, last_incident = row

        # No prior incidents OR already at max → no recovery needed
        if not last_incident or current_trust >= TRUST_MAX:
            return current_trust

        # Lazy recovery: count how many full recovery periods passed since last incident
        try:
            last_dt = datetime.fromisoformat(last_incident)
        except Exception:
            return current_trust

        elapsed_days = (datetime.now(timezone.utc) - last_dt).days
        periods = elapsed_days // TRUST_RECOVERY_PERIOD_DAYS

        if periods <= 0:
            return current_trust

        recovered = min(
            TRUST_MAX,
            current_trust + (periods * TRUST_RECOVERY_PER_PERIOD),
        )

        if recovered > current_trust:
            conn.execute(
                "UPDATE insider_training SET trust_score = ? WHERE ip = ?",
                (recovered, ip),
            )
            _log_trust_change(
                conn, ip, session_id, current_trust, recovered,
                f"time_recovery_{periods}_periods",
            )
            print(f"[TRUST] {ip}: recovered {periods} periods → {current_trust:.2f} → {recovered:.2f}")

        return recovered


def apply_incident_decay(ip, session_id, composite_score):
    """
    Apply trust decay at the end of a session.
    Order: time recovery (via get_current_trust) → decay → save.
    Auto-flags for removal if trust hits 0.
    Returns (trust_before, trust_after).
    """
    trust_before = get_current_trust(ip, session_id)
    delta = composite_score * TRUST_DECAY_RATE
    trust_after = max(0.0, trust_before - delta)

    with get_conn() as conn:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """UPDATE insider_training
               SET trust_score = ?, last_incident_at = ?, last_seen = ?
               WHERE ip = ?""",
            (trust_after, now, now, ip),
        )
        _log_trust_change(
            conn, ip, session_id, trust_before, trust_after,
            "incident_decay", composite=composite_score,
        )

        # If trust hit zero, auto-flag for revocation
        if trust_after <= 0.0:
            conn.execute(
                """UPDATE insider_training
                   SET status = 'flagged_removal', revocation_recommended = 1
                   WHERE ip = ?""",
                (ip,),
            )
            print(f"[TRUST] {ip}: trust hit 0.0 → auto-flagged for revocation")

    print(f"[TRUST] {ip}: {trust_before:.2f} → {trust_after:.2f} (decay from composite={composite_score})")
    return trust_before, trust_after


def apply_course_bonus(ip, session_id, course_level):
    """
    Add a fixed trust bonus when a training course is assigned/completed.
    Returns (trust_before, trust_after).
    """
    trust_before = get_current_trust(ip, session_id)
    trust_after = min(TRUST_MAX, trust_before + TRUST_COURSE_COMPLETION_BONUS)

    with get_conn() as conn:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """UPDATE insider_training
               SET trust_score = ?, last_course_completed_at = ?
               WHERE ip = ?""",
            (trust_after, now, ip),
        )
        _log_trust_change(
            conn, ip, session_id, trust_before, trust_after,
            f"course_{course_level}_assigned",
        )

    print(f"[TRUST] {ip}: {trust_before:.2f} → {trust_after:.2f} (course {course_level} bonus)")
    return trust_before, trust_after


def get_trust_band(trust_score):
    """Map a trust score (0.0-1.0) to an action band."""
    if trust_score < TRUST_REVOCATION_THRESHOLD:
        return "revoke"
    if trust_score < TRUST_WARNING_THRESHOLD:
        return "warn_supervisor"
    if trust_score < TRUST_HEALTHY_THRESHOLD:
        return "assign_training"
    return "normal_monitoring"