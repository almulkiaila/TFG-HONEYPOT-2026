import logging
import socket
import argparse
import paramiko
import threading
import json
from datetime import datetime, timezone
import uuid
from db import init_db, save_command, save_llm_analysis, save_canary
from insider_profiler import (
    profile_insider, init_profiler_db,
    update_profile_from_llm, update_training_from_llm,
    apply_incident_decay, apply_course_bonus, get_trust_band,
     match_courses_from_tags,
)
import os
import requests
from dotenv import load_dotenv
from insider_profiler import flag_for_removal
import httpx
from openai import OpenAI
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.path.join(BASE_DIR, "llm_events.json")
BEACON_EVENTS_FILE = os.path.join(BASE_DIR, "beacon_events.json")
CORRELATION_LOG = os.path.join(BASE_DIR, "correlation_events.json")

# Auto-detect machine IP for canary file URLs
def get_local_ip():
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()
BEACON_PORT = os.environ.get("BEACON_PORT", "8888")
BEACON_URL = f"http://{LOCAL_IP}:{BEACON_PORT}"

with open(os.path.join(BASE_DIR, "system.json")) as f:
    raw = f.read()
    # Replace placeholder with actual IP
    raw = raw.replace("{{BEACON_URL}}", BEACON_URL)
    system_data = json.loads(raw)

print(f"[*] Beacon URL for canary files: {BEACON_URL}")


logging_format = logging.Formatter("%(message)s")
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
host_key = paramiko.RSAKey(filename=os.path.join(BASE_DIR, "server.key"))

CANARY_FILES = {
    "config.env",
    "passwords.txt",
    "aws_credentials.txt",
    "db_backup_2025.sql",
    "users_dump.sql",
    "salaries_2025.csv",
    "vpn_config.ovpn",
    "notes.txt"
}


WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("root", "root"),
    ("devops", "devops123"),
    ("backup", "backup"),
    ("test", "test123"),
]

funnel_logger = logging.getLogger("FunnelLogger")
funnel_logger.setLevel(logging.INFO)
funnel_handler = logging.FileHandler(os.path.join(BASE_DIR, "audits.log"))
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger("CredsLogger")
creds_logger.setLevel(logging.INFO)
creds_handler = logging.FileHandler(os.path.join(BASE_DIR, "cmd_audits.log"))
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


_file_lock = threading.Lock()


def log_event(logger, event_data):
    logger.info(json.dumps(event_data))


def save_llm_event(event):
    with _file_lock:
        with open(EVENTS_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")


LLM_URL = os.environ.get("UNI_LLM_URL", "https://localhost:4000/v1")
LLM_API_KEY = os.environ.get("UNI_LLM_API_KEY", "")
LLM_MODEL = os.environ.get("UNI_LLM_MODEL", "gpt-oss:20b")


_http_client = httpx.Client(verify=False, timeout=300.0)
_llm_client = OpenAI(
    base_url=LLM_URL,
    api_key=LLM_API_KEY,
    http_client=_http_client,
)


def call_llm(prompt):
    
    try:
        response = _llm_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a cybersecurity analysis assistant. Return only valid JSON when requested. Do not include any thinking, reasoning, or explanation outside the JSON object. Do not use <think> tags."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
            max_tokens=3000,
        )
        result = response.choices[0].message.content or ""
        print(f"[LLM] Response received ({len(result)} chars)")
        return result
    except Exception as e:
        print(f"[LLM] ERROR: {e}")
        return '{"attack_stage": "unknown", "risk_level": "unknown"}'

def parse_json_from_llm(raw_output):
    """Safely extract JSON from LLM output."""
    start = raw_output.find("{")
    end = raw_output.rfind("}") + 1
    if start == -1:
        return None
    
    json_str = raw_output[start:end] if end > 0 else raw_output[start:]
    
    # If model cut off before closing brace, try to fix it
    if end == 0 or json_str.count("{") > json_str.count("}"):
        # Trim trailing incomplete value (e.g. cut-off string)
        json_str = json_str.rstrip()
        if json_str.endswith(","):
            json_str = json_str[:-1]
        # Close any open quotes and add closing brace
        if json_str.count('"') % 2 != 0:
            json_str += '"'
        json_str += "}"
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        print(f"[parse_json] Failed to parse: {json_str[:200]}")
        return None


# ── LLM Analysis (incremental, every N commands) ─────────────
def run_llm_analysis(session, commands):
    commands_text = "\n".join(commands)

    prompt = f"""You are a cybersecurity expert analyzing SSH honeypot commands.

Commands executed:
{commands_text}

Classification rules (apply in this order):
- If ANY command contains "shadow", "sudo bash", "sudo su" → attack_stage = "privilege_escalation"
- If ANY command contains "config.env", ".csv", ".sql", "dump" → attack_stage = "data_exfiltration"
- If ANY command contains "sudo -l", "sudo cat" → attack_stage = "privilege_escalation"
- If commands are ONLY whoami, ls, pwd, uname, uptime, ifconfig → attack_stage = "reconnaissance"

risk_level rules:
- "critical" if /etc/shadow, sudo bash, or sudo su appears
- "high" if sudo -l, config.env, or sensitive files appear
- "medium" if ls, cat on non-sensitive files
- "low" if only whoami, pwd, uname

Return ONLY this JSON, nothing else:
{{"attack_stage": "...", "risk_level": "..."}}"""

    raw_output = call_llm(prompt)
    analysis_json = parse_json_from_llm(raw_output)

    if analysis_json is None:
        analysis_json = {"attack_stage": "unknown", "risk_level": "unknown"}
    else:
        # Normalize attack stage
        stage = analysis_json.get("attack_stage", "").lower().strip()
        if "recon" in stage:
            analysis_json["attack_stage"] = "reconnaissance"
        elif "exploit" in stage:
            analysis_json["attack_stage"] = "exploitation"
        elif "privilege" in stage:
            analysis_json["attack_stage"] = "privilege_escalation"
        elif "exfil" in stage:
            analysis_json["attack_stage"] = "data_exfiltration"
        else:
            analysis_json["attack_stage"] = stage or "unknown"

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "llm_analysis",
        "session_id": session["session_id"],
        "client_ip": session["ip"],
        "attack_stage": analysis_json.get("attack_stage", "unknown"),
        "risk_level": analysis_json.get("risk_level", "unknown"),
        "commands": ", ".join(commands),
    }
    save_llm_event(event)
    print(f"[LLM ANALYSIS] stage={analysis_json.get('attack_stage')} risk={analysis_json.get('risk_level')}")
    return analysis_json   


# ── Session Summary (end of session) ─────────────────────────
def run_session_summary(session, commands, canaries_touched=None, duration_seconds=0):
    if canaries_touched is None:
        canaries_touched = []

    commands_text = "\n".join(commands)

    # Step 1: Run behavioral profiling FIRST
    profile = profile_insider(session, commands, canaries_touched, duration_seconds)
    
    trust_before, trust_after = apply_incident_decay(
        session["ip"], session["session_id"], profile["composite_score"]
    )
    trust_band = get_trust_band(trust_after)
    print(f"[TRUST] {session['ip']}: {trust_before:.2f} → {trust_after:.2f} (band: {trust_band})")
   
    accessed_files = [c["file"] for c in canaries_touched]
    cmd_lower = commands_text.lower()
    session_artifacts = (
        f"Files this session actually accessed: "
        f"{', '.join(accessed_files) if accessed_files else 'NONE'}\n"
        f"Used sudo/privilege escalation: {'YES' if 'sudo' in cmd_lower else 'NO'}\n"
        f"Ran a database dump: "
        f"{'YES' if any(k in cmd_lower for k in ('mysqldump', 'pg_dump', 'dump')) else 'NO'}\n"
        f"Touched /etc/shadow: {'YES' if 'shadow' in cmd_lower else 'NO'}"
    )
   
    canary_context = ""
    if canaries_touched:
        canary_context = "\n\nSensitive files accessed (canary/decoy files):\n"
        for c in canaries_touched:
            canary_context += f"- {c['file']} opened {c['access_count']} time(s), prior commands: {c['commands_before']}\n"
    else:
        canary_context = "\n\nNo sensitive decoy files were accessed."

   
    beacon_context = ""
    try:
        if os.path.exists(BEACON_EVENTS_FILE):
            with open(BEACON_EVENTS_FILE, "r") as f:
                beacon_events = [json.loads(line) for line in f if line.strip()]

            session_ip = session["ip"]
            relevant = [
                e for e in beacon_events
                if e.get("attacker_ip") == session_ip
                and e.get("event_type") == "beacon_triggered"
            ]

            if relevant:
                beacon_context = "\n\nWeb beacons triggered by same IP:\n"
                for b in relevant:
                    beacon_context += f"- {b.get('route_accessed')} ({b.get('alert', '')})\n"
            else:
                beacon_context = "\n\nNo web beacons triggered."
    except Exception as e:
        print(f"[session_summary] beacon read error: {e}")
        beacon_context = "\n\nNo beacon data available."

    correlation_context = ""
    try:
        if os.path.exists(CORRELATION_LOG):
            with open(CORRELATION_LOG, "r") as f:
                corr_events = [json.loads(line) for line in f if line.strip()]

            session_ip = session["ip"]
            relevant_corr = [
                e for e in corr_events
                if e.get("attacker_ip") == session_ip
            ]

            if relevant_corr:
                correlation_context = "\n\nCross-vector correlation alerts for this IP:\n"
                for c in relevant_corr:
                    correlation_context += (
                        f"- {c.get('canary_files_accessed')} accessed via SSH, "
                        f"then {c.get('beacon_routes_accessed')} accessed via web "
                        f"within 30min (risk: {c.get('risk_level')})\n"
                    )
            else:
                correlation_context = "\n\nNo cross-vector correlation detected."
    except Exception as e:
        print(f"[session_summary] correlation read error: {e}")
        correlation_context = "\n\nNo correlation data available."

    
    profile_context = f"""

INSIDER BEHAVIORAL SCORES (computed automatically, 0.0 to 1.0):
- Composite score: {profile['composite_score']} (closer to 0 = negligent/accidental, closer to 1 = malicious/deliberate)
- Command sophistication: {profile['sophistication_score']} (advanced Linux commands vs basic ones)
- Navigation efficiency: {profile['efficiency_score']} (went straight to targets vs wandered)
- Canary file intent: {profile['canary_intent_score']} (deliberate targeting of sensitive files vs accidental)
- Time behavior: {profile['time_score']} (fast+targeted vs slow+exploring)
- Lateral movement SSH-to-Web: {'YES' if profile['lateral_movement'] else 'NO'}
- Web terminal used: {'YES' if profile.get('web_terminal_used') else 'NO'}
- Repeat offender: {'YES' if profile['is_repeat_offender'] else 'NO'} ({profile['previous_sessions']} prior sessions, {profile['total_canary_accesses']} total canary accesses)
- Session duration: {profile['duration_seconds']:.0f} seconds, {profile['total_commands']} commands
- Behavioral observations: {profile['reasoning']}
- Behavioural tags (policy vocabulary): {', '.join(profile.get('behavior_tags', [])) or 'none'}

TRAINING HISTORY FOR THIS IP:
- Current training level: {profile['training_level']}/3
- Training status: {profile['training_status']}
{profile['courses_info']}

AVAILABLE COURSES (organization offers 3 progressive courses):
    - Course 1: 'Security Awareness Fundamentals' (basic) — password management, phishing, data classification
    - Course 2: 'Data Handling & Access Control' (intermediate) — sensitive files, least privilege, reporting
    - Course 3: 'Advanced Security Policy Compliance' (advanced) — incident response, acceptable use, legal
    - After all 3 courses: if employee still violates, recommend access revocation
 
    CCRITICAL RULE for recommended_training_level:
    - The current training level is {profile['training_level']}. This means courses 1 to {profile['training_level']} are ALREADY DONE.
    - NEVER recommend the same or lower level than {profile['training_level']}
    - If current level is already 3, set recommended_training_level to 3 and recommend access revocation in training_action

    SEVERITY RULES for training level (apply BEFORE the progression rule above):
    - If insider_type=malicious AND any of: /etc/shadow accessed, sudo su/bash used,
      3+ canaries accessed, 2+ credential canaries accessed → recommended_training_level MUST be 3
    - If insider_type=malicious AND 1 credential canary OR lateral movement → recommended_training_level MUST be minimum 2
    - If insider_type=negligent AND 1 canary accessed accidentally → recommended_training_level = 1
    - If insider_type=negligent AND multiple canaries OR repeat offender → recommended_training_level = 2

    PROGRESSION RULE (apply after severity):
    - Final recommended_training_level must always be >= {min(profile['training_level'] + 1, 3)}
    - So if severity says 2 but current level is already 2, recommend 3
"""

    prompt = f"""You are a cybersecurity recommendation system for an internal honeypot deployed within an organization. Your job is to:
1. Classify the insider as malicious or negligent
2. Recommend training or action

Commands: {commands_text}
{canary_context}
{beacon_context}
{correlation_context}
{profile_context}


CROSS-VECTOR CORRELATION:
If cross-vector correlation alerts are present for this IP, this means the 
same actor was observed on both SSH and the internal web portal within 30 
minutes. Consider this as supporting evidence when classifying intent, but 
still apply RULE 1 and RULE 2 below — a correlation alone does not 
automatically imply malicious classification.
CRITICAL CLASSIFICATION RULES (apply in this exact order):
RULE 1 — Hard malicious indicators (override the composite score):
If the commands contain ANY of the following, classify as "malicious":
  - "sudo cat /etc/shadow" or any access to /etc/shadow
  - "sudo su", "sudo bash", or any root shell escalation
  - Access to 2 or more canary files in the same session
  - Access to 2+ credential-class canaries (config.env, passwords.txt,
    aws_credentials.txt, vpn_config.ovpn) in the same session
  - Access to ANY credential-class canary AFTER sudo commands
  - Access to ANY credential-class canary by a repeat offender
    (previous_sessions > 1)
  - Commands rate > 15 per minute (automated tool signature)

NOTE: A single credential-class canary access by a first-time offender
with no sudo usage may be negligent — use composite_score and navigation
pattern to decide (RULE 3).

RULE 2 — Hard negligent indicators:
If RULE 1 does not match AND the session shows:
  - Only basic commands (ls, cd, pwd, whoami, help) with at most 1 accidental canary access
  - Long duration (>120s) with wandering navigation
  - No sudo usage
Then classify as "negligent".

RULE 3 — Ambiguous cases:
If neither RULE 1 nor RULE 2 clearly applies, use the composite_score as guidance:
  - composite >= 0.5 → malicious
  - composite < 0.5 → negligent
  But you MUST justify your choice based on specific commands, not just the score.

RISK LEVEL RULES (first match wins):
  - "critical" if ANY of:
      * /etc/shadow accessed or sudo su/bash used
      * 3+ canaries accessed in one session
      * 2+ credential-class canaries accessed (config.env, passwords.txt,
        aws_credentials.txt, vpn_config.ovpn)
  - "high" if ANY of:
      * exactly 1 credential-class canary accessed WITH navigation toward it
        (not accidental - commands show deliberate path)
      * 2 non-credential canaries accessed
      * lateral movement detected (SSH + web beacon same IP)
  - "medium" if:
      * 1 credential canary accessed with no prior navigation (possible accident)
      * 1 non-credential canary accessed deliberately
      * sudo -l alone
  - "low" if:
      * only basic recon commands, no sensitive files touched

FORMAT RULES:
- Every value MUST be a short plain string, NOT an array or object
- recommended_training_level must be a number 0-3
- Keep each value under 30 words
- In insider_reasoning, cite SPECIFIC commands from the session as evidence

- Current trust score: {trust_after:.2f} (was {trust_before:.2f} before this session)
- Trust band: {trust_band}  (thresholds: <0.2=revoke, <0.4=warn, <0.7=train, ≥0.7=normal)

RECOMMENDATION QUALITY RULES:

The three fields below (mitigation, deception_recommendation, detection_rule)
must be tailored to THIS session. A reviewer should be able to read your
recommendation and tell which session it came from. Generic advice that could
apply to any session is a failure.

GROUNDING REQUIREMENT (mandatory):
- Build each recommendation around the artifacts in "SESSION ARTIFACTS" below.
- If a file was accessed, name that exact file. If no canary file was accessed,
  base the recommendation on the actual commands run (recon pattern, privilege
  check, directory traversal, etc).
- Do NOT default to config.env. Only mention a file this session actually touched.

WHAT EACH FIELD MUST DO:
- mitigation: one concrete admin/access-control action, scoped to the resource
  THIS actor reached. Name the account, file/permission, or privilege to change.
- deception_recommendation: one deception change targeted at the exact artifact
  this actor interacted with. Vary the technique to fit the artifact — a
  credential file, a data dump, a config with URLs, a privilege check and a
  recon sweep each call for a different deception. Describe the mechanism.
- detection_rule: one SIEM rule keyed to the actual command sequence observed
  this session — command pattern, time window, and triggering combination.

NEUTRAL EXAMPLE (different domain — shows the level of specificity expected,
do NOT reuse its content):
  Session: attacker read a printer-spool file then queried an LDAP endpoint.
  - mitigation: "Remove print-operator group's read access to the spool
     directory; that role does not require LDAP query rights."
  - deception_recommendation: "Seed the spool directory with a decoy job whose
     metadata points to a monitored LDAP bind account, so any follow-on query
     reveals the actor."
  - detection_rule: "Flag sessions where a spool-file read is followed by an
     LDAP bind from the same host within 2 minutes."

SESSION ARTIFACTS (build your recommendations around these):
{session_artifacts}

Return ONLY this JSON:
{{
  "attack_path": "short description of what they did step by step",
  "final_intent": "their goal in one sentence",
  "risk_level": "low",
  "insider_type": "negligent",
  "insider_reasoning": "cite specific commands and explain why malicious or negligent",
  "recommended_training_level": 1,
  "training_action": "what training to assign or what HR action to take",
  "mitigation": "one security action for admin",
  "deception_recommendation": "one SPECIFIC honeypot change based on what this attacker did — e.g. if they read config.env, add a beacon URL inside it; if they used sudo, add a fake sudo log entry; if they ran mysqldump, add a fake database with traceable data. Do NOT just say 'add a fake file'.",
  "detection_rule": "one SPECIFIC SIEM alert based on the exact commands this attacker used — include the command pattern, time window, and what combination of events triggers it. Do NOT just say 'alert on sudo'."
}}

IMPORTANT: Return ONLY the JSON object above. No markdown, no explanation, no schema."""

    raw_output = call_llm(prompt)
    print(f"\n[DEBUG RAW LLM OUTPUT for session {session['session_id']}]")
    print(raw_output[:2000])
    print(f"[END DEBUG]\n")
    summary = parse_json_from_llm(raw_output)

    if summary is None:
        summary = {
            "attack_path": "unknown",
            "final_intent": "unknown",
            "risk_level": "unknown",
            "insider_type": "unknown",
            "insider_reasoning": profile["reasoning"],
            "recommended_training_level": profile["training_level"],
            "training_action": "unknown",
            "mitigation": "unknown",
            "deception_recommendation": "unknown",
            "detection_rule": "unknown",
        }

    
    insider_type = summary.get("insider_type", "unknown")
    training_action = summary.get("training_action", "unknown")
    update_profile_from_llm(session["session_id"], session["ip"], insider_type, training_action)

    
    try:
        llm_training_level = int(summary.get("recommended_training_level", 0))
    except (ValueError, TypeError):
        llm_training_level = 0

    
    current = profile["training_level"]

    if trust_band == "revoke":
       
        print(f"[TRUST] {session['ip']} below revocation threshold → flagging")
        flag_for_removal(session["ip"])
        training_action = f"Access revocation recommended (trust={trust_after:.2f}, band={trust_band})"
        llm_training_level = current

    elif trust_band in ("warn_supervisor", "assign_training"):
        
        if current >= 3:
            print(f"[TRAINING] All 3 courses exhausted at trust={trust_after:.2f} → revocation")
            flag_for_removal(session["ip"])
            training_action = f"All courses completed but trust still low ({trust_after:.2f}) — revocation"
        else:
            
            tag_level = match_courses_from_tags(profile.get("behavior_tags", []))
            llm_training_level = max(llm_training_level, tag_level)

            # Force progression: never repeat a course already done
            if llm_training_level <= current:
                llm_training_level = current + 1
            
            
            if insider_type == "malicious" and llm_training_level < 3:
                llm_training_level = 3
                print(f"[TRAINING] Malicious actor → forcing Course 3")
            
            update_training_from_llm(session["ip"], llm_training_level)
            
            apply_course_bonus(session["ip"], session["session_id"], llm_training_level)
            training_action = (
                f"{training_action} | Trust={trust_after:.2f} ({trust_band}) → "
                f"Course {llm_training_level} assigned"
            )

    else:  # normal_monitoring
        if insider_type == "malicious":
            if current >= 3:
                # Curriculum already exhausted → recommend revocation
                print(f"[TRAINING] Malicious actor, all courses done → revocation")
                flag_for_removal(session["ip"])
                training_action = (
                    f"Malicious actor; curriculum exhausted (level {current}) "
                    f"→ access revocation recommended (trust={trust_after:.2f})"
                )
                llm_training_level = current
            else:
                # Fast-track straight to the most advanced course
                llm_training_level = 3
                print(f"[TRAINING] Malicious actor at healthy trust → fast-track Course 3")
                update_training_from_llm(session["ip"], llm_training_level)
                apply_course_bonus(session["ip"], session["session_id"], llm_training_level)
                training_action = (
                    f"Malicious activity detected at healthy trust "
                    f"(trust={trust_after:.2f}) → Course {llm_training_level} "
                    f"assigned (fast-track, FR-17)"
                )
        else:
            print(f"[TRUST] {session['ip']} trust healthy ({trust_after:.2f}) → no action")
            training_action = f"Normal monitoring (trust={trust_after:.2f})"
            llm_training_level = current

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "session_summary",
        "session_id": session["session_id"],
        "client_ip": session["ip"],
        "attack_path": summary.get("attack_path", "unknown"),
        "final_intent": summary.get("final_intent", "unknown"),
        "risk_level": summary.get("risk_level", "unknown"),
        "insider_type": insider_type,
        "insider_reasoning": summary.get("insider_reasoning", profile["reasoning"]),
        "insider_composite_score": profile["composite_score"],
        "sophistication_score": profile["sophistication_score"],
        "efficiency_score": profile["efficiency_score"],
        "canary_intent_score": profile["canary_intent_score"],
        "lateral_movement": profile["lateral_movement"],
        "web_terminal_used": profile.get("web_terminal_used", False),
        "mitigation": summary.get("mitigation", "unknown"),
        "deception_recommendation": summary.get("deception_recommendation", "unknown"),
        "detection_rule": summary.get("detection_rule", "unknown"),
        "training_action": training_action,
        "training_level": profile["training_level"],
        "recommended_training_level": llm_training_level,
        "trust_before": trust_before,
        "trust_after": trust_after,
        "trust_band": trust_band,
        "commands": ", ".join(commands),
        "canaries_accessed": ", ".join([c["file"] for c in canaries_touched]),
    }
    save_llm_analysis(event)
    save_llm_event(event)
    print(f"[SESSION SUMMARY] risk={summary.get('risk_level')} insider={insider_type}")
    print(f"[LLM REASONING] {summary.get('insider_reasoning', '')[:100]}")
    print(f"[TRAINING] {training_action[:80]}")
    return event


# ── Canary file detection ────────────────────────────────────
def check_canary(cmd_clean, session, commands, client_ip, canaries_touched):
    read_cmds = ("cat ", "head ", "tail ")
    if not any(cmd_clean.startswith(c) for c in read_cmds):
        return

    filename = cmd_clean.split(" ", 1)[1].strip()
    basename = filename.split("/")[-1]

    if basename not in CANARY_FILES:
        return

    access_count = sum(1 for c in commands if basename in c)
    idx = len(commands) - 1
    commands_before = commands[max(0, idx - 3) : idx]

    existing = next((c for c in canaries_touched if c["file"] == basename), None)
    if existing:
        existing["access_count"] = access_count
    else:
        canaries_touched.append(
            {
                "file": basename,
                "access_count": access_count,
                "commands_before": ", ".join(commands_before),
            }
        )

    canary_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "canary_triggered",
        "canary_file": basename,
        "session_id": session["session_id"],
        "client_ip": client_ip,
        "access_count": access_count,
        "commands_before": ", ".join(commands_before),
        "total_commands_in_session": len(commands),
        "risk_level": "critical",
    }
    save_llm_event(canary_event)
    save_canary(canary_event)
    print(f"🍯 CANARY TRIGGERED: {basename} by {client_ip} (count: {access_count})")



def emulated_shell(channel, client_ip, session_id):
    channel.send(b"\r\ncorporate-jumpbox2$ ")
    command = b""
    command_count = 0
    commands = []
    canaries_touched = []
    session = {"session_id": session_id, "ip": client_ip}
    current_path = "/"
    start_time = datetime.now(timezone.utc)

    while True:
        char = channel.recv(1)
        if not char:
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "session_end",
                "client_ip": client_ip,
                "session_id": session_id,
                "commands_executed": command_count,
                "duration_seconds": duration,
            }
            if commands:
                threading.Thread(
                    target=run_session_summary,
                    args=(session, commands.copy(), canaries_touched.copy(), duration),
                    daemon=True,
                ).start()
            log_event(funnel_logger, event)
            channel.close()
            break

       
        if char == b"\x7f":
            if len(command) > 0:
                command = command[:-1]
                channel.send(b"\b \b")
            continue

       
        if char == b"\t":
            continue

        
        if char == b"\x03":
            command = b""
            channel.send(b"^C\r\ncorporate-jumpbox2$ ")
            continue

        # Echo non-Enter characters
        if char != b"\r":
            channel.send(char)
            command += char
            continue

        # ── Enter pressed ─────────────────────────────────
        cmd_clean = command.decode(errors="ignore").strip()
        if cmd_clean:
            command_count += 1
            commands.append(cmd_clean)
        command = b""

        channel.send(b"\r\n")

        # ── Command handling ──────────────────────────────
        response = b""

        if cmd_clean == "":
            pass  # empty command, just show prompt

        elif cmd_clean == "exit":
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "session_end",
                "client_ip": client_ip,
                "session_id": session_id,
                "commands_executed": command_count,
                "duration_seconds": duration,
            }
            if commands:
                threading.Thread(
                    target=run_session_summary,
                    args=(session, commands.copy(), canaries_touched.copy(), duration),
                    daemon=True,
                ).start()
            log_event(funnel_logger, event)
            channel.send(b"logout\r\n")
            channel.close()
            break

        elif cmd_clean == "pwd":
            response = (current_path + "\r\n").encode()

        elif cmd_clean == "whoami":
            response = (system_data["user"] + "\r\n").encode()

        elif cmd_clean == "id":
            user = system_data["user"]
            response = f"uid=1001({user}) gid=1001({user}) groups=1001({user}),27(sudo),33(www-data)\r\n".encode()

        elif cmd_clean == "hostname":
            response = b"corporate-jumpbox2\r\n"

        elif cmd_clean == "uname -a":
            response = b"Linux corporate-jumpbox2 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux\r\n"

        elif cmd_clean == "uname":
            response = b"Linux\r\n"

        elif cmd_clean == "uptime":
            response = b" 21:32:10 up 12 days,  3:41,  1 user,  load average: 0.02, 0.03, 0.01\r\n"

        elif cmd_clean == "w":
            user = system_data["user"]
            response = (
                f" 21:32:10 up 12 days,  3:41,  1 user,  load average: 0.02, 0.03, 0.01\r\n"
                f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n"
                f"{user:8s} pts/0    {client_ip:16s} 21:30    0.00s  0.01s  0.00s w\r\n"
            ).encode()

        elif cmd_clean == "ifconfig":
            response = (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n"
                "        inet6 fe80::250:56ff:feab:1234  prefixlen 64  scopeid 0x20<link>\r\n"
                "        ether 08:00:27:ab:12:34  txqueuelen 1000  (Ethernet)\r\n"
                "        RX packets 10234  bytes 9123123 (9.1 MB)\r\n"
                "        TX packets 5231  bytes 4123412 (4.1 MB)\r\n"
                "\r\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
                "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\r\n"
            ).encode()

        elif cmd_clean in ("ip a", "ip addr"):
            response = (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\r\n"
                "    inet 127.0.0.1/8 scope host lo\r\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\r\n"
                "    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0\r\n"
            ).encode()

        elif cmd_clean == "ps aux":
            response = (
                "USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND\r\n"
                "root         1  0.0  0.1 169436 13124 ?     Ss   Apr07   0:03 /sbin/init\r\n"
                "root       412  0.0  0.0  72304  5684 ?     Ss   Apr07   0:00 /usr/sbin/sshd -D\r\n"
                "mysql      523  0.1  1.2 1834208 98432 ?    Ssl  Apr07   2:14 /usr/sbin/mysqld\r\n"
                "www-data   601  0.0  0.3 214572 28104 ?     S    Apr07   0:12 /usr/sbin/apache2\r\n"
                "root       734  0.0  0.0  55276  3784 ?     Ss   Apr07   0:00 /usr/sbin/cron\r\n"
                f"{system_data['user']:8s}  1042  0.0  0.0  21476  5128 pts/0  Ss   21:30   0:00 -bash\r\n"
            ).encode()

        elif cmd_clean == "netstat -tlnp" or cmd_clean == "ss -tlnp":
            response = (
                "State    Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\r\n"
                "LISTEN   0       128     0.0.0.0:22          0.0.0.0:*          sshd\r\n"
                "LISTEN   0       80      127.0.0.1:3306      0.0.0.0:*          mysqld\r\n"
                "LISTEN   0       511     0.0.0.0:80          0.0.0.0:*          apache2\r\n"
                "LISTEN   0       128     0.0.0.0:8888        0.0.0.0:*          python3\r\n"
            ).encode()

        elif cmd_clean == "env" or cmd_clean == "printenv":
            response = (
                "SHELL=/bin/bash\r\n"
                f"USER={system_data['user']}\r\n"
                "HOME=/home/devops-admin\r\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
                "LANG=en_US.UTF-8\r\n"
                "DB_HOST=127.0.0.1\r\n"
                "DB_USER=app_readonly\r\n"
                "DB_PASS=r3adOnly!2025\r\n"
                "AWS_REGION=eu-west-1\r\n"
            ).encode()

        elif cmd_clean == "cat /etc/passwd":
            response = (
                "root:x:0:0:root:/root:/bin/bash\r\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
                "sshd:x:113:65534::/run/sshd:/usr/sbin/nologin\r\n"
                "mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false\r\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
                f"{system_data['user']}:x:1001:1001::/home/{system_data['user']}:/bin/bash\r\n"
            ).encode()

        elif cmd_clean == "cat /etc/shadow":
            response = b"cat: /etc/shadow: Permission denied\r\n"

        elif cmd_clean == "sudo cat /etc/shadow":
            response = (
                "root:$6$rounds=656000$fakehash...::0:99999:7:::\r\n"
                f"{system_data['user']}:$6$rounds=656000$anotherfake...::0:99999:7:::\r\n"
                "mysql:!:19450::::::\r\n"
            ).encode()

        elif cmd_clean == "sudo -l":
            response = (
                f"User {system_data['user']} may run the following commands on corporate-jumpbox2:\r\n"
                "    (ALL : ALL) ALL\r\n"
            ).encode()

        elif cmd_clean.startswith("sudo ") and cmd_clean != "sudo -l":
            response = b"Command executed with root privileges.\r\n"

        elif cmd_clean == "ls":
            files = system_data["filesystem"].get(current_path, [])
            response = ("  ".join(files) + "\r\n").encode() if files else b"\r\n"

        elif cmd_clean in ("ls -la", "ls -al", "ll"):
            files = system_data["filesystem"].get(current_path, [])
            response = f"total {len(files) * 4}\r\n".encode()
            response += b"drwxr-xr-x  2 root root 4096 Apr 10 09:12 .\r\n"
            response += b"drwxr-xr-x 18 root root 4096 Apr 07 14:30 ..\r\n"
            for fname in files:
                response += f"-rw-r--r--  1 root root  1024 Apr 10 09:12 {fname}\r\n".encode()

        elif cmd_clean.startswith("cat "):
            filename = cmd_clean.split(" ", 1)[1]
            # Support absolute paths
            if filename.startswith("/"):
                full_path = filename
            else:
                full_path = (
                    current_path.rstrip("/") + "/" + filename
                    if current_path != "/"
                    else "/" + filename
                )
            content = system_data["files"].get(full_path)
            if content:
                # Replace \n with \r\n for proper terminal display
                content_fixed = content.replace("\r\n", "\n").replace("\n", "\r\n")
                response = (content_fixed + "\r\n").encode()
            else:
                response = f"cat: {filename}: No such file or directory\r\n".encode()
            check_canary(cmd_clean, session, commands, client_ip, canaries_touched)

        elif cmd_clean.startswith("head ") or cmd_clean.startswith("tail "):
            filename = cmd_clean.split(" ")[-1]
            full_path = (
                current_path.rstrip("/") + "/" + filename
                if current_path != "/"
                else "/" + filename
            )
            content = system_data["files"].get(full_path)
            if content:
                lines = content.split("\n")
                if cmd_clean.startswith("head"):
                    response = ("\r\n".join(lines[:10]) + "\r\n").encode()
                else:
                    response = ("\r\n".join(lines[-10:]) + "\r\n").encode()
            else:
                response = f"{cmd_clean.split()[0]}: {filename}: No such file or directory\r\n".encode()
            check_canary(cmd_clean, session, commands, client_ip, canaries_touched)

        elif cmd_clean.startswith("mysql"):
            response = b"ERROR 1045 (28000): Access denied for user 'admin'@'localhost'\r\n"

        elif cmd_clean.startswith("mysqldump"):
            response = b"mysqldump: Got error: 1045: Access denied for user\r\n"

        elif cmd_clean.startswith("wget ") or cmd_clean.startswith("curl "):
            response = f"bash: {cmd_clean.split()[0]}: command not found\r\n".encode()

        elif cmd_clean.startswith("nmap"):
            response = b""
            for port, service in system_data.get("services", {}).items():
                response += f"{port}/tcp open {service}\r\n".encode()

        elif cmd_clean.startswith("cd "):
            target = cmd_clean.split(" ", 1)[1]
            if target == "..":
                if current_path != "/":
                    current_path = os.path.dirname(current_path.rstrip("/")) or "/"
                response = b""
            elif target in ("~", ""):
                current_path = f"/home/{system_data['user']}"
                response = b""
            elif target.startswith("/"):
                # Absolute path
                if target in system_data["filesystem"]:
                    current_path = target
                    response = b""
                else:
                    response = f"bash: cd: {target}: No such file or directory\r\n".encode()
            else:
                new_path = (
                    current_path.rstrip("/") + "/" + target
                    if current_path != "/"
                    else "/" + target
                )
                if new_path in system_data["filesystem"]:
                    current_path = new_path
                    response = b""
                else:
                    response = f"bash: cd: {target}: No such file or directory\r\n".encode()

        elif cmd_clean == "history":
            response = b""
            for i, c in enumerate(commands[:-1], 1):
                response += f"  {i}  {c}\r\n".encode()

        elif cmd_clean in ("clear", "reset"):
            response = b"\033[2J\033[H"

        elif cmd_clean == "date":
            now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
            response = (now + "\r\n").encode()

        elif cmd_clean.startswith("echo "):
            text = cmd_clean[5:]
            response = (text + "\r\n").encode()

        elif cmd_clean in ("help", "?"):
            response = (
                "GNU bash, version 5.1.16(1)-release\r\n"
                "Type 'help' for more information.\r\n"
            ).encode()

        else:
            response = f"bash: {cmd_clean.split()[0]}: command not found\r\n".encode()

        # Log command
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "command",
            "client_ip": client_ip,
            "session_id": session_id,
            "command": cmd_clean,
            "response": response.decode(errors="ignore"),
            "attack_stage": "unknown",
            "risk_level": "unknown",
        }
        log_event(creds_logger, event)
        save_command(event)

        channel.send(response)
        channel.send(b"corporate-jumpbox2$ ")

        # Periodic LLM analysis every N commands
        N = 8
        if commands and len(commands) % N == 0:
            threading.Thread(
                target=run_llm_analysis,
                args=(session, commands[-N:]),
                daemon=True,
            ).start()


# ── SSH Server ───────────────────────────────────────────────
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        success = (username, password) in WEAK_CREDENTIALS

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "auth_attempt",
            "client_ip": self.client_ip,
            "username": username,
            "password": password,
            "success": success,
        }
        log_event(funnel_logger, event)

        return paramiko.AUTH_SUCCESSFUL if success else paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


# ── Client handler ───────────────────────────────────────────
def client_handle(client, addr):
    client_ip = addr[0]
    print(f"[+] Connection from {client_ip}")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip)
        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print(f"[-] No channel opened from {client_ip}")
            return

        session_id = str(uuid.uuid4())
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "session_start",
            "client_ip": client_ip,
            "session_id": session_id,
        }
        log_event(funnel_logger, event)

        banner = "Welcome to Ubuntu 22.04.4 LTS (Jammy Jellyfish)\r\n\r\n"
        banner += " * Documentation:  https://help.ubuntu.com\r\n"
        banner += " * Management:     https://landscape.canonical.com\r\n"
        banner += " * Support:        https://ubuntu.com/advantage\r\n\r\n"
        banner += f"Last login: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')} from 10.0.2.1\r\n"
        channel.send(banner.encode())

        emulated_shell(channel, client_ip, session_id)

    except Exception as error:
        print(f"[!] Error handling {client_ip}: {error}")
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()


# ── Main server loop ─────────────────────────────────────────
def honeypot(address, port):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)

    print(f"[*] SSH Honeypot listening on {address}:{port}")
    print(f"[*] LLM: {LLM_MODEL} via {LLM_URL}")

    while True:
        try:
            client, addr = socks.accept()
            t = threading.Thread(
                target=client_handle,
                args=(client, addr),
                daemon=True,
            )
            t.start()
        except Exception as error:
            print(f"[!] Accept error: {error}")


if __name__ == "__main__":
    init_db()
    init_profiler_db()

    parser = argparse.ArgumentParser(description="SSH Honeypot with LLM analysis")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()

    honeypot(args.host, args.port)