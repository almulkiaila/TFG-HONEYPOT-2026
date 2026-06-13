#!/bin/bash
SSH_HOST="localhost"
SSH_PORT="2222"
WEB_HOST="http://localhost:8888"
LOG_FILE="lateral_movement_results.log"
EVENTS_FILE="$HOME/Honeypot/llm_events.json"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

> "$LOG_FILE"
log "LATERAL MOVEMENT TEST"
echo "=============================================" | tee -a "$LOG_FILE"

# STEP 1: web first
log "STEP 1: Accessing internal portal"
curl -s "$WEB_HOST/" > /dev/null
curl -s "$WEB_HOST/login" > /dev/null
curl -s "$WEB_HOST/dashboard" > /dev/null
curl -s "$WEB_HOST/admin" > /dev/null
curl -s "$WEB_HOST/admin/terminal" > /dev/null
log "  -> portal routes accessed"
sleep 2

# STEP 2: SSH via expect
log "STEP 2: SSH session via expect"
expect -c '
spawn ssh -o StrictHostKeyChecking=no admin@localhost -p 2222
expect "password:"
send "admin\r"
expect "$ "
send "whoami\r"
expect "$ "
send "cd opt\r"
expect "$ "
send "cd app\r"
expect "$ "
send "ls\r"
expect "$ "
send "cat config.env\r"
expect "$ "
send "cd /home/devops-admin\r"
expect "$ "
send "ls\r"
expect "$ "
send "cat vpn_config.ovpn\r"
expect "$ "
send "exit\r"
expect eof
' | tee -a "$LOG_FILE"

log "SSH session complete"

# STEP 3: poll for session_summary instead of fixed sleep
log "STEP 3: Waiting for LLM session summary (up to 180s)..."
FOUND=""
for i in $(seq 1 36); do
    sleep 5
    LAST=$(grep '"event_type": "session_summary"' "$EVENTS_FILE" | tail -1)
    if [ -n "$LAST" ]; then
        FOUND="$LAST"
        log "  -> session_summary found after ~$((i*5))s"
        break
    fi
    log "  ... still waiting ($((i*5))s)"
done

echo "=============================================" | tee -a "$LOG_FILE"
log "RESULTS"

if [ -n "$FOUND" ]; then
    echo "$FOUND" | python3 -m json.tool | tee -a "$LOG_FILE"
else
    log "  !! session_summary not found within timeout"
fi

echo "" | tee -a "$LOG_FILE"
log "--- Correlation events (latest) ---"
tail -1 ~/Honeypot/correlation_events.json | tee -a "$LOG_FILE"

echo "=============================================" | tee -a "$LOG_FILE"
log "TEST COMPLETE — results saved to $LOG_FILE"