#!/usr/bin/env bash
# ==============================================================
#  run_all.sh — Launch the full honeypot stack
#
#  Components:
#    1. db.py + insider_profiler   — DB init (tables created)
#    2. beacon_server.py           — web decoy portal (background)
#    3. correlator.py              — background, polls every 10s
#    4. ssh_honeypot.py            — main honeypot (foreground)
#
#  Usage:
#    chmod +x run_all.sh
#    ./run_all.sh
#    ./run_all.sh --port 2222      # custom SSH port
# ==============================================================

set -e

PYTHON="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# ── Colors ────────────────────────────────────────────────────
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

HONEYPOT_ARGS="$@"

PIDS=()

cleanup() {
    echo ""
    echo -e "${YELLOW}[run_all] Shutting down...${NC}"
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            echo "  ↳ stopped PID $pid"
        fi
    done
    echo -e "${GREEN}[run_all] All components stopped.${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── 1. Pre-flight checks ─────────────────────────────────────
echo "========================================"
echo "  🍯 Honeypot Stack Launcher"
echo "========================================"

# Python
if ! command -v "$PYTHON" &>/dev/null; then
    echo -e "${RED}[✗] Python not found ($PYTHON)${NC}"
    exit 1
fi
echo -e "${GREEN}[✔] Python:  $($PYTHON --version 2>&1)${NC}"

# Required files
MISSING=0
for f in ssh_honeypot.py insider_profiler.py db.py correlator.py beacon_server.py server.key system.json; do
    if [[ ! -f "$f" ]]; then
        echo -e "${RED}[✗] Missing: $f${NC}"
        MISSING=1
    fi
done
if [[ $MISSING -eq 1 ]]; then
    echo -e "${RED}    Make sure run_all.sh is in the same directory as your project files.${NC}"
    exit 1
fi
echo -e "${GREEN}[✔] All source files present${NC}"

# Python dependencies
DEPS_OK=1
for pkg in paramiko requests dotenv flask openai httpx urllib3; do
    if ! $PYTHON -c "import $pkg" 2>/dev/null; then
        echo -e "${RED}[✗] Missing Python package: $pkg${NC}"
        DEPS_OK=0
    fi
done
if [[ $DEPS_OK -eq 0 ]]; then
    echo "    pip install paramiko requests python-dotenv flask openai httpx urllib3"
    exit 1
fi
echo -e "${GREEN}[✔] Python dependencies OK${NC}"

# University LLM endpoint (LiteLLM proxy → Ollama)
if [[ -f .env ]]; then
    set -a
    source .env
    set +a
fi
LLM_URL="${UNI_LLM_URL:-https://192.168.43.171:4000/v1}"
if curl -sk --max-time 5 -H "Authorization: Bearer $UNI_LLM_API_KEY" "$LLM_URL/models" >/dev/null 2>&1; then
    echo -e "${GREEN}[✔] LLM endpoint reachable at $LLM_URL${NC}"
else
    echo -e "${YELLOW}[!] LLM endpoint not reachable at $LLM_URL${NC}"
    echo "    LLM analysis will use fallback responses (attack_stage/risk_level = \"unknown\")."
fi
echo ""

# ── 2. Initialize database ───────────────────────────────────
echo -e "${GREEN}[1/4] Initializing database...${NC}"
$PYTHON -c "
from db import init_db
from insider_profiler import init_profiler_db
init_db()
init_profiler_db()
"
echo -e "${GREEN}  ↳ honeypot.db ready${NC}"

# ── 3. Start beacon server (background) ──────────────────────
BEACON_PORT="${BEACON_PORT:-8888}"
echo -e "${GREEN}[2/4] Starting beacon server on port $BEACON_PORT...${NC}"
$PYTHON beacon_server.py >> "$LOG_DIR/beacon_server.log" 2>&1 &
PIDS+=($!)
echo -e "${GREEN}  ↳ beacon_server PID $!  (log → $LOG_DIR/beacon_server.log)${NC}"

# ── 4. Start correlator (background) ─────────────────────────
echo -e "${GREEN}[3/4] Starting correlator...${NC}"
$PYTHON correlator.py >> "$LOG_DIR/correlator.log" 2>&1 &
PIDS+=($!)
echo -e "${GREEN}  ↳ correlator PID $!  (log → $LOG_DIR/correlator.log)${NC}"

# ── 5. Start SSH honeypot (foreground) ────────────────────────
echo -e "${GREEN}[4/4] Starting SSH honeypot...${NC}"
echo "========================================"
echo "  Press Ctrl+C to stop everything"
echo "========================================"
echo ""

$PYTHON ssh_honeypot.py $HONEYPOT_ARGS