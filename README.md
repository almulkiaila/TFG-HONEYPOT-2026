# Honeypot Insider Threat Detection System

A research prototype combining an SSH honeypot, a decoy corporate intranet
portal, deterministic behavioral scoring, a persistent trust-score model, and
LLM-based session analysis to detect and respond to **insider threats** —
actors who already hold legitimate access but misuse it.

Developed as part of a Bachelor's Thesis (TFG) in Computer Engineering:
*"Sistema de recomendación para honeypots con soporte en LLM"
(Recommendation system for honeypots with LLM support)*.

---

## ⚠️ Disclaimer

This is a **research/educational honeypot**. It must be deployed in an
**isolated, controlled environment** (e.g. an isolated LAN/VLAN). Do **not**
expose it to the public internet. By design:

- The SSH service accepts a fixed set of weak credentials and grants access to
  an emulated shell.
- The web portal accepts **any** submitted credentials.
- A hidden admin panel and web terminal are intentionally reachable but
  unlinked.

All of this is intentional deception — never run it outside an isolated test
network.

---

## Architecture Overview

The system is organised into five logical layers, communicating through a
shared persistence layer (JSON logs + SQLite) rather than direct calls, so
that analysis never blocks the interactive shell:

- **Deception layer**
  - `ssh_honeypot.py` — SSH-2 honeypot (Paramiko) emulating a corporate
    jumpbox (`corporate-jumpbox2`), with a synthetic filesystem and 7 canary
    (honeytoken) files.
  - `beacon_server.py` — Flask-based decoy intranet portal ("NEXUScorp") with
    ~20 endpoints, including a hidden `/admin` panel and `/admin/terminal`
    web terminal, plus SQL-injection detection on `/login`.

- **Persistence layer**
  - `db.py` — SQLite schema (`commands`, `canary_events`, `beacon_events`,
    `llm_analysis`, `correlation_events`, plus the profiler tables).
  - Line-delimited JSON event streams: `llm_events.json`,
    `beacon_events.json`, `correlation_events.json`, `insider_profiles.json`.

- **Analysis layer**
  - `insider_profiler.py` — computes 7 behavioral dimensions (command
    sophistication, navigation efficiency, canary intent, temporal behavior,
    lateral movement, recidivism, web-terminal access), aggregates them into
    a composite score, maintains a per-IP **trust score** (decay + recovery),
    and drives a 3-course progressive training/revocation policy.
  - LLM integration inside `ssh_honeypot.py`: incremental analysis every 8
    commands, and a full session-level summary at session end.

- **Correlation layer**
  - `correlator.py` — standalone polling process (every 10s) that links SSH
    canary accesses with web beacon events from the same IP within a
    30-minute window, emitting `attack_correlation` alerts.

- **Monitoring layer** (optional)
  - Wazuh SIEM integration via `local_rules.xml` and
    `wazuh_localfile_config.xml`.

---

## Repository Structure

    .
    ├── ssh_honeypot.py              # SSH honeypot + LLM analysis pipeline
    ├── beacon_server.py             # NEXUScorp decoy web portal (Flask)
    ├── correlator.py                # Cross-vector correlation engine
    ├── insider_profiler.py          # Behavioral scoring + trust score model
    ├── db.py                        # SQLite persistence layer
    │
    ├── run_all.sh                   # Launches the full stack
    ├── server.key                   # SSH host key (honeypot identity)
    ├── system.json                  # Synthetic filesystem definition
    ├── .env.example                 # Environment variable template
    │
    ├── evaluate.py                  # LLM pipeline evaluation (30 labeled sessions)
    ├── evaluate_baseline.py         # Deterministic baseline classifier evaluation
    ├── test_sessions.json           # Labeled test dataset (30 sessions)
    │
    ├── lateral_movement_test.sh     # End-to-end lateral movement test
    ├── rules_validation.sh          # Wazuh alerting validation script
    │
    ├── local_rules.xml              # Custom Wazuh detection rules
    ├── wazuh_localfile_config.xml   # <localfile> blocks for ossec.conf
    │
    ├── requirements.txt
    └── README.md

---

## Requirements

- Linux (developed and tested on Ubuntu 22.04)
- Python 3.10+
- An OpenAI-compatible LLM endpoint (e.g. Ollama served through LiteLLM,
  local or remote). The system was evaluated against an open-weight ~20B
  parameter model (`gpt-oss:20b`).
- (Optional) Wazuh single-node installation for SIEM integration and the
  real-time dashboard.

---

## Installation

### 1. Clone and set up a virtual environment

```bash
git clone <this-repo-url>
cd Honeypot

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt`:

```
paramiko
requests
python-dotenv
flask
openai
httpx
urllib3
```

### 2. SSH host key

A `server.key` is included for convenience. To generate a fresh one instead:

```bash
ssh-keygen -t rsa -b 2048 -f server.key -N ""
```

### 3. Configure environment variables

Copy the template and fill in your own values:

```bash
cp .env.example .env
```

Edit `.env`:

```env
UNI_LLM_URL=https://<your-llm-endpoint>/v1
UNI_LLM_API_KEY=<your-api-key>
UNI_LLM_MODEL=gpt-oss:20b
BEACON_PORT=8888
```

> `.env` is git-ignored — **never commit real credentials**.

If the LLM endpoint uses a self-signed certificate, the included HTTP client
(`httpx`, TLS verification disabled) handles it automatically — no extra setup
needed.

#### Running a local LLM (no API key required)

```bash
ollama pull gpt-oss:20b
ollama serve
```

Point `UNI_LLM_URL` to your local Ollama/LiteLLM endpoint (e.g.
`http://localhost:4000/v1`) and leave `UNI_LLM_API_KEY` as an empty/placeholder
string — `call_llm()` falls back to a safe default response
(`{"attack_stage": "unknown", "risk_level": "unknown"}`) if the endpoint is
unreachable, so the honeypot keeps capturing raw events regardless.

---

## Running the System

```bash
chmod +x run_all.sh
./run_all.sh
```

This will:

1. Verify Python, all source files, and required packages are present
2. Check whether the LLM endpoint (Ollama by default at `:11434`) is reachable
3. Initialise the SQLite database (`honeypot.db`) and all tables
4. Start the beacon server in the background on port 8888 (configurable via
   `BEACON_PORT`) — logs to `logs/beacon_server.log`
5. Start the correlator in the background, polling every 10s — logs to
   `logs/correlator.log`
6. Start the SSH honeypot in the foreground on port 2222

Custom SSH port:

```bash
./run_all.sh --port 2222
```

Stop everything with `Ctrl+C` (the script terminates all background processes
cleanly).

---

## Using the Honeypot

### Connect via SSH

| Username | Password   |
|----------|-----------|
| admin    | admin     |
| root     | root      |
| devops   | devops123 |
| backup   | backup    |
| test     | test123   |

```bash
ssh devops@localhost -p 2222
```

The emulated shell presents itself as `corporate-jumpbox2` (Ubuntu 22.04) and
supports a representative subset of Linux commands (`ls`, `cd`, `pwd`,
`whoami`, `id`, `uname -a`, `ifconfig`, `ip a`, `netstat`/`ss`, `ps aux`,
`env`/`printenv`, `cat`/`head`/`tail`, `sudo -l`, `sudo cat /etc/shadow`,
`history`, etc.).

### Canary files

Seven decoy files trigger high-priority `canary_triggered` events when read:

- `config.env`
- `passwords.txt`
- `aws_credentials.txt`
- `db_backup_2025.sql`
- `users_dump.sql`
- `salaries_2025.csv`
- `vpn_config.ovpn`

### Access the web portal

```
http://localhost:8888
```

NEXUScorp accepts any login credentials (except detected SQL injection
payloads on `/login`, which trigger a `critical` event). The portal includes
`/dashboard`, `/contacts`, `/tickets`, `/docs`, and a hidden, unlinked
`/admin` panel with `/admin/terminal` — both treated as high/critical-severity
signals if reached.

---

## How the Analysis Pipeline Works

1. **Incremental analysis** (`run_llm_analysis`): every 8 commands, a
   background thread sends the recent command window to the LLM, which
   returns an `attack_stage` and `risk_level`, logged as an `llm_analysis`
   event.

2. **Session summary** (`run_session_summary`): on session end, the
   behavioral profiler (`profile_insider`) computes the 7-dimension composite
   score, the trust model applies incident decay (`apply_incident_decay`),
   and the LLM is queried with the full transcript, canary/beacon/correlation
   context, and the behavioral profile to produce: `attack_path`,
   `final_intent`, `risk_level`, `insider_type`, `insider_reasoning`,
   `recommended_training_level`, `training_action`, `mitigation`,
   `deception_recommendation`, and `detection_rule`.

3. **Progressive response policy**: the trust band (`normal_monitoring`,
   `assign_training`, `warn_supervisor`, `revoke`) — not the LLM's raw
   suggestion — determines the final action: no action, course assignment
   (1→3), supervisor warning, or an access-revocation recommendation surfaced
   to a human operator.

---

## Generated Files (runtime, git-ignored)

| File | Description |
|------|-------------|
| `honeypot.db` (+ `-shm`/`-wal`) | SQLite database — all structured data |
| `llm_events.json` | Main event stream (commands, canary triggers, LLM analysis, session summaries, trust changes) |
| `beacon_events.json` | Web honeypot events (incl. SQL injection, web terminal) |
| `correlation_events.json` | Cross-vector correlation alerts |
| `insider_profiles.json` | Per-session behavioral profiles (7 scores + composite) |
| `audits.log` | SSH session/auth events |
| `cmd_audits.log` | Per-command log |
| `logs/beacon_server.log` | Beacon server output |
| `logs/correlator.log` | Correlator output |

### Querying the database

Commands for a specific session:

```bash
sqlite3 honeypot.db "
SELECT command, response
FROM commands
WHERE session_id = '<session_id>'
ORDER BY id;"
```

Trust score history for an IP:

```bash
sqlite3 honeypot.db "
SELECT timestamp, trust_before, trust_after, change_reason, trust_band
FROM trust_score_history
WHERE ip = '<ip_address>'
ORDER BY id;"
```

---

## Evaluation

### LLM-integrated pipeline (30 labeled sessions)

```bash
python evaluate.py
```

Uses an isolated database (`honeypot_eval.db`), wiped and reinitialised at the
start of each run.

Optional flags:

```bash
python evaluate.py --runs 3        # repeat each session 3x (consistency analysis)
python evaluate.py --sessions 5    # quick test on the first 5 sessions
python evaluate.py --skip-stages   # skip incremental attack-stage classification (faster)
python evaluate.py --keep-db       # don't wipe the eval DB between runs
```

Outputs:

- `eval_results.csv` — per-session predictions, reasoning, latency, retries
- `eval_metrics.json` — accuracy, precision, recall, F1, FPR, risk-level
  accuracy (exact and within-one-step), JSON parse success rate, average
  latency, training-level accuracy
- `eval_confusion_matrix.csv` — malicious vs. negligent confusion matrix

### Deterministic baseline (no LLM)

```bash
python evaluate_baseline.py
```

Evaluates the behavioral scoring engine alone (composite score ≥ 0.5 ⇒
malicious), using the same `insider_profiler.py` functions as the live
system, against the same 30 labeled sessions — used as a comparison point
against the full LLM pipeline.

### Lateral movement functional test

```bash
chmod +x lateral_movement_test.sh
./lateral_movement_test.sh
```

Simulates: an SSH session reading `config.env` (a credential-class canary
containing an embedded portal URL), followed by web portal navigation
(`/`, `/login`, `/dashboard`, `/admin`, `/admin/terminal`) from the same IP.
Validates that the correlator detects the pattern within the 30-minute window
and emits a `critical` `attack_correlation` event.

---

## Wazuh SIEM Integration (Optional)

The honeypot operates fully standalone — Wazuh adds real-time alerting and a
dashboard on top of the existing JSON event streams.

### 1. Install Wazuh

Follow the official single-node deployment guide:
https://documentation.wazuh.com

### 2. Register log sources

Add the contents of `wazuh_localfile_config.xml` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf` on the Wazuh manager, adjusting the file paths to
your honeypot's actual location:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/Honeypot/llm_events.json</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/path/to/Honeypot/beacon_events.json</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/path/to/Honeypot/correlation_events.json</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/path/to/Honeypot/insider_profiles.json</location>
</localfile>
```

### 3. Install custom detection rules

```bash
sudo cp local_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
```

`local_rules.xml` includes rules for, among others:

| Rule ID | Trigger | Level |
|---|---|---|
| 100502 | Privilege escalation (`sudo`, `shadow`, `passwd`) | 12 |
| 100503 | Data exfiltration pattern (`.sql`, `.csv`, `config.env`, `dump`...) | 12 |
| 100600 | Cross-vector correlation (`attack_correlation`) | 15 |
| 100700 | Canary file accessed | 13 |
| 100701 | Repeated canary access | 14 |
| 100402 | SQL injection on `/login` | 15 |
| 100403 | Hidden admin panel accessed | 13 |
| 100404 / 100405 | Web terminal accessed / command executed | 15 |
| 100110 | Brute force (5+ failed logins / 60s) | 10 |
| 100901–100903 | Trust band changes (training / supervisor / revocation) | 7 / 10 / 12 |

### 4. Validate alerting

```bash
chmod +x rules_validation.sh
./rules_validation.sh
```

### 5. Dashboard

Access the Wazuh dashboard at `https://localhost`. A custom dashboard
("Honeypot Insider Threat Intelligence") can be built with three regions:

- **Top** — global metrics (sessions, canary accesses, malicious
  classifications, commands), attack-stage distribution, top attacker IPs,
  risk-level distribution.
- **Middle** — session summaries (LLM output: risk level, insider type,
  composite score, attack path, intent, training action, mitigation), trust
  score per IP, negligent vs. malicious split.
- **Bottom** — command log with matched Wazuh rules, and incremental LLM
  analysis as it happens.

---

## Key Design Notes

- **No real privilege exposure**: the emulated shell never executes
  attacker-supplied commands on the host OS — all responses are synthetic.
- **Resilient by design**: an unreachable or failing LLM never blocks the
  honeypot; raw event capture continues, and the shell stays responsive
  (incremental/summary analysis runs in background threads).
- **Credentials isolation**: all secrets (LLM endpoint, API key, model) are
  read from environment variables via `python-dotenv`, never hardcoded.
- **Dual persistence**: every event is written to both line-delimited JSON
  (for SIEM ingestion) and SQLite (for structured offline queries).
- **Human-in-the-loop**: access revocation is always a *recommendation*
  surfaced through the SIEM/database, never enforced automatically — there is
  no real resource to revoke in a honeypot.

---

## Known Limitations

- **LLM non-determinism**: even at temperature 0.1, classifications are not
  guaranteed to be fully reproducible across runs.
- **Hallucination risk**: free-text fields (detection rule, deception
  recommendation, reasoning) may reference details not strictly present in the
  session — the structured behavioral scores serve as a cross-check.
- **Prompt injection surface**: attacker-typed commands are embedded directly
  into LLM prompts; the low temperature and structured output format mitigate
  but do not eliminate this risk.

---

## License

Developed for academic purposes as part of a Bachelor's Thesis (TFG),
Universidad de Málaga, 2026.