# SSH Honeypot – Base Implementation

## Description

This project implements a medium-interaction SSH honeypot in Python.  
It simulates an SSH service, captures authentication attempts, logs executed commands, and provides a basic emulated shell environment.

The system is designed as the foundational infrastructure for a Bachelor's Thesis focused on integrating Large Language Models (LLMs) to support behavioral analysis and deception strategy recommendations.

---

## Current Features

- SSH server using Paramiko
- TCP socket listener
- Custom authentication handling
- Credential logging (username & password attempts)
- Command logging per interaction
- Basic emulated Linux shell (`pwd`, `whoami`, `ls`, etc.)
- Multi-client support using threading
- Rotating log files

---

## Architecture Overview

Application Layer → SSH (Paramiko)  
Transport Layer → TCP  
Network Layer → IP  

Main components:

- `socket` → Handles TCP connections
- `paramiko.Transport` → Manages SSH protocol and encryption
- `Server` class → Defines authentication and channel behavior
- `emulated_shell()` → Simulates interactive terminal
- Logging module → Stores credentials and command activity

---

## Requirements

- Python 3.x
- Paramiko

---

## Installation

Create and activate a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate
pip install paramiko
```

---

## Running the Honeypot

Start the server:

```bash
python3 ssh_honeypot.py
```

You should see:

```
SSH server is listening on port 2223.
```

Open another terminal and connect:

```bash
ssh -p 2223 username@127.0.0.1
```

Default credentials (if configured in script):
- Username: username
- Password: password

---

## Logs

Two log files are generated:

- `audits.log` → Authentication attempts and flow events
- `cmd_audits.log` → Executed commands

Logs currently stored in text format.  