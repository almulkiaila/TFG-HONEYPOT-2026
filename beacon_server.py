"""
beacon_server.py — Realistic Corporate Intranet Honeypot (Web Decoy)
Replaces the old bare-bones Flask beacon server with a convincing
internal employee portal that logs every interaction.

"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import ipaddress
import os
import secrets
from db import save_beacon_db

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BEACON_LOG = os.path.join(BASE_DIR, "beacon_events.json")


#beacon token mapping
BEACON_ROUTES = {
    "/":                   ("root-redirect",      "low"),
    "/login":              ("login-portal",       "low"),
    "/dashboard":          ("dashboard",          "low"),
    "/contacts":           ("contacts-directory", "low"),
    "/contacts/export":    ("contacts-export",    "medium"),
    "/tickets":            ("it-tickets",         "low"),
    "/tickets/new":        ("it-tickets",         "low"),
    "/docs":               ("internal-docs",      "low"),
    "/docs/onboarding":    ("internal-docs",      "low"),
    "/docs/vpn-setup":     ("internal-docs",      "medium"),
    "/admin":              ("admin-panel",        "high"),
    "/admin/users":        ("admin-users",        "high"),
    "/admin/settings":     ("admin-settings",     "high"),
    "/admin/terminal":     ("web-terminal",       "critical"),
    "/api/v1/health":      ("api-health",         "low"),
    "/api/v1/status":      ("api-status",         "low"),
    "/api/v1/users":       ("api-users",          "medium"),
    "/api/v1/employees":   ("api-employees",      "medium"),
    "/api/v1/auth/verify": ("api-auth-verify",    "high"),
    "/api/v1/vpn/config":  ("api-vpn-config",     "high"),
    "/api/v1/aws/status":  ("api-aws-status",     "high"),
    "/metrics/db":         ("db-metrics",         "medium"),
    "/backup":             ("backup-file",        "high"),
}

FAKE_EMPLOYEES = [
    {"id": 1, "name": "Carlos Mendoza",     "dept": "Engineering",  "email": "c.mendoza@corp-internal.net",   "ext": "2041", "role": "Senior Backend Developer"},
    {"id": 2, "name": "Laura Fernández",    "dept": "Engineering",  "email": "l.fernandez@corp-internal.net", "ext": "2042", "role": "DevOps Lead"},
    {"id": 3, "name": "Miguel Ángel Torres","dept": "IT Security",  "email": "ma.torres@corp-internal.net",   "ext": "2100", "role": "Security Analyst"},
    {"id": 4, "name": "Ana Belén Ruiz",     "dept": "HR",           "email": "ab.ruiz@corp-internal.net",     "ext": "3010", "role": "HR Manager"},
    {"id": 5, "name": "David García López", "dept": "Finance",      "email": "d.garcia@corp-internal.net",    "ext": "4001", "role": "Financial Controller"},
    {"id": 6, "name": "Patricia Navarro",   "dept": "Engineering",  "email": "p.navarro@corp-internal.net",   "ext": "2043", "role": "Frontend Developer"},
    {"id": 7, "name": "Roberto Jiménez",    "dept": "IT Security",  "email": "r.jimenez@corp-internal.net",   "ext": "2101", "role": "SOC Analyst"},
    {"id": 8, "name": "Elena Martín Soto",  "dept": "Legal",        "email": "e.martin@corp-internal.net",    "ext": "5001", "role": "Compliance Officer"},
]

FAKE_TICKETS = [
    {"id": "INC-2041", "title": "VPN disconnects after 30min idle",  "status": "Open",        "priority": "Medium",   "assignee": "Laura Fernández",    "created": "2025-04-14"},
    {"id": "INC-2039", "title": "Onboarding laptop not provisioned", "status": "In Progress", "priority": "High",     "assignee": "Miguel Á. Torres",   "created": "2025-04-12"},
    {"id": "INC-2035", "title": "DB replication lag on prod-db-02",  "status": "Resolved",    "priority": "Critical", "assignee": "Carlos Mendoza",     "created": "2025-04-10"},
    {"id": "INC-2033", "title": "Expired SSL cert on staging",       "status": "Resolved",    "priority": "High",     "assignee": "Laura Fernández",    "created": "2025-04-08"},
]





def save_beacon(event):
    with open(BEACON_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")
    save_beacon_db(event)

def handle_beacon(route, extra=None):
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    token, risk = BEACON_ROUTES.get(route, ("portal-page", "low"))

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "beacon_triggered",
        "source": "honeypot_beacon", 
        "token": token,
        "route_accessed": route,
        "attacker_ip": attacker_ip,
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "method": request.method,
        "risk_level": risk,
        "alert": f"{route} accessed (risk={risk})",
    }
    if extra:
        event.update(extra)

    save_beacon(event)
    print(f"BEACON: {route} from {attacker_ip} (risk={risk})")


LAYOUT_CSS = """
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; color: #1a1a2e; }

  /* Top navbar */
  .topbar {
    background: #1a1a2e; color: #fff; padding: 0 24px;
    display: flex; align-items: center; height: 52px;
    box-shadow: 0 2px 8px rgba(0,0,0,.15);
  }
  .topbar .logo { font-weight: 700; font-size: 15px; letter-spacing: .5px; }
  .topbar .logo span { color: #4fc3f7; }
  .topbar nav { margin-left: 36px; display: flex; gap: 4px; }
  .topbar nav a {
    color: #b0bec5; text-decoration: none; font-size: 13px;
    padding: 6px 14px; border-radius: 6px; transition: .15s;
  }
  .topbar nav a:hover, .topbar nav a.active { background: rgba(255,255,255,.1); color: #fff; }
  .topbar .user-info { margin-left: auto; font-size: 12px; color: #78909c; }
  .topbar .user-info strong { color: #e0e0e0; }

  /* Page container */
  .page { max-width: 1100px; margin: 28px auto; padding: 0 20px; }
  .page h1 { font-size: 22px; font-weight: 600; margin-bottom: 6px; }
  .page .subtitle { font-size: 13px; color: #607d8b; margin-bottom: 24px; }

  /* Cards */
  .card {
    background: #fff; border-radius: 10px; padding: 22px 26px;
    box-shadow: 0 1px 4px rgba(0,0,0,.06); margin-bottom: 20px;
  }
  .card h2 { font-size: 15px; font-weight: 600; margin-bottom: 14px; color: #263238; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; background: #f5f7fa; color: #607d8b;
       font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; border-bottom: 2px solid #e0e0e0; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; }
  tr:hover td { background: #fafbfc; }

  /* Badges */
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-open     { background: #fff3e0; color: #e65100; }
  .badge-progress { background: #e3f2fd; color: #1565c0; }
  .badge-resolved { background: #e8f5e9; color: #2e7d32; }
  .badge-critical { background: #ffebee; color: #c62828; }
  .badge-high     { background: #fff3e0; color: #e65100; }
  .badge-medium   { background: #e3f2fd; color: #1565c0; }

  /* Stats row */
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: #fff; border-radius: 10px; padding: 18px 22px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
  .stat-card .label { font-size: 11px; color: #90a4ae; text-transform: uppercase; letter-spacing: .5px; font-weight: 600; }
  .stat-card .value { font-size: 28px; font-weight: 700; margin-top: 4px; color: #1a1a2e; }
  .stat-card .sub   { font-size: 11px; color: #78909c; margin-top: 2px; }

  /* Forms */
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 12px; font-weight: 600; color: #607d8b; margin-bottom: 5px; }
  .form-group input, .form-group textarea, .form-group select {
    width: 100%; padding: 9px 12px; border: 1px solid #ddd; border-radius: 6px;
    font-size: 13px; font-family: inherit; transition: .15s;
  }
  .form-group input:focus, .form-group textarea:focus { border-color: #4fc3f7; outline: none; box-shadow: 0 0 0 3px rgba(79,195,247,.15); }
  .btn {
    display: inline-block; padding: 9px 22px; border-radius: 6px; font-size: 13px;
    font-weight: 600; cursor: pointer; border: none; transition: .15s;
  }
  .btn-primary { background: #1a1a2e; color: #fff; }
  .btn-primary:hover { background: #2a2a4e; }
  .btn-secondary { background: #e0e0e0; color: #333; }

  /* Search bar */
  .searchbar { position: relative; margin-bottom: 20px; }
  .searchbar input { padding-left: 36px; }
  .searchbar::before { content: '🔍'; position: absolute; left: 12px; top: 9px; font-size: 14px; }

  /* Footer */
  .footer { text-align: center; padding: 24px; font-size: 11px; color: #b0bec5; }
</style>
"""


def navbar(active=""):
    return f"""
    <div class="topbar">
      <div class="logo">NEXUS<span>corp</span></div>
      <nav>
        <a href="/dashboard" class="{'active' if active=='dashboard' else ''}">Dashboard</a>
        <a href="/contacts" class="{'active' if active=='contacts' else ''}">Contacts</a>
        <a href="/tickets" class="{'active' if active=='tickets' else ''}">Tickets</a>
        <a href="/docs" class="{'active' if active=='docs' else ''}">Docs</a>
      </nav>
      <div class="user-info">Logged in as <strong>devops-admin</strong> · <a href="/login" style="color:#4fc3f7;font-size:12px;">Logout</a></div>
    </div>
    """


# ═══════════════════════════════════════════════════════════════
#   ROUTES
# ═══════════════════════════════════════════════════════════════


@app.route("/")
def home():
    handle_beacon("/")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    handle_beacon("/login")
    user = request.form.get("username", "") or request.args.get("user", "")
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    

    sqli_keywords = ["OR", "1=1", "'", "--", "SELECT", "DROP", "UNION"]
    is_sqli = any(k.upper() in user.upper() for k in sqli_keywords)

    if is_sqli:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "sql_injection",
            "token": "login-portal",
            "route_accessed": "/login",
            "attacker_ip": attacker_ip,
            
            "payload": user,
            "user_agent": request.headers.get("User-Agent", "unknown"),
            "risk_level": "critical",
            "alert": "SQL INJECTION DETECTED",
        }
        save_beacon(event)
        print(f" SQLI: /login from {attacker_ip}")

    error_msg = ""
    if request.method == "POST" and user:
        error_msg = '<p style="color:#c62828;font-size:13px;margin-bottom:12px;">⚠ Invalid credentials. Please try again.</p>'
        if not is_sqli:
            return redirect("/dashboard")

    return render_template_string(f"""<!DOCTYPE html><html><head>
    <title>NEXUScorp — Sign In</title>
    {LAYOUT_CSS}
    <style>
      body {{ display:flex; align-items:center; justify-content:center; min-height:100vh; background: linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%); }}
      .login-box {{ background:#fff; border-radius:14px; padding:40px 36px; width:380px; box-shadow:0 8px 32px rgba(0,0,0,.2); }}
      .login-box h1 {{ font-size:20px; margin-bottom:4px; }}
      .login-box .sub {{ font-size:12px; color:#90a4ae; margin-bottom:24px; }}
      .login-box .logo-top {{ font-size:18px; font-weight:700; margin-bottom:20px; color:#1a1a2e; }}
      .login-box .logo-top span {{ color:#4fc3f7; }}
    </style></head><body>
    <div class="login-box">
      <div class="logo-top">NEXUS<span>corp</span></div>
      <h1>Sign in to your account</h1>
      <p class="sub">Internal Employee Portal · Authorized personnel only</p>
      {error_msg}
      <form method="POST">
        <div class="form-group"><label>Username or Email</label><input name="username" placeholder="e.g. c.mendoza" autocomplete="off"></div>
        <div class="form-group"><label>Password</label><input name="password" type="password" placeholder="••••••••"></div>
        <button class="btn btn-primary" style="width:100%;margin-top:4px;">Sign In</button>
      </form>
      <p style="font-size:11px;color:#b0bec5;margin-top:16px;text-align:center;">Forgot password? Contact IT Security — ext. 2100</p>
    </div>
    <div class="footer" style="position:fixed;bottom:0;width:100%;color:rgba(255,255,255,.3);">
      &copy; 2025 NEXUScorp · Internal use only · v3.2.1
    </div>
    </body></html>""")



@app.route("/dashboard")
def dashboard():
    handle_beacon("/dashboard")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Dashboard — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('dashboard')}
    <div class="page">
      <h1>Dashboard</h1>
      <p class="subtitle">Overview for April 2025 · Last updated 2 hours ago</p>
      <div class="stats">
        <div class="stat-card"><div class="label">Active Employees</div><div class="value">127</div><div class="sub">+3 this month</div></div>
        <div class="stat-card"><div class="label">Open Tickets</div><div class="value">14</div><div class="sub">2 critical</div></div>
        <div class="stat-card"><div class="label">Systems Online</div><div class="value">98.7%</div><div class="sub">1 degraded</div></div>
        <div class="stat-card"><div class="label">VPN Connections</div><div class="value">34</div><div class="sub">active now</div></div>
      </div>
      <div class="card">
        <h2>Recent Activity</h2>
        <table>
          <tr><th>Time</th><th>User</th><th>Action</th><th>Resource</th></tr>
          <tr><td>09:41</td><td>c.mendoza</td><td>Deployed</td><td>api-gateway v2.1.4</td></tr>
          <tr><td>09:32</td><td>l.fernandez</td><td>SSH session</td><td>prod-db-02</td></tr>
          <tr><td>09:15</td><td>ma.torres</td><td>Updated rule</td><td>WAF policy #412</td></tr>
          <tr><td>08:58</td><td>p.navarro</td><td>Merged PR</td><td>frontend-portal #87</td></tr>
          <tr><td>08:41</td><td>d.garcia</td><td>Downloaded</td><td>Q1-financial-report.xlsx</td></tr>
        </table>
      </div>
      <div class="card">
        <h2>System Notices</h2>
        <p style="font-size:13px;color:#607d8b;line-height:1.7;">
          <strong style="color:#e65100;">⚠ Scheduled maintenance:</strong> prod-db-02 reboot on Sunday 20 Apr 02:00–04:00 UTC.<br>
          <strong>✓ Resolved:</strong> SSL certificate renewed for staging.nexuscorp.internal (INC-2033).<br>
          <strong>📋 Reminder:</strong> All teams must complete Q2 access review by April 30.
        </p>
      </div>
    </div>
    <div class="footer">&copy; 2025 NEXUScorp Internal Portal · v3.2.1</div>
    </body></html>""")



@app.route("/contacts")
def contacts():
    handle_beacon("/contacts")
    rows = ""
    for e in FAKE_EMPLOYEES:
        rows += f"<tr><td>{e['name']}</td><td>{e['dept']}</td><td>{e['role']}</td><td><a href='mailto:{e['email']}'>{e['email']}</a></td><td>{e['ext']}</td></tr>"

    return render_template_string(f"""<!DOCTYPE html><html><head><title>Contacts — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('contacts')}
    <div class="page">
      <h1>Employee Directory</h1>
      <p class="subtitle">Internal contacts · {len(FAKE_EMPLOYEES)} employees</p>
      <div class="searchbar"><input placeholder="Search by name, department, or role..." autocomplete="off"></div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">
          <h2 style="margin:0;">All Contacts</h2>
          <a href="/contacts/export" class="btn btn-secondary" style="font-size:12px;padding:6px 14px;">📥 Export CSV</a>
        </div>
        <table>
          <tr><th>Name</th><th>Department</th><th>Role</th><th>Email</th><th>Ext.</th></tr>
          {rows}
        </table>
      </div>
    </div>
    <div class="footer">&copy; 2025 NEXUScorp Internal Portal · v3.2.1</div>
    </body></html>""")


@app.route("/contacts/export")
def contacts_export():
    handle_beacon("/contacts/export")
    csv = "Name,Department,Role,Email,Extension\n"
    for e in FAKE_EMPLOYEES:
        csv += f"{e['name']},{e['dept']},{e['role']},{e['email']},{e['ext']}\n"
    return csv, 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=employees_export.csv"}


# ── Tickets ───────────────────────────────────────────────────
@app.route("/tickets")
def tickets():
    handle_beacon("/tickets")
    rows = ""
    for t in FAKE_TICKETS:
        status_class = {"Open": "open", "In Progress": "progress", "Resolved": "resolved"}.get(t["status"], "")
        prio_class = t["priority"].lower()
        rows += f"""<tr>
          <td><strong>{t['id']}</strong></td>
          <td>{t['title']}</td>
          <td><span class="badge badge-{status_class}">{t['status']}</span></td>
          <td><span class="badge badge-{prio_class}">{t['priority']}</span></td>
          <td>{t['assignee']}</td>
          <td>{t['created']}</td>
        </tr>"""

    return render_template_string(f"""<!DOCTYPE html><html><head><title>Tickets — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('tickets')}
    <div class="page">
      <h1>IT Service Desk</h1>
      <p class="subtitle">Incident tracking · {len(FAKE_TICKETS)} tickets</p>
      <div style="margin-bottom:16px;"><a href="/tickets/new" class="btn btn-primary">+ New Ticket</a></div>
      <div class="card">
        <table>
          <tr><th>ID</th><th>Title</th><th>Status</th><th>Priority</th><th>Assignee</th><th>Created</th></tr>
          {rows}
        </table>
      </div>
    </div>
    <div class="footer">&copy; 2025 NEXUScorp Internal Portal · v3.2.1</div>
    </body></html>""")


@app.route("/tickets/new", methods=["GET", "POST"])
def ticket_new():
    handle_beacon("/tickets/new")
    if request.method == "POST":
        return redirect("/tickets")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>New Ticket — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('tickets')}
    <div class="page">
      <h1>Create Ticket</h1>
      <p class="subtitle">Submit an IT support request</p>
      <div class="card" style="max-width:600px;">
        <form method="POST">
          <div class="form-group"><label>Subject</label><input name="subject" placeholder="Brief description of the issue"></div>
          <div class="form-group"><label>Priority</label><select name="priority"><option>Low</option><option>Medium</option><option selected>High</option><option>Critical</option></select></div>
          <div class="form-group"><label>Category</label><select name="category"><option>Network</option><option>Access</option><option>Hardware</option><option>Software</option><option>Security</option></select></div>
          <div class="form-group"><label>Description</label><textarea name="description" rows="5" placeholder="Describe the issue in detail..."></textarea></div>
          <button class="btn btn-primary">Submit Ticket</button>
        </form>
      </div>
    </div>
    </body></html>""")



@app.route("/docs")
def docs():
    handle_beacon("/docs")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Docs — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('docs')}
    <div class="page">
      <h1>Internal Documentation</h1>
      <p class="subtitle">Knowledge base &amp; procedures</p>
      <div class="card">
        <h2>Quick Links</h2>
        <table>
          <tr><th>Document</th><th>Category</th><th>Last Updated</th></tr>
          <tr><td><a href="/docs/onboarding">New Employee Onboarding Guide</a></td><td>HR</td><td>2025-03-15</td></tr>
          <tr><td><a href="/docs/vpn-setup">VPN Configuration &amp; Setup</a></td><td>IT</td><td>2025-04-01</td></tr>
          <tr><td><a href="#">Database Backup Procedures</a></td><td>Engineering</td><td>2025-02-22</td></tr>
          <tr><td><a href="#">Incident Response Playbook</a></td><td>Security</td><td>2025-04-10</td></tr>
          <tr><td><a href="#">AWS Infrastructure Overview</a></td><td>Engineering</td><td>2025-03-28</td></tr>
        </table>
      </div>
    </div>
    </body></html>""")


@app.route("/docs/onboarding")
def docs_onboarding():
    handle_beacon("/docs/onboarding")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Onboarding — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('docs')}
    <div class="page">
      <h1>New Employee Onboarding Guide</h1>
      <p class="subtitle">Last updated: March 15, 2025 · Author: Ana Belén Ruiz (HR)</p>
      <div class="card" style="line-height:1.8;font-size:14px;">
        <h2>1. First Day Setup</h2>
        <p>Collect your laptop and badge from IT desk (Room 204, Building A). Your temporary credentials will be provided in a sealed envelope. <strong>Change your password immediately</strong> via the self-service portal.</p>
        <h2 style="margin-top:18px;">2. Network Access</h2>
        <p>Connect to <code>CORP-INTERNAL</code> WiFi using your AD credentials. VPN setup is required for remote work — see <a href="/docs/vpn-setup">VPN Configuration Guide</a>.</p>
        <h2 style="margin-top:18px;">3. Required Training</h2>
        <p>Complete the following within your first week: Security Awareness (mandatory), Data Handling Policy review, and Code of Conduct acknowledgment.</p>
        <h2 style="margin-top:18px;">4. Key Contacts</h2>
        <p>IT Help Desk: ext. 2100 · HR: ext. 3010 · Your direct manager will schedule a welcome meeting.</p>
      </div>
    </div>
    </body></html>""")


@app.route("/docs/vpn-setup")
def docs_vpn():
    handle_beacon("/docs/vpn-setup")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>VPN Setup — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('docs')}
    <div class="page">
      <h1>VPN Configuration &amp; Setup</h1>
      <p class="subtitle">Last updated: April 1, 2025 · Author: Laura Fernández (DevOps)</p>
      <div class="card" style="line-height:1.8;font-size:14px;">
        <h2>Prerequisites</h2>
        <p>Download OpenVPN client from the IT software center. You need your AD credentials and a valid MFA token.</p>
        <h2 style="margin-top:18px;">Configuration</h2>
        <p>Config file location: <code>/etc/openvpn/nexuscorp.ovpn</code><br>
        Gateway: <code>vpn.nexuscorp.internal:1194</code><br>
        Protocol: UDP · Cipher: AES-256-GCM</p>
        <h2 style="margin-top:18px;">Troubleshooting</h2>
        <p>If connection drops after 30 minutes, check keepalive settings. Open a ticket via <a href="/tickets/new">IT Service Desk</a> for persistent issues.</p>
      </div>
    </div>
    </body></html>""")


#admin(HIDDEN,no link exists anywhere on the portal)
@app.route("/admin")
def admin():
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    referer = request.headers.get("Referer", "")

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "beacon_triggered",
        "source": "honeypot_beacon", 
        "token": "admin-panel",
        "route_accessed": "/admin",
        "attacker_ip": attacker_ip,
        
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "method": request.method,
        "referer": referer,
        # Always high/critical — no link exists so any visit is suspicious
        "risk_level": "high",
        "alert": (
            "HIDDEN ADMIN PANEL — direct URL navigation, no link exists on portal. "
            f"Likely obtained URL from leaked config file. Referer: '{referer or 'none'}'"
        ),
    }
    save_beacon(event)
    
    print(f"HIDDEN ADMIN HIT by {attacker_ip} (referer: {referer or 'none'})")

    
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Admin — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('admin')}
    <div class="page">
      <h1>Administration Panel</h1>
      <p class="subtitle">Restricted area · Access logged</p>
      <div class="stats">
        <div class="stat-card"><div class="label">Total Users</div><div class="value">127</div></div>
        <div class="stat-card"><div class="label">Active Sessions</div><div class="value">34</div></div>
        <div class="stat-card"><div class="label">Failed Logins (24h)</div><div class="value" style="color:#c62828;">7</div></div>
      </div>
      <div class="card">
        <h2>Quick Actions</h2>
        <p style="font-size:13px;display:flex;gap:10px;flex-wrap:wrap;">
          <a href="/admin/users" class="btn btn-primary">Manage Users</a>
          <a href="/admin/settings" class="btn btn-secondary">System Settings</a>
          <a href="/admin/terminal" class="btn btn-secondary">Server Terminal</a>
          <a href="/backup" class="btn btn-secondary">Download Backup</a>
          <a href="/metrics/db" class="btn btn-secondary">DB Metrics</a>
        </p>
      </div>
    </div>
    </body></html>""")


@app.route("/admin/users")
def admin_users():
    handle_beacon("/admin/users")
    rows = ""
    for e in FAKE_EMPLOYEES:
        rows += f"<tr><td>{e['id']}</td><td>{e['name']}</td><td>{e['email']}</td><td>{e['dept']}</td><td><span class='badge badge-open'>Active</span></td></tr>"
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Users — Admin — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('admin')}
    <div class="page">
      <h1>User Management</h1>
      <p class="subtitle">All registered users</p>
      <div class="card"><table>
        <tr><th>ID</th><th>Name</th><th>Email</th><th>Department</th><th>Status</th></tr>
        {rows}
      </table></div>
    </div></body></html>""")


@app.route("/admin/settings")
def admin_settings():
    handle_beacon("/admin/settings")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Settings — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('admin')}
    <div class="page">
      <h1>System Settings</h1>
      <p class="subtitle">Configuration · Changes require approval</p>
      <div class="card" style="max-width:600px;">
        <div class="form-group"><label>SMTP Server</label><input value="smtp.nexuscorp.internal:587" readonly></div>
        <div class="form-group"><label>LDAP Server</label><input value="ldap://ad.nexuscorp.internal:389" readonly></div>
        <div class="form-group"><label>Backup Schedule</label><input value="Daily at 02:00 UTC" readonly></div>
        <div class="form-group"><label>Session Timeout</label><input value="30 minutes" readonly></div>
        <div class="form-group"><label>Max Login Attempts</label><input value="5" readonly></div>
        <p style="font-size:12px;color:#90a4ae;margin-top:12px;">Contact IT Security (ext. 2100) to request configuration changes.</p>
      </div>
    </div></body></html>""")


#Web Terminal
@app.route("/admin/terminal", methods=["GET", "POST"])
def admin_terminal():
    attacker_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "web_terminal_accessed",
        "source": "honeypot_beacon", 
        "token": "web-terminal",
        "route_accessed": "/admin/terminal",
        "attacker_ip": attacker_ip,
        
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "method": request.method,
        "risk_level": "critical",
        "alert": "WEB TERMINAL ACCESSED — strong malicious indicator",
    }
    save_beacon(event)
    print(f" WEB TERMINAL accessed by {attacker_ip} — MALICIOUS INDICATOR")

    if request.method == "POST":
        cmd = request.form.get("cmd", "")
        if cmd:
            cmd_event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "web_terminal_command",
                "source": "honeypot_beacon",
                "token": "web-terminal",
                "route_accessed": "/admin/terminal",
                "attacker_ip": attacker_ip,
                
                "command": cmd,
                "risk_level": "critical",
                "alert": f"WEB TERMINAL COMMAND: {cmd}",
            }
            save_beacon(cmd_event)
            print(f" WEB TERMINAL COMMAND from {attacker_ip}: {cmd}")

    cmd = request.form.get("cmd", "") if request.method == "POST" else ""
    output = ""
    if cmd:
        fake_responses = {
            "whoami":       "www-data",
            "id":           "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "pwd":          "/var/www/html",
            "ls":           "index.html  config.env  uploads/  .htaccess",
            "uname -a":     "Linux web-srv01 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false",
            "hostname":     "web-srv01",
            "ifconfig":     "eth0: inet 10.0.2.100  netmask 255.255.255.0",
            "ps aux":       "USER  PID %CPU COMMAND\nroot    1  0.0 /sbin/init\nwww   412  0.1 apache2\nmysql 523  0.2 mysqld",
            "netstat -tlnp":"tcp  0.0.0.0:80    LISTEN  apache2\ntcp  0.0.0.0:3306  LISTEN  mysqld\ntcp  0.0.0.0:22    LISTEN  sshd",
        }
        output = fake_responses.get(cmd.strip(), f"bash: {cmd.split()[0] if cmd.split() else cmd}: command not found")

    return render_template_string(f"""<!DOCTYPE html><html><head><title>Terminal — NEXUScorp</title>{LAYOUT_CSS}
    <style>
      .term {{ background:#1a1a2e; color:#00ff41; font-family:'Courier New',monospace; border-radius:10px; padding:20px; min-height:300px; }}
      .term-output {{ white-space:pre-wrap; font-size:13px; line-height:1.6; margin-bottom:12px; }}
      .term-input {{ display:flex; align-items:center; gap:8px; }}
      .term-input span {{ color:#00ff41; font-size:13px; }}
      .term-input input {{ flex:1; background:transparent; border:none; color:#00ff41; font-family:'Courier New',monospace; font-size:13px; outline:none; }}
      .term-warning {{ background:#fff3e0; border:1px solid #ffcc80; border-radius:8px; padding:12px 16px; margin-bottom:16px; font-size:12px; color:#e65100; }}
    </style></head><body>
    {navbar('admin')}
    <div class="page">
      <h1>Server Terminal</h1>
      <p class="subtitle">Remote management console · web-srv01 · All commands are logged</p>
      <div class="term-warning">This terminal provides limited shell access to web-srv01 for authorized administrators only. All activity is monitored and recorded.</div>
      <div class="card term">
        <div class="term-output">{'web-srv01:~$ ' + cmd + chr(10) + output + chr(10) if cmd else 'Welcome to NEXUScorp Remote Terminal v1.2' + chr(10) + 'Type a command below.' + chr(10)}</div>
        <form method="POST" class="term-input">
          <span>web-srv01:~$</span>
          <input name="cmd" autofocus autocomplete="off" placeholder="type command...">
        </form>
      </div>
    </div>
    </body></html>""")


# ── API endpoints ─────────────────────────────────────────────

@app.route("/api/v1/health")
def api_health():
    handle_beacon("/api/v1/health")
    return jsonify({"status": "ok", "version": "2.1.4", "uptime": "12d 3h"}), 200

@app.route("/api/v1/status")
def api_status():
    handle_beacon("/api/v1/status")
    return jsonify({"status": "running", "db": "connected", "cache": "ok", "workers": 4}), 200

@app.route("/api/v1/users")
def api_users():
    handle_beacon("/api/v1/users")
    return jsonify({"error": "Unauthorized", "message": "Bearer token required"}), 401

@app.route("/api/v1/employees")
def api_employees():
    handle_beacon("/api/v1/employees")
    return jsonify({"error": "Unauthorized", "message": "Bearer token required"}), 401

@app.route("/api/v1/auth/verify", methods=["GET", "POST"])
def api_auth():
    handle_beacon("/api/v1/auth/verify")
    return jsonify({"error": "Unauthorized", "message": "Invalid or expired token"}), 401

@app.route("/api/v1/vpn/config")
def api_vpn():
    handle_beacon("/api/v1/vpn/config")
    return jsonify({"error": "Forbidden", "message": "VPN config requires admin role"}), 403

@app.route("/api/v1/aws/status")
def api_aws():
    handle_beacon("/api/v1/aws/status")
    return jsonify({"error": "Forbidden", "message": "AWS endpoints restricted"}), 403

@app.route("/metrics/db")
def metrics_db():
    handle_beacon("/metrics/db")
    return jsonify({"connections": 12, "queries_per_sec": 34, "replication_lag_ms": 45, "status": "healthy"}), 200

@app.route("/backup")
def backup():
    handle_beacon("/backup")
    return render_template_string(f"""<!DOCTYPE html><html><head><title>Backup — NEXUScorp</title>{LAYOUT_CSS}</head><body>
    {navbar('admin')}
    <div class="page">
      <h1>Database Backup</h1>
      <div class="card">
        <p style="font-size:13px;color:#607d8b;">Preparing download...</p>
        <table style="margin-top:12px;">
          <tr><th>File</th><th>Size</th><th>Created</th><th>Action</th></tr>
          <tr><td>db_backup_2025-04-15.sql.gz</td><td>24.3 MB</td><td>2025-04-15 02:00 UTC</td><td><a href="#" style="color:#1565c0;">Download</a></td></tr>
          <tr><td>db_backup_2025-04-14.sql.gz</td><td>24.1 MB</td><td>2025-04-14 02:00 UTC</td><td><a href="#" style="color:#1565c0;">Download</a></td></tr>
        </table>
      </div>
    </div></body></html>""")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("BEACON_PORT", 8888)), debug=False, threaded=True)
