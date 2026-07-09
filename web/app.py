"""
MeridianConnect — Staff Portal — deliberately vulnerable Flask app for pentest practice.

*** FOR LOCAL / ISOLATED LAB USE ONLY. DO NOT DEPLOY ON A PUBLIC NETWORK. ***

Every vulnerability here is intentional. Look for "VULN:" comments throughout
this file — a real pentest report would find these without any hand-holding,
so treat the comments as your own internal notes, not something the app
surfaces to you.
"""
import os
import sqlite3
import hashlib
import subprocess
from flask import (
    Flask, request, render_template, redirect, url_for, session,
    g, jsonify, abort
)
from lxml import etree
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "meridian.db")
DOCS_DIR = os.path.join(BASE_DIR, "hr_docs")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")

app = Flask(__name__)
app.secret_key = "dev"  # VULN: hardcoded, guessable Flask secret key -> forgeable session cookies
app.config["DEBUG"] = True  # VULN: debug mode enabled -> verbose tracebacks, Werkzeug console

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------------- helpers --

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def log_action(actor, action):
    try:
        db = get_db()
        db.execute("INSERT INTO audit_log (actor, action) VALUES (?,?)", (actor, action))
        db.commit()
    except Exception:
        pass


def require_admin_role(user):
    """Returns True if the current session is allowed into the system
    administration area. Enforces role == admin/hr_admin — EXCEPT for the
    'preview_as' support feature, which is the intended IDOR-style bypass
    for this lab (see admin_dashboard for the full explanation)."""
    if not user:
        return False
    if user["role"] in ("admin", "hr_admin"):
        return True
    preview_as = request.args.get("preview_as")
    if preview_as:
        db_check = get_db()
        preview_user = db_check.execute(
            "SELECT * FROM users WHERE id=?", (preview_as,)
        ).fetchone()
        if preview_user:
            log_action(user["email"], f"used admin preview_as={preview_as} (unauthorized)")
            return True
    return False

# ------------------------------------------------------------------ pages --

@app.route("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)

@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /internal/\n"
        "Disallow: /backup/\n"
        "Disallow: /.git/\n"
        "Sitemap: /sitemap.xml\n"
    )
    return app.response_class(body, mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap():
    body = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/directory</loc></url>
  <url><loc>/login</loc></url>
  <url><loc>/register</loc></url>
</urlset>"""
    return app.response_class(body, mimetype="application/xml")


# ------------------------------------------------------------------- auth --

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            error = "This email address is already registered."
        elif not email or not password or not full_name:
            error = "Please complete all fields."
        else:
            db.execute(
                "INSERT INTO users (email, password, full_name, role, department, bio) "
                "VALUES (?,?,?,?,?,?)",
                (email, md5(password), full_name, "employee", "Unassigned", ""),
            )
            db.commit()
            log_action(email, "self-registered")
            return redirect(url_for("login", registered="1"))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        db = get_db()

        # VULN: string-concatenated SQL query -> classic auth-bypass SQL injection.
        query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{md5(password)}'"
        try:
            row = db.execute(query).fetchone()
        except sqlite3.OperationalError:
            row = None

        if row:
            session["uid"] = row["id"]
            session["role"] = row["role"]
            log_action(email, "login_success")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid email or password."
            log_action(email, "login_failed")
            # VULN: no rate limiting, lockout, or CAPTCHA on repeated failed logins.
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    debug_token = None
    if request.method == "POST":
        email = request.form.get("email", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user:
            # VULN: reset token is predictable — md5 of a fixed string containing only
            # the user's numeric ID, no randomness, no expiry. It's also echoed straight
            # back in the HTTP response here rather than only being emailed, which is a
            # separate (also common in the wild) "dev left debug output in prod" bug.
            token = md5(f"reset-{user['id']}-meridian")
            db.execute("UPDATE users SET reset_token=? WHERE id=?", (token, user["id"]))
            db.commit()
            debug_token = token
            message = "If that email address exists in our system, a reset link has been sent."
        else:
            message = "If that email address exists in our system, a reset link has been sent."
    return render_template("forgot_password.html", message=message, debug_token=debug_token)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token=?", (token,)).fetchone()
    if not user:
        return render_template("reset_password.html", invalid=True)
    if request.method == "POST":
        new_password = request.form.get("password", "")
        db.execute("UPDATE users SET password=?, reset_token=NULL WHERE id=?",
                   (md5(new_password), user["id"]))
        db.commit()
        log_action(user["email"], "password_reset")
        return redirect(url_for("login", reset="1"))
    return render_template("reset_password.html", invalid=False, user=user)

# -------------------------------------------------------------- dashboard --

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user)


@app.route("/directory")
def directory():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    db = get_db()

    if q:
        # VULN: search box concatenates directly into SQL -> UNION-injectable.
        query = f"SELECT * FROM users WHERE full_name LIKE '%{q}%' OR department LIKE '%{q}%'"
        try:
            results = db.execute(query).fetchall()
        except sqlite3.OperationalError as e:
            # VULN: raw DB error surfaced to the client, helps an attacker fingerprint
            # column counts etc. during error-based injection.
            return render_template("directory.html", user=user, results=[], q=q,
                                    db_error=str(e))
    else:
        results = db.execute("SELECT * FROM users WHERE is_active=1").fetchall()

    return render_template("directory.html", user=user, results=results, q=q, db_error=None)


@app.route("/employee/<int:emp_id>")
def employee_profile(emp_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    emp = db.execute("SELECT * FROM users WHERE id=?", (emp_id,)).fetchone()
    if not emp:
        abort(404)
    # VULN: emp['bio'] is rendered with Jinja's |safe filter in the template ->
    # stored XSS for anything saved into a profile's bio field.
    return render_template("employee_profile.html", user=user, emp=emp)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    if request.method == "POST":
        bio = request.form.get("bio", "")
        full_name = request.form.get("full_name", user["full_name"])
        # VULN: mass assignment. The visible form only has name + bio fields, but the
        # handler also trusts an optional 'role' field if the client includes one in
        # the POST body — no server-side allowlist of which fields are actually editable.
        # There's also no CSRF token on this endpoint.
        role = request.form.get("role")
        db.execute("UPDATE users SET bio=?, full_name=? WHERE id=?", (bio, full_name, user["id"]))
        if role and role != user["role"]:
            db.execute("UPDATE users SET role=? WHERE id=?", (role, user["id"]))
            log_action(user["email"], f"role changed to {role} via profile update")
        db.commit()
        return redirect(url_for("profile", saved="1"))
    fresh = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    return render_template("profile.html", user=fresh)


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    f = request.files.get("avatar")
    if f and f.filename:
        # VULN: unrestricted file upload. No extension allowlist, no content-type check,
        # no magic-byte validation. Filename is taken almost as-is and saved straight
        # into a web-servable static directory.
        safe_ish_name = f.filename.replace("..", "")
        dest = os.path.join(UPLOAD_DIR, safe_ish_name)
        f.save(dest)
        db = get_db()
        db.execute("UPDATE users SET avatar=? WHERE id=?",
                   (f"/static/uploads/{safe_ish_name}", user["id"]))
        db.commit()
        log_action(user["email"], f"uploaded avatar {safe_ish_name}")
    return redirect(url_for("profile"))


# --------------------------------------------------------------- payslips --

@app.route("/payslip/<int:payslip_id>")
def view_payslip(payslip_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    # VULN: IDOR. No check that payslip.user_id matches the logged-in user (or that the
    # requester has an HR role). IDs are sequential integers, trivial to enumerate.
    payslip = db.execute("SELECT * FROM payslips WHERE id=?", (payslip_id,)).fetchone()
    if not payslip:
        abort(404)
    owner = db.execute("SELECT * FROM users WHERE id=?", (payslip["user_id"],)).fetchone()
    return render_template("payslip.html", user=user, payslip=payslip, owner=owner)

# ----------------------------------------------------------------- admin --

@app.route("/admin")
def admin_dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # VULN: IDOR-style access control bypass via ?preview_as=<user_id> — see
    # require_admin_role() for the full explanation. A normal employee who
    # discovers a known admin user ID (directory enumeration / the payslip
    # IDOR bug both leak this) can pass ?preview_as=<that id> and slip past
    # the role check without ever being an admin themselves.
    if not require_admin_role(user):
        abort(403)

    db = get_db()
    employees = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    docs = db.execute("SELECT * FROM documents ORDER BY id").fetchall()
    logs = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 25").fetchall()
    return render_template("admin.html", user=user, employees=employees, docs=docs, logs=logs)


@app.route("/admin/give-admin", methods=["GET", "POST"])
def give_admin():
    # VULN: CSRF. State-changing action reachable via a plain GET, no CSRF token, no
    # re-authentication. An attacker hosting <img src="/admin/give-admin?target=N">
    # anywhere on the web could silently promote user N the moment a logged-in
    # victim's browser happens to load that page. Also reachable via the same
    # preview_as bypass as the rest of the admin area.
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not require_admin_role(user):
        abort(403)
    target = request.values.get("target")
    if target:
        db = get_db()
        db.execute("UPDATE users SET role='admin' WHERE id=?", (target,))
        db.commit()
        log_action(user["email"], f"granted admin to user {target} via unauthenticated GET")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/network-tool", methods=["GET", "POST"])
def network_tool():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not require_admin_role(user):
        abort(403)
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULN: OS command injection. User input is shell-interpolated directly into a
        # ping command executed with shell=True.
        cmd = f"ping -c 1 -W 1 {host}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5, text=True)
            output = (result.stdout or "") + (result.stderr or "")
        except Exception as e:
            output = str(e)
        log_action(user["email"], f"ran network diagnostics against {host}")
    return render_template("network_tool.html", user=user, output=output)


@app.route("/admin/webhook-test", methods=["GET", "POST"])
def webhook_test():
    # VULN: SSRF. This "verify your integration URL" feature fetches an arbitrary
    # server-supplied URL with no allowlist and no blocking of internal/link-local
    # ranges. The internal API service is reachable from here but not directly from
    # the outside, making this endpoint a pivot point into internal-only services.
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not require_admin_role(user):
        abort(403)
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        try:
            r = requests.get(url, timeout=3)
            result = f"Status: {r.status_code}\n\n{r.text[:2000]}"
        except Exception as e:
            result = f"Error: {e}"
        log_action(user["email"], f"tested webhook url {url}")
    return render_template("webhook_test.html", user=user, result=result)


@app.route("/admin/import-employees", methods=["GET", "POST"])
def import_employees():
    # VULN: XXE. Bulk employee import accepts XML and parses it with external entity
    # resolution enabled and no DTD restrictions — a crafted DOCTYPE can read local
    # files from the server's filesystem.
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not require_admin_role(user):
        abort(403)
    result = None
    if request.method == "POST":
        f = request.files.get("xmlfile")
        if f:
            data = f.read()
            try:
                parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
                tree = etree.fromstring(data, parser=parser)
                names = [el.text for el in tree.iter("name")]
                result = ("Imported records: " + ", ".join(n for n in names if n)) if names \
                    else etree.tostring(tree).decode(errors="replace")
            except Exception as e:
                result = f"Import failed: {e}"
        log_action(user["email"], "ran bulk employee XML import")
    return render_template("import_employees.html", user=user, result=result)


# ------------------------------------------------------------- doc viewer --

@app.route("/docs")
def docs_list():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    docs = db.execute("SELECT * FROM documents").fetchall()
    return render_template("docs.html", user=user, docs=docs)


@app.route("/docs/view")
def docs_view():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    filename = request.args.get("file", "handbook_2026.txt")
    # VULN: path traversal. filename is joined directly onto the docs directory with
    # no sanitization, so "../" sequences escape the intended directory entirely.
    target = os.path.join(DOCS_DIR, filename)
    try:
        with open(target, "r", errors="replace") as fh:
            content = fh.read()
        return render_template("doc_view.html", user=user, filename=filename, content=content)
    except Exception as e:
        return render_template("doc_view.html", user=user, filename=filename,
                                content=f"Error reading file: {e}")

# ------------------------------------------------------- recon / OSINT bait --

@app.route("/.git/config")
def git_config_leak():
    # VULN: simulates an accidentally-deployed .git directory in the web root, leaking
    # a stale credential reference in a commit-log-style comment.
    body = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "[remote \"origin\"]\n"
        "\turl = https://git.meridiantalent.com/internal/staff-portal.git\n"
        "# TODO(farah): remove before deploy - old_api_key=nx_live_4f9a2c8e1b\n"
    )
    return app.response_class(body, mimetype="text/plain")


@app.route("/backup/config.php.bak")
def backup_leak():
    # VULN: forgotten backup file left in the web root, exposing DB credentials.
    body = (
        "<?php\n"
        "// old config, superseded 2025-11-02\n"
        "define('DB_HOST', 'db.internal.meridiantalent.com');\n"
        "define('DB_USER', 'meridian_app');\n"
        "define('DB_PASS', 'Ch4ngeMe!2025');\n"
    )
    return app.response_class(body, mimetype="text/plain")


# ------------------------------------------------------------------- main --

if __name__ == "__main__":
    from seed import seed
    seed()
    app.run(host="0.0.0.0", port=5000, debug=True)
