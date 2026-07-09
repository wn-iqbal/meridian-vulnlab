"""
Meridian Talent Group Internal API — deliberately vulnerable JWT-based REST API for pentest practice.

*** FOR LOCAL / ISOLATED LAB USE ONLY. DO NOT DEPLOY ON A PUBLIC NETWORK. ***

Simulates the backend the internal mobile/self-service app talks to. Reachable
from the web container via http://api:5001/ and exposed externally through
nginx at /api/*.

Every vulnerability here is intentional. Look for "VULN:" comments.
"""
import jwt
import hashlib
import time
from flask import Flask, request, jsonify
from faker import Faker

app = Flask(__name__)

# VULN: short, guessable HS256 signing secret. Common short wordlist entries
# crack this in seconds with a tool like jwt_tool or hashcat (mode 16500).
JWT_SECRET = "MeridianKey2024"
JWT_ALG = "HS256"

fake = Faker()
Faker.seed(1337)

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

# --------------------------------------------------------------- fake data --

USERS = {
    1: {"id": 1, "email": "admin@meridiantalent.com", "password": md5("admin123"),
        "full_name": "System Administrator", "role": "admin", "department": "Information Technology",
        "ssn": "911223-14-5566", "salary": 15000},
    2: {"id": 2, "email": "hr.manager@meridiantalent.com", "password": md5("Summer2024!"),
        "full_name": "Farah Aziz binti Kamarudin", "role": "hr_admin", "department": "Human Resources",
        "ssn": "880102-10-1234", "salary": 9500},
    3: {"id": 3, "email": "jane.tan@meridiantalent.com", "password": md5("Password123"),
        "full_name": "Tan Mei Ling", "role": "employee", "department": "Finance",
        "ssn": "920415-08-5678", "salary": 5200},
    4: {"id": 4, "email": "iqbal.rahman@meridiantalent.com", "password": md5("qwerty123"),
        "full_name": "Iqbal Rahman bin Zulkifli", "role": "employee", "department": "Information Technology",
        "ssn": "950630-11-2233", "salary": 6100},
}


def issue_token(user, expire=False):
    payload = {"sub": user["id"], "email": user["email"], "role": user["role"]}
    if expire:
        payload["exp"] = int(time.time()) + 3600
    # VULN: tokens issued without an 'exp' claim by default -> they never expire,
    # and there is no server-side revocation list either.
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token_unsafe(token):
    """VULN: manually inspects the header and, if alg is 'none', trusts the
    payload with NO signature verification at all."""
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        return None

    if header.get("alg", "").lower() == "none":
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None

    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidSignatureError:
        return None
    except Exception:
        return None


def auth_user():
    authz = request.headers.get("Authorization", "")
    if not authz.startswith("Bearer "):
        return None
    token = authz.split(" ", 1)[1]
    return decode_token_unsafe(token)


# ------------------------------------------------------------------ routes --

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "meridian-internal-api"})


@app.route("/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    for u in USERS.values():
        if u["email"] == email and u["password"] == md5(password):
            token = issue_token(u, expire=False)
            return jsonify({"token": token})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/logout", methods=["POST"])
def api_logout():
    """VULN: 'logs out' the client but there is no server-side token blocklist
    and tokens carry no 'exp' claim, so the exact same Bearer token presented
    before this call still works fine afterwards, indefinitely."""
    return jsonify({"message": "logged out (client-side only, token not revoked)"})


@app.route("/employees", methods=["GET"])
def list_employees():
    payload = auth_user()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    # VULN: returns full records including ssn/salary/password hash to ANY
    # authenticated user regardless of role, even though the client app this
    # API serves only ever displays name/department in its own UI.
    return jsonify(list(USERS.values()))


@app.route("/employees/<int:emp_id>/salary", methods=["GET"])
def get_salary(emp_id):
    payload = auth_user()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    # VULN: no check that payload['sub'] == emp_id or role in ('admin','hr_admin').
    # Any authenticated employee can view anyone else's salary just by changing the URL.
    user = USERS.get(emp_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": emp_id, "salary": user["salary"]})


@app.route("/profile", methods=["GET", "PATCH"])
def api_profile():
    payload = auth_user()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    uid = payload.get("sub")
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "not found"}), 404

    if request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        # VULN: whatever fields the client sends get applied, including 'role'
        # -> privilege escalation, since there's no allowlist of editable fields.
        for k, v in data.items():
            if k in user:
                user[k] = v
        return jsonify(user)

    return jsonify(user)


@app.route("/debug/whoami", methods=["GET"])
def debug_whoami():
    """Internal-only debug endpoint, not meant to be reachable from outside the
    docker network — but has no auth at all, making it a good SSRF pivot target
    from the web app's webhook-tester feature."""
    return jsonify({
        "service": "meridian-internal-api",
        "note": "this endpoint should not be reachable from the public internet",
        "internal_users": len(USERS),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
