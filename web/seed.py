"""
Seeds instance/meridian.db with fake employees, users, and documents.
Run once at container start (idempotent - checks if already seeded).
NOTE: This is a deliberately vulnerable lab app. Do not deploy publicly.
"""
import sqlite3
import os
import hashlib
import random
from faker import Faker

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "meridian.db")
fake = Faker()
Faker.seed(1337)
random.seed(1337)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'employee',
    department TEXT,
    bio TEXT DEFAULT '',
    ssn TEXT,
    salary INTEGER,
    avatar TEXT DEFAULT '/static/uploads/default.png',
    reset_token TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    department TEXT,
    confidential INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS payslips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    period TEXT NOT NULL,
    gross REAL,
    net REAL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    actor TEXT,
    action TEXT
);
"""

def md5(s):
    # intentionally weak hashing for the lab (crackable) - DO NOT use in real apps
    return hashlib.md5(s.encode()).hexdigest()

def seed():
    first_run = not os.path.exists(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        conn.close()
        print("[seed] already seeded, skipping")
        return

    print("[seed] seeding database...")

    users = [
        ("admin@meridiantalent.com", md5("admin123"), "System Administrator", "admin", "Information Technology", "I keep the lights on.", "911223-14-5566", 15000),
        ("hr.manager@meridiantalent.com", md5("Summer2024!"), "Farah Aziz binti Kamarudin", "hr_admin", "Human Resources", "HR Manager at Meridian Talent Group. Ask me about leave policy.", "880102-10-1234", 9500),
        ("jane.tan@meridiantalent.com", md5("Password123"), "Tan Mei Ling", "employee", "Finance", "Finance analyst, suka spreadsheet.", "920415-08-5678", 5200),
        ("iqbal.rahman@meridiantalent.com", md5("qwerty123"), "Iqbal Rahman bin Zulkifli", "employee", "Information Technology", "Backend dev. <b>Coffee addict.</b>", "950630-11-2233", 6100),
    ]

    depts = [
        "Information Technology",
        "Finance",
        "Human Resources",
        "Learning & Development",
        "Corporate Services",
        "Marketing & Communications",
        "Legal & Compliance",
        "Strategy & Planning",
    ]
    for _ in range(26):
        name = fake.name()
        email = name.lower().replace(" ", ".").replace("'", "") + "@meridiantalent.com"
        users.append((
            email,
            md5(fake.password(length=10, special_chars=False)),
            name,
            "employee",
            random.choice(depts),
            fake.sentence(nb_words=10),
            fake.ssn(),
            random.randint(3200, 8800),
        ))

    for email, pw, name, role, dept, bio, ssn, salary in users:
        conn.execute(
            "INSERT INTO users (email, password, full_name, role, department, bio, ssn, salary) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (email, pw, name, role, dept, bio, ssn, salary),
        )

    # a couple of payslips per real named user (first 4)
    for uid in range(1, 5):
        for period in ["2026-04", "2026-05", "2026-06"]:
            gross = 4000 + uid * 500
            net = gross * 0.85
            conn.execute(
                "INSERT INTO payslips (user_id, period, gross, net, notes) VALUES (?,?,?,?,?)",
                (uid, period, gross, net, "Auto-generated payslip."),
            )

    # documents, one flagged confidential (path traversal target)
    docs = [
        ("Employee Handbook 2026", "handbook_2026.txt", "General", 0),
        ("Leave Policy", "leave_policy.txt", "Human Resources", 0),
        ("IT Acceptable Use Policy", "it_aup.txt", "Information Technology", 0),
        ("Q2 Salary Review (CONFIDENTIAL)", "salary_review_q2.txt", "Human Resources", 1),
    ]
    for title, fn, dept, conf in docs:
        conn.execute(
            "INSERT INTO documents (title, filename, department, confidential) VALUES (?,?,?,?)",
            (title, fn, dept, conf),
        )

    conn.commit()
    conn.close()
    print(f"[seed] done. {len(users)} users seeded.")

if __name__ == "__main__":
    seed()
