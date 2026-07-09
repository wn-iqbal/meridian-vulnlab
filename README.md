# MeridianConnect — Staff Portal — Web Pentest Lab

A deliberately vulnerable internal staff portal for a fictional company,
**Meridian Talent Group**, built for practice real-world web exploitation against a realistic, self-contained
target.

**⚠️ FOR LOCAL / ISOLATED USE ONLY.** Every vulnerability in this app is
intentional and undefended. Never expose it to the internet, a shared
network, or any environment you don't fully control.

Meridian Talent Group is entirely fictional — any resemblance to a real
company is coincidental.

## What's in the box

- **`web`** — "MeridianConnect", the staff self-service portal (Flask,
  server-rendered HTML, session-cookie auth). Employee directory, payslips,
  company documents, profile management, a system administration panel.
- **`api`** — a small internal REST API the staff mobile/self-service app
  would talk to (Flask, JWT auth).
- **`nginx`** — reverse proxy in front of both, so it feels like hitting one
  real target (`web` on `/`, `api` on `/api/`).

~30 fake employees, realistic-looking internal documents/policies, an audit
log, and a full spread of vulnerability classes across authentication,
injection, access control, file handling, SSRF, XXE, and JWT/API design.
There is no scoring, flag, or progress system — this is meant to feel like a
real assessment, not a CTF. Track your own findings the way you would on an
actual engagement: in your notes, building toward a report.

**Note on `/admin` access control:** unlike a simple "no check at all" bug,
the system administration panel here has a *real* role check (only `admin` /
`hr_admin` accounts pass) — but that check can be bypassed via an IDOR-style
flaw in a "support preview" feature. This is intentionally closer to how
broken access control actually shows up in real applications: a check that
exists but can be tricked, not one that's simply missing.

## Quick start

Requires Docker + Docker Compose.

```bash
cd meridian-vulnlab
docker compose up --build
```

Then browse to **http://localhost:8080**

Seeded accounts (also discoverable through the app itself — don't peek unless
you're stuck):

| Email                             | Password      | Role      |
|------------------------------------|---------------|-----------|
| jane.tan@meridiantalent.com        | Password123   | employee  |
| hr.manager@meridiantalent.com      | Summer2024!   | hr_admin  |
| admin@meridiantalent.com           | admin123      | admin     |

You can also just click **Register** and create your own low-privilege
account — several vulnerabilities specifically start from "I'm just a normal
logged-in employee, now what."

To stop: `docker compose down`. To fully reset (wipe the seeded database and
uploaded files):
```bash
docker compose down -v
rm -f web/instance/meridian.db web/static/uploads/*
docker compose up --build
```

## Rules of engagement (for yourself)

This is your own local lab, so there's no "scope" in the legal sense, but
treat it like a real engagement anyway — it's good habit-forming:

- Only attack `localhost:8080` (and `localhost:8080/api/`). Don't scan or
  brute-force anything else on your machine/network.
- Don't run destructive tests (e.g. `rm -rf` via command injection) — the
  goal is to *prove* impact, not nuke your own filesystem. Prefer `id`,
  `whoami`, `cat /etc/passwd` style proof-of-concept commands.
- Write notes as you go, and produce an actual short report at the end. See
  "Suggested workflow" below.

## Suggested workflow (how a real junior pentester should approach this)

1. **Recon** — check `/robots.txt`, view source on the homepage before
   logging in. Note what's reachable pre-auth, and what the app itself hints
   at existing but not wanting you to see.
2. **Register a normal account** and map the app: what pages exist, what does
   a normal employee see, where does data come from (URLs with IDs, search
   boxes, file references, upload forms).
3. **Enumerate input points** — every form field, query param, header,
   uploaded file, and URL path segment is a potential entry point. Use Burp
   Suite (or your proxy of choice) to intercept and replay requests.
4. **Test systematically per vulnerability class.** `CHALLENGES.md` gives you
   a structured checklist if you want one, or explore blind for the fuller
   "real pentest" feel.
5. **Chain vulnerabilities** — several bugs here are more interesting
   combined (e.g. a CSRF-able admin action plus stored XSS = full account
   takeover via a single malicious link; SSRF reaching an internal API with a
   weak JWT secret).
6. **Write it up.** For each finding: affected endpoint, steps to reproduce,
   evidence (request/response), impact, and remediation. That discipline is
   worth more long-term than the exploitation itself.

If you get stuck, `CHALLENGES.md` has hints ordered roughly by difficulty,
and `SOLUTIONS.md` has full walkthroughs — spoilers, so try to earn it first.

## Tooling this lab plays nicely with

- **Burp Suite** (Community is fine) — proxy everything through it, use
  Repeater for the injection points, Intruder for the brute-force challenge.
- **curl / httpie** — several challenges (API/JWT ones especially) are
  faster from the command line.
- **jwt.io** or `pyjwt` — for decoding/forging tokens in the API challenges.
- **sqlmap** — optional, but try the SQLi challenges manually first; you'll
  learn more, and sqlmap will still work fine here once you understand what
  it's doing.

## Structure

```
meridian-vulnlab/
├── docker-compose.yml
├── nginx/nginx.conf
├── web/                  # MeridianConnect staff portal (Flask)
│   ├── app.py
│   ├── seed.py
│   ├── templates/
│   ├── static/
│   └── hr_docs/
├── api/                  # internal JWT API (Flask)
│   └── app.py
├── CHALLENGES.md          # player-facing hint list, no answers
├── SOLUTIONS.md           # full walkthrough / answer key
└── VULN_MAP.md            # internal design doc (also fine to read)
```
