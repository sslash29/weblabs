# NovaFreight Logistics — Vulnerable Web App Lab

A deliberately vulnerable "company website" for hands-on web app pentest
practice: a public marketing site, customer portal, support desk, and admin
panel for a fictional freight logistics company. Built with **zero
third-party dependencies** — pure Python 3 standard library — so it runs
anywhere `python3` runs, no `pip`/`venv` required.

See `SCOPE.md` for a formal rules-of-engagement doc treating this like a real
client authorization. Read that first — it sets the frame for how to approach
the rest of this.

## Quick start

```bash
python3 run.py
# -> NovaFreight lab running at http://127.0.0.1:8000

python3 run.py --reset   # wipe + reseed the database and uploaded files
```

Seeded accounts (also discoverable via the app itself — SQLi/cracking is
part of the exercise, but here they are for convenience):

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | admin |
| `alice` | `alice123` | customer |
| `bob` | `bob2024` | customer |
| `carol` | `carolpass` | customer |

## How to approach this

Play it black-box first. The source is right here in this directory and
nothing stops you from reading it, but you'll get more out of this if you
treat the running app the way you'd treat a real target — recon, map the
attack surface, form hypotheses, confirm with a proxy (Burp/ZAP/mitmproxy all
work fine against `127.0.0.1:8000`). Read the code afterward to check your
understanding, or when you're stuck and don't want the full walkthrough in
`SOLUTIONS.md` yet.

## Objectives

Each vulnerability yields a flag (`FLAG{...}`) somewhere in the response —
in the page body, a JSON field, or a file. That's your self-check; no
answer key needed unless you want one (`SOLUTIONS.md`).

1. **SQL injection — authentication bypass.** Log in as `admin` without
   knowing the password.
2. **SQL injection — UNION-based data extraction.** The shipment search
   feature is injectable. Extract data from a table that isn't part of the
   normal search flow.
3. **Broken access control.** The admin panel (`/admin`) doesn't actually
   verify you're an admin the way it should. Get in without valid admin
   credentials.
4. **IDOR.** Customer invoices are viewable by ID. As a low-privilege
   customer, view an invoice that isn't yours — specifically, the one
   belonging to the company's own internal account.
5. **Stored XSS → admin impact.** The support ticket system renders
   customer-submitted content somewhere it shouldn't. Get a payload to
   execute in an admin's browser session and exfiltrate something
   admin-only back to yourself (there's a `/collect?c=...` endpoint that
   acts as your "attacker server," and a `/collected` page to check what it
   caught — open the relevant admin page in an actual browser as `admin`
   to trigger it, curl alone won't execute JS).
6. **Path traversal.** A file-download feature in the support desk doesn't
   constrain the filename parameter. Read a file you shouldn't be able to.
7. **Unrestricted file upload.** Both the careers page and the support
   ticket form accept file uploads with no type/content validation. Turn
   that into something worse than a stored file.
8. **CSRF.** An account settings action is both missing CSRF protection
   *and* doesn't require POST — meaning a single cross-site link or
   auto-submitting page can trigger it. Prove it.
9. **Information disclosure.** Recon the site properly (check `robots.txt`,
   guess at common backup file paths) and find a file that was never meant
   to be publicly reachable. It contains secrets that unlock other findings.
10. **SSRF.** An admin-only "fetch a preview from a URL" tool makes
    server-side requests on your behalf. There's an internal-only API
    endpoint in this same app that isn't linked from anywhere and rejects
    direct requests — get to it anyway.
11. **Broken authentication (JWT).** There's a small JSON API
    (`/api/login`, `/api/me`, `/api/admin/stats`) issuing its own
    hand-rolled tokens. The verification logic trusts something it
    shouldn't. Forge an admin token without ever knowing a password.
12. **Weak credential storage.** Passwords aren't hashed the way they
    should be. If you dump the user table (see #2 or #3), you should be
    able to recover at least one plaintext password offline.
13. **(Bonus, hard) SSTI → sandbox escape → RCE.** The contact page's
    "preview your message" feature evaluates part of your input as a
    template expression, with a naive sandbox. Break out of the sandbox and
    achieve arbitrary code execution on the server — then use that access to
    read something that's only reachable via the OS process itself, not
    via any HTTP route. This one is genuinely RCE on your own machine; see
    `SCOPE.md` §6 before you touch it.

Bonus/no-flag exercises worth doing anyway because they're realistic:

- The app leaks stack traces on unhandled errors (`DEBUG=True`, like the
  leaked config file says). Use that to speed up your SQLi enumeration.
- Missing security headers generally (no CSP, no clickjacking protection).
  Worth noting in a "report" even without a flag attached.

## Project layout

```
run.py            entry point
app/
  config.py       constants incl. the intentionally leaked secrets
  db.py           schema + seed data
  core.py         tiny stdlib HTTP framework (router, sessions, request/response)
  templates.py    shared HTML layout + CSS
  views.py        every route handler — this is where the vulnerabilities live
static/css/       stylesheet
uploads/          resumes/ and tickets/ — where uploads land (unrestricted, on purpose)
data/             sqlite db + a simulated "attacker collection" log
flag.txt          target for the path traversal exercise
```

## Resetting

`python3 run.py --reset` wipes the database and reseeds it. It does **not**
clear `uploads/resumes/` or `uploads/tickets/` — delete those by hand if you
want a fully pristine state after testing the upload vectors.

## A note on realism

This isn't a checklist app where each page has exactly one obvious bug
labeled for you. A few things are deliberately inconsistent, the way real
apps are: the customer-facing ticket view *does* correctly check ownership
while the invoice view doesn't; some inputs are escaped and others aren't.
That inconsistency is itself worth noticing — it's usually where the real
bugs hide in production apps too.
