# MeridianPay — Vulnerable Fintech Network + Web App Lab

A deliberately vulnerable "digital bank" for hands-on pentest practice
against a fictional fintech company: an online banking web app *plus* a
small internal network segment behind it (an ops console, a legacy backup
relay, a health probe). Built with **zero third-party dependencies** — pure
Python 3 standard library — so it runs anywhere `python3` runs, no
`pip`/`venv` required.

This is the second lab in this series (after NovaFreight/lab1) and is
pitched a step harder: no debug tracebacks to lean on, access control that
mostly works until one API endpoint doesn't, and objectives that chain
across services instead of living in one file. It's meant to exercise the
combined skill set of CCNA-level network recon, eJPT/CJCA-level service and
web enumeration, and CWES-level exploitation technique.

See `SCOPE.md` for a formal rules-of-engagement doc treating this like a
real client authorization. Read that first — it sets the frame for how to
approach the rest of this, and lists everything that's actually in scope.

## Quick start

```bash
python3 run.py
# -> starts all four services on 127.0.0.1: 8000, 8081, 2121, 9090

python3 run.py --reset   # wipe + reseed the DB and regenerate backup/statement files
```

Seeded accounts (also discoverable via the app itself — SQLi/cracking is
part of the exercise, but here they are for convenience):

| Username | Password | Role |
|---|---|---|
| `admin` | `Adm1n_Ops#2024` | admin |
| `alice` | `alice123` | customer |
| `bob` | `bob2024` | customer |
| `carol` | `carolpass` | customer |
| `svc_reports` | *(weak — crack it, see objective 14)* | service |

## How to approach this

Play it black-box first. Start with recon against `127.0.0.1` the way
you'd approach an external footprint — you weren't handed a list of open
ports for a real engagement either. The source is right here in this
directory and nothing stops you from reading it, but you'll get more out of
this treating the running services the way you'd treat a real target: scan,
enumerate, form hypotheses, confirm with a proxy (Burp/ZAP/mitmproxy all
work fine against `127.0.0.1:8000`) or the appropriate protocol client for
the non-HTTP services.

## Objectives

Each vulnerability yields a flag (`FLAG{...}`) somewhere in the
response — in the page body, a JSON field, a banner, or a file. That's your
self-check; no answer key needed unless you want one (`SOLUTIONS.md`).

**Recon / network services**

1. **Service fingerprinting.** Find and identify all four listening
   services on `127.0.0.1` and grab a banner from the one that just sits
   there waiting for a connection.
2. **Anonymous file transfer access.** One of the four services is a
   backup/file-transfer service that shouldn't still be internet-reachable.
   It speaks enough real FTP that standard clients work against it.
3. **Weak/default credentials.** A second internal-only service is
   protected by nothing but a guessable username/password pair — one you
   may also stumble into via objective 2.

**Web application — online banking portal (port 8000)**

4. **SQL injection — authentication bypass.** Log in as `admin` without
   knowing the password.
5. **SQL injection — data extraction without an error oracle.** The
   transaction search feature is injectable, but this app doesn't leak
   stack traces or raw SQL on failure the way a less-hardened target would.
   You'll need to work out the column count blind before you can pull
   anything out of a table that isn't part of the normal search flow.
6. **IDOR.** Account statements are viewable by ID. As a low-privilege
   customer, view an account that isn't yours — specifically, the one
   belonging to the company's own internal treasury.
7. **Privilege escalation via mass assignment.** The mobile API has an
   account-update endpoint that accepts more fields than it should. Turn a
   regular customer into an admin without ever touching the database
   directly, then use that to reach the admin console.
8. **Stored XSS → admin impact.** The support ticket system renders
   customer-submitted content somewhere it shouldn't. Get a payload to
   execute in an admin's browser session and exfiltrate an admin-only
   secret back to yourself (there's a `/collect?c=...` endpoint that acts
   as your "attacker server," and a `/collected` page to check what it
   caught — open the relevant admin page in an actual browser as an admin
   to trigger it, curl alone won't execute JS).
9. **CSRF.** Adding a payee to your account is both missing CSRF protection
   *and* doesn't require POST — meaning a single cross-site link or
   auto-submitting page can trigger it. Prove it.
10. **Path traversal.** A statement-download feature doesn't constrain the
    filename parameter the way the account-ownership check next to it
    suggests it might. Read a file you shouldn't be able to.
11. **Unrestricted file upload → command injection.** The identity
    verification (KYC) upload accepts any file with no validation at all.
    On its own that's a finding; chained with how the admin "generate
    verification report" tool handles what you named the file, it's worse.
12. **SSRF.** An admin-only "verify recipient bank" tool makes
    server-side requests on your behalf and always attaches an internal
    credential to them. There's an internal-only ledger API in this same
    app that isn't linked from anywhere and rejects direct requests — get
    to it anyway.
13. **Broken authentication (JWT).** The mobile JSON API
    (`/api/login`, `/api/me`, `/api/admin/reports`) issues its own
    hand-rolled, properly-signature-checked tokens — `alg: none` won't get
    you anywhere here. The signing secret itself is the weak point, and
    it's not hiding anywhere in the web app.
14. **Weak credential storage.** Passwords aren't hashed the way they
    should be. Dump the user table (several objectives above get you
    there) and recover at least one plaintext password offline — one of
    the accounts is weak enough to be worth the trouble.
15. **Business logic flaw.** The internal transfer feature checks that you
    have sufficient funds before letting a transfer go through... for one
    sign of one input. Find the sign it forgot to check.
16. **(Bonus, hard) Insecure deserialization → RCE.** A legacy "bulk import"
    admin feature deserializes a client-supplied blob with Python's
    `pickle`. That's arbitrary code execution by design once you control
    the bytes. See `SCOPE.md` §6 before you touch it.

Objectives 10, 11, and 16 — plus the command injection in objective 3's
follow-through on the ops console — all converge on the same file,
`core_flag.txt` at the project root, which is otherwise unreachable by any
other route in this app. That's deliberate: in a real environment, multiple
independent bugs often lead to the same crown jewel, and "how many
*different* ways can an attacker reach this asset" is itself worth putting
in a report.

Bonus/no-flag exercises worth doing anyway because they're realistic:

- `robots.txt` and an HTML comment on the homepage both hint at
  infrastructure worth knowing about before you've scanned for it — notice
  them anyway, the way you would in a real recon pass.
- Missing security headers generally (no CSP, no clickjacking protection).
  Worth noting in a "report" even without a flag attached.
- The ops console (port 8081) has zero rate limiting on `/login` — a
  default-credential guess doesn't need to be a single lucky try.

## Project layout

```
run.py                entry point — starts all four services
app/
  config.py            constants, ports, and secrets (see note below)
  db.py                schema, seed data, backup/statement file generation
  core.py               tiny stdlib HTTP framework for the main web app
  templates.py           shared HTML layout + CSS
  views.py                every web-app route handler — most vulnerabilities live here
services/
  backup_relay.py        the FTP-style service on tcp/2121
  ops_console.py          the internal ops tool on tcp/8081
  health_probe.py         the banner service on tcp/9090
static/css/              stylesheet
uploads/kyc/             unrestricted KYC uploads land here
backups/                  files served by the FTP-style relay (regenerated on reset)
data/                     sqlite db, generated statements, attacker-collection log
core_flag.txt             the shared RCE/path-traversal objective (generated on first run)
```

**A note on secrets:** unlike a checklist app where every secret sits in a
leaked file the web app itself serves, the JWT signing secret and the ops
console credentials are **not** reachable from the web app on port 8000 at
all. They only leak via the backup relay (port 2121). If you're stuck on
objective 13 or 3, that's the missing step — this lab wants you to treat
"map the whole footprint first" as load-bearing, not optional.

## Resetting

`python3 run.py --reset` wipes the database and regenerates the backup and
statement files. It does **not** clear `uploads/kyc/` — delete that by hand
if you want a fully pristine state after testing the upload vector. It also
does not reset account balances mid-run outside of a full reset, so if
objective 15 leaves the treasury account looking odd, that's expected until
your next `--reset`.

## A note on realism

This isn't a checklist app where each page has exactly one obvious bug
labeled for you. A few things are deliberately inconsistent, the way real
apps are: the account-detail view has no ownership check while the
transaction-search and statement-download views right next to it do; some
inputs are escaped and others aren't; one admin tool validates nothing
about an uploaded file's *name* while trusting its *content* completely,
and another does the reverse. That inconsistency is itself worth noticing —
it's usually where the real bugs hide in production apps too.
