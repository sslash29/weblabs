import base64
import hashlib
import hmac
import json
import mimetypes
import os
import pickle
import re
import secrets
import sqlite3
import subprocess
import time
import urllib.request
from datetime import datetime

from . import config, db, templates
from .core import Response, redirect, not_found, forbidden, route, new_session, drop_session

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def is_admin(req):
    u = req.current_user
    return bool(u) and u["role"] == "admin"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(config.JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def jwt_decode(token: str):
    """Strict verification: unlike a naive implementation, alg=none is
    rejected outright. The catch is the HMAC secret itself -- it's never
    exposed anywhere in this web app, only in the ops backup relay leak."""
    try:
        h, p, s = token.split(".")
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        alg = str(header.get("alg", "")).upper()
        if alg != "HS256":
            return None
        expected = b64url_encode(hmac.new(config.JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expected, s):
            return payload
    except Exception:
        pass
    return None


def bearer_payload(req):
    auth = req.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return jwt_decode(auth[7:].strip())


def page(title, body, req):
    return Response(templates.layout(title, body, user=req.current_user))


def json_resp(obj, status=200):
    return Response(json.dumps(obj, indent=2), status=status, content_type="application/json")


# ---------------------------------------------------------------------------
# public site
# ---------------------------------------------------------------------------

@route("GET", "/")
def home(req):
    body = """
    <!-- ops note: legacy backup relay (tcp/2121) still up from the 2019
         migration, decommission ticket OPS-4471 never closed -->
    <section class="hero">
      <h1>Banking built for how you actually move money.</h1>
      <p>MeridianPay powers everyday checking, savings, and payments for over
      200,000 customers. Open an account, manage transfers, and get support
      from real humans.</p>
      <a class="btn" href="/register">Open an account</a>
      <a class="btn secondary" href="/security">Our security commitment</a>
    </section>
    <div class="card">
      <h2>Why MeridianPay</h2>
      <p>Instant transfers, no hidden fees, and a support team that answers.
      Built by a small team who cares about getting the fundamentals right.</p>
    </div>
    """
    return page("Home", body, req)


@route("GET", "/about")
def about(req):
    body = """
    <h1>About MeridianPay</h1>
    <div class="card">
      <p>Founded in 2016, MeridianPay Financial Technologies, Inc. is a
      fictional digital banking platform built for security-training
      purposes. Nothing here represents a real financial institution, and no
      real funds or customer data exist anywhere in this system.</p>
      <p>Our engineering team maintains this customer portal, support desk,
      and internal operations tooling described throughout the site.</p>
    </div>
    """
    return page("About", body, req)


@route("GET", "/security")
def security_page(req):
    body = """
    <h1>Security at MeridianPay</h1>
    <div class="card">
      <p>We take the security of customer funds seriously. Highlights of our
      program:</p>
      <ul>
        <li>Encryption in transit and at rest</li>
        <li>Regular penetration testing by internal and third-party teams</li>
        <li>24/7 fraud monitoring</li>
      </ul>
      <p class="footer-note">This is a training lab. This page is aspirational, not a claim of fact.</p>
    </div>
    """
    return page("Security", body, req)


@route("GET", "/contact")
def contact_get(req):
    body = """
    <h1>Contact Us</h1>
    <div class="card form-narrow">
      <p>For account issues, please use the <a href="/support">support desk</a>
      once logged in. General inquiries:</p>
      <p><strong>Email:</strong> hello@meridianpay.example</p>
    </div>
    """
    return page("Contact Us", body, req)


@route("GET", "/robots.txt")
def robots(req):
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /internal/\n",
        content_type="text/plain; charset=utf-8",
    )


@route("GET", "/static/css/style.css")
def static_css(req):
    return Response(templates.CSS, content_type="text/css; charset=utf-8")


@route("GET", "/collect")
def collect(req):
    val = req.query.get("c", "")
    os.makedirs(os.path.dirname(config.COLLECT_LOG), exist_ok=True)
    with open(config.COLLECT_LOG, "a") as f:
        f.write(f"{datetime.utcnow().isoformat()} | referer={req.headers.get('referer','-')} | data={val}\n")
    return Response("", content_type="text/plain")


@route("GET", "/collected")
def collected(req):
    content = ""
    if os.path.exists(config.COLLECT_LOG):
        with open(config.COLLECT_LOG) as f:
            content = f.read()
    body = (
        "<h1>Attacker Log Viewer</h1>"
        "<p class='footer-note'>Simulates an external listener capturing data sent to /collect?c=...</p>"
        f"<pre>{templates.e(content) or '(empty)'}</pre>"
    )
    return page("Collected", body, req)


@route("GET", "/uploads/kyc/<filename>")
def serve_kyc_file(req, filename):
    if not is_admin(req):
        return forbidden("Admins only.")
    path = os.path.join(config.KYC_DIR, filename)
    if not os.path.isfile(path):
        return not_found()
    with open(path, "rb") as f:
        data = f.read()
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(data, content_type=ctype)


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------

def login_page_html(error=None):
    err = f'<div class="msg-error">{templates.e(error)}</div>' if error else ""
    return f"""
    <h1>Log In</h1>
    {err}
    <div class="card form-narrow">
      <form method="POST" action="/login">
        <label for="username">Username</label>
        <input id="username" name="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required>
        <button class="btn" type="submit">Log in</button>
      </form>
      <p class="footer-note">New here? <a href="/register">Open an account</a></p>
    </div>
    """


@route("GET", "/login")
def login_get(req):
    if req.current_user:
        return redirect("/accounts")
    return page("Log In", login_page_html(), req)


def login_post(req):
    username = req.form.get("username", "")
    password = req.form.get("password", "")
    conn = db.get_conn()
    pwhash = db.md5(password)
    sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{pwhash}'"
    try:
        row = conn.execute(sql).fetchone()
    except sqlite3.Error:
        conn.close()
        return page("Log In", login_page_html(error="Login failed."), req)
    conn.close()
    if not row:
        return page("Log In", login_page_html(error="Invalid username or password."), req)
    sid = new_session(row["id"])
    resp = redirect("/accounts")
    resp.set_cookie("sid", sid, httponly=True, path="/")
    return resp


route("POST", "/login")(login_post)


def register_page_html(error=None):
    err = f'<div class="msg-error">{templates.e(error)}</div>' if error else ""
    return f"""
    <h1>Open an Account</h1>
    {err}
    <div class="card form-narrow">
      <form method="POST" action="/register">
        <label for="username">Username</label>
        <input id="username" name="username" required>
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required>
        <button class="btn" type="submit">Create account</button>
      </form>
    </div>
    """


@route("GET", "/register")
def register_get(req):
    if req.current_user:
        return redirect("/accounts")
    return page("Register", register_page_html(), req)


def register_post(req):
    username = req.form.get("username", "").strip()
    email_ = req.form.get("email", "").strip()
    password = req.form.get("password", "")
    if not username or not email_ or not password:
        return page("Register", register_page_html(error="All fields are required."), req)
    conn = db.get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,datetime('now'))",
            (username, email_, db.md5(password), "customer"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return page("Register", register_page_html(error="Username or email already taken."), req)
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    conn.execute(
        "INSERT INTO accounts (user_id, account_number, nickname, acct_type, balance, notes, created_at) "
        "VALUES (?,?,?,?,?,?,datetime('now'))",
        (row["id"], f"MP-{secrets.randbelow(89999999)+10000000}", f"{username} - Everyday Checking", "checking", 25.00, None),
    )
    conn.commit()
    conn.close()
    sid = new_session(row["id"])
    resp = redirect("/accounts")
    resp.set_cookie("sid", sid, httponly=True, path="/")
    return resp


route("POST", "/register")(register_post)


@route("GET", "/logout")
def logout(req):
    sid = req.cookies.get("sid")
    if sid:
        drop_session(sid)
    resp = redirect("/")
    resp.set_cookie("sid", "", max_age=0, path="/")
    return resp


# ---------------------------------------------------------------------------
# customer portal - accounts
# ---------------------------------------------------------------------------

@route("GET", "/accounts")
def accounts_list(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    accts = conn.execute("SELECT * FROM accounts WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
    conn.close()
    flag_html = ""
    if user["username"] == "svc_reports":
        flag_html = templates.flag_banner("FLAG{weak_password_md5_cracked}")
    rows = "".join(
        f"""<div class="acct-row">
          <div><strong>{templates.e(a['nickname'])}</strong><br>
          <span class="footer-note">{templates.e(a['account_number'])} &middot; {templates.e(a['acct_type'])}</span></div>
          <div class="balance{' negative' if a['balance'] < 0 else ''}">${a['balance']:,.2f}</div>
          <div><a class="btn small" href="/accounts/{a['id']}">View</a></div>
        </div>"""
        for a in accts
    ) or "<p>No accounts yet.</p>"
    body = f"""
    <h1>Your Accounts</h1>
    {flag_html}
    <div class="card">{rows}</div>
    """
    return page("Accounts", body, req)


@route("GET", "/accounts/<account_id>")
def account_detail(req, account_id):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    # BUG: fetched by ID with no ownership check -- IDOR.
    acct = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    txns = (
        conn.execute("SELECT * FROM transactions WHERE account_id=? ORDER BY id DESC LIMIT 20", (account_id,)).fetchall()
        if acct else []
    )
    conn.close()
    if not acct:
        return not_found()
    flag_html = ""
    owner_warning = ""
    owned = acct["user_id"] == user["id"]
    if not owned:
        owner_warning = '<div class="msg-error">Note: this account does not belong to you, yet you can view it.</div>'
        if acct["id"] == 1:
            flag_html = templates.flag_banner("FLAG{idor_treasury_account_exposed}")
    txn_rows = "".join(
        f"<tr><td>{templates.e(t['created_at'])}</td><td>{templates.e(t['counterparty'])}</td><td>${t['amount']:,.2f}</td></tr>"
        for t in txns
    ) or "<tr><td colspan='3'>No transactions.</td></tr>"
    tools = ""
    if owned:
        tools = (
            f"<p><a href='/transactions/search?account={acct['id']}'>Search transactions</a> &middot; "
            f"<a href='/statement/download?account={acct['id']}&file=statement_{acct['id']}.txt'>Download statement</a></p>"
        )
    body = f"""
    <h1>{templates.e(acct['nickname'])}</h1>
    {flag_html}
    {owner_warning}
    <div class="card">
      <p class="balance{' negative' if acct['balance'] < 0 else ''}">${acct['balance']:,.2f}</p>
      <p class="footer-note">{templates.e(acct['account_number'])} &middot; {templates.e(acct['acct_type'])}</p>
      <p>{templates.e(acct['notes'] or '')}</p>
    </div>
    <div class="card">
      <h2>Recent activity</h2>
      <table><tr><th>Date</th><th>Counterparty</th><th>Amount</th></tr>{txn_rows}</table>
      {tools}
    </div>
    """
    return page(acct["nickname"], body, req)


@route("GET", "/transactions/search")
def transactions_search(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    account_id = req.query.get("account", "")
    q = req.query.get("q", "")
    conn = db.get_conn()
    acct = conn.execute("SELECT * FROM accounts WHERE id=? AND user_id=?", (account_id, user["id"])).fetchone()
    if not acct:
        conn.close()
        return forbidden("You do not have access to that account.")
    results_html = ""
    if q:
        # BUG: string-built SQL. No stack traces (DEBUG=False) -- malformed
        # payloads just show a generic error, so column-count discovery has
        # to be done blind (ORDER BY / UNION SELECT NULL trial and error)
        # rather than read off a traceback like a less-hardened app would show.
        sql = (
            "SELECT counterparty, amount, memo, created_at FROM transactions "
            f"WHERE account_id={account_id} AND counterparty LIKE '%{q}%'"
        )
        try:
            rows = conn.execute(sql).fetchall()
            if rows:
                results_html = "<table><tr><th>Counterparty</th><th>Amount</th><th>Memo</th><th>Date</th></tr>"
                for r in rows:
                    results_html += (
                        f"<tr><td>{templates.e(r[0])}</td><td>{r[1]}</td>"
                        f"<td>{templates.e(r[2] or '')}</td><td>{templates.e(r[3])}</td></tr>"
                    )
                results_html += "</table>"
            else:
                results_html = "<p>No matching transactions.</p>"
        except sqlite3.Error:
            results_html = '<div class="msg-error">Search failed.</div>'
    conn.close()
    body = f"""
    <h1>Search Transactions — {templates.e(acct['nickname'])}</h1>
    <div class="card">
      <form action="/transactions/search" method="GET" class="form-narrow">
        <input type="hidden" name="account" value="{templates.e(account_id)}">
        <label for="q">Counterparty contains</label>
        <input id="q" name="q" value="{templates.e(q)}">
        <button class="btn" type="submit">Search</button>
      </form>
    </div>
    <div class="card">{results_html}</div>
    """
    return page("Search Transactions", body, req)


@route("GET", "/statement/download")
def statement_download(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    account_id = req.query.get("account", "")
    filename = req.query.get("file", "")
    if not account_id or not filename:
        return not_found()
    conn = db.get_conn()
    acct = conn.execute("SELECT * FROM accounts WHERE id=? AND user_id=?", (account_id, user["id"])).fetchone()
    conn.close()
    if not acct:
        return forbidden("You do not have access to that account.")
    # BUG: ownership of the *account* is checked above, but the filename
    # itself is joined with zero sanitization -- classic path traversal.
    path = os.path.join(config.STATEMENT_DIR, filename)
    if not os.path.isfile(path):
        return not_found()
    with open(path, "rb") as f:
        data = f.read()
    return Response(data, content_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# transfers & payees
# ---------------------------------------------------------------------------

def transfer_form_html(user, error=None, flag_html="", message=None):
    conn = db.get_conn()
    accts = conn.execute("SELECT * FROM accounts WHERE user_id=?", (user["id"],)).fetchall()
    conn.close()
    opts = "".join(f"<option value='{a['id']}'>{templates.e(a['nickname'])} ({templates.e(a['account_number'])})</option>" for a in accts)
    err = f'<div class="msg-error">{templates.e(error)}</div>' if error else ""
    msg = f'<div class="msg-ok">{templates.e(message)}</div>' if message else ""
    return f"""
    <h1>Transfer Money</h1>
    {err}{msg}{flag_html}
    <div class="card form-narrow">
      <form method="POST" action="/transfer">
        <label for="from_account">From</label>
        <select id="from_account" name="from_account">{opts}</select>
        <label for="to_account_number">To account number</label>
        <input id="to_account_number" name="to_account_number" placeholder="MP-XXXXXXXX" required>
        <label for="amount">Amount (USD)</label>
        <input id="amount" name="amount" type="text" placeholder="100.00" required>
        <button class="btn" type="submit">Send transfer</button>
      </form>
    </div>
    """


@route("GET", "/transfer")
def transfer_get(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    return page("Transfer", transfer_form_html(user), req)


def transfer_post(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    from_account_id = req.form.get("from_account", "")
    to_account_number = req.form.get("to_account_number", "").strip()
    try:
        amount = float(req.form.get("amount", "0"))
    except ValueError:
        amount = 0.0

    conn = db.get_conn()
    from_acct = conn.execute("SELECT * FROM accounts WHERE id=? AND user_id=?", (from_account_id, user["id"])).fetchone()
    to_acct = conn.execute("SELECT * FROM accounts WHERE account_number=?", (to_account_number,)).fetchone()

    error = None
    flag_html = ""
    message = None
    if not from_acct:
        error = "Source account not found."
    elif not to_acct:
        error = "Recipient account number not found."
    elif from_acct["id"] == to_acct["id"]:
        error = "Cannot transfer to the same account."
    elif amount == 0:
        error = "Enter a nonzero amount."
    elif amount > 0 and from_acct["balance"] < amount:
        error = "Insufficient funds."
    else:
        # BUG: only the positive-amount path checks sufficient funds. A
        # negative amount sails through untouched, moving money the wrong
        # direction and letting the sender's own balance inflate.
        new_from_balance = from_acct["balance"] - amount
        new_to_balance = to_acct["balance"] + amount
        conn.execute("UPDATE accounts SET balance=? WHERE id=?", (new_from_balance, from_acct["id"]))
        conn.execute("UPDATE accounts SET balance=? WHERE id=?", (new_to_balance, to_acct["id"]))
        conn.execute(
            "INSERT INTO transactions (account_id,counterparty,amount,memo,created_at) VALUES (?,?,?,?,datetime('now'))",
            (from_acct["id"], to_acct["nickname"], -amount, "Transfer out"),
        )
        conn.execute(
            "INSERT INTO transactions (account_id,counterparty,amount,memo,created_at) VALUES (?,?,?,?,datetime('now'))",
            (to_acct["id"], from_acct["nickname"], amount, "Transfer in"),
        )
        conn.commit()
        message = f"Transferred ${amount:,.2f} to {to_acct['account_number']}."
        if amount < 0:
            flag_html = templates.flag_banner("FLAG{business_logic_negative_amount_transfer}")
    conn.close()
    return page("Transfer", transfer_form_html(user, error=error, flag_html=flag_html, message=message), req)


route("POST", "/transfer")(transfer_post)


@route("GET", "/recipients")
def recipients_list(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    rows = conn.execute("SELECT * FROM recipients WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    conn.close()
    flag_html = templates.flag_banner("FLAG{csrf_payee_added}") if req.query.get("csrf_demo") == "1" else ""
    rows_html = "".join(
        f"<tr><td>{templates.e(r['name'])}</td><td>{templates.e(r['bank_name'] or '')}</td><td>{templates.e(r['account_number'])}</td></tr>"
        for r in rows
    ) or "<tr><td colspan='3'>No saved payees yet.</td></tr>"
    body = f"""
    <h1>Saved Payees</h1>
    {flag_html}
    <div class="card">
      <table><tr><th>Name</th><th>Bank</th><th>Account #</th></tr>{rows_html}</table>
    </div>
    <div class="card form-narrow">
      <h2>Add a payee</h2>
      <form method="POST" action="/recipients/add">
        <label for="name">Payee name</label>
        <input id="name" name="name" required>
        <label for="bank_name">Bank name</label>
        <input id="bank_name" name="bank_name">
        <label for="account_number">Account number</label>
        <input id="account_number" name="account_number" required>
        <button class="btn" type="submit">Add payee</button>
      </form>
    </div>
    """
    return page("Payees", body, req)


def recipients_add(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    name = req.get("name", "").strip()
    bank_name = req.get("bank_name", "").strip()
    account_number = req.get("account_number", "").strip()
    # BUG: this handler is wired to both GET and POST, and there's no CSRF
    # token check -- a state-changing action reachable via a plain GET link.
    added_via_get = req.method == "GET" and "account_number" in req.query and account_number
    if name and account_number:
        conn = db.get_conn()
        conn.execute(
            "INSERT INTO recipients (user_id,name,bank_name,account_number,created_at) VALUES (?,?,?,?,datetime('now'))",
            (user["id"], name, bank_name, account_number),
        )
        conn.commit()
        conn.close()
    resp = redirect("/recipients" + ("?csrf_demo=1" if added_via_get else ""))
    return resp


route("GET", "/recipients/add")(recipients_add)
route("POST", "/recipients/add")(recipients_add)


# ---------------------------------------------------------------------------
# KYC / identity verification (unrestricted upload)
# ---------------------------------------------------------------------------

@route("GET", "/kyc")
def kyc_get(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    docs = conn.execute("SELECT * FROM kyc_documents WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    conn.close()
    rows = "".join(
        f"<tr><td>{templates.e(d['doc_type'])}</td><td>{templates.e(d['filename'])}</td>"
        f"<td><span class='badge {d['status']}'>{d['status']}</span></td></tr>"
        for d in docs
    ) or "<tr><td colspan='3'>No documents uploaded yet.</td></tr>"
    body = f"""
    <h1>Identity Verification</h1>
    <div class="card">
      <table><tr><th>Type</th><th>File</th><th>Status</th></tr>{rows}</table>
    </div>
    <div class="card form-narrow">
      <h2>Upload a document</h2>
      <form method="POST" action="/kyc/upload" enctype="multipart/form-data">
        <label for="doc_type">Document type</label>
        <select id="doc_type" name="doc_type">
          <option value="id_card">Government ID</option>
          <option value="proof_of_address">Proof of address</option>
        </select>
        <label for="document">File</label>
        <input id="document" name="document" type="file" required>
        <button class="btn" type="submit">Upload</button>
      </form>
    </div>
    """
    return page("Identity Verification", body, req)


def kyc_upload(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    doc_type = req.form.get("doc_type", "id_card")
    if "document" in req.files:
        f = req.files["document"]
        orig_name = f["filename"]
        # BUG: no extension/content-type/magic-byte validation whatsoever --
        # the disk-safe name below is only to keep the filesystem tidy, the
        # untrusted original name is still stored verbatim in the DB (see
        # admin_kyc_report for where that comes back to bite us).
        if orig_name:
            raw_ext = os.path.splitext(orig_name)[1][:12]
            ext = re.sub(r"[^A-Za-z0-9.]", "", raw_ext) or ".bin"
            stored_name = secrets.token_hex(8) + ext
            os.makedirs(config.KYC_DIR, exist_ok=True)
            with open(os.path.join(config.KYC_DIR, stored_name), "wb") as out:
                out.write(f["content"])
            conn = db.get_conn()
            conn.execute(
                "INSERT INTO kyc_documents (user_id,doc_type,filename,stored_name,status,created_at) "
                "VALUES (?,?,?,?,?,datetime('now'))",
                (user["id"], doc_type, orig_name, stored_name, "pending"),
            )
            conn.commit()
            conn.close()
    return redirect("/kyc")


route("POST", "/kyc/upload")(kyc_upload)


# ---------------------------------------------------------------------------
# support desk (stored XSS lives here)
# ---------------------------------------------------------------------------

@route("GET", "/support")
def support_list(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    tickets = conn.execute("SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    conn.close()
    rows = "".join(
        f"<tr><td><a href='/support/{t['id']}'>#{t['id']}</a></td><td>{templates.e(t['subject'])}</td>"
        f"<td><span class='badge {t['status']}'>{t['status']}</span></td></tr>"
        for t in tickets
    ) or "<tr><td colspan='3'>No tickets yet.</td></tr>"
    body = f"""
    <h1>Support</h1>
    <div class="card">
      <table><tr><th>ID</th><th>Subject</th><th>Status</th></tr>{rows}</table>
    </div>
    <div class="card">
      <h2>New ticket</h2>
      <form method="POST" action="/support/new" class="form-narrow">
        <label for="subject">Subject</label>
        <input id="subject" name="subject" required>
        <label for="body">Message</label>
        <textarea id="body" name="body" rows="4" required></textarea>
        <button class="btn" type="submit">Submit ticket</button>
      </form>
    </div>
    """
    return page("Support", body, req)


def support_new(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    subject = req.form.get("subject", "").strip()
    body_txt = req.form.get("body", "").strip()
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO tickets (user_id, subject, body, status, created_at) VALUES (?,?,?,?,datetime('now'))",
        (user["id"], subject, body_txt, "open"),
    )
    conn.commit()
    conn.close()
    return redirect("/support")


route("POST", "/support/new")(support_new)


@route("GET", "/support/<ticket_id>")
def support_detail(req, ticket_id):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    t = conn.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,)).fetchone()
    replies = conn.execute("SELECT * FROM ticket_replies WHERE ticket_id=? ORDER BY id", (ticket_id,)).fetchall() if t else []
    conn.close()
    if not t or t["user_id"] != user["id"]:
        return forbidden("You do not have access to this ticket.")
    replies_html = "".join(
        f'<div class="comment"><strong>{templates.e(r["author"])}:</strong> {templates.e(r["body"])}</div>'
        for r in replies
    )
    body = f"""
    <h1>Ticket #{t['id']}: {templates.e(t['subject'])}</h1>
    <div class="card">
      <p><span class="badge {t['status']}">{t['status']}</span></p>
      <div class="comment">{templates.e(t['body'])}</div>
      {replies_html}
    </div>
    """
    return page(f"Ticket #{t['id']}", body, req)


# ---------------------------------------------------------------------------
# admin console
# ---------------------------------------------------------------------------

@route("GET", "/admin")
def admin_dashboard(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    users_c = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    tickets_c = conn.execute("SELECT COUNT(*) c FROM tickets").fetchone()["c"]
    kyc_c = conn.execute("SELECT COUNT(*) c FROM kyc_documents").fetchone()["c"]
    conn.close()
    body = f"""
    {templates.flag_banner("FLAG{mass_assignment_privesc_admin_reached}")}
    <h1>Ops Admin Console</h1>
    <div class="card">
      <p>Users: {users_c} &middot; Tickets: {tickets_c} &middot; KYC docs: {kyc_c}</p>
      <p>
        <a href="/admin/users">Manage users</a> &middot;
        <a href="/admin/tickets">Support tickets</a> &middot;
        <a href="/admin/kyc">KYC documents</a> &middot;
        <a href="/admin/tools/verify-bank">Verify recipient bank tool</a> &middot;
        <a href="/admin/import">Bulk import (legacy)</a> &middot;
        <a href="/admin/secrets">Ops secrets</a>
      </p>
    </div>
    """
    return page("Admin", body, req)


@route("GET", "/admin/users")
def admin_users(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    rows_html = "".join(
        f"<tr><td>{r['id']}</td><td>{templates.e(r['username'])}</td><td>{templates.e(r['email'])}</td>"
        f"<td><code>{r['password_hash']}</code></td><td>{templates.e(r['role'])}</td></tr>"
        for r in rows
    )
    body = f"""
    <h1>Users</h1>
    <div class="card">
      <table><tr><th>ID</th><th>Username</th><th>Email</th><th>Password Hash (MD5)</th><th>Role</th></tr>{rows_html}</table>
    </div>
    """
    return page("Admin - Users", body, req)


ADMIN_SECRET_JS = '<script>window.MP_ADMIN_FLAG = "FLAG{stored_xss_admin_secrets_exfiltrated}";</script>'


@route("GET", "/admin/secrets")
def admin_secrets(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    body = f"""
    {ADMIN_SECRET_JS}
    <h1>Ops Secrets</h1>
    <div class="card">
      <p><strong>Internal ledger API token:</strong> <code>{templates.e(config.INTERNAL_LEDGER_TOKEN)}</code></p>
      <p class="footer-note">Only visible to admins. If you got here via a customer support
      ticket rendering unsanitized HTML, that's the finding.</p>
    </div>
    """
    return page("Admin - Secrets", body, req)


@route("GET", "/admin/tickets")
def admin_tickets(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT tickets.*, users.username FROM tickets JOIN users ON tickets.user_id=users.id ORDER BY tickets.id DESC"
    ).fetchall()
    conn.close()
    rows_html = "".join(
        f"<tr><td>#{r['id']}</td><td>{templates.e(r['username'])}</td>"
        f"<td>{templates.e(r['subject'])}</td><td>{templates.e(r['status'])}</td>"
        f"<td><a href='/admin/tickets/{r['id']}'>Open</a></td></tr>"
        for r in rows
    )
    body = f"""
    {ADMIN_SECRET_JS}
    <h1>Support Tickets (Admin)</h1>
    <div class="card">
      <table><tr><th>ID</th><th>Customer</th><th>Subject</th><th>Status</th><th></th></tr>{rows_html}</table>
    </div>
    """
    return page("Admin - Tickets", body, req)


@route("GET", "/admin/tickets/<ticket_id>")
def admin_ticket_detail(req, ticket_id):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    t = conn.execute(
        "SELECT tickets.*, users.username FROM tickets JOIN users ON tickets.user_id=users.id WHERE tickets.id=?",
        (ticket_id,),
    ).fetchone()
    replies = conn.execute("SELECT * FROM ticket_replies WHERE ticket_id=? ORDER BY id", (ticket_id,)).fetchall()
    conn.close()
    if not t:
        return not_found()
    replies_html = "".join(
        f'<div class="comment"><strong>{templates.e(r["author"])}:</strong> {templates.e(r["body"])}</div>'
        for r in replies
    )
    body = f"""
    {ADMIN_SECRET_JS}
    <h1>Ticket #{t['id']}: {templates.e(t['subject'])}</h1>
    <div class="card">
      <p><strong>From:</strong> {templates.e(t['username'])} &middot; <span class="badge {t['status']}">{t['status']}</span></p>
      <!-- BUG: unlike the customer-facing view, this renders the body raw -->
      <div class="comment">{t['body']}</div>
      {replies_html}
      <form method="POST" action="/admin/tickets/{t['id']}/reply">
        <label for="body">Reply</label>
        <textarea id="body" name="body" rows="3" required></textarea>
        <button class="btn" type="submit">Send reply</button>
      </form>
    </div>
    """
    return page(f"Admin - Ticket #{t['id']}", body, req)


def admin_ticket_reply(req, ticket_id):
    if not is_admin(req):
        return forbidden("Admins only.")
    body_txt = req.form.get("body", "").strip()
    if body_txt:
        conn = db.get_conn()
        conn.execute(
            "INSERT INTO ticket_replies (ticket_id, author, body, created_at) VALUES (?,?,?,datetime('now'))",
            (ticket_id, "MeridianPay Support", body_txt),
        )
        conn.commit()
        conn.close()
    return redirect(f"/admin/tickets/{ticket_id}")


route("POST", "/admin/tickets/<ticket_id>/reply")(admin_ticket_reply)


@route("GET", "/admin/kyc")
def admin_kyc(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT kyc_documents.*, users.username FROM kyc_documents JOIN users ON kyc_documents.user_id=users.id ORDER BY kyc_documents.id DESC"
    ).fetchall()
    conn.close()
    rows_html = "".join(
        f"<tr><td>{templates.e(d['username'])}</td><td>{templates.e(d['doc_type'])}</td>"
        f"<td>{templates.e(d['filename'])}</td>"
        f"<td><a href='/uploads/kyc/{templates.e(d['stored_name'])}' target='_blank'>view</a></td>"
        f"<td><a href='/admin/kyc/{d['id']}/report'>generate report</a></td></tr>"
        for d in rows
    ) or "<tr><td colspan='5'>No documents yet.</td></tr>"
    body = f"""
    <h1>KYC Documents</h1>
    <div class="card">
      <table><tr><th>Customer</th><th>Type</th><th>Filename</th><th>File</th><th>Report</th></tr>{rows_html}</table>
    </div>
    """
    return page("Admin - KYC", body, req)


@route("GET", "/admin/kyc/<doc_id>/report")
def admin_kyc_report(req, doc_id):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    doc = conn.execute("SELECT * FROM kyc_documents WHERE id=?", (doc_id,)).fetchone()
    conn.close()
    if not doc:
        return not_found()
    label = doc["filename"]  # attacker-controlled at upload time
    doc_type = doc["doc_type"]
    # BUG: the customer-supplied original filename is interpolated straight
    # into a shell command used to build a "verification report" -- classic
    # OS command injection (CWE-78).
    cmd = f"echo 'MeridianPay KYC verification report' && echo 'Document: {label}' && echo 'Type: {doc_type}' && date"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5, text=True)
        output = result.stdout + result.stderr
    except Exception as ex:
        output = str(ex)
    body = f"""
    <h1>KYC Verification Report</h1>
    <div class="card"><pre>{templates.e(output)}</pre></div>
    """
    return page("Admin - KYC Report", body, req)


def fetch_tool_html(result_html="", url=""):
    return f"""
    <h1>Verify Recipient Bank</h1>
    <div class="card">
      <p class="footer-note">Fetches routing/verification data from a bank-provided URL for
      manual review before a large outbound wire is approved.</p>
      <form method="POST" action="/admin/tools/verify-bank" class="form-narrow">
        <label for="url">Verification URL</label>
        <input id="url" name="url" value="{templates.e(url)}" placeholder="https://bank.example/verify/12345">
        <button class="btn" type="submit">Fetch</button>
      </form>
    </div>
    <div class="card">{result_html}</div>
    """


@route("GET", "/admin/tools/verify-bank")
def admin_fetch_get(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    return page("Admin - Verify Bank", fetch_tool_html(), req)


def admin_fetch_post(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    url = req.form.get("url", "").strip()
    result_html = ""
    if url:
        try:
            # BUG (SSRF): this tool blindly attaches the internal ledger
            # token to *any* URL an admin supplies, including internal ones.
            r = urllib.request.Request(
                url,
                headers={"X-Internal-Ledger-Token": config.INTERNAL_LEDGER_TOKEN, "User-Agent": "MeridianPay-BankVerify/1.0"},
            )
            with urllib.request.urlopen(r, timeout=5) as resp:
                data = resp.read(4000)
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = repr(data)
            result_html = f"<pre>{templates.e(text)}</pre>"
        except Exception as ex:
            result_html = f'<div class="msg-error">Fetch failed: {templates.e(str(ex))}</div>'
    return page("Admin - Verify Bank", fetch_tool_html(result_html=result_html, url=url), req)


route("POST", "/admin/tools/verify-bank")(admin_fetch_post)


def import_page_html(result_html=""):
    return f"""
    <h1>Bulk Import Transactions (Legacy Format)</h1>
    <div class="card">
      <p class="footer-note">Accepts a base64-encoded legacy export blob from the old ops
      host. Kept around for one remaining downstream integration; scheduled for removal.</p>
      <form method="POST" action="/admin/import" class="form-narrow">
        <label for="payload">Base64 payload</label>
        <textarea id="payload" name="payload" rows="6"></textarea>
        <button class="btn" type="submit">Import</button>
      </form>
    </div>
    <div class="card">{result_html}</div>
    """


@route("GET", "/admin/import")
def admin_import_get(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    return page("Admin - Import", import_page_html(), req)


def admin_import_post(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    payload = req.form.get("payload", "").strip()
    result_html = ""
    if payload:
        try:
            raw = base64.b64decode(payload)
            # BUG (CWE-502): legacy format is a raw pickle blob. Deliberately
            # unsafe -- see SCOPE.md Special Authorization before you use this.
            obj = pickle.loads(raw)
            result_html = f"<pre>Imported object: {templates.e(repr(obj))}</pre>"
        except Exception as ex:
            result_html = f'<div class="msg-error">Import failed: {templates.e(str(ex))}</div>'
    return page("Admin - Import", import_page_html(result_html=result_html), req)


route("POST", "/admin/import")(admin_import_post)


@route("GET", "/internal/ledger-api")
def internal_ledger(req):
    token = req.headers.get("x-internal-ledger-token")
    if token != config.INTERNAL_LEDGER_TOKEN:
        return forbidden("Internal use only.")
    payload = {
        "ledger": "MP-CORE-LEDGER",
        "total_assets_under_management_usd": 812400000,
        "note": "This endpoint is for the internal ledger mesh only.",
        "flag": "FLAG{ssrf_internal_ledger_access}",
    }
    return json_resp(payload)


# ---------------------------------------------------------------------------
# JSON API (mobile app backend) - homemade JWT
# ---------------------------------------------------------------------------

def api_login(req):
    data = req.json or {}
    username = data.get("username", "")
    password = data.get("password", "")
    conn = db.get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?", (username, db.md5(password))
    ).fetchone()
    conn.close()
    if not row:
        return json_resp({"error": "invalid credentials"}, status=401)
    token = jwt_encode({"sub": row["id"], "username": row["username"], "role": row["role"], "iat": int(time.time())})
    return json_resp({"token": token})


route("POST", "/api/login")(api_login)


def api_me(req):
    payload = bearer_payload(req)
    if not payload:
        return json_resp({"error": "unauthorized"}, status=401)
    return json_resp({"user": payload})


route("GET", "/api/me")(api_me)


def api_admin_reports(req):
    payload = bearer_payload(req)
    if not payload or payload.get("role") != "admin":
        return json_resp({"error": "unauthorized"}, status=403)
    return json_resp(
        {
            "total_deposits_usd": 48213309.12,
            "active_accounts": 4021,
            "flag": "FLAG{jwt_weak_secret_forgery}",
        }
    )


route("GET", "/api/admin/reports")(api_admin_reports)


ACCOUNT_UPDATE_FIELDS = ["email", "role"]  # BUG: 'role' should never be client-settable (mass assignment)


def api_account_update(req):
    payload = bearer_payload(req)
    if not payload:
        return json_resp({"error": "unauthorized"}, status=401)
    user_id = payload.get("sub")
    data = req.json or {}
    sets, values = [], []
    for k in ACCOUNT_UPDATE_FIELDS:
        if k in data:
            sets.append(f"{k}=?")
            values.append(data[k])
    conn = db.get_conn()
    if sets:
        values.append(user_id)
        conn.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", values)
        conn.commit()
    row = conn.execute("SELECT id, username, email, role FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return json_resp({"error": "not found"}, status=404)
    return json_resp({"user": dict(row)})


route("POST", "/api/account/update")(api_account_update)
