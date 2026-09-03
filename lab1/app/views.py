import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import sqlite3
import time
import urllib.request
from datetime import datetime

from . import config, db, templates
from .core import Response, redirect, not_found, forbidden, route, new_session, drop_session

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def login_required(req):
    return req.current_user


def is_admin(req):
    return req.cookies.get("role") == "admin"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(config.SECRET_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def jwt_decode(token: str):
    try:
        h, p, s = token.split(".")
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        alg = str(header.get("alg", "HS256")).lower()
        if alg == "none":
            return payload
        expected = b64url_encode(hmac.new(config.SECRET_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
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


def render_mini_template(tpl_str, context):
    def repl(m):
        expr = m.group(1).strip()
        try:
            result = eval(expr, {"__builtins__": {}}, dict(context))
            return str(result)
        except Exception as ex:
            return f"[template error: {ex}]"
    return re.sub(r"\{\{(.*?)\}\}", repl, tpl_str, flags=re.S)


def page(title, body, req):
    return Response(templates.layout(title, body, user=req.current_user))


# ---------------------------------------------------------------------------
# public site
# ---------------------------------------------------------------------------

@route("GET", "/")
def home(req):
    body = """
    <section class="hero">
      <h1>Global Freight, Delivered On Time.</h1>
      <p>NovaFreight moves over 40,000 containers a year across 30 countries.
      Track shipments, manage invoices, and talk to support — all in one place.</p>
      <a class="btn" href="/register">Create an account</a>
      <a class="btn secondary" href="/careers">We're hiring</a>
    </section>
    <div class="card">
      <h2>Track a shipment</h2>
      <form action="/search" method="GET" class="form-narrow">
        <label for="q">Tracking number, origin, or destination</label>
        <input id="q" name="q" placeholder="e.g. NF-100234">
        <button class="btn" type="submit">Search</button>
      </form>
    </div>
    <div class="card">
      <h2>Latest news</h2>
      <p><a href="/blog">Read our blog</a> for hub openings, hiring news, and quarterly reports.</p>
    </div>
    """
    return page("Home", body, req)


@route("GET", "/about")
def about(req):
    body = """
    <h1>About NovaFreight</h1>
    <div class="card">
      <p>Founded in 2011, NovaFreight Logistics Inc. operates ocean, air, and ground
      freight services out of 14 regional hubs. We are a fictional company built
      for security-training purposes — nothing here represents a real business.</p>
      <p>Our platform team maintains this customer portal, support desk, and
      internal operations tooling described throughout the site.</p>
    </div>
    """
    return page("About", body, req)


@route("GET", "/careers")
def careers(req):
    applied = req.query.get("applied")
    notice = '<div class="msg-ok">Thanks — your application has been received.</div>' if applied else ""
    body = f"""
    <h1>Careers</h1>
    {notice}
    <div class="card">
      <div class="job"><h3>Logistics Coordinator — Rotterdam</h3><p>Coordinate inbound/outbound freight scheduling for our EU hub.</p></div>
      <div class="job"><h3>Customs Broker — Los Angeles</h3><p>Manage customs documentation and compliance for Pacific lanes.</p></div>
      <div class="job"><h3>Warehouse Ops Lead — Baltimore</h3><p>Own day-to-day warehouse operations and staff scheduling.</p></div>
    </div>
    <div class="card">
      <h2>Apply</h2>
      <form action="/careers/apply" method="POST" enctype="multipart/form-data" class="form-narrow">
        <label for="name">Full name</label>
        <input id="name" name="name" required>
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required>
        <label for="cover_letter">Cover letter</label>
        <textarea id="cover_letter" name="cover_letter" rows="4"></textarea>
        <label for="resume">Resume</label>
        <input id="resume" name="resume" type="file">
        <button class="btn" type="submit">Submit application</button>
      </form>
    </div>
    """
    return page("Careers", body, req)


def careers_apply(req):
    name = req.form.get("name", "").strip()
    email_ = req.form.get("email", "").strip()
    cover = req.form.get("cover_letter", "").strip()
    resume_name = None
    if "resume" in req.files:
        f = req.files["resume"]
        filename = f["filename"]
        if filename:
            os.makedirs(config.RESUME_DIR, exist_ok=True)
            dest = os.path.join(config.RESUME_DIR, filename)
            with open(dest, "wb") as out:
                out.write(f["content"])
            resume_name = filename
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO job_applications (name,email,cover_letter,resume_filename,created_at) VALUES (?,?,?,?,datetime('now'))",
        (name, email_, cover, resume_name),
    )
    conn.commit()
    conn.close()
    return redirect("/careers?applied=1")


route("POST", "/careers/apply")(careers_apply)


@route("GET", "/blog")
def blog_list(req):
    conn = db.get_conn()
    posts = conn.execute("SELECT * FROM blog_posts ORDER BY id DESC").fetchall()
    conn.close()
    items = "".join(
        f'<div class="card"><h2><a href="/blog/{p["id"]}">{templates.e(p["title"])}</a></h2>'
        f'<p class="footer-note">by {templates.e(p["author"])} &middot; {p["created_at"]}</p>'
        f'<p>{templates.e(p["body"][:180])}&hellip;</p></div>'
        for p in posts
    )
    return page("News", f"<h1>Company News</h1>{items}", req)


@route("GET", "/blog/<post_id>")
def blog_detail(req, post_id):
    conn = db.get_conn()
    post = conn.execute("SELECT * FROM blog_posts WHERE id=?", (post_id,)).fetchone()
    comments = conn.execute("SELECT * FROM comments WHERE post_id=? ORDER BY id", (post_id,)).fetchall()
    conn.close()
    if not post:
        return not_found()
    comments_html = "".join(
        f'<div class="comment"><strong>{templates.e(c["author"])}</strong>'
        f' &middot; {c["created_at"]}<br>{c["body"]}</div>'
        for c in comments
    ) or "<p class='footer-note'>No comments yet.</p>"
    body = f"""
    <h1>{templates.e(post['title'])}</h1>
    <p class="footer-note">by {templates.e(post['author'])} &middot; {post['created_at']}</p>
    <div class="card"><p>{templates.e(post['body'])}</p></div>
    <h2>Comments</h2>
    {comments_html}
    <div class="card">
      <form method="POST" action="/blog/{post_id}/comment">
        <label for="author">Name</label>
        <input id="author" name="author" placeholder="Anonymous">
        <label for="body">Comment</label>
        <textarea id="body" name="body" rows="3" required></textarea>
        <button class="btn" type="submit">Post comment</button>
      </form>
    </div>
    """
    return page(post["title"], body, req)


def blog_comment(req, post_id):
    author = req.form.get("author", "").strip() or "Anonymous"
    body_txt = req.form.get("body", "").strip()
    if body_txt:
        conn = db.get_conn()
        conn.execute(
            "INSERT INTO comments (post_id, author, body, created_at) VALUES (?,?,?,datetime('now'))",
            (post_id, author, body_txt),
        )
        conn.commit()
        conn.close()
    return redirect(f"/blog/{post_id}")


route("POST", "/blog/<post_id>/comment")(blog_comment)


@route("GET", "/contact")
def contact_get(req):
    return page("Contact Us", contact_page_html(), req)


def contact_page_html(preview_html=None, name="", message=""):
    preview_block = f'<div class="card"><h2>Preview</h2><p>{preview_html}</p></div>' if preview_html else ""
    return f"""
    <h1>Contact Us</h1>
    <div class="card form-narrow">
      <form method="POST" action="/contact/preview">
        <label for="name">Name</label>
        <input id="name" name="name" value="{templates.e(name)}">
        <label for="message">Message</label>
        <textarea id="message" name="message" rows="4">{templates.e(message)}</textarea>
        <button class="btn" type="submit">Preview message</button>
      </form>
    </div>
    {preview_block}
    """


def contact_preview(req):
    name = req.form.get("name", "").strip() or "Guest"
    message = req.form.get("message", "")
    tpl = f"Hi {name}! Preview of your message: {message} — our team replies within 1 business day."
    rendered = render_mini_template(tpl, {"name": name, "message": message})
    return page("Contact Us", contact_page_html(preview_html=rendered, name=name, message=message), req)


route("POST", "/contact/preview")(contact_preview)


@route("GET", "/search")
def search(req):
    q = req.query.get("q", "")
    results_html = ""
    error_html = ""
    if q:
        conn = db.get_conn()
        sql = (
            "SELECT tracking_number, origin, destination, status FROM shipments "
            f"WHERE tracking_number LIKE '%{q}%' OR origin LIKE '%{q}%' OR destination LIKE '%{q}%'"
        )
        try:
            rows = conn.execute(sql).fetchall()
            if rows:
                results_html = "<table><tr><th>Tracking #</th><th>Origin</th><th>Destination</th><th>Status</th></tr>"
                for r in rows:
                    results_html += (
                        f"<tr><td>{templates.e(r[0])}</td><td>{templates.e(r[1])}</td>"
                        f"<td>{templates.e(r[2])}</td><td>{templates.e(r[3])}</td></tr>"
                    )
                results_html += "</table>"
            else:
                results_html = "<p>No shipments matched your search.</p>"
        except sqlite3.Error as ex:
            if config.DEBUG:
                error_html = (
                    f'<div class="msg-error"><strong>Query failed.</strong><pre>{templates.e(str(ex))}\n\nSQL: {templates.e(sql)}</pre></div>'
                )
            else:
                error_html = '<div class="msg-error">Search failed.</div>'
        conn.close()
    body = f"""
    <h1>Shipment Search</h1>
    <div class="card">
      <form action="/search" method="GET" class="form-narrow">
        <label for="q">Tracking number, origin, or destination</label>
        <input id="q" name="q" value="{templates.e(q)}">
        <button class="btn" type="submit">Search</button>
      </form>
    </div>
    {error_html}
    <div class="card">{results_html}</div>
    """
    return page("Search", body, req)


@route("GET", "/robots.txt")
def robots(req):
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /backup/\nDisallow: /internal/\n",
        content_type="text/plain; charset=utf-8",
    )


@route("GET", "/backup/config.py.bak")
def backup_leak(req):
    content = f'''# NovaFreight internal config -- ops backup, do not commit
SECRET_KEY = "{config.SECRET_KEY}"
INTERNAL_API_TOKEN = "{config.INTERNAL_API_TOKEN}"
DB_PATH = "data/novafreight.db"
DEBUG = True
MAIL_SERVER = "smtp.internal.novafreight.example"
'''
    return Response(content, content_type="text/plain; charset=utf-8")


@route("GET", "/static/css/style.css")
def static_css(req):
    return Response(templates.CSS, content_type="text/css; charset=utf-8")


@route("GET", "/uploads/resumes/<filename>")
def serve_resume(req, filename):
    path = os.path.join(config.RESUME_DIR, filename)
    if not os.path.isfile(path):
        return not_found()
    with open(path, "rb") as f:
        data = f.read()
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(data, content_type=ctype)


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


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------

def login_page_html(error=None):
    err = f'<div class="msg-error">{templates.e(error)}</div>' if error else ""
    return f"""
    <h1>Login</h1>
    {err}
    <div class="card form-narrow">
      <form method="POST" action="/login">
        <label for="username">Username</label>
        <input id="username" name="username" required>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required>
        <button class="btn" type="submit">Log in</button>
      </form>
      <p class="footer-note">New here? <a href="/register">Create an account</a></p>
    </div>
    """


@route("GET", "/login")
def login_get(req):
    if req.current_user:
        return redirect("/dashboard")
    return page("Login", login_page_html(), req)


def login_post(req):
    username = req.form.get("username", "")
    password = req.form.get("password", "")
    conn = db.get_conn()
    pwhash = db.md5(password)
    sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password_hash = '{pwhash}'"
    try:
        row = conn.execute(sql).fetchone()
    except sqlite3.Error as ex:
        conn.close()
        err = str(ex) if config.DEBUG else "Login failed."
        return page("Login", login_page_html(error=err), req)
    conn.close()
    if not row:
        return page("Login", login_page_html(error="Invalid username or password."), req)
    sid = new_session(row["id"])
    resp = redirect("/dashboard")
    resp.set_cookie("sid", sid, httponly=True, path="/")
    resp.set_cookie("role", row["role"], httponly=False, path="/")
    return resp


route("POST", "/login")(login_post)


def register_page_html(error=None):
    err = f'<div class="msg-error">{templates.e(error)}</div>' if error else ""
    return f"""
    <h1>Register</h1>
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
        return redirect("/dashboard")
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
    row = conn.execute("SELECT id, role FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    sid = new_session(row["id"])
    resp = redirect("/dashboard")
    resp.set_cookie("sid", sid, httponly=True, path="/")
    resp.set_cookie("role", row["role"], httponly=False, path="/")
    return resp


route("POST", "/register")(register_post)


@route("GET", "/logout")
def logout(req):
    sid = req.cookies.get("sid")
    if sid:
        drop_session(sid)
    resp = redirect("/")
    resp.set_cookie("sid", "", max_age=0, path="/")
    resp.set_cookie("role", "", max_age=0, path="/")
    return resp


# ---------------------------------------------------------------------------
# customer portal
# ---------------------------------------------------------------------------

@route("GET", "/dashboard")
def dashboard(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    shipments = conn.execute("SELECT * FROM shipments WHERE user_id=?", (user["id"],)).fetchall()
    invoices = conn.execute("SELECT * FROM invoices WHERE user_id=?", (user["id"],)).fetchall()
    conn.close()
    ship_rows = "".join(
        f"<tr><td>{templates.e(s['tracking_number'])}</td><td>{templates.e(s['origin'])}</td>"
        f"<td>{templates.e(s['destination'])}</td><td>{templates.e(s['status'])}</td></tr>"
        for s in shipments
    ) or "<tr><td colspan='4'>No shipments yet.</td></tr>"
    inv_rows = "".join(
        f"<tr><td><a href='/invoice/{i['id']}'>#{i['id']}</a></td><td>{templates.e(i['description'])}</td>"
        f"<td>${i['amount']:,.2f}</td></tr>"
        for i in invoices
    ) or "<tr><td colspan='3'>No invoices yet.</td></tr>"
    body = f"""
    <h1>Welcome, {templates.e(user['username'])}</h1>
    <div class="card">
      <h2>Your shipments</h2>
      <table><tr><th>Tracking #</th><th>Origin</th><th>Destination</th><th>Status</th></tr>{ship_rows}</table>
    </div>
    <div class="card">
      <h2>Your invoices</h2>
      <table><tr><th>Invoice</th><th>Description</th><th>Amount</th></tr>{inv_rows}</table>
    </div>
    """
    return page("Dashboard", body, req)


@route("GET", "/invoice/<invoice_id>")
def invoice_view(req, invoice_id):
    user = req.current_user
    if not user:
        return redirect("/login")
    conn = db.get_conn()
    inv = conn.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    conn.close()
    if not inv:
        return not_found()
    flag_html = ""
    if inv["user_id"] != user["id"]:
        flag_html = templates.flag_banner("FLAG{idor_admin_invoice_exposed}") if inv["user_id"] == 1 else (
            '<div class="msg-error">Note: this invoice does not belong to your account, yet you can view it.</div>'
        )
    body = f"""
    <h1>Invoice #{inv['id']}</h1>
    {flag_html}
    <div class="card">
      <p><strong>Description:</strong> {templates.e(inv['description'])}</p>
      <p><strong>Amount:</strong> ${inv['amount']:,.2f}</p>
      <p><strong>Notes:</strong> {templates.e(inv['notes'] or '')}</p>
      <p><strong>Date:</strong> {inv['created_at']}</p>
    </div>
    """
    return page(f"Invoice #{inv['id']}", body, req)


def account_page_html(user, message=None, flag_html=""):
    msg = f'<div class="msg-ok">{templates.e(message)}</div>' if message else ""
    return f"""
    <h1>Account Settings</h1>
    {msg}
    {flag_html}
    <div class="card form-narrow">
      <p><strong>Username:</strong> {templates.e(user['username'])}</p>
      <p><strong>Current email:</strong> {templates.e(user['email'])}</p>
      <form method="POST" action="/account/update">
        <label for="email">New email</label>
        <input id="email" name="email" type="email" placeholder="{templates.e(user['email'])}">
        <button class="btn" type="submit">Update email</button>
      </form>
    </div>
    """


@route("GET", "/account")
def account_get(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    return page("Account", account_page_html(user), req)


def account_update(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    new_email = req.get("email", "").strip()
    changed_via_get = req.method == "GET" and "email" in req.query and new_email
    if new_email:
        conn = db.get_conn()
        conn.execute("UPDATE users SET email=? WHERE id=?", (new_email, user["id"]))
        conn.commit()
        conn.close()
        conn2 = db.get_conn()
        user = conn2.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        conn2.close()
    flag_html = templates.flag_banner("FLAG{csrf_email_changed}") if changed_via_get else ""
    return page("Account", account_page_html(user, message="Email updated." if new_email else None, flag_html=flag_html), req)


route("GET", "/account/update")(account_update)
route("POST", "/account/update")(account_update)


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
      <form method="POST" action="/support/new" enctype="multipart/form-data" class="form-narrow">
        <label for="subject">Subject</label>
        <input id="subject" name="subject" required>
        <label for="body">Message</label>
        <textarea id="body" name="body" rows="4" required></textarea>
        <label for="attachment">Attachment (optional)</label>
        <input id="attachment" name="attachment" type="file">
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
    attachment_name = None
    if "attachment" in req.files:
        f = req.files["attachment"]
        filename = f["filename"]
        if filename:
            os.makedirs(config.TICKET_DIR, exist_ok=True)
            dest = os.path.join(config.TICKET_DIR, filename)
            with open(dest, "wb") as out:
                out.write(f["content"])
            attachment_name = filename
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO tickets (user_id, subject, body, status, attachment, created_at) VALUES (?,?,?,?,?,datetime('now'))",
        (user["id"], subject, body_txt, "open", attachment_name),
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
    attach_html = ""
    if t["attachment"]:
        attach_html = (
            f"<p><strong>Attachment:</strong> "
            f"<a href='/support/download?ticket={t['id']}&file={templates.e(t['attachment'])}'>{templates.e(t['attachment'])}</a></p>"
        )
    replies_html = "".join(
        f'<div class="comment"><strong>{templates.e(r["author"])}:</strong> {templates.e(r["body"])}</div>'
        for r in replies
    )
    body = f"""
    <h1>Ticket #{t['id']}: {templates.e(t['subject'])}</h1>
    <div class="card">
      <p><span class="badge {t['status']}">{t['status']}</span></p>
      <div class="comment">{templates.e(t['body'])}</div>
      {attach_html}
      {replies_html}
    </div>
    """
    return page(f"Ticket #{t['id']}", body, req)


@route("GET", "/support/download")
def support_download(req):
    user = req.current_user
    if not user:
        return redirect("/login")
    filename = req.query.get("file", "")
    if not filename:
        return not_found()
    path = os.path.join(config.TICKET_DIR, filename)
    if not os.path.isfile(path):
        return not_found()
    with open(path, "rb") as f:
        data = f.read()
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return Response(data, content_type=ctype)


# ---------------------------------------------------------------------------
# admin
# ---------------------------------------------------------------------------

@route("GET", "/admin")
def admin_dashboard(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    users_c = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    tickets_c = conn.execute("SELECT COUNT(*) c FROM tickets").fetchone()["c"]
    apps_c = conn.execute("SELECT COUNT(*) c FROM job_applications").fetchone()["c"]
    conn.close()
    body = f"""
    {templates.flag_banner("FLAG{broken_access_control_admin_reached}")}
    <h1>Ops Admin Dashboard</h1>
    <div class="card">
      <p>Users: {users_c} &middot; Tickets: {tickets_c} &middot; Applications: {apps_c}</p>
      <p>
        <a href="/admin/users">Manage users</a> &middot;
        <a href="/admin/tickets">Support tickets</a> &middot;
        <a href="/admin/applications">Job applications</a> &middot;
        <a href="/admin/tools/fetch">Carrier label fetch tool</a>
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
      <table><tr><th>ID</th><th>Username</th><th>Email</th><th>Password Hash</th><th>Role</th></tr>{rows_html}</table>
    </div>
    """
    return page("Admin - Users", body, req)


ADMIN_FLAG_JS = '<script>window.ADMIN_FLAG = "FLAG{stored_xss_admin_flag_exfiltrated}";</script>'


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
    {ADMIN_FLAG_JS}
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
    attach_html = ""
    if t["attachment"]:
        attach_html = (
            f"<p><strong>Attachment:</strong> "
            f"<a href='/support/download?ticket={t['id']}&file={templates.e(t['attachment'])}'>{templates.e(t['attachment'])}</a></p>"
        )
    replies_html = "".join(
        f'<div class="comment"><strong>{templates.e(r["author"])}:</strong> {templates.e(r["body"])}</div>'
        for r in replies
    )
    body = f"""
    {ADMIN_FLAG_JS}
    <h1>Ticket #{t['id']}: {templates.e(t['subject'])}</h1>
    <div class="card">
      <p><strong>From:</strong> {templates.e(t['username'])} &middot; <span class="badge {t['status']}">{t['status']}</span></p>
      <div class="comment">{t['body']}</div>
      {attach_html}
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
            (ticket_id, "NovaFreight Support", body_txt),
        )
        conn.commit()
        conn.close()
    return redirect(f"/admin/tickets/{ticket_id}")


route("POST", "/admin/tickets/<ticket_id>/reply")(admin_ticket_reply)


@route("GET", "/admin/applications")
def admin_applications(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    conn = db.get_conn()
    rows = conn.execute("SELECT * FROM job_applications ORDER BY id DESC").fetchall()
    conn.close()
    cells = []
    for r in rows:
        if r["resume_filename"]:
            link = f"<a href='/uploads/resumes/{templates.e(r['resume_filename'])}' target='_blank'>{templates.e(r['resume_filename'])}</a>"
        else:
            link = "-"
        cells.append(
            f"<tr><td>{templates.e(r['name'])}</td><td>{templates.e(r['email'])}</td>"
            f"<td>{templates.e((r['cover_letter'] or '')[:80])}</td><td>{link}</td></tr>"
        )
    rows_html = "".join(cells) or "<tr><td colspan='4'>No applications yet.</td></tr>"
    body = f"""
    <h1>Job Applications</h1>
    <div class="card">
      <table><tr><th>Name</th><th>Email</th><th>Cover letter</th><th>Resume</th></tr>{rows_html}</table>
    </div>
    """
    return page("Admin - Applications", body, req)


def fetch_tool_html(result_html="", url=""):
    return f"""
    <h1>Carrier Label Fetch Tool</h1>
    <div class="card">
      <p class="footer-note">Fetches a shipment label preview from a carrier-provided URL for QA review.</p>
      <form method="POST" action="/admin/tools/fetch" class="form-narrow">
        <label for="url">Carrier URL</label>
        <input id="url" name="url" value="{templates.e(url)}" placeholder="https://carrier.example/label/12345">
        <button class="btn" type="submit">Fetch preview</button>
      </form>
    </div>
    <div class="card">{result_html}</div>
    """


@route("GET", "/admin/tools/fetch")
def admin_fetch_get(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    return page("Admin - Fetch Tool", fetch_tool_html(), req)


def admin_fetch_post(req):
    if not is_admin(req):
        return forbidden("Admins only.")
    url = req.form.get("url", "").strip()
    result_html = ""
    if url:
        try:
            r = urllib.request.Request(
                url,
                headers={"X-Internal-Token": config.INTERNAL_API_TOKEN, "User-Agent": "NovaFreight-CarrierFetch/1.0"},
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
    return page("Admin - Fetch Tool", fetch_tool_html(result_html=result_html, url=url), req)


route("POST", "/admin/tools/fetch")(admin_fetch_post)


@route("GET", "/internal/warehouse-api")
def internal_warehouse(req):
    token = req.headers.get("x-internal-token")
    if token != config.INTERNAL_API_TOKEN:
        return forbidden("Internal use only.")
    payload = {
        "warehouse": "NF-DC-EAST-3",
        "inventory_value_usd": 18250000,
        "note": "This endpoint is for the internal carrier mesh only.",
        "flag": "FLAG{ssrf_internal_warehouse_access}",
    }
    return Response(json.dumps(payload, indent=2), content_type="application/json")


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
        return Response(json.dumps({"error": "invalid credentials"}), status=401, content_type="application/json")
    token = jwt_encode({"sub": row["id"], "username": row["username"], "role": row["role"], "iat": int(time.time())})
    return Response(json.dumps({"token": token}), content_type="application/json")


route("POST", "/api/login")(api_login)


def api_me(req):
    payload = bearer_payload(req)
    if not payload:
        return Response(json.dumps({"error": "unauthorized"}), status=401, content_type="application/json")
    return Response(json.dumps({"user": payload}), content_type="application/json")


route("GET", "/api/me")(api_me)


def api_admin_stats(req):
    payload = bearer_payload(req)
    if not payload or payload.get("role") != "admin":
        return Response(json.dumps({"error": "unauthorized"}), status=403, content_type="application/json")
    return Response(
        json.dumps(
            {
                "total_revenue_usd": 4820133.12,
                "active_shipments": 214,
                "flag": "FLAG{jwt_alg_none_forgery}",
            }
        ),
        content_type="application/json",
    )


route("GET", "/api/admin/stats")(api_admin_stats)
