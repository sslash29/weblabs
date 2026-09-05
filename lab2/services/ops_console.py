"""Core Banking Ops Console -- an internal change-management / diagnostics
tool for banking ops engineers that should live on a restricted management
VLAN, but is reachable on this host same as everything else. Protected by
weak default credentials, and its network diagnostics "ping" tool shells
out with the host field unsanitized.
"""
import html
import os
import secrets
import subprocess
import threading
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from app import config

SESSIONS = set()


def e(s):
    return html.escape(str(s), quote=True)


PAGE_CSS = """
body { font-family: Consolas, "Courier New", monospace; background: #12181c; color: #d7dee3;
       margin: 0; padding: 0; }
.wrap { max-width: 720px; margin: 40px auto; padding: 0 20px; }
h1 { color: #7fd3c7; font-size: 1.3rem; border-bottom: 1px solid #2a353c; padding-bottom: 10px; }
.card { background: #1a2228; border: 1px solid #2a353c; border-radius: 6px; padding: 18px 22px; margin-bottom: 18px; }
input { width: 100%; padding: 8px 10px; margin-bottom: 12px; background: #0e1418; border: 1px solid #2a353c;
        color: #d7dee3; border-radius: 4px; font-family: inherit; }
label { display: block; font-size: 0.8rem; color: #8fa0aa; margin-bottom: 4px; }
button { background: #2a7f70; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
a { color: #7fd3c7; }
pre { background: #0e1418; padding: 12px; border-radius: 4px; overflow-x: auto; }
.flag { background: #12302a; color: #ffd166; border: 1px dashed #ffd166; padding: 10px 14px;
        border-radius: 6px; margin-bottom: 16px; }
.err { color: #ff8a80; }
.footer-note { color: #6b7b84; font-size: 0.8rem; }
"""


def layout(title, body):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>{e(title)} · Core Banking Ops Console</title>
<style>{PAGE_CSS}</style></head>
<body><div class="wrap">
<h1>Core Banking Ops Console</h1>
{body}
</div></body></html>"""


def flag(text):
    return f'<div class="flag">Objective complete: <code>{e(text)}</code></div>'


class Handler(BaseHTTPRequestHandler):
    server_version = "MeridianPay-OpsConsole/0.9-legacy"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _cookies(self):
        c = http_cookies.SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:
            return {}
        return {k: v.value for k, v in c.items()}

    def _authed(self):
        sid = self._cookies().get("opssid")
        return bool(sid) and sid in SESSIONS

    def _send(self, body, status=200, set_cookie=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_form(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        return {k: v[0] for k, v in parse_qs(raw.decode(errors="replace"), keep_blank_values=True).items()}

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._redirect("/dashboard" if self._authed() else "/login")
        if path == "/login":
            return self._send(layout("Login", self._login_form()))
        if path == "/dashboard":
            if not self._authed():
                return self._redirect("/login")
            return self._send(layout("Dashboard", self._dashboard()))
        if path == "/diagnostics":
            if not self._authed():
                return self._redirect("/login")
            return self._send(layout("Diagnostics", self._diagnostics_form()))
        if path == "/logout":
            return self._redirect("/login")
        self._send("<h1>404</h1>", status=404)

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._read_form()
        if path == "/login":
            user = form.get("username", "")
            pw = form.get("password", "")
            if user == config.OPS_CONSOLE_USER and pw == config.OPS_CONSOLE_PASS:
                sid = secrets.token_hex(16)
                SESSIONS.add(sid)
                c = http_cookies.SimpleCookie()
                c["opssid"] = sid
                c["opssid"]["path"] = "/"
                c["opssid"]["httponly"] = True
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", c.output(header="").strip())
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(layout("Login", self._login_form(error="Invalid credentials.")))
        if path == "/diagnostics/ping":
            if not self._authed():
                return self._redirect("/login")
            host = form.get("host", "")
            output = self._run_ping(host)
            return self._send(layout("Diagnostics", self._diagnostics_form(host=host, output=output)))
        self._send("<h1>404</h1>", status=404)

    # -- pages --------------------------------------------------------------

    def _login_form(self, error=None):
        err = f'<p class="err">{e(error)}</p>' if error else ""
        return f"""
        {err}
        <div class="card">
          <form method="POST" action="/login">
            <label for="username">Username</label>
            <input id="username" name="username">
            <label for="password">Password</label>
            <input id="password" name="password" type="password">
            <button type="submit">Log in</button>
          </form>
          <p class="footer-note">Internal tool. Ops team only.</p>
        </div>
        """

    def _dashboard(self):
        return f"""
        {flag("FLAG{default_creds_ops_console}")}
        <div class="card">
          <p>Welcome back. This console manages change tickets and low-level network
          diagnostics for the core banking environment.</p>
          <p><a href="/diagnostics">Network diagnostics</a> &middot; <a href="/logout">Log out</a></p>
        </div>
        """

    def _diagnostics_form(self, host="", output=None):
        out_html = f"<div class='card'><pre>{e(output)}</pre></div>" if output is not None else ""
        return f"""
        <div class="card">
          <p class="footer-note">Runs a single ICMP probe against a host on the internal network.</p>
          <form method="POST" action="/diagnostics/ping">
            <label for="host">Host</label>
            <input id="host" name="host" value="{e(host)}" placeholder="127.0.0.1">
            <button type="submit">Ping</button>
          </form>
        </div>
        {out_html}
        """

    def _run_ping(self, host):
        # BUG (CWE-78): host is dropped straight into a shell command.
        cmd = f"ping -c 1 -W 2 {host}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=8, text=True)
            return (result.stdout or "") + (result.stderr or "")
        except Exception as ex:
            return str(ex)


def run():
    server = ThreadingHTTPServer((config.HOST, config.OPS_CONSOLE_PORT), Handler)
    print(f"Core Banking Ops Console listening on http://{config.HOST}:{config.OPS_CONSOLE_PORT}")
    server.serve_forever()
