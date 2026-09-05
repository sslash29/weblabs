import email
import html
import json
import re
import secrets
import threading
import traceback
from http import cookies as http_cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

from . import config

ROUTES = []  # (method, compiled_regex, handler, param_names)
SESSIONS = {}  # sid -> {"user_id": int}
_SESSION_LOCK = threading.Lock()


def route(method, path):
    param_names = re.findall(r"<(\w+)>", path)
    pattern = re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", path)
    regex = re.compile(f"^{pattern}$")

    def decorator(fn):
        ROUTES.append((method.upper(), regex, fn, param_names))
        return fn

    return decorator


def new_session(user_id):
    sid = secrets.token_hex(24)
    with _SESSION_LOCK:
        SESSIONS[sid] = {"user_id": user_id}
    return sid


def get_session(sid):
    with _SESSION_LOCK:
        return SESSIONS.get(sid)


def drop_session(sid):
    with _SESSION_LOCK:
        SESSIONS.pop(sid, None)


class Request:
    def __init__(self, method, path, query, headers, cookies, body_bytes):
        self.method = method
        self.path = path
        self.query = query  # dict[str, str] (first value)
        self.headers = headers  # lowercased keys
        self.cookies = cookies  # dict[str, str]
        self.body_bytes = body_bytes
        self.form = {}
        self.files = {}  # name -> {"filename":..., "content":bytes, "content_type":...}
        self.json = None
        self._parse_body()

    def _parse_body(self):
        ctype = self.headers.get("content-type", "")
        if not self.body_bytes:
            return
        if ctype.startswith("application/x-www-form-urlencoded"):
            qs = parse_qs(self.body_bytes.decode(errors="replace"), keep_blank_values=True)
            self.form = {k: v[0] for k, v in qs.items()}
        elif ctype.startswith("multipart/form-data"):
            self._parse_multipart(ctype)
        elif ctype.startswith("application/json"):
            try:
                self.json = json.loads(self.body_bytes.decode(errors="replace"))
            except Exception:
                self.json = None

    def _parse_multipart(self, ctype):
        header_bytes = f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode()
        msg = email.message_from_bytes(header_bytes + self.body_bytes)
        if not msg.is_multipart():
            return
        for part in msg.get_payload():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            if filename:
                self.files[name] = {
                    "filename": filename,
                    "content": part.get_payload(decode=True) or b"",
                    "content_type": part.get_content_type(),
                }
            else:
                payload = part.get_payload(decode=True) or b""
                self.form[name] = payload.decode(errors="replace")

    def get(self, key, default=""):
        return self.form.get(key, self.query.get(key, default))

    @property
    def current_user(self):
        sid = self.cookies.get("sid")
        if not sid:
            return None
        sess = get_session(sid)
        if not sess:
            return None
        from . import db
        conn = db.get_conn()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
        conn.close()
        return row


class Response:
    def __init__(self, body="", status=200, headers=None, content_type="text/html; charset=utf-8"):
        self.status = status
        self.headers = dict(headers or {})
        self.headers.setdefault("Content-Type", content_type)
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.set_cookies = []  # list of raw Set-Cookie header strings

    def set_cookie(self, name, value, httponly=True, path="/", max_age=None, samesite=None):
        c = http_cookies.SimpleCookie()
        c[name] = value
        c[name]["path"] = path
        if httponly:
            c[name]["httponly"] = True
        if max_age is not None:
            c[name]["max-age"] = max_age
        if samesite:
            c[name]["samesite"] = samesite
        raw = c.output(header="").strip()
        self.set_cookies.append(raw)
        return self


def redirect(location, status=302):
    return Response("", status=status, headers={"Location": location})


def not_found():
    return Response("<h1>404 Not Found</h1>", status=404)


def forbidden(msg="403 Forbidden"):
    return Response(f"<h1>{html.escape(msg)}</h1>", status=403)


def _parse_cookies(header_val):
    if not header_val:
        return {}
    c = http_cookies.SimpleCookie()
    try:
        c.load(header_val)
    except Exception:
        return {}
    return {k: v.value for k, v in c.items()}


class Handler(BaseHTTPRequestHandler):
    server_version = "MeridianPayWeb/3.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _dispatch(self, method):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        raw_qs = parse_qs(parsed.query, keep_blank_values=True)
        query = {k: v[0] for k, v in raw_qs.items()}
        headers = {k.lower(): v for k, v in self.headers.items()}
        cookies = _parse_cookies(self.headers.get("Cookie"))

        length = int(headers.get("content-length", 0) or 0)
        body_bytes = self.rfile.read(length) if length else b""

        req = Request(method, path, query, headers, cookies, body_bytes)

        candidates = [r for r in ROUTES if r[0] == method and r[1].match(path)]
        candidates.sort(key=lambda r: 0 if not r[3] else 1)

        if candidates:
            _, regex, fn, param_names = candidates[0]
            kwargs = regex.match(path).groupdict()
            try:
                resp = fn(req, **kwargs)
            except Exception:
                if config.DEBUG:
                    tb = traceback.format_exc()
                    body = (
                        "<h1>500 Internal Server Error</h1>"
                        f"<pre>{html.escape(tb)}</pre>"
                    )
                    resp = Response(body, status=500)
                else:
                    resp = Response("<h1>500 Internal Server Error</h1>", status=500)
            self._write(resp)
            return

        self._write(not_found())

    def _write(self, resp: Response):
        body = resp.body
        self.send_response(resp.status)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        for sc in resp.set_cookies:
            self.send_header("Set-Cookie", sc)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def run():
    import app.views  # noqa: F401  (registers routes)
    server = ThreadingHTTPServer((config.HOST, config.WEB_PORT), Handler)
    print(f"MeridianPay web app running at http://{config.HOST}:{config.WEB_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
