#!/usr/bin/env python3
"""
Meridian Global Freight - Internal Operations Service
Not intended for external exposure. Access restricted to the internal
service network. See ops runbook OPS-1147 for the migration plan away
from the legacy render endpoint.
"""
import base64
import json
import pickle
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_plus

FLAG4 = "MERIDIAN{ssrf_p1v0t_t0_1nt3rn4l}"


class Handler(BaseHTTPRequestHandler):
    server_version = "MeridianInternal/0.9"

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/status":
            self._json(200, {
                "service": "meridian-internal-ops",
                "version": "0.9.1-beta",
                "flag": FLAG4,
                "note": "TODO: remove /debug/render before prod launch (tracked in OPS-1147)"
            })
        elif self.path == "/":
            self._json(200, {"service": "meridian-internal-ops", "status": "up"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/debug/render":
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length)
            try:
                text = raw.decode("utf-8", errors="strict")
            except Exception:
                self._json(400, {"error": "bad body"})
                return

            data = text.strip()
            if data.startswith("data="):
                data = unquote_plus(data[len("data="):])
            else:
                # allow raw JSON {"data": "..."} too
                try:
                    parsed = json.loads(text)
                    data = parsed.get("data", data)
                except Exception:
                    pass

            try:
                blob = base64.b64decode(data)
                obj = pickle.loads(blob)  # legacy state renderer - trusted internal callers only
                self._json(200, {"result": repr(obj)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 5000), Handler)
    print("internal-ops listening on :5000")
    server.serve_forever()
