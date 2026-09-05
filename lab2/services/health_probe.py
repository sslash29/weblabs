"""Trivial health/status probe -- sends a banner on connect and closes.
A warm-up recon target: nmap -sV / a plain `nc` banner grab is enough to
fingerprint it and pick up the hint pointing at the backup relay.
"""
import socket
import threading

from app import config

BANNER = (
    "MeridianPay-HealthProbe/2.3 (internal-build 2019-legacy)\r\n"
    "status: ok\r\n"
    "hint: legacy ops backup relay still reachable on this host (see ticket OPS-4471)\r\n"
    "FLAG{service_banner_recon}\r\n"
)


def _handle_client(conn):
    try:
        conn.settimeout(5)
        conn.sendall(BANNER.encode())
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def run():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((config.HOST, config.HEALTH_PROBE_PORT))
    srv.listen(20)
    print(f"Health probe listening on {config.HOST}:{config.HEALTH_PROBE_PORT}")
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()
