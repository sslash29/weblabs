"""MeridianPay Ops Backup Relay -- a minimal, real (passive-mode-only) FTP
server left running from a 2019 ops-host migration that was never finished.
Anonymous access is accepted for any USER/PASS combination -- that's the
intended finding. It serves whatever is in app/config.BACKUP_DIR.

Speaks enough real FTP (USER/PASS/SYST/PWD/TYPE/PASV/LIST/RETR/QUIT) that
standard clients (curl, lftp, the `ftp` CLI, FileZilla) all work against it.
"""
import os
import socket
import threading
import time

from app import config


def _fmt_listing(path):
    lines = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        size = st.st_size
        mtime = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
        lines.append(f"-rw-r--r-- 1 ops ops {size:>10} {mtime} {name}")
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def _open_pasv():
    data_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_srv.bind((config.HOST, 0))
    data_srv.listen(1)
    return data_srv


def _handle_client(conn):
    conn.settimeout(120)
    rfile = conn.makefile("rb", buffering=0)

    def send(line):
        conn.sendall((line + "\r\n").encode())

    data_srv = None
    try:
        send("220 MeridianPay Ops Backup Relay (legacy build 2019) ready.")
        while True:
            raw = rfile.readline()
            if not raw:
                break
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1].strip() if len(parts) > 1 else ""

            if cmd == "USER":
                send("331 Password required, anonymous access accepted.")
            elif cmd == "PASS":
                send("230 Login successful.")
            elif cmd == "SYST":
                send("215 UNIX Type: L8")
            elif cmd == "PWD":
                send('257 "/" is the current directory.')
            elif cmd in ("TYPE", "OPTS"):
                send("200 OK.")
            elif cmd == "CWD":
                send("250 Directory unchanged (flat layout, no subdirectories).")
            elif cmd == "PASV":
                if data_srv:
                    try:
                        data_srv.close()
                    except OSError:
                        pass
                data_srv = _open_pasv()
                port = data_srv.getsockname()[1]
                p1, p2 = port // 256, port % 256
                ip_parts = config.HOST.split(".")
                send(f"227 Entering Passive Mode ({','.join(ip_parts)},{p1},{p2}).")
            elif cmd == "LIST" or cmd == "NLST":
                if not data_srv:
                    send("425 Use PASV first.")
                    continue
                send("150 Opening ASCII mode data connection for file list.")
                try:
                    data_srv.settimeout(10)
                    dconn, _addr = data_srv.accept()
                    dconn.sendall(_fmt_listing(config.BACKUP_DIR).encode())
                    dconn.close()
                    send("226 Transfer complete.")
                except OSError:
                    send("425 Data connection failed.")
                finally:
                    data_srv.close()
                    data_srv = None
            elif cmd == "RETR":
                if not data_srv:
                    send("425 Use PASV first.")
                    continue
                filename = os.path.basename(arg)
                path = os.path.join(config.BACKUP_DIR, filename)
                if not filename or not os.path.isfile(path):
                    send("550 File not found.")
                    data_srv.close()
                    data_srv = None
                    continue
                send(f"150 Opening BINARY mode data connection for {filename}.")
                try:
                    data_srv.settimeout(10)
                    dconn, _addr = data_srv.accept()
                    with open(path, "rb") as fh:
                        dconn.sendall(fh.read())
                    dconn.close()
                    send("226 Transfer complete.")
                except OSError:
                    send("425 Data connection failed.")
                finally:
                    data_srv.close()
                    data_srv = None
            elif cmd == "QUIT":
                send("221 Goodbye.")
                break
            else:
                send("502 Command not implemented.")
    except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
        pass
    finally:
        if data_srv:
            try:
                data_srv.close()
            except OSError:
                pass
        try:
            conn.close()
        except OSError:
            pass


def run():
    os.makedirs(config.BACKUP_DIR, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((config.HOST, config.BACKUP_RELAY_PORT))
    srv.listen(20)
    print(f"Ops Backup Relay (FTP-style, anonymous) listening on {config.HOST}:{config.BACKUP_RELAY_PORT}")
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=_handle_client, args=(conn,), daemon=True).start()
