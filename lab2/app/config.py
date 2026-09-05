import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.path.join(BASE_DIR, "data", "meridianpay.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
KYC_DIR = os.path.join(UPLOAD_DIR, "kyc")
TICKET_DIR = os.path.join(UPLOAD_DIR, "tickets")
STATIC_DIR = os.path.join(BASE_DIR, "static")
STATEMENT_DIR = os.path.join(BASE_DIR, "data", "statements")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
COLLECT_LOG = os.path.join(BASE_DIR, "data", "collected_exfil.log")
CORE_FLAG_FILE = os.path.join(BASE_DIR, "core_flag.txt")
TRAVERSAL_HINT_FILE = os.path.join(BASE_DIR, "data", "internal_notes.txt")

HOST = "127.0.0.1"
WEB_PORT = 8000            # public web app: marketing site, online banking, admin console, mobile API
OPS_CONSOLE_PORT = 8081    # "internal" change-management / diagnostics tool, mistakenly reachable
BACKUP_RELAY_PORT = 2121   # legacy FTP-style backup transfer service, anonymous access left on
HEALTH_PROBE_PORT = 9090   # trivial TCP health/status banner service

# Hardened relative to a typical "everything leaks" training app: DEBUG is
# off, no stack traces, no obvious /backup/*.bak on the web app itself.
# Secrets below are NOT reachable from the web app (port 8000) by design —
# they only leak via the backup relay (2121), which is the intended
# "network misconfiguration" finding that unlocks several web-app objectives.
DEBUG = False

JWT_SECRET = "mp$hmac_9f1c_legacy_2019"
INTERNAL_LEDGER_TOKEN = "mp-ledger-internal-7f3a9c"

OPS_CONSOLE_USER = "ops"
OPS_CONSOLE_PASS = "ChangeMe2019!"

DB_SVC_USER = "meridianpay_svc"
DB_SVC_PASS = "Svc_Pass_2019!"

os.environ.setdefault("LAB_CORE_FLAG", "FLAG{rce_core_flag_captured}")
CORE_FLAG = os.environ["LAB_CORE_FLAG"]
