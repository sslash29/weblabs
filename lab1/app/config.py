import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "novafreight.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESUME_DIR = os.path.join(UPLOAD_DIR, "resumes")
TICKET_DIR = os.path.join(UPLOAD_DIR, "tickets")
STATIC_DIR = os.path.join(BASE_DIR, "static")
FLAG_FILE = os.path.join(BASE_DIR, "flag.txt")
COLLECT_LOG = os.path.join(BASE_DIR, "data", "collected_exfil.log")

HOST = "127.0.0.1"
PORT = 8000

# Intentionally weak/leaked secrets for the lab. Reachable in-app at
# /backup/config.py.bak (a "misplaced" ops backup file).
SECRET_KEY = "nf_dev_9f8a3c2e1b_secret"
INTERNAL_API_TOKEN = "nf-internal-7a2e9c"
DEBUG = True

os.environ.setdefault("LAB_RCE_FLAG", "FLAG{ssti_sandbox_escape_rce}")
RCE_PROOF_FLAG = os.environ["LAB_RCE_FLAG"]
