import hashlib
import os
import sqlite3
from datetime import datetime

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    account_number TEXT UNIQUE NOT NULL,
    nickname TEXT NOT NULL,
    acct_type TEXT NOT NULL,
    balance REAL NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    counterparty TEXT NOT NULL,
    amount REAL NOT NULL,
    memo TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    bank_name TEXT,
    account_number TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ticket_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kyc_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    doc_type TEXT NOT NULL,
    filename TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS internal_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    value TEXT NOT NULL
);
"""


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def get_conn():
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(force=False):
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    os.makedirs(config.KYC_DIR, exist_ok=True)
    os.makedirs(config.TICKET_DIR, exist_ok=True)
    os.makedirs(config.STATEMENT_DIR, exist_ok=True)
    os.makedirs(config.BACKUP_DIR, exist_ok=True)

    fresh = force or not os.path.exists(config.DB_PATH)
    if force and os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)

    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()

    if fresh:
        seed(conn)
    else:
        write_statements(conn)
    conn.close()

    write_backup_files()
    write_internal_notes()
    write_core_flag()


def seed(conn):
    now = lambda: datetime.utcnow().isoformat(timespec="seconds")

    users = [
        ("admin", "ops-admin@meridianpay.example", md5("Adm1n_Ops#2024"), "admin"),
        ("alice", "alice.nguyen@customer.example", md5("alice123"), "customer"),
        ("bob", "bob.reyes@customer.example", md5("bob2024"), "customer"),
        ("carol", "carol.kim@customer.example", md5("carolpass"), "customer"),
        ("svc_reports", "svc-reports@meridianpay.example", md5("Passw0rd1"), "service"),
    ]
    for username, email, pwhash, role in users:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            (username, email, pwhash, role, now()),
        )

    accounts = [
        # user_id, account_number, nickname, type, balance, notes
        (1, "MP-00000001", "MeridianPay Corporate Treasury", "treasury", 2450000.00,
         "CONFIDENTIAL - operating reserve, internal use only, do not disclose to customers. "
         "FLAG{idor_treasury_account_exposed}"),
        (2, "MP-10029341", "Alice - Everyday Checking", "checking", 4230.18, None),
        (3, "MP-10029342", "Bob - Everyday Checking", "checking", 912.44, None),
        (3, "MP-10029343", "Bob - High-Yield Savings", "savings", 15000.00, None),
        (4, "MP-10029344", "Carol - Everyday Checking", "checking", 102.90, None),
    ]
    acct_ids = {}
    for user_id, acct_no, nick, atype, balance, notes in accounts:
        cur = conn.execute(
            "INSERT INTO accounts (user_id, account_number, nickname, acct_type, balance, notes, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (user_id, acct_no, nick, atype, balance, notes, now()),
        )
        acct_ids[acct_no] = cur.lastrowid

    transactions = [
        ("MP-00000001", "Payroll Processor Inc.", -184200.00, "Biweekly payroll run"),
        ("MP-00000001", "Federal Reserve ACH", 500000.00, "Treasury funding transfer"),
        ("MP-10029341", "Greenfield Grocers", -84.12, "Card purchase"),
        ("MP-10029341", "Employer Direct Deposit", 2100.00, "Payroll"),
        ("MP-10029342", "City Power & Light", -110.55, "Utility bill"),
        ("MP-10029343", "Transfer from Checking", 500.00, "Savings top-up"),
        ("MP-10029344", "Riverside Coffee Co.", -6.25, "Card purchase"),
    ]
    for acct_no, counterparty, amount, memo in transactions:
        conn.execute(
            "INSERT INTO transactions (account_id, counterparty, amount, memo, created_at) VALUES (?,?,?,?,?)",
            (acct_ids[acct_no], counterparty, amount, memo, now()),
        )

    conn.execute(
        "INSERT INTO recipients (user_id, name, bank_name, account_number, created_at) VALUES (?,?,?,?,?)",
        (2, "Bob Reyes", "MeridianPay", "MP-10029342", now()),
    )

    conn.execute(
        "INSERT INTO tickets (user_id, subject, body, status, created_at) VALUES (?,?,?,?,?)",
        (2, "Can't find last month's statement",
         "Hi, I don't see my August statement in the portal, could someone check?",
         "open", now()),
    )

    conn.execute(
        "INSERT INTO internal_flags (name, value) VALUES (?,?)",
        ("blind_sqli_probe", "FLAG{sqli_transactions_data_extracted}"),
    )

    conn.commit()
    write_statements(conn)


def write_statements(conn):
    """Generates the per-account plaintext statement files served by
    /statement/download. The download route itself does not sanitize the
    'file' query param against these -- that's the path traversal bug."""
    os.makedirs(config.STATEMENT_DIR, exist_ok=True)
    accounts = conn.execute("SELECT * FROM accounts").fetchall()
    for a in accounts:
        txns = conn.execute(
            "SELECT * FROM transactions WHERE account_id=? ORDER BY id", (a["id"],)
        ).fetchall()
        lines = [
            f"MeridianPay Account Statement",
            f"Account: {a['nickname']} ({a['account_number']})",
            f"Balance: ${a['balance']:,.2f}",
            "",
            f"{'Date':<22}{'Counterparty':<32}{'Amount':>12}",
        ]
        for t in txns:
            lines.append(f"{t['created_at']:<22}{t['counterparty']:<32}{t['amount']:>12,.2f}")
        path = os.path.join(config.STATEMENT_DIR, f"statement_{a['id']}.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")


def write_backup_files():
    """Simulates a legacy nightly backup job dropping files for the ops
    backup relay (see services/backup_relay.py) to serve over its
    FTP-like protocol. NOT reachable from the web app on port 8000."""
    os.makedirs(config.BACKUP_DIR, exist_ok=True)

    sql_dump = f"""-- MeridianPay nightly DB export -- meridianpay_core -- DO NOT COMMIT
-- generated by legacy-backup-job v1 (2019), superseded, left running

INSERT INTO users (username, email, password_hash, role) VALUES
  ('admin', 'ops-admin@meridianpay.example', '{md5("Adm1n_Ops#2024")}', 'admin'),
  ('alice', 'alice.nguyen@customer.example', '{md5("alice123")}', 'customer'),
  ('bob', 'bob.reyes@customer.example', '{md5("bob2024")}', 'customer'),
  ('carol', 'carol.kim@customer.example', '{md5("carolpass")}', 'customer');

-- FLAG{{anon_ftp_backup_exposed}}
"""
    with open(os.path.join(config.BACKUP_DIR, "meridianpay_db_backup.sql.bak"), "w") as f:
        f.write(sql_dump)

    env_bak = f"""# .env.ops -- legacy ops host, migrated 2019, decommission pending
JWT_SECRET={config.JWT_SECRET}
INTERNAL_LEDGER_TOKEN={config.INTERNAL_LEDGER_TOKEN}
DB_SVC_USER={config.DB_SVC_USER}
DB_SVC_PASS={config.DB_SVC_PASS}
OPS_CONSOLE_USER={config.OPS_CONSOLE_USER}
OPS_CONSOLE_PASS={config.OPS_CONSOLE_PASS}
OPS_CONSOLE_URL=http://127.0.0.1:{config.OPS_CONSOLE_PORT}/
NOTE=rotate these before this host is decommissioned -- ticket OPS-4471, opened 2019, still open
"""
    with open(os.path.join(config.BACKUP_DIR, ".env.ops.bak"), "w") as f:
        f.write(env_bak)

    readme = """This directory is served by the legacy Ops Backup Relay (see the service
listening on tcp/2121). It mirrors nightly DB and config backups from the
old ops host that was never decommissioned. Anonymous read access was left
enabled "temporarily" during the 2019 migration.
"""
    with open(os.path.join(config.BACKUP_DIR, "README.txt"), "w") as f:
        f.write(readme)


def write_internal_notes():
    os.makedirs(os.path.dirname(config.TRAVERSAL_HINT_FILE), exist_ok=True)
    with open(config.TRAVERSAL_HINT_FILE, "w") as f:
        f.write(
            "Internal ops note: statement export tool reads straight from the "
            "filesystem path it's given. Someone should sandbox that. "
            "-- filed as tech debt, not prioritized.\n"
        )


def write_core_flag():
    with open(config.CORE_FLAG_FILE, "w") as f:
        f.write(config.CORE_FLAG + "\n")
