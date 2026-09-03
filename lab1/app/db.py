import hashlib
import os
import sqlite3
from datetime import datetime, timedelta

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

CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    description TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shipments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    tracking_number TEXT UNIQUE NOT NULL,
    origin TEXT,
    destination TEXT,
    status TEXT,
    invoice_id INTEGER
);

CREATE TABLE IF NOT EXISTS blog_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    attachment TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ticket_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    cover_letter TEXT,
    resume_filename TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
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
    os.makedirs(config.RESUME_DIR, exist_ok=True)
    os.makedirs(config.TICKET_DIR, exist_ok=True)

    fresh = force or not os.path.exists(config.DB_PATH)
    if force and os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)

    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()

    if fresh:
        seed(conn)
    conn.close()


def seed(conn):
    now = lambda: datetime.utcnow().isoformat(timespec="seconds")

    users = [
        ("admin", "ops-admin@novafreight.example", md5("admin123"), "admin"),
        ("alice", "alice@customerco.example", md5("alice123"), "customer"),
        ("bob", "bob@shippersinc.example", md5("bob2024"), "customer"),
        ("carol", "carol@retailhub.example", md5("carolpass"), "customer"),
    ]
    for username, email, pwhash, role in users:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            (username, email, pwhash, role, now()),
        )

    invoices = [
        (1, 48500.00, "Q4 Internal Ops Retainer", "CONFIDENTIAL - wire transfer routing on file. FLAG{idor_admin_invoice_exposed}"),
        (2, 1240.50, "Freight - Container #A1187", "Net 30. Customer: Alice / CustomerCo."),
        (3, 875.00, "Freight - Container #B2210", "Net 30. Customer: Bob / Shippers Inc."),
        (4, 3320.75, "Freight - Container #C3390", "Net 15. Customer: Carol / RetailHub."),
    ]
    for user_id, amount, desc, notes in invoices:
        conn.execute(
            "INSERT INTO invoices (user_id, amount, description, notes, created_at) VALUES (?,?,?,?,?)",
            (user_id, amount, desc, notes, now()),
        )

    shipments = [
        (2, "NF-100234", "Rotterdam, NL", "Newark, US", "In Transit", 2),
        (3, "NF-100511", "Shenzhen, CN", "Los Angeles, US", "Customs Hold", 3),
        (4, "NF-100888", "Hamburg, DE", "Baltimore, US", "Delivered", 4),
    ]
    for user_id, track, origin, dest, status, invoice_id in shipments:
        conn.execute(
            "INSERT INTO shipments (user_id, tracking_number, origin, destination, status, invoice_id) VALUES (?,?,?,?,?,?)",
            (user_id, track, origin, dest, status, invoice_id),
        )

    posts = [
        (
            "NovaFreight Opens New Rotterdam Hub",
            "We're excited to announce our newest transshipment hub in Rotterdam, "
            "boosting European throughput by 30% starting this quarter. Our team "
            "worked closely with port authorities to fast-track customs clearance "
            "for priority freight.",
            "Comms Team",
        ),
        (
            "Q3 Customer Satisfaction Report",
            "Thanks to everyone who filled out our Q3 survey. On-time delivery "
            "climbed to 96.2%, and support response time dropped to under 4 hours "
            "on average. Read the full breakdown on our investor relations page.",
            "Comms Team",
        ),
        (
            "Hiring Across Logistics Coordination",
            "NovaFreight is growing! We're hiring logistics coordinators, customs "
            "brokers, and warehouse ops leads across three continents. Check our "
            "careers page for open roles.",
            "HR Team",
        ),
    ]
    for title, body, author in posts:
        conn.execute(
            "INSERT INTO blog_posts (title, body, author, created_at) VALUES (?,?,?,?)",
            (title, body, author, now()),
        )

    conn.execute(
        "INSERT INTO comments (post_id, author, body, created_at) VALUES (?,?,?,?)",
        (1, "PortWatcher22", "Great news, Rotterdam needed more capacity badly.", now()),
    )
    conn.execute(
        "INSERT INTO comments (post_id, author, body, created_at) VALUES (?,?,?,?)",
        (2, "LogisticsFan", "96.2% on-time is impressive for this lane.", now()),
    )

    conn.execute(
        "INSERT INTO tickets (user_id, subject, body, status, attachment, created_at) VALUES (?,?,?,?,?,?)",
        (2, "Missing BOL for NF-100234", "Hi, I can't find the bill of lading for my shipment NF-100234, could you resend it?", "open", None, now()),
    )

    conn.execute(
        "INSERT INTO secrets (name, value) VALUES (?,?)",
        ("payroll_export_2024.csv", "FLAG{sqli_union_secrets_dumped}"),
    )
    conn.execute(
        "INSERT INTO secrets (name, value) VALUES (?,?)",
        ("carrier_api_master_key", "nf-carrier-key-8d2f1a-DO-NOT-SHARE"),
    )

    conn.commit()
