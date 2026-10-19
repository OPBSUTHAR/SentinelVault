"""SQLite storage layer — synchronous, WAL mode, zero-config.

All vault item secrets live in `vault_items.ciphertext` (AES-256-GCM blobs).
Only non-sensitive metadata (category, scores, timestamps) is stored in clear
for fast dashboard aggregation.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    kdf_salt BLOB NOT NULL,
    verifier TEXT NOT NULL,
    recovery_wrapped_key TEXT,
    recovery_created_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions_meta (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vault_items (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'login',
    ciphertext TEXT NOT NULL,
    favorite INTEGER NOT NULL DEFAULT 0,
    strength_score INTEGER,
    password_updated_at TEXT,
    breached_count INTEGER,
    breach_checked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS breach_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,              -- password | account
    subject_hash TEXT NOT NULL,      -- sha1 prefix of password / sha256 of email
    subject_label TEXT NOT NULL DEFAULT '',
    breach_name TEXT NOT NULL DEFAULT '',
    breach_date TEXT,
    pwn_count INTEGER NOT NULL DEFAULT 0,
    data_classes TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL DEFAULT 'medium',
    source TEXT NOT NULL DEFAULT 'hibp',
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    meta TEXT NOT NULL DEFAULT '{}',
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    item_id TEXT,
    label TEXT NOT NULL DEFAULT '',
    ciphertext TEXT NOT NULL,
    expires_at TEXT,
    max_views INTEGER NOT NULL DEFAULT 1,
    views INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS share_views (
    id TEXT PRIMARY KEY,
    share_id TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    viewed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS emergency_contacts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    relationship TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS emergency_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    bundle_ciphertext TEXT,
    bundle_token_hint TEXT NOT NULL DEFAULT '',
    token_secret TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL,
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS rotation_events (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    item_ids TEXT NOT NULL,
    policy TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_items_user ON vault_items(user_id);
CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user_id, read);
CREATE INDEX IF NOT EXISTS idx_breach_user ON breach_events(user_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(10)}"


_conn: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        db_path = Path(settings.DATABASE_PATH)
        if not db_path.is_absolute():
            db_path = Path(__file__).resolve().parent.parent / db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(db_path), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA busy_timeout=5000")
        _conn.executescript(_SCHEMA)
        _conn.commit()
    return _conn


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return get_db().execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    return get_db().execute(sql, params).fetchone()


def execute(sql: str, params: tuple = ()) -> None:
    conn = get_db()
    conn.execute(sql, params)
    conn.commit()


def reset_connection() -> None:
    """Test helper: drop the cached connection (e.g. after DB path change)."""
    global _conn
    if _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
    _conn = None
