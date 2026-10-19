"""Client-carried end-to-end encrypted backup / restore.

On serverless hosting (Vercel) each function instance has its own ephemeral
filesystem, so the same account can "disappear" depending on which instance
serves a request. This service lets the browser keep a full encrypted backup
of the user's data (ciphertexts only — the server never sees plaintext) and
re-seed any fresh instance on demand.

Merge rules keep both directions safe:
- rows are matched by id; updates only apply when the incoming copy is newer
  (``updated_at`` timestamps) — otherwise the server copy wins.
- view/read counters that live server-side (shares) are only inserted when
  absent, never overwritten.
"""
from __future__ import annotations

import base64

from ..db import execute, new_id, query, query_one, utcnow

BUNDLE_VERSION = 1

# table -> (conflict-column, mutable columns)
_TABLES = {
    "vault_items": ("updated_at", ["category", "ciphertext", "favorite", "strength_score",
                                   "password_updated_at", "breached_count", "breach_checked_at", "updated_at"]),
    "shares": (None, []),  # insert-if-absent only (views/revoked stay server-authoritative)
    "emergency_contacts": (None, []),  # insert-if-absent only
    "emergency_requests": ("decided_at", ["status", "bundle_ciphertext", "decided_at"]),
}

# Only real BLOB columns need base64 bridging; ciphertext fields are already
# base64 *text* (AES-GCM tokens) and must pass through byte-for-byte unchanged.
_BLOB_KEYS = {"kdf_salt"}


def _to_json(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    return value


def _from_json(value):
    return value


def _encode_row(row) -> dict:
    return {key: _to_json(value) for key, value in dict(row).items()}


def _decode_row(row: dict, blob_keys: set[str]) -> dict:
    out = {}
    for key, value in row.items():
        if key in blob_keys and isinstance(value, str):
            try:
                out[key] = base64.b64decode(value)
                continue
            except Exception:
                pass
        out[key] = value
    return out


def export_bundle(user_id: str) -> dict:
    user = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not user:
        return {"ok": False, "error": "user_missing"}
    bundle = {
        "version": BUNDLE_VERSION,
        "saved_at": utcnow(),
        "email": user["email"],
        "user": _encode_row(user),
    }
    for table in _TABLES:
        bundle[table] = [
            _encode_row(row)
            for row in query(f"SELECT * FROM {table} WHERE user_id = ?", (user_id,))
        ]
    return {"ok": True, "bundle": bundle}


def _restore_user(bundle_user: dict, auth_user_id: str | None) -> tuple[str | None, bool, str]:
    email = (bundle_user.get("email") or "").strip().lower()
    if not email or not bundle_user.get("kdf_salt") or not bundle_user.get("verifier"):
        return None, False, "Malformed backup bundle"
    existing = query_one("SELECT * FROM users WHERE email = ?", (email,))
    if existing:
        if auth_user_id != existing["id"]:
            return None, False, "Account already exists on this instance — sign in instead"
        incoming_updated = bundle_user.get("updated_at") or ""
        if incoming_updated and incoming_updated > (existing["updated_at"] or ""):
            user_row = _decode_row(bundle_user, _BLOB_KEYS)
            execute(
                "UPDATE users SET display_name = ?, kdf_salt = ?, verifier = ?, recovery_wrapped_key = ?,"
                " recovery_created_at = ?, updated_at = ? WHERE id = ?",
                (
                    user_row.get("display_name", existing["display_name"]),
                    user_row["kdf_salt"],
                    user_row["verifier"],
                    user_row.get("recovery_wrapped_key", existing["recovery_wrapped_key"]),
                    user_row.get("recovery_created_at", existing["recovery_created_at"]),
                    user_row.get("updated_at", existing["updated_at"]),
                    existing["id"],
                ),
            )
        return existing["id"], False, ""
    user_row = _decode_row(bundle_user, _BLOB_KEYS)
    now = utcnow()
    execute(
        "INSERT INTO users (id, email, display_name, kdf_salt, verifier, recovery_wrapped_key,"
        " recovery_created_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_row.get("id") or new_id("user"),
            email,
            user_row.get("display_name") or email.split("@")[0],
            user_row["kdf_salt"],
            user_row["verifier"],
            user_row.get("recovery_wrapped_key", ""),
            user_row.get("recovery_created_at", now),
            user_row.get("created_at", now),
            user_row.get("updated_at", now),
        ),
    )
    return query_one("SELECT id FROM users WHERE email = ?", (email,))["id"], True, ""


def _restore_table(table: str, rows: list[dict] | None, user_id: str) -> int:
    conflict_col, mutable = _TABLES[table]
    count = 0
    for row in rows or []:
        row_id = row.get("id")
        if not row_id:
            continue
        decoded = _decode_row(row, _BLOB_KEYS)
        existing = query_one(f"SELECT * FROM {table} WHERE id = ?", (row_id,))
        if existing is None:
            cols = list(decoded.keys())
            if "user_id" in cols:
                decoded["user_id"] = user_id
            placeholders = ", ".join("?" for _ in cols)
            execute(
                f"INSERT OR IGNORE INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
                tuple(decoded[c] for c in cols),
            )
            count += 1
            continue
        if not mutable:
            continue
        if conflict_col and (row.get(conflict_col) or "") > (existing[conflict_col] or ""):
            sets = ", ".join(f"{col} = ?" for col in mutable)
            execute(
                f"UPDATE {table} SET {sets} WHERE id = ?",
                tuple(decoded.get(col, existing[col]) for col in mutable) + (row_id,),
            )
            count += 1
    return count


def restore_bundle(bundle: dict, auth_user_id: str | None = None) -> dict:
    if not isinstance(bundle, dict):
        return {"ok": False, "status": 400, "error": "Malformed backup bundle"}
    user_id, created, error = _restore_user(bundle.get("user") or {}, auth_user_id)
    if not user_id:
        status = 409 if "exists" in error else 400
        return {"ok": False, "status": status, "error": error}
    restored = {}
    for table in _TABLES:
        # never let a bundle carrying another account's rows in
        rows = [r for r in (bundle.get(table) or []) if not r.get("user_id") or r.get("user_id") == bundle.get("user", {}).get("id")]
        restored[table] = _restore_table(table, rows, user_id)
    return {"ok": True, "user_id": user_id, "created": created, "restored": restored, "saved_at": utcnow()}
