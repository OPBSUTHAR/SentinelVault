"""Vault item service — every secret is encrypted with a subkey of the master key."""
from __future__ import annotations

import json

from ..crypto.engine import decrypt, derive_subkey, encrypt
from ..db import execute, new_id, query, query_one, utcnow
from . import generator, strength

ITEM_FIELDS = ("title", "username", "email", "password", "url", "notes", "totp_secret", "tags")


def _item_key(master_key: bytes) -> bytes:
    return derive_subkey(master_key, b"sentinelvault:vault-items")


def _encrypt_payload(master_key: bytes, item_id: str, data: dict) -> str:
    payload = {}
    for field in ITEM_FIELDS:
        value = data.get(field, [] if field == "tags" else "")
        payload[field] = value if value is not None else ([] if field == "tags" else "")
    return encrypt(_item_key(master_key), json.dumps(payload).encode("utf-8"), aad=item_id.encode("utf-8"))


def _decrypt_row(master_key: bytes, row) -> dict:
    data = json.loads(decrypt(_item_key(master_key), row["ciphertext"], aad=row["id"].encode("utf-8")))
    item = {
        "id": row["id"],
        "category": row["category"],
        "favorite": bool(row["favorite"]),
        "strength_score": row["strength_score"],
        "breached_count": row["breached_count"],
        "breach_checked_at": row["breach_checked_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "password_updated_at": row["password_updated_at"],
    }
    item.update(data)
    return item


def _score_for(password: str, username: str = "", email: str = "", title: str = "") -> int:
    hints = [
        username.split("@")[0] if username else "",
        email.split("@")[0] if email else "",
        title,
    ]
    return strength.analyze(password or "", [h for h in hints if h])["score"]


def list_items(user_id: str, master_key: bytes, category: str | None = None) -> list[dict]:
    rows = query("SELECT * FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC", (user_id,))
    items = []
    for row in rows:
        item = _decrypt_row(master_key, row)
        if category and item["category"] != category:
            continue
        item["has_password"] = bool(item.get("password"))
        item["password"] = None  # never list secrets
        items.append(item)
    return items


def list_items_internal(user_id: str, master_key: bytes) -> list[dict]:
    """Full items (passwords included) — used by health/reuse analysis only."""
    rows = query("SELECT * FROM vault_items WHERE user_id = ?", (user_id,))
    return [_decrypt_row(master_key, row) for row in rows]


def get_item(user_id: str, master_key: bytes, item_id: str) -> dict | None:
    row = query_one("SELECT * FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
    return _decrypt_row(master_key, row) if row else None


def create_item(user_id: str, master_key: bytes, data: dict) -> dict:
    item_id = new_id("item")
    now = utcnow()
    score = _score_for(data.get("password", ""), data.get("username", ""), data.get("email", ""), data.get("title", ""))
    execute(
        "INSERT INTO vault_items (id, user_id, category, ciphertext, favorite, strength_score,"
        " password_updated_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            item_id,
            user_id,
            data.get("category", "login"),
            _encrypt_payload(master_key, item_id, data),
            1 if data.get("favorite") else 0,
            score,
            now,
            now,
            now,
        ),
    )
    return get_item(user_id, master_key, item_id)


def update_item(user_id: str, master_key: bytes, item_id: str, data: dict) -> dict | None:
    row = query_one("SELECT * FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
    if not row:
        return None
    current = _decrypt_row(master_key, row)
    merged = {**{k: current.get(k) for k in ITEM_FIELDS}, **{k: v for k, v in data.items() if v is not None and k in ITEM_FIELDS}}
    if not data.get("password"):  # keep old password when blank
        merged["password"] = current.get("password", "")
    now = utcnow()
    password_changed = data.get("password") and data["password"] != current.get("password")
    score = _score_for(merged.get("password", ""), merged.get("username", ""), merged.get("email", ""), merged.get("title", ""))
    execute(
        "UPDATE vault_items SET category = ?, ciphertext = ?, favorite = ?, strength_score = ?,"
        " password_updated_at = CASE WHEN ? THEN ? ELSE password_updated_at END, updated_at = ? WHERE id = ? AND user_id = ?",
        (
            data.get("category", current.get("category", "login")),
            _encrypt_payload(master_key, item_id, merged),
            1 if data.get("favorite", current.get("favorite")) else 0,
            score,
            1 if password_changed else 0,
            now,
            now,
            item_id,
            user_id,
        ),
    )
    if password_changed:
        execute(
            "UPDATE vault_items SET breached_count = NULL, breach_checked_at = NULL WHERE id = ?",
            (item_id,),
        )
    return get_item(user_id, master_key, item_id)


def delete_item(user_id: str, item_id: str) -> bool:
    row = query_one("SELECT id FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
    if not row:
        return False
    execute("DELETE FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
    return True


def rotate_items(user_id: str, master_key: bytes, item_ids: list[str], policy: str = "strong") -> dict:
    """Auto-rotation: generate new passwords meeting a policy and swap them in."""
    rotated = []
    for item_id in item_ids:
        row = query_one("SELECT * FROM vault_items WHERE id = ? AND user_id = ?", (item_id, user_id))
        if not row:
            continue
        current = _decrypt_row(master_key, row)
        new_password = generator.generate_with_policy(policy)
        updated = update_item(user_id, master_key, item_id, {"password": new_password})
        rotated.append({
            "id": item_id,
            "title": updated.get("title", current.get("title", "")),
            "new_password": new_password,
            "old_score": current.get("strength_score"),
            "new_score": updated.get("strength_score"),
        })
    event_id = new_id("rot")
    execute(
        "INSERT INTO rotation_events (id, user_id, item_ids, policy, created_at) VALUES (?, ?, ?, ?, ?)",
        (event_id, user_id, json.dumps(item_ids), json.dumps({"policy": policy}), utcnow()),
    )
    return {"rotated": rotated, "count": len(rotated), "policy": policy, "event_id": event_id}


def reencrypt_all(user_id: str, old_master_key: bytes, new_master_key: bytes) -> int:
    """Re-encrypt every item when the master key changes (password change / recovery)."""
    rows = query("SELECT * FROM vault_items WHERE user_id = ?", (user_id,))
    count = 0
    for row in rows:
        try:
            plaintext = decrypt(_item_key(old_master_key), row["ciphertext"], aad=row["id"].encode("utf-8"))
        except Exception:
            continue
        ciphertext = encrypt(_item_key(new_master_key), plaintext, aad=row["id"].encode("utf-8"))
        execute("UPDATE vault_items SET ciphertext = ?, updated_at = ? WHERE id = ?", (ciphertext, utcnow(), row["id"]))
        count += 1
    return count
