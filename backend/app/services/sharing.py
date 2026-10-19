"""Secure sharing — tokenized, expiring, view-limited links to encrypted snapshots.

The share token is generated as ``{share_id}.{secret}`` so the server can find
the row by id, while the AES-GCM key is derived ONLY from the full token. A
wrong or tampered token fails GCM authentication — there is no way to read a
share without the exact link.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from ..config import settings
from ..crypto.engine import decrypt, encrypt, generate_share_token, share_key_from_token
from ..db import execute, new_id, query, query_one, utcnow
from . import vault as vault_service

SNAPSHOT_FIELDS = ("title", "username", "email", "password", "url", "notes", "totp_secret")


def _parse_iso(value: str | None):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def create_share(
    user_id: str,
    master_key: bytes,
    item_id: str,
    label: str = "",
    expires_in_hours: int = 72,
    max_views: int = 5,
    include_password: bool = True,
) -> dict | None:
    item = vault_service.get_item(user_id, master_key, item_id)
    if not item:
        return None

    snapshot = {field: item.get(field, "") or "" for field in SNAPSHOT_FIELDS}
    if not include_password:
        snapshot["password"] = ""

    share_id = new_id("share")
    token = f"{share_id}.{generate_share_token()}"
    key = share_key_from_token(token)
    ciphertext = encrypt(key, json.dumps(snapshot).encode("utf-8"), aad=share_id.encode("utf-8"))

    hours = max(1, min(int(expires_in_hours or 72), 24 * 30))
    views = max(1, min(int(max_views or 1), 50))
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    execute(
        "INSERT INTO shares (id, user_id, item_id, label, ciphertext, expires_at, max_views, views, revoked, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)",
        (share_id, user_id, item_id, label or item.get("title", ""), ciphertext, expires_at, views, utcnow()),
    )
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    return {
        "id": share_id,
        "token": token,
        "url": f"{base}/share/{token}",
        "expires_at": expires_at,
        "max_views": views,
        "label": label or item.get("title", ""),
    }


def list_shares(user_id: str) -> list[dict]:
    rows = query(
        "SELECT id, item_id, label, expires_at, max_views, views, revoked, created_at FROM shares"
        " WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    )
    now = datetime.now(timezone.utc)
    out = []
    for row in rows:
        expires = _parse_iso(row["expires_at"])
        expired = bool(expires and now > expires)
        out.append({
            "id": row["id"],
            "item_id": row["item_id"],
            "label": row["label"],
            "expires_at": row["expires_at"],
            "max_views": row["max_views"],
            "views": row["views"],
            "revoked": bool(row["revoked"]),
            "expired": expired,
            "active": not row["revoked"] and not expired and row["views"] < row["max_views"],
            "created_at": row["created_at"],
        })
    return out


def revoke_share(user_id: str, share_id: str) -> bool:
    row = query_one("SELECT id FROM shares WHERE id = ? AND user_id = ?", (share_id, user_id))
    if not row:
        return False
    execute("UPDATE shares SET revoked = 1 WHERE id = ? AND user_id = ?", (share_id, user_id))
    return True


def view_share(token: str, ip: str = "", user_agent: str = "") -> dict:
    """Public endpoint: resolve a share token (no auth) and return the snapshot."""
    if not token or "." not in token:
        return {"ok": False, "status": 400, "error": "Invalid share link"}
    share_id, _, secret = token.partition(".")
    row = query_one("SELECT * FROM shares WHERE id = ?", (share_id,))
    if not row:
        return {"ok": False, "status": 404, "error": "Share not found"}
    if row["revoked"]:
        return {"ok": False, "status": 410, "error": "This share was revoked by its owner"}
    expires = _parse_iso(row["expires_at"])
    if expires and datetime.now(timezone.utc) > expires:
        return {"ok": False, "status": 410, "error": "This share link has expired"}
    if row["views"] >= row["max_views"]:
        return {"ok": False, "status": 410, "error": "This share reached its view limit"}

    key = share_key_from_token(token)
    try:
        snapshot = json.loads(decrypt(key, row["ciphertext"], aad=share_id.encode("utf-8")))
    except Exception:
        return {"ok": False, "status": 403, "error": "Invalid share token"}

    new_views = row["views"] + 1
    execute("UPDATE shares SET views = ? WHERE id = ?", (new_views, share_id))
    execute(
        "INSERT INTO share_views (id, share_id, ip, user_agent, viewed_at) VALUES (?, ?, ?, ?, ?)",
        (new_id("sv"), share_id, ip or "", user_agent or "", utcnow()),
    )
    return {
        "ok": True,
        "item": snapshot,
        "label": row["label"],
        "remaining_views": max(row["max_views"] - new_views, 0),
        "expires_at": row["expires_at"],
    }
