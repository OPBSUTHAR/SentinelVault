"""Emergency access — designated contacts can request the vault; the owner
approves and an encrypted bundle is released to the requester.

Flow:
1. Owner registers emergency contacts (name/email/phone).
2. A contact starts a request and receives a one-time request token
   ``{request_id}.{secret}`` — they keep it private.
3. The owner sees the request in the dashboard and approves (their vault must
   be unlocked, so the snapshot is built from the in-memory master key).
4. The requester checks the status with their token and, once approved,
   receives the released vault snapshot.

Note (documented tradeoff): the server keeps the request token so it can
encrypt the bundle at approval time. In a production deployment this would be
replaced by wrapping the bundle key with the contact's public key (X25519) so
that even the server cannot decrypt it.
"""
from __future__ import annotations

import hashlib
import json
import secrets

from ..crypto.engine import derive_subkey, encrypt
from ..db import execute, new_id, query, query_one, utcnow
from . import vault as vault_service


def _token_hint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _bundle_key(token: str) -> bytes:
    return derive_subkey(token.encode("utf-8"), b"sentinelvault:emergency-bundle")


def add_contact(user_id: str, name: str, email: str, phone: str = "", relationship: str = "") -> dict:
    contact_id = new_id("contact")
    execute(
        "INSERT INTO emergency_contacts (id, user_id, name, email, phone, relationship, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (contact_id, user_id, name.strip(), email.strip().lower(), phone.strip(), relationship.strip(), utcnow()),
    )
    return {"id": contact_id, "name": name.strip(), "email": email.strip().lower(), "phone": phone, "relationship": relationship}


def list_contacts(user_id: str) -> list[dict]:
    rows = query(
        "SELECT id, name, email, phone, relationship, created_at FROM emergency_contacts"
        " WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,),
    )
    return [dict(row) for row in rows]


def remove_contact(user_id: str, contact_id: str) -> bool:
    row = query_one("SELECT id FROM emergency_contacts WHERE id = ? AND user_id = ?", (contact_id, user_id))
    if not row:
        return False
    execute("DELETE FROM emergency_contacts WHERE id = ? AND user_id = ?", (contact_id, user_id))
    return True


def create_request(email: str, message: str = "") -> dict:
    contact = query_one("SELECT * FROM emergency_contacts WHERE email = ?", ((email or "").strip().lower(),))
    if not contact:
        return {"ok": False, "status": 404, "error": "No emergency contact found with that email"}

    request_id = new_id("emreq")
    token = f"{request_id}.{secrets.token_urlsafe(24)}"
    execute(
        "INSERT INTO emergency_requests (id, user_id, contact_id, status, bundle_ciphertext, bundle_token_hint,"
        " token_secret, requested_at) VALUES (?, ?, ?, 'pending', NULL, ?, ?, ?)",
        (request_id, contact["user_id"], contact["id"], _token_hint(token), token, utcnow()),
    )
    return {
        "ok": True,
        "request_id": request_id,
        "token": token,
        "contact_name": contact["name"],
        "message": "Request sent. Keep your access token safe — you will need it to check approval status.",
    }


def check_request(token: str) -> dict:
    if not token or "." not in token:
        return {"ok": False, "status": 400, "error": "Invalid request token"}
    request_id, _, _secret = token.partition(".")
    row = query_one("SELECT * FROM emergency_requests WHERE id = ?", (request_id,))
    if not row or row["bundle_token_hint"] != _token_hint(token):
        return {"ok": False, "status": 403, "error": "Invalid request token"}

    result = {
        "ok": True,
        "request_id": request_id,
        "status": row["status"],
        "requested_at": row["requested_at"],
        "decided_at": row["decided_at"],
    }
    if row["status"] == "approved" and row["bundle_ciphertext"]:
        from ..crypto.engine import decrypt

        try:
            result["bundle"] = json.loads(decrypt(_bundle_key(token), row["bundle_ciphertext"], aad=request_id.encode("utf-8")))
        except Exception:
            result["bundle"] = None
            result["error"] = "Bundle could not be decrypted"
    return result


def list_requests(user_id: str) -> list[dict]:
    rows = query(
        "SELECT r.id, r.contact_id, r.status, r.bundle_token_hint, r.requested_at, r.decided_at,"
        " c.name AS contact_name, c.email AS contact_email"
        " FROM emergency_requests r LEFT JOIN emergency_contacts c ON c.id = r.contact_id"
        " WHERE r.user_id = ? ORDER BY r.requested_at DESC",
        (user_id,),
    )
    return [dict(row) for row in rows]


def decide_request(user_id: str, request_id: str, approve: bool, master_key: bytes | None) -> dict:
    row = query_one("SELECT * FROM emergency_requests WHERE id = ? AND user_id = ?", (request_id, user_id))
    if not row:
        return {"ok": False, "status": 404, "error": "Request not found"}
    if row["status"] != "pending":
        return {"ok": False, "status": 409, "error": f"Request already {row['status']}"}

    if not approve:
        execute(
            "UPDATE emergency_requests SET status = 'denied', decided_at = ? WHERE id = ?",
            (utcnow(), request_id),
        )
        return {"ok": True, "status": "denied", "request_id": request_id}

    if master_key is None:
        return {"ok": False, "status": 401, "error": "Vault must be unlocked to release an emergency bundle"}

    items = vault_service.list_items_internal(user_id, master_key)
    snapshot = [
        {
            "title": item.get("title", ""),
            "category": item.get("category", "login"),
            "username": item.get("username", ""),
            "email": item.get("email", ""),
            "password": item.get("password", ""),
            "url": item.get("url", ""),
            "notes": item.get("notes", ""),
            "totp_secret": item.get("totp_secret", ""),
        }
        for item in items
    ]
    bundle = encrypt(_bundle_key(row["token_secret"]), json.dumps(snapshot).encode("utf-8"), aad=request_id.encode("utf-8"))
    execute(
        "UPDATE emergency_requests SET status = 'approved', bundle_ciphertext = ?, decided_at = ? WHERE id = ?",
        (bundle, utcnow(), request_id),
    )
    return {"ok": True, "status": "approved", "request_id": request_id, "items_included": len(snapshot)}
