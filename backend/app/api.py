"""SentinelVault REST API — all routes under /api."""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone

import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel

from .config import settings
from .crypto.engine import (
    compute_verifier,
    derive_master_key,
    generate_recovery_key,
    generate_salt,
    totp_code,
    totp_generate_secret,
    totp_seconds_left,
    totp_uri,
    totp_verify,
    unwrap_master_key,
    verify_master_key,
    wrap_master_key,
)
from .db import execute, new_id, query_one, utcnow
from .security import (
    b64_master_key,
    client_agent,
    client_ip,
    create_token,
    get_current,
    get_optional_current,
    get_unlocked,
)
from .services import anomaly, breach, emergency, generator, health, phishing, sharing, strength
from .services import sync as sync_service
from .services import vault as vault_service

router = APIRouter()
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterBody(BaseModel):
    email: str
    display_name: str = ""
    password: str


class LoginBody(BaseModel):
    email: str
    password: str


class UnlockBody(BaseModel):
    password: str


class RecoveryBody(BaseModel):
    email: str
    recovery_key: str
    new_password: str


class ChangePasswordBody(BaseModel):
    current_password: str = ""
    new_password: str


class ItemBody(BaseModel):
    category: str = "login"
    title: str = ""
    username: str = ""
    email: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp_secret: str = ""
    tags: list[str] = []
    favorite: bool = False


class RotateBody(BaseModel):
    item_ids: list[str]
    policy: str = "strong"


class RotateOneBody(BaseModel):
    policy: str = "strong"


class StrengthBody(BaseModel):
    password: str
    user_inputs: list[str] = []


class GenerateBody(BaseModel):
    kind: str = "password"          # password | passphrase
    policy: str = ""
    length: int | None = None
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True
    avoid_ambiguous: bool = True
    words: int = 4


class CheckPasswordBody(BaseModel):
    password: str


class CheckEmailBody(BaseModel):
    email: str


class CheckUrlBody(BaseModel):
    url: str


class ShareBody(BaseModel):
    item_id: str
    label: str = ""
    expires_in_hours: int = 72
    max_views: int = 5
    include_password: bool = True


class ContactBody(BaseModel):
    name: str
    email: str
    phone: str = ""
    relationship: str = ""


class EmergencyRequestBody(BaseModel):
    email: str
    message: str = ""


class DecideBody(BaseModel):
    approve: bool = True


class TotpCodeBody(BaseModel):
    secret: str


class TotpVerifyBody(BaseModel):
    secret: str
    code: str


class TotpQrBody(BaseModel):
    secret: str = ""
    account: str = ""
    issuer: str = "SentinelVault"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _public_user(user) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "created_at": user["created_at"],
        "has_recovery": bool(user["recovery_wrapped_key"]),
    }


def _get_user_by_email(email: str):
    return query_one("SELECT * FROM users WHERE email = ?", ((email or "").strip().lower(),))


def _get_user(user_id: str):
    return query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def _valid_email(email: str) -> bool:
    return bool(EMAIL_RE.fullmatch((email or "").strip()))


def _check_master_password(password: str) -> list[str]:
    problems = []
    if len(password or "") < 10:
        problems.append("Master password must be at least 10 characters")
    report = strength.analyze(password or "")
    if report["score"] < 30:
        problems.append("Master password is too weak — " + "; ".join(report["feedback"][:2]))
    return problems


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@router.post("/auth/register")
def register(body: RegisterBody, request: Request):
    email = (body.email or "").strip().lower()
    if not _valid_email(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    if _get_user_by_email(email):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    problems = _check_master_password(body.password)
    if problems:
        raise HTTPException(status_code=400, detail="; ".join(problems))

    kdf_salt = generate_salt()
    master_key = derive_master_key(body.password, kdf_salt)
    recovery_key = generate_recovery_key()
    user_id = new_id("user")
    now = utcnow()
    execute(
        "INSERT INTO users (id, email, display_name, kdf_salt, verifier, recovery_wrapped_key,"
        " recovery_created_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            email,
            body.display_name.strip() or email.split("@")[0],
            kdf_salt,
            compute_verifier(master_key),
            wrap_master_key(recovery_key, master_key),
            now,
            now,
            now,
        ),
    )
    token = create_token(user_id)
    anomaly.record_login(user_id, True, client_ip(request), client_agent(request))
    user = _get_user(user_id)
    return {
        "token": token,
        "master_key": b64_master_key(master_key),
        "user": _public_user(user),
        "recovery_key": recovery_key,
        "recovery_note": "Save this recovery key somewhere safe and offline. It is shown only once and it is the "
                         "only way back into your vault if you forget the master password.",
    }


@router.post("/auth/login")
def login(body: LoginBody, request: Request):
    user = _get_user_by_email(body.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    master_key = derive_master_key(body.password, user["kdf_salt"])
    if not verify_master_key(master_key, user["verifier"]):
        anomaly.record_login(user["id"], False, client_ip(request), client_agent(request))
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(user["id"])
    anomaly.record_login(user["id"], True, client_ip(request), client_agent(request))
    return {"token": token, "master_key": b64_master_key(master_key), "user": _public_user(user)}


@router.post("/auth/unlock")
def unlock(body: UnlockBody, request: Request, auth: dict = Depends(get_current)):
    user = _get_user(auth["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="Unknown account")
    master_key = derive_master_key(body.password, user["kdf_salt"])
    if not verify_master_key(master_key, user["verifier"]):
        anomaly.record_login(user["id"], False, client_ip(request), client_agent(request))
        raise HTTPException(status_code=401, detail="Incorrect master password")
    return {"ok": True, "unlocked": True, "master_key": b64_master_key(master_key)}


@router.post("/auth/lock")
def lock(auth: dict = Depends(get_current)):
    # Stateless design: locking = the client drops its in-memory master key.
    return {"ok": True, "locked": True}


@router.post("/auth/change-password")
def change_password(body: ChangePasswordBody, auth: dict = Depends(get_unlocked)):
    user = _get_user(auth["user_id"])
    problems = _check_master_password(body.new_password)
    if problems:
        raise HTTPException(status_code=400, detail="; ".join(problems))
    old_mk = auth["master_key"]
    new_salt = generate_salt()
    new_mk = derive_master_key(body.new_password, new_salt)
    new_recovery = generate_recovery_key()
    reencrypted = vault_service.reencrypt_all(user["id"], old_mk, new_mk)
    execute(
        "UPDATE users SET kdf_salt = ?, verifier = ?, recovery_wrapped_key = ?, recovery_created_at = ?,"
        " updated_at = ? WHERE id = ?",
        (new_salt, compute_verifier(new_mk), wrap_master_key(new_recovery, new_mk), utcnow(), utcnow(), user["id"]),
    )
    return {
        "ok": True,
        "reencrypted_items": reencrypted,
        "master_key": b64_master_key(new_mk),
        "recovery_key": new_recovery,
        "recovery_note": "Your recovery key was rotated — save the new one, the old one no longer works.",
    }


@router.post("/auth/recovery")
def recover(body: RecoveryBody, request: Request):
    user = _get_user_by_email(body.email)
    if not user or not user["recovery_wrapped_key"]:
        raise HTTPException(status_code=404, detail="No recovery data for that account")
    try:
        old_mk = unwrap_master_key(body.recovery_key.strip(), user["recovery_wrapped_key"])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid recovery key")
    if not verify_master_key(old_mk, user["verifier"]):
        raise HTTPException(status_code=400, detail="Recovery key does not match this account")
    problems = _check_master_password(body.new_password)
    if problems:
        raise HTTPException(status_code=400, detail="; ".join(problems))

    new_salt = generate_salt()
    new_mk = derive_master_key(body.new_password, new_salt)
    new_recovery = generate_recovery_key()
    reencrypted = vault_service.reencrypt_all(user["id"], old_mk, new_mk)
    execute(
        "UPDATE users SET kdf_salt = ?, verifier = ?, recovery_wrapped_key = ?, recovery_created_at = ?,"
        " updated_at = ? WHERE id = ?",
        (new_salt, compute_verifier(new_mk), wrap_master_key(new_recovery, new_mk), utcnow(), utcnow(), user["id"]),
    )
    token = create_token(user["id"])
    anomaly.record_login(user["id"], True, client_ip(request), client_agent(request))
    return {
        "ok": True,
        "token": token,
        "master_key": b64_master_key(new_mk),
        "reencrypted_items": reencrypted,
        "recovery_key": new_recovery,
    }


@router.get("/auth/me")
def me(auth: dict = Depends(get_current)):
    user = _get_user(auth["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="Unknown account")
    return {"user": _public_user(user), "unlocked": auth["unlocked"]}


# ---------------------------------------------------------------------------
# Vault items
# ---------------------------------------------------------------------------

@router.get("/vault/items")
def list_items(category: str | None = None, auth: dict = Depends(get_unlocked)):
    return {"items": vault_service.list_items(auth["user_id"], auth["master_key"], category)}


@router.post("/vault/items")
def create_item(body: ItemBody, auth: dict = Depends(get_unlocked)):
    if not body.title.strip():
        raise HTTPException(status_code=400, detail="Title is required")
    item = vault_service.create_item(auth["user_id"], auth["master_key"], body.model_dump())
    return {"item": item}


@router.get("/vault/items/{item_id}")
def get_item(item_id: str, auth: dict = Depends(get_unlocked)):
    item = vault_service.get_item(auth["user_id"], auth["master_key"], item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item": item}


@router.put("/vault/items/{item_id}")
def update_item(item_id: str, body: ItemBody, auth: dict = Depends(get_unlocked)):
    item = vault_service.update_item(auth["user_id"], auth["master_key"], item_id, body.model_dump())
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item": item}


@router.delete("/vault/items/{item_id}")
def delete_item(item_id: str, auth: dict = Depends(get_unlocked)):
    if not vault_service.delete_item(auth["user_id"], item_id):
        raise HTTPException(status_code=404, detail="Item not found")
    return {"ok": True}


@router.post("/vault/items/{item_id}/rotate")
def rotate_one(item_id: str, body: RotateOneBody, auth: dict = Depends(get_unlocked)):
    result = vault_service.rotate_items(auth["user_id"], auth["master_key"], [item_id], body.policy)
    if not result["rotated"]:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.post("/vault/rotate")
def rotate_bulk(body: RotateBody, auth: dict = Depends(get_unlocked)):
    if not body.item_ids:
        raise HTTPException(status_code=400, detail="item_ids is required")
    return vault_service.rotate_items(auth["user_id"], auth["master_key"], body.item_ids, body.policy)


@router.get("/vault/health")
def vault_health(auth: dict = Depends(get_unlocked)):
    return {"health": health.compute(auth["user_id"], auth["master_key"])}


@router.get("/vault/items/{item_id}/totp")
def item_totp(item_id: str, auth: dict = Depends(get_unlocked)):
    item = vault_service.get_item(auth["user_id"], auth["master_key"], item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    secret = item.get("totp_secret") or ""
    if not secret:
        raise HTTPException(status_code=404, detail="No 2FA secret stored for this item")
    return {"code": totp_code(secret), "seconds_left": totp_seconds_left()}


@router.post("/vault/seed-demo")
def seed_demo(request: Request, auth: dict = Depends(get_unlocked)):
    """Populate the vault with a realistic demo set (idempotent per title)."""
    existing = {i["title"] for i in vault_service.list_items(auth["user_id"], auth["master_key"])}
    demo = [
        ("Gmail", "login", "omprakash", "Personal email", "correct-horse-battery-staple-92!", "https://mail.google.com", 92),
        ("GitHub", "login", "omprakashsuhar", "Developer account", "Tr0ub4dor&3-correct-horse", "https://github.com", 88),
        ("Netflix", "login", "omprakash", "Streaming", "netflix2019", "https://netflix.com", 12),
        ("Amazon", "login", "omprakash.s", "Shopping", "Qz7#kLmW2!pXe9Rt", "https://amazon.in", 90),
        ("SBI Bank", "login", "omprakash suthar", "Net banking", "sbi@2019", "https://onlinesbi.sbi", 15),
        ("HDFC Bank", "login", "omprakash.suthar", "Net banking", "Qz7#kLmW2!pXe9Rt", "https://hdfcbank.com", 90),
        ("Instagram", "login", "omprakash_official", "Social", "insta_password1", "https://instagram.com", 22),
        ("LinkedIn", "login", "omprakash-suthar", "Professional", "L!nked1n#2024$Secure", "https://linkedin.com", 85),
        ("Discord", "login", "omprakash#2210", "Community", "d1sc0rd_rocks!", "https://discord.com", 45),
        ("Steam", "login", "omprakash_gamer", "Gaming", "password123", "https://store.steampowered.com", 8),
        ("IRCTC", "login", "omprakash_s", "Travel", "Irctc@Train8Travel!", "https://irctc.co.in", 80),
        ("Paytm", "login", "9876543210", "Payments", "paytm@123", "https://paytm.com", 18),
        ("Robinhood", "login", "omprakash.s", "Investing", "hunter2hunter2", "https://robinhood.com", 20),
        ("Proton Mail", "login", "omprakash.suthar", "Encrypted email", "V!0let-GaRden-77#Orbit", "https://proton.me", 94),
    ]
    created = 0
    for title, category, username, notes, password, url, _score in demo:
        if title in existing:
            continue
        vault_service.create_item(auth["user_id"], auth["master_key"], {
            "title": title,
            "category": category,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "tags": ["demo"],
        })
        created += 1

    # Live HIBP k-anonymity checks for the two intentionally-weak secrets
    for weak_title, weak_password in (("Netflix", "netflix2019"), ("Steam", "password123"), ("SBI Bank", "sbi@2019"), ("Paytm", "paytm@123"), ("Robinhood", "hunter2hunter2")):
        rows = [i for i in vault_service.list_items(auth["user_id"], auth["master_key"]) if i["title"] == weak_title]
        if not rows:
            continue
        result = breach.check_password(weak_password)
        if result.get("available") and result.get("breached"):
            execute(
                "UPDATE vault_items SET breached_count = ?, breach_checked_at = ? WHERE id = ?",
                (result["count"], utcnow(), rows[0]["id"]),
            )

    return {"ok": True, "created": created, "algo": None}


# ---------------------------------------------------------------------------
# Tools (public helpers used by the UI live widgets)
# ---------------------------------------------------------------------------

@router.post("/tools/strength")
def tools_strength(body: StrengthBody):
    return {"report": strength.analyze(body.password, body.user_inputs)}


@router.post("/tools/generate")
def tools_generate(body: GenerateBody):
    if body.kind == "passphrase":
        return {"password": generator.passphrase(words=max(3, min(body.words, 10))), "kind": "passphrase"}
    if body.policy:
        return {"password": generator.generate_with_policy(body.policy), "kind": "password", "policy": body.policy}
    return {
        "password": generator.generate(
            length=max(8, min(body.length or 16, 64)),
            upper=body.upper,
            lower=body.lower,
            digits=body.digits,
            symbols=body.symbols,
            avoid_ambiguous=body.avoid_ambiguous,
        ),
        "kind": "password",
    }


@router.get("/tools/policies")
def tools_policies():
    return {"policies": generator.POLICIES}


@router.post("/tools/phishing")
def tools_phishing(body: CheckUrlBody):
    return {"result": phishing.analyze_url(body.url)}


@router.post("/tools/totp/code")
def tools_totp_code(body: TotpCodeBody):
    if not body.secret:
        raise HTTPException(status_code=400, detail="secret is required")
    return {"code": totp_code(body.secret), "seconds_left": totp_seconds_left()}


@router.post("/tools/totp/verify")
def tools_totp_verify(body: TotpVerifyBody):
    return {"valid": totp_verify(body.secret, body.code)}


@router.post("/tools/totp/generate")
def tools_totp_generate():
    secret = totp_generate_secret()
    return {"secret": secret, "uri": totp_uri(secret, account="you@example.com")}


@router.post("/tools/totp/qr")
def tools_totp_qr(body: TotpQrBody):
    secret = body.secret or totp_generate_secret()
    uri = totp_uri(secret, account=body.account or "you@example.com", issuer=body.issuer)
    image = qrcode.make(uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return Response(content=buffer.getvalue(), media_type="image/png", headers={"X-Totp-Secret": secret})


# ---------------------------------------------------------------------------
# Security & breach monitoring
# ---------------------------------------------------------------------------

@router.post("/security/check-password")
def check_password(body: CheckPasswordBody, auth: dict = Depends(get_current)):
    result = breach.check_password(body.password)
    if auth["unlocked"]:
        for item in vault_service.list_items_internal(auth["user_id"], auth["master_key"]):
            if item.get("password") == body.password:
                execute(
                    "UPDATE vault_items SET breached_count = ?, breach_checked_at = ? WHERE id = ?",
                    ((result.get("count") or 0) if result.get("breached") else 0, utcnow(), item["id"]),
                )
    return {"result": result}


@router.post("/security/check-email")
def check_email(body: CheckEmailBody, auth: dict = Depends(get_current)):
    if not _valid_email(body.email):
        raise HTTPException(status_code=400, detail="Enter a valid email address")
    result = breach.check_email(body.email.strip().lower())
    items = [] if not auth["unlocked"] else vault_service.list_items_internal(auth["user_id"], auth["master_key"])
    impact = breach.assess_impact(body.email.strip().lower(), result.get("breaches", []), items)
    return {"result": result, "impact": impact}


@router.get("/security/events")
def security_events(limit: int = 50, auth: dict = Depends(get_current)):
    return {"events": anomaly.list_events(auth["user_id"], limit)}


@router.get("/security/alerts")
def security_alerts(limit: int = 50, unread_only: bool = False, auth: dict = Depends(get_current)):
    return {
        "alerts": anomaly.list_alerts(auth["user_id"], limit, unread_only),
        "unread": anomaly.unread_count(auth["user_id"]),
    }


@router.post("/security/alerts/{alert_id}/read")
def mark_alert(alert_id: str, auth: dict = Depends(get_current)):
    if not anomaly.mark_alert_read(auth["user_id"], alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True, "unread": anomaly.unread_count(auth["user_id"])}


@router.get("/security/summary")
def security_summary(auth: dict = Depends(get_current)):
    events = anomaly.list_events(auth["user_id"], 200)
    failures_24h = sum(1 for e in events if e["event_type"] == "login_failed")
    return {
        "unread_alerts": anomaly.unread_count(auth["user_id"]),
        "events_tracked": len(events),
        "recent_failures": failures_24h,
    }


# ---------------------------------------------------------------------------
# Sharing
# ---------------------------------------------------------------------------

@router.post("/shares")
def create_share(body: ShareBody, auth: dict = Depends(get_unlocked)):
    share = sharing.create_share(
        auth["user_id"], auth["master_key"], body.item_id,
        label=body.label, expires_in_hours=body.expires_in_hours,
        max_views=body.max_views, include_password=body.include_password,
    )
    if not share:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"share": share}


@router.get("/shares")
def list_shares(auth: dict = Depends(get_current)):
    return {"shares": sharing.list_shares(auth["user_id"])}


@router.delete("/shares/{share_id}")
def revoke_share(share_id: str, auth: dict = Depends(get_current)):
    if not sharing.revoke_share(auth["user_id"], share_id):
        raise HTTPException(status_code=404, detail="Share not found")
    return {"ok": True}


@router.get("/shares/view/{token}")
def view_share(token: str, request: Request):
    result = sharing.view_share(token, client_ip(request), client_agent(request))
    if not result.get("ok"):
        raise HTTPException(status_code=result.get("status", 400), detail=result.get("error", "Share unavailable"))
    return result


# ---------------------------------------------------------------------------
# Emergency access
# ---------------------------------------------------------------------------

@router.get("/emergency/contacts")
def list_contacts(auth: dict = Depends(get_current)):
    return {"contacts": emergency.list_contacts(auth["user_id"])}


@router.post("/emergency/contacts")
def add_contact(body: ContactBody, auth: dict = Depends(get_current)):
    if not body.name.strip() or not _valid_email(body.email):
        raise HTTPException(status_code=400, detail="Name and a valid email are required")
    return {"contact": emergency.add_contact(auth["user_id"], body.name, body.email, body.phone, body.relationship)}


@router.delete("/emergency/contacts/{contact_id}")
def remove_contact(contact_id: str, auth: dict = Depends(get_current)):
    if not emergency.remove_contact(auth["user_id"], contact_id):
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"ok": True}


@router.post("/emergency/request")
def create_emergency_request(body: EmergencyRequestBody):
    result = emergency.create_request(body.email, body.message)
    if not result.get("ok"):
        raise HTTPException(status_code=result.get("status", 400), detail=result.get("error", "Request failed"))
    return result


@router.get("/emergency/check/{token}")
def check_emergency_request(token: str):
    result = emergency.check_request(token)
    if not result.get("ok"):
        raise HTTPException(status_code=result.get("status", 400), detail=result.get("error", "Invalid token"))
    return result


@router.get("/emergency/requests")
def list_emergency_requests(auth: dict = Depends(get_current)):
    return {"requests": emergency.list_requests(auth["user_id"])}


@router.post("/emergency/requests/{request_id}/decide")
def decide_emergency_request(request_id: str, body: DecideBody, auth: dict = Depends(get_current)):
    master_key = auth["master_key"] if (body.approve and auth["unlocked"]) else None
    result = emergency.decide_request(auth["user_id"], request_id, body.approve, master_key)
    if not result.get("ok"):
        raise HTTPException(status_code=result.get("status", 400), detail=result.get("error", "Decision failed"))
    return result


# ---------------------------------------------------------------------------
# Encrypted backup sync (client-carried state so any serverless instance works)
# ---------------------------------------------------------------------------

@router.get("/sync/backup")
def sync_backup(auth: dict = Depends(get_current)):
    result = sync_service.export_bundle(auth["user_id"])
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail="No data for this account on this instance")
    return result


@router.post("/sync/restore")
def sync_restore(bundle: dict, auth: dict | None = Depends(get_optional_current)):
    result = sync_service.restore_bundle(bundle, auth["user_id"] if auth else None)
    if not result.get("ok"):
        raise HTTPException(status_code=result.get("status", 400), detail=result.get("error", "Restore failed"))
    return result


# ---------------------------------------------------------------------------
# Dashboard aggregate
# ---------------------------------------------------------------------------

@router.get("/dashboard")
def dashboard(auth: dict = Depends(get_current)):
    unread = anomaly.unread_count(auth["user_id"])
    data = {
        "unread_alerts": unread,
        "recent_alerts": anomaly.list_alerts(auth["user_id"], 5),
        "recent_events": anomaly.list_events(auth["user_id"], 5),
        "unlocked": auth["unlocked"],
        "items": 0,
        "health": None,
        "change_now": [],
    }
    if auth["unlocked"]:
        report = health.compute(auth["user_id"], auth["master_key"])
        data["items"] = report["total"]
        data["health"] = report
        data["change_now"] = report["change_now"]
    return data


@router.get("/ping")
def ping():
    return {"status": "ok", "app": settings.APP_NAME, "time": datetime.now(timezone.utc).isoformat()}
