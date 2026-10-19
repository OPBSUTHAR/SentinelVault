"""Stateless JWT auth + per-request master key header (serverless-safe).

Design notes:
- The JWT proves identity (signed, self-contained) — no server-side session store.
- The AES master key lives ONLY in the client's memory. Vault-touching requests
  carry it in the ``X-SV-Key`` header (base64 of the 32-byte key); the server
  uses it transiently for encryption/decryption and never persists it.
- This makes every server instance interchangeable — critical on serverless
  platforms (Vercel) where requests may land on different instances.
"""
from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from .config import settings
from .db import query_one

_bearer = HTTPBearer(auto_error=False)
MASTER_KEY_HEADER = "x-sv-key"
KEY_LEN = 32

ACCOUNT_NOT_SYNCED = "account_not_synced"


def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "sid": "sess_" + secrets.token_hex(8),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def b64_master_key(master_key: bytes) -> str:
    return base64.b64encode(master_key).decode("ascii")


def _decode_master_key(raw: str | None) -> bytes | None:
    if not raw:
        return None
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        return None
    return key if len(key) == KEY_LEN else None


def _claims(credentials: HTTPAuthorizationCredentials | None) -> dict:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        return jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

def get_current(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Returns {"user_id", "session_id", "unlocked", "master_key"}.

    Raises 409 ``account_not_synced`` when the account row is not present on
    this instance — the client answers that by pushing its encrypted backup.
    """
    claims = _claims(credentials)
    user_id = claims.get("sub", "")
    session_id = claims.get("sid", "")
    master_key = _decode_master_key(request.headers.get(MASTER_KEY_HEADER))
    if not query_one("SELECT id FROM users WHERE id = ?", (user_id,)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=ACCOUNT_NOT_SYNCED)
    return {
        "user_id": user_id,
        "session_id": session_id,
        "unlocked": master_key is not None,
        "master_key": master_key,
    }


def get_unlocked(auth: dict = Depends(get_current)) -> dict:
    if not auth.get("unlocked"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Vault is locked — unlock with your master password",
        )
    return auth


def get_optional_current(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict | None:
    """Like get_current but returns None instead of raising (used by sync/restore)."""
    try:
        return get_current(request=request, credentials=credentials)
    except HTTPException:
        return None


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def client_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")
