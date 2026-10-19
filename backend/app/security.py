"""JWT auth + in-memory unlocked session store.

Design: the JWT carries (user_id, session_id). The master key derived from the
user's master password lives ONLY in this process's memory, keyed by session id,
with a sliding TTL. Restarting the server locks every vault by construction.
"""
from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from .config import settings

_bearer = HTTPBearer(auto_error=False)
_lock = threading.Lock()

# session_id -> {"user_id", "master_key", "created_at", "last_used"}
_sessions: dict[str, dict] = {}


def _now() -> float:
    return time.time()


def create_token(user_id: str, session_id: str) -> str:
    payload = {
        "sub": user_id,
        "sid": session_id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_session(user_id: str, master_key: bytes) -> str:
    session_id = "sess_" + secrets.token_hex(16)
    with _lock:
        _sessions[session_id] = {
            "user_id": user_id,
            "master_key": master_key,
            "created_at": _now(),
            "last_used": _now(),
        }
    return session_id


def lock_session(session_id: str) -> None:
    """Lock = drop the in-memory master key but keep the session so unlock can re-attach."""
    with _lock:
        session = _sessions.get(session_id)
        if session:
            session["master_key"] = None


def unlock_session(session_id: str, user_id: str, master_key: bytes) -> bool:
    """Attach a freshly derived master key to an existing session."""
    with _lock:
        session = _sessions.get(session_id)
        if not session or session.get("user_id") != user_id:
            return False
        session["master_key"] = master_key
        session["last_used"] = _now()
        return True


def _purge_expired() -> None:
    ttl = settings.SESSION_TTL_MINUTES * 60
    with _lock:
        expired = [sid for sid, s in _sessions.items() if _now() - s["last_used"] > ttl]
        for sid in expired:
            _sessions.pop(sid, None)


def _get_session(session_id: str) -> dict | None:
    _purge_expired()
    with _lock:
        session = _sessions.get(session_id)
        if session:
            session["last_used"] = _now()
        return session


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
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """Returns {"user_id", "session_id", "unlocked", "master_key"}."""
    claims = _claims(credentials)
    user_id = claims.get("sub", "")
    session_id = claims.get("sid", "")
    session = _get_session(session_id)
    if session and session.get("user_id") == user_id and session.get("master_key") is not None:
        return {
            "user_id": user_id,
            "session_id": session_id,
            "unlocked": True,
            "master_key": session["master_key"],
        }
    return {"user_id": user_id, "session_id": session_id, "unlocked": False, "master_key": None}


def get_unlocked(auth: dict = Depends(get_current)) -> dict:
    if not auth.get("unlocked"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Vault is locked — unlock with your master password",
        )
    return auth


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def client_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")
