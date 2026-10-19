"""Cryptographic engine — the core of SentinelVault.

Key hierarchy
-------------
    master_password --Argon2id(kdf_salt)--> master_key        (never persisted)
    master_key --HMAC-SHA256--> auth_verifier                  (stored: proves knowledge of password)
    recovery_key (random 32B) wraps master_key with AES-256-GCM (stored: enables recovery)

Data encryption
---------------
    AES-256-GCM with a fresh 96-bit random nonce per encryption.
    Stored token format: base64(nonce || ciphertext || tag)
    Optional AAD (e.g. the record id) binds ciphertext to its context.

All key material is generated with os.urandom (CSPRNG).
Parameters are module-level so the KDF cost is auditable and tunable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Argon2id parameters (OWASP-recommended range) ---
ARGON2_TIME_COST = 3          # iterations
ARGON2_MEMORY_COST = 65536    # 64 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_master_key(master_password: str, kdf_salt: bytes) -> bytes:
    """Argon2id(master_password, salt) -> 32-byte master key. Never stored."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=kdf_salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def compute_verifier(master_key: bytes) -> str:
    """Deterministic verifier proving key knowledge without storing the key."""
    return hmac.new(master_key, b"sentinelvault:auth-verifier", hashlib.sha256).hexdigest()


def verify_master_key(master_key: bytes, stored_verifier: str) -> bool:
    return hmac.compare_digest(compute_verifier(master_key), stored_verifier)


def derive_subkey(master_key: bytes, info: bytes) -> bytes:
    """Domain-separated subkeys from the master key (HKDF-SHA256)."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(master_key)


# ---------------------------------------------------------------------------
# Symmetric encryption (AES-256-GCM)
# ---------------------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt(key: bytes, token: str, aad: bytes = b"") -> bytes:
    raw = base64.b64decode(token)
    if len(raw) < NONCE_LEN + 16:
        raise ValueError("ciphertext too short")
    return AESGCM(key).decrypt(raw[:NONCE_LEN], raw[NONCE_LEN:], aad or None)


# ---------------------------------------------------------------------------
# Recovery key (master password loss -> recovery key system)
# ---------------------------------------------------------------------------

def generate_recovery_key() -> str:
    """Human-transferable recovery key, grouped for readability."""
    raw = secrets.token_bytes(32)
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    groups = [b32[i:i + 8] for i in range(0, len(b32), 8)]
    return "-".join(groups)


def _recovery_key_bytes(recovery_key: str) -> bytes:
    normalized = recovery_key.replace("-", "").replace(" ", "").upper()
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    raw = base64.b32decode(padded)
    if len(raw) != 32:
        raise ValueError("invalid recovery key length")
    return raw


def wrap_master_key(recovery_key: str, master_key: bytes) -> str:
    """Encrypt the master key under the recovery key (AES-256-GCM)."""
    return encrypt(_recovery_key_bytes(recovery_key), master_key, b"sentinelvault:recovery")


def unwrap_master_key(recovery_key: str, wrapped: str) -> bytes:
    return decrypt(_recovery_key_bytes(recovery_key), wrapped, b"sentinelvault:recovery")


# ---------------------------------------------------------------------------
# Breach lookup helpers (k-anonymity: only a 5-char SHA-1 prefix ever leaves)
# ---------------------------------------------------------------------------

def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    digest = sha1_hex(password)
    return digest[:5], digest[5:]


# ---------------------------------------------------------------------------
# Share-link keys (token in URL fragment, server stores only ciphertext)
# ---------------------------------------------------------------------------

def generate_share_token() -> str:
    return secrets.token_urlsafe(32)


def share_key_from_token(token: str) -> bytes:
    return hashlib.sha256(b"sentinelvault:share:" + token.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) — stdlib implementation
# ---------------------------------------------------------------------------

def totp_generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def totp_code(secret_b32: str, at_time: float | None = None, period: int = 30, digits: int = 6) -> str:
    counter = int((at_time if at_time is not None else time.time()) // period)
    return _totp_hotp(secret_b32, counter, digits)


def totp_seconds_left(period: int = 30) -> int:
    return period - int(time.time()) % period


def totp_verify(secret_b32: str, code: str, window: int = 1, period: int = 30, digits: int = 6) -> bool:
    now = time.time()
    for offset in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret_b32, now + offset * period, period, digits), code.strip()):
            return True
    return False


def totp_uri(secret_b32: str, account: str, issuer: str = "SentinelVault", digits: int = 6, period: int = 30) -> str:
    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&digits={digits}&period={period}"
    )
