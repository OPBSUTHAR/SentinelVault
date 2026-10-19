"""Breach monitoring — Have I Been Pwned integration.

Passwords: k-anonymity range API (free, no key). Only the first 5 hex chars of
the SHA-1 hash ever leave the server; the suffix is matched locally.

Emails/accounts: live checks need an HIBP API key. Without one we fall back to
a reference catalog of major breaches so the UI stays informative.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import httpx

from ..config import settings
from ..crypto.engine import sha1_prefix_suffix

# Reference catalog (offline fallback / context for impact assessment)
REFERENCE_BREACHES = [
    {"name": "Collection #1", "date": "2019-01-07", "pwn_count": 772_904_991,
     "data_classes": ["Email addresses", "Passwords"], "severity": "critical"},
    {"name": "Collection #2-5", "date": "2019-02-07", "pwn_count": 845_000_000,
     "data_classes": ["Email addresses", "Passwords"], "severity": "critical"},
    {"name": "LinkedIn", "date": "2021-06-22", "pwn_count": 700_000_000,
     "data_classes": ["Email addresses", "Passwords", "Phone numbers"], "severity": "critical"},
    {"name": "Adobe", "date": "2013-10-04", "pwn_count": 152_445_165,
     "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"], "severity": "high"},
    {"name": "Dropbox", "date": "2012-07-01", "pwn_count": 68_648_009,
     "data_classes": ["Email addresses", "Passwords"], "severity": "high"},
    {"name": "MySpace", "date": "2008-07-01", "pwn_count": 359_420_698,
     "data_classes": ["Email addresses", "Passwords", "Usernames"], "severity": "high"},
    {"name": "Tumblr", "date": "2013-02-28", "pwn_count": 65_469_298,
     "data_classes": ["Email addresses", "Passwords"], "severity": "medium"},
    {"name": "Canva", "date": "2019-05-24", "pwn_count": 137_272_116,
     "data_classes": ["Email addresses", "Passwords", "Usernames", "Geographic locations"], "severity": "high"},
    {"name": "Twitter", "date": "2018-07-01", "pwn_count": 88_000_000,
     "data_classes": ["Email addresses", "Passwords"], "severity": "high"},
    {"name": "Facebook", "date": "2019-04-03", "pwn_count": 533_000_000,
     "data_classes": ["Email addresses", "Phone numbers", "Names"], "severity": "critical"},
    {"name": "RockYou2021", "date": "2021-06-04", "pwn_count": 3_200_000_000,
     "data_classes": ["Passwords"], "severity": "critical"},
    {"name": "Wattpad", "date": "2020-06-01", "pwn_count": 271_334_751,
     "data_classes": ["Email addresses", "Passwords", "Usernames"], "severity": "high"},
]


def check_password(password: str) -> dict:
    """k-anonymity check against the Pwned Passwords corpus."""
    prefix, suffix = sha1_prefix_suffix(password)
    try:
        response = httpx.get(
            f"{settings.HIBP_PWNED_URL}/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "SentinelVault"},
            timeout=10.0,
        )
        response.raise_for_status()
        count = 0
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip().upper() == suffix:
                count = int(parts[1])
                break
        return {"breached": count > 0, "count": count, "available": True, "source": "hibp-k-anonymity"}
    except Exception as exc:  # network down / offline demo
        return {"breached": False, "count": 0, "available": False,
                "error": f"Breach service unavailable: {exc.__class__.__name__}", "source": "hibp-k-anonymity"}


def check_email(email: str) -> dict:
    """Live account breach lookup (needs API key) with catalog fallback."""
    if not settings.HIBP_API_KEY:
        return {
            "available": False,
            "email": email,
            "message": "Live account checks need an HIBP API key (set HIBP_API_KEY). "
                       "Showing the reference breach catalog instead.",
            "breaches": REFERENCE_BREACHES[:8],
            "source": "reference_catalog",
        }
    try:
        response = httpx.get(
            f"{settings.HIBP_API_URL}/breachedaccount/{email}?truncateResponse=false",
            headers={
                "hibp-api-key": settings.HIBP_API_KEY,
                "User-Agent": "SentinelVault",
            },
            timeout=15.0,
        )
        if response.status_code == 404:
            return {"available": True, "email": email, "breaches": [], "source": "hibp"}
        response.raise_for_status()
        breaches = [
            {
                "name": b.get("Name", ""),
                "date": (b.get("BreachDate") or ""),
                "pwn_count": b.get("PwnCount", 0),
                "data_classes": b.get("DataClasses", []),
                "severity": _severity_for(b.get("PwnCount", 0)),
            }
            for b in response.json()
        ]
        return {"available": True, "email": email, "breaches": breaches, "source": "hibp"}
    except Exception as exc:
        return {"available": False, "email": email,
                "error": f"HIBP request failed: {exc.__class__.__name__}",
                "breaches": REFERENCE_BREACHES[:8], "source": "reference_catalog"}


def _severity_for(pwn_count: int) -> str:
    if pwn_count >= 100_000_000:
        return "critical"
    if pwn_count >= 1_000_000:
        return "high"
    if pwn_count >= 10_000:
        return "medium"
    return "low"


def assess_impact(email: str, breaches: list[dict], items: list[dict]) -> dict:
    """Breach impact assessment: which vault accounts are exposed, how bad, what to do."""
    affected_items = [
        {"item_id": it["id"], "title": it["title"], "username": it.get("username", "")}
        for it in items
        if email.lower() in f"{it.get('email') or ''} {it.get('username') or ''}".lower()
    ]
    max_severity = "low"
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    password_exposed = False
    for breach in breaches:
        if order.get(breach.get("severity", "low"), 0) > order[max_severity]:
            max_severity = breach.get("severity", "low")
        if any("password" in dc.lower() for dc in breach.get("data_classes", [])):
            password_exposed = True

    recommendations: list[str] = []
    if password_exposed:
        recommendations.append(f"Change passwords for the {len(affected_items)} affected account(s) now — "
                               "this breach exposed plaintext or hashed passwords.")
    if any("email" in dc.lower() for dc in (breaches[0].get("data_classes", []) if breaches else [])):
        recommendations.append("Watch for targeted phishing emails referencing this breach.")
    if not breaches:
        recommendations.append("No breaches found for this address — keep monitoring.")

    return {
        "email": email,
        "breach_count": len(breaches),
        "max_severity": max_severity if breaches else "none",
        "password_exposed": password_exposed,
        "affected_accounts": affected_items,
        "recommendations": recommendations,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def email_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:24]


def breaches_to_json(breaches: list[dict]) -> str:
    return json.dumps(breaches)
