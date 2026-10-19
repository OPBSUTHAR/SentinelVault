"""Phishing-site detection — lexical and structural URL heuristics.

No external API needed: scores a URL from its components (host shape, brand
keyword abuse, suspicious TLDs, punycode, redirect tricks) and explains itself.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

BRAND_KEYWORDS = (
    "paypal", "apple", "google", "gmail", "microsoft", "outlook", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "telegram", "binance", "coinbase", "metamask",
    "bank", "sbi", "hdfc", "icici", "axis", "kotak", "chase", "wellsfargo", "hsbc",
    "steam", "roblox", "discord", "github", "dropbox", "adobe", "linkedin", "xbox",
    "playstation", "spotify", "twitter", "irctc", "uidai", "epfo", "incometax",
)

SUSPICIOUS_TLDS = (
    ".zip", ".mov", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work",
    ".click", ".link", ".country", ".stream", ".gdn", ".loan", ".review", ".kim",
    ".cricket", ".science", ".party", ".racing", ".win", ".men", ".bid",
)

SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in", "s.id",
)

FREE_HOSTS = (
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "github.io",
    "netlify.app", "vercel.app", "pages.dev", "web.app", "firebaseapp.com",
    "glitch.me", "repl.co", "godaddysites.com", "square.site", "myshopify.com",
)

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "confirm", "password", "credential", "wallet", "recovery", "unlock", "billing",
    "invoice", "payment", "gift", "bonus", "prize", "free", "urgent", "suspended",
    "limited", "kyc",
)


def analyze_url(url: str) -> dict:
    raw = (url or "").strip()
    if not raw:
        return {"url": "", "valid": False, "score": 0, "verdict": "invalid", "findings": []}
    if "://" not in raw:
        raw = "http://" + raw

    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if not host:
        return {"url": url, "valid": False, "score": 0, "verdict": "invalid", "findings": []}

    findings: list[dict] = []
    score = 0

    def add(fid: str, severity: str, points: int, detail: str) -> None:
        nonlocal score
        score += points
        findings.append({"id": fid, "severity": severity, "detail": detail})

    try:
        ipaddress.ip_address(host)
        add("ip_host", "critical", 40, "The address is a raw IP — legitimate login pages use domain names.")
    except ValueError:
        pass

    labels = host.split(".")
    tld = "." + labels[-1] if len(labels) > 1 else ""
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host

    if "xn--" in host:
        add("punycode", "critical", 25, "Punycode (IDN) hostname — can visually imitate a real brand.")

    brand = next((b for b in BRAND_KEYWORDS if b in host), None)
    if brand:
        official = brand in ("google", "gmail") and registrable in ("google.com", "gmail.com")
        official = official or registrable in (f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.in", f"{brand}.co.in")
        if not official:
            add("brand_mismatch", "critical", 25, f"'{brand}' appears in the domain, but '{registrable}' is not its official domain.")

    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", "high", 18, f"TLD '{tld}' is frequently abused for phishing and malware.")

    if host in SHORTENERS:
        add("shortener", "medium", 12, "URL shortener hides the true destination.")

    if any(host.endswith(fh) for fh in FREE_HOSTS):
        add("free_hosting", "low", 8, "Hosted on a free website service — unusual for a real login portal.")

    if host.count("-") >= 2:
        add("many_hyphens", "medium", 8, "Multiple hyphens in the domain — a common look-alike trick.")

    digit_count = sum(ch.isdigit() for ch in host)
    if digit_count >= 4:
        add("digits", "low", 6, "Many digits in the domain name.")

    if len(labels) >= 4:
        add("deep_subdomain", "medium", 8, "Deeply nested subdomain structure.")

    if len(host) > 32:
        add("long_host", "low", 5, "Unusually long hostname.")

    if "@" in (parsed.netloc or ""):
        add("at_trick", "critical", 25, "'@' in the URL — everything before it is ignored by browsers.")

    path_query = f"{parsed.path or ''}?{parsed.query or ''}"
    hit_words = [w for w in SUSPICIOUS_WORDS if w in raw.lower()]
    if hit_words:
        add("lure_words", "low", min(10, 3 * len(hit_words)), "Lure keywords: " + ", ".join(hit_words[:5]) + ".")

    if parsed.scheme == "http":
        add("no_https", "medium", 8, "No HTTPS — pages that ask for passwords should always be encrypted.")

    if re.search(r"\.(exe|scr|apk|msi|vbs|bat|cmd|jar|rar|zip)(\?|$)", parsed.path or "", re.I):
        add("download", "high", 15, "Links directly to an executable or archive.")

    if any(k in (parsed.query or "").lower() for k in ("url=", "redirect=", "next=", "goto=", "continue=")):
        add("redirect_param", "medium", 10, "Possible open-redirect parameter.")

    score = min(score, 100)
    if score >= 60:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    elif score > 0:
        verdict = "likely_safe"
    else:
        verdict = "safe"

    return {
        "url": url,
        "valid": True,
        "host": host,
        "registrable_domain": registrable,
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
