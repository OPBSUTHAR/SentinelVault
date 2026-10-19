"""Password strength & pattern analysis (zxcvbn-inspired, zero deps).

Produces a 0-100 score, entropy estimate, detected patterns, human-readable
feedback and crack-time estimates for several attack scenarios.
"""
from __future__ import annotations

import math
import re

# ---------------------------------------------------------------------------
# Reference data (compact embedded lists — extended in the ML roadmap)
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "welcome", "jesus", "ninja", "mustang",
    "password1", "123456789", "adobe123", "admin", "root", "toor", "pass",
    "test", "guest", "login", "starwars", "hello", "freedom", "whatever",
    "nicole", "jennifer", "hunter", "harley", "secret", "summer", "winter",
    "spring", "autumn", "internet", "service", "canada", "america", "india",
    "maggie", "pepper", "cookie", "banana", "orange", "purple", "silver",
    "diamond", "gemini", "internet", "samsung", "google", "facebook", "twitter",
    "linkedin", "instagram", "whatsapp", "computer", "monitor", "keyboard",
    "princess", "pokemon", "batman", "matrix", "alexander", "soccer", "hockey",
    "killer", "george", "charlie", "andrew", "daniel", "joshua", "matthew",
    "amanda", "jessica", "sarah", "hannah", "taylor", "thomas", "robert",
    "william", "richard", "joseph", "charles", "steven", "patrick", "donald",
    "loveme", "flower", "summer1", "winter1", "spring1", "abcdef", "abcdefg",
    "aaaaaaaa", "zzzzzzzz", "11111111", "00000000", "1q2w3e4r", "1qaz2wsx",
    "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm", "password123",
    "letmein1", "welcome1", "admin123", "administrator", "changeme", "secret1",
}

DICTIONARY_WORDS = {
    "apple", "orange", "purple", "silver", "golden", "diamond", "planet",
    "rocket", "guitar", "garden", "flower", "summer", "winter", "spring",
    "coffee", "chocolate", "cookie", "banana", "cherry", "melon", "peach",
    "cloud", "storm", "thunder", "lightning", "mountain", "river", "ocean",
    "forest", "desert", "island", "bridge", "castle", "tower", "garden",
    "dragon", "phoenix", "tiger", "eagle", "falcon", "panther", "wizard",
    "knight", "warrior", "hunter", "shadow", "blade", "sword", "shield",
    "magic", "power", "energy", "future", "matrix", "cyber", "robot",
    "engine", "system", "network", "server", "client", "portal", "vector",
}

KEYBOARD_ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
ALPHA_SEQ = "abcdefghijklmnopqrstuvwxyz"

LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "8": "b", "3": "e", "1": "i", "!": "i",
    "0": "o", "$": "s", "5": "s", "7": "t", "+": "t", "9": "g", "6": "g",
})

RATINGS = [
    (80, "strong"), (60, "good"), (40, "fair"), (20, "weak"), (0, "very weak"),
]


def _leet_normalize(text: str) -> str:
    return text.lower().translate(LEET_MAP)


def _longest_sequence_run(text: str) -> tuple[int, str]:
    """Longest run of characters consecutive along a keyboard row / alphabet / digits."""
    best, best_kind = 0, ""
    lowered = text.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(lowered)):
            run = 1
            for j in range(i, len(lowered) - 1):
                a, b = lowered[j], lowered[j + 1]
                if a in row and b in row and abs(row.index(b) - row.index(a)) == 1:
                    run += 1
                else:
                    break
            if run > best:
                best, best_kind = run, "keyboard"
    for base in (ALPHA_SEQ, "0123456789"):
        for i in range(len(lowered)):
            run = 1
            for j in range(i, len(lowered) - 1):
                a, b = lowered[j], lowered[j + 1]
                if a in base and b in base and base.index(b) - base.index(a) == 1:
                    run += 1
                else:
                    break
            if run > best:
                best, best_kind = run, "sequence"
    return best, best_kind


def _repeated_substring(text: str) -> int:
    """Length of the longest repeated-block pattern (e.g. 'abcabcabc' -> 3)."""
    n = len(text)
    for block in range(1, n // 2 + 1):
        if n % block == 0:
            piece = text[:block]
            if piece * (n // block) == text:
                return block
    return 0


def _pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return pool or 1


def human_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("century", "centuries", 3155760000),
        ("year", "years", 31557600),
        ("month", "months", 2592000),
        ("day", "days", 86400),
        ("hour", "hours", 3600),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    ]
    for name, plural, size in units:
        if seconds >= size:
            value = seconds / size
            if value >= 100:
                return f"{value:,.0f} {plural}"
            return f"{value:.1f} {plural}" if value < 10 else f"{value:.0f} {plural}"
    return "instantly"


def analyze(password: str, user_inputs: list[str] | None = None) -> dict:
    """Analyze a password → score, entropy, patterns, feedback, crack times."""
    password = password or ""
    length = len(password)
    pool = _pool_size(password)
    lower = password.lower()
    leet = _leet_normalize(password)

    patterns: list[dict] = []
    feedback: list[str] = []
    penalties_bits = 0.0

    # Base entropy from length + character pool
    entropy_bits = length * math.log2(pool) if length else 0.0

    # 1) Common password check (raw and leet-normalized)
    if lower in COMMON_PASSWORDS or leet in COMMON_PASSWORDS:
        patterns.append({"type": "common_password", "detail": "Found in common password lists"})
        feedback.append("This is one of the most commonly used passwords — attackers try it first.")
        entropy_bits = min(entropy_bits, 8.0)

    # 2) Dictionary words (leet-aware)
    for word in DICTIONARY_WORDS:
        if length >= 5 and word in leet and word not in ("",):
            patterns.append({"type": "dictionary_word", "detail": f"Contains the word '{word}'"})
            penalties_bits += len(word) * 2.5
            if word in {"password", "admin", "welcome", "login", "secret"}:
                feedback.append(f"Avoid dictionary words like '{word}'.")
            break

    # 3) Sequences / keyboard walks
    run_len, run_kind = _longest_sequence_run(password)
    if run_len >= 4:
        patterns.append({"type": run_kind, "detail": f"Contains a {run_len}-character {run_kind} pattern"})
        penalties_bits += (run_len - 1) * 2.0
        feedback.append("Straight sequences (like '12345' or 'qwerty') are easy to guess.")

    # 4) Repeats
    block = _repeated_substring(lower)
    if block and length >= 4:
        patterns.append({"type": "repeat", "detail": f"Repeated block of {block} characters"})
        penalties_bits += (length - block) * 1.5
        feedback.append("Repetition ('abcabcabc') adds little real strength.")

    # 5) Dates / years
    if re.search(r"(19|20)\d{2}", password):
        patterns.append({"type": "date", "detail": "Contains a year"})
        penalties_bits += 8
        feedback.append("Years and dates are commonly guessed.")
    if re.search(r"\b\d{2}[/\-.]\d{2}[/\-.]\d{2,4}\b", password):
        patterns.append({"type": "date", "detail": "Looks like a date"})
        penalties_bits += 12

    # 6) Only digits / single class
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes == 1 and length:
        patterns.append({"type": "single_charset", "detail": "Uses only one character type"})
        feedback.append("Mix uppercase, lowercase, digits and symbols.")

    # 7) Personal hints (emails, names passed by the caller)
    for hint in user_inputs or []:
        hint = (hint or "").strip().lower()
        if len(hint) >= 4 and hint in leet:
            patterns.append({"type": "personal_info", "detail": f"Contains personal info '{hint}'"})
            penalties_bits += len(hint) * 3.0
            feedback.append("Avoid names, emails and other personal details.")

    entropy_bits = max(entropy_bits - penalties_bits, 4.0) if length else 0.0

    # Score: entropy-driven with hard caps for structural weaknesses
    score = min(round(entropy_bits / 90 * 100), 100)
    if lower in COMMON_PASSWORDS or leet in COMMON_PASSWORDS:
        score = min(score, 10)
    if length < 8:
        score = min(score, 40)
        feedback.append("Use at least 12 characters (16+ is ideal).")
    if classes == 1 and length:
        score = min(score, 45)
    if length >= 16 and classes >= 3 and not any(p["type"] == "common_password" for p in patterns):
        score = min(score + 8, 100)
    if not feedback:
        feedback.append("Good password — no obvious patterns detected.")
    score = max(0, min(100, score))

    guesses = 2 ** entropy_bits
    crack_times = {
        "online_throttled": human_duration(guesses / 100),          # 100 attempts/hour
        "online_unthrottled": human_duration(guesses / 1000),       # ~1k guesses/sec
        "offline_slow_hash": human_duration(guesses / 1e4),         # bcrypt-ish
        "offline_fast_hash": human_duration(guesses / 1e10),        # GPU cluster
    }

    rating = next(label for threshold, label in RATINGS if score >= threshold)

    return {
        "score": score,
        "rating": rating,
        "entropy_bits": round(entropy_bits, 1),
        "length": length,
        "charset_classes": classes,
        "patterns": patterns,
        "feedback": feedback[:4],
        "crack_times": crack_times,
        "estimated_guesses_log10": round(math.log10(guesses), 1) if guesses > 0 else 0,
    }
