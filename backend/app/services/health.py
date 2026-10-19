"""Password health dashboard — aggregates strength, reuse, aging and breach status."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from . import vault as vault_service

STALE_DAYS = 365
WEAK_SCORE = 50


def _age_days(iso_timestamp: str | None) -> int:
    if not iso_timestamp:
        return 0
    try:
        then = datetime.fromisoformat(iso_timestamp)
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - then).days, 0)
    except Exception:
        return 0


def compute(user_id: str, master_key: bytes, strength_analyzer=None) -> dict:
    items = vault_service.list_items_internal(user_id, master_key)
    total = len(items)

    # Reuse detection: identical passwords across items
    groups: dict[str, list[str]] = {}
    for item in items:
        password = item.get("password") or ""
        if password:
            groups.setdefault(hashlib.sha256(password.encode()).hexdigest(), []).append(item["id"])
    reused_ids = {iid for ids in groups.values() if len(ids) > 1 for iid in ids}

    results = []
    weak_count = breached_count = stale_count = 0
    score_sum = 0
    for item in items:
        score = item.get("strength_score")
        if score is None:
            score = 0
        score_sum += score
        age = _age_days(item.get("password_updated_at") or item.get("updated_at"))
        reused = item["id"] in reused_ids
        breached = (item.get("breached_count") or 0) > 0
        weak = score < WEAK_SCORE
        stale = age > STALE_DAYS
        if weak:
            weak_count += 1
        if breached:
            breached_count += 1
        if stale:
            stale_count += 1

        issues = []
        if breached:
            issues.append(f"Found in a data breach ({item['breached_count']:,} occurrences) — change it now")
        if reused:
            issues.append("Reused across multiple accounts")
        if weak:
            issues.append("Weak password")
        if stale:
            issues.append(f"Not changed in {age} days")

        results.append({
            "id": item["id"],
            "title": item.get("title", ""),
            "username": item.get("username", ""),
            "category": item.get("category", "login"),
            "score": score,
            "age_days": age,
            "reused": reused,
            "reuse_group_size": len(groups.get(hashlib.sha256((item.get("password") or "").encode()).hexdigest(), [])) if item.get("password") else 0,
            "breached": breached,
            "breached_count": item.get("breached_count") or 0,
            "needs_rotation": breached or reused or weak or stale,
            "issues": issues,
        })

    avg_strength = (score_sum / total) if total else 0
    reuse_ratio = (len(reused_ids) / total) if total else 0
    breach_ratio = (breached_count / total) if total else 0
    stale_ratio = (stale_count / total) if total else 0
    overall = max(0, min(100, round(avg_strength - reuse_ratio * 25 - breach_ratio * 35 - stale_ratio * 8))) if total else 0

    distribution = {
        "strong": sum(1 for r in results if r["score"] >= 80),
        "good": sum(1 for r in results if 60 <= r["score"] < 80),
        "fair": sum(1 for r in results if 40 <= r["score"] < 60),
        "weak": sum(1 for r in results if r["score"] < 40),
    }

    actions: list[str] = []
    change_now = [r for r in results if r["breached"] or (r["reused"] and r["score"] < 70)]
    if change_now:
        actions.append(f"{len(change_now)} account(s) need changing now")
    if reuse_ratio > 0:
        actions.append(f"{len(reused_ids)} account(s) reuse the same password")
    if weak_count:
        actions.append(f"{weak_count} weak password(s) — use the generator to upgrade")
    if stale_count:
        actions.append(f"{stale_count} password(s) older than a year")
    if not actions:
        actions.append("Vault looks healthy — keep it up!")

    return {
        "overall_score": overall,
        "grade": _grade(overall),
        "total": total,
        "avg_strength": round(avg_strength, 1),
        "weak_count": weak_count,
        "reused_count": len(reused_ids),
        "breached_count": breached_count,
        "stale_count": stale_count,
        "distribution": distribution,
        "top_actions": actions,
        "change_now": [{"id": r["id"], "title": r["title"], "issues": r["issues"]} for r in change_now],
        "items": sorted(results, key=lambda r: r["score"]),
    }


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"
