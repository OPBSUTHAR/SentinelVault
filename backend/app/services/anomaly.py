"""Login anomaly detection — behavioral rules + alert feed.

Signals tracked per user: device (user-agent hash), IP /16 subnet, login hour,
failure bursts. Each signal is compared against the user's own history so the
"anomaly" is personal, not global.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from ..crypto.engine import derive_subkey  # noqa: F401  (kept for future encrypted event payloads)
from ..db import execute, new_id, query, utcnow


def _event_payload(event_type: str, severity: str, ip: str, agent: str, detail: dict) -> dict:
    return {
        "event_type": event_type,
        "severity": severity,
        "ip": ip or "",
        "user_agent": agent or "",
        "detail": detail or {},
    }


def _insert_event(user_id: str, payload: dict) -> str:
    event_id = new_id("evt")
    execute(
        "INSERT INTO security_events (id, user_id, event_type, severity, ip, user_agent, detail, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event_id,
            user_id,
            payload["event_type"],
            payload["severity"],
            payload["ip"],
            payload["user_agent"],
            json.dumps(payload["detail"]),
            utcnow(),
        ),
    )
    return event_id


def create_alert(user_id: str, kind: str, severity: str, title: str, message: str, meta: dict | None = None) -> str:
    alert_id = new_id("alert")
    execute(
        "INSERT INTO alerts (id, user_id, kind, severity, title, message, meta, read, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
        (alert_id, user_id, kind, severity, title, message, json.dumps(meta or {}), utcnow()),
    )
    return alert_id


def record_login(user_id: str, success: bool, ip: str, agent: str) -> dict:
    """Record an auth attempt and run the anomaly rules for this user."""
    history = query(
        "SELECT * FROM security_events WHERE user_id = ? AND event_type IN ('login_success','login_failed')"
        " ORDER BY created_at DESC LIMIT 200",
        (user_id,),
    )
    device_hash = hashlib.sha256((agent or "").encode()).hexdigest()[:12]
    subnet = ".".join((ip or "").split(".")[:2])
    now = datetime.now(timezone.utc)
    hour = now.hour

    event_type = "login_success" if success else "login_failed"
    severity = "info"
    detail: dict = {"device": device_hash, "subnet": subnet, "hour": hour}
    alerts: list[tuple[str, str, str, str]] = []

    seen_devices = {json.loads(r["detail"] or "{}").get("device") for r in history}
    seen_subnets = {json.loads(r["detail"] or "{}").get("subnet") for r in history}

    if history and device_hash not in seen_devices:
        severity = "warning"
        alerts.append((
            "new_device", "warning",
            "New device signed in",
            f"Sign-in from a device we haven't seen before (fingerprint {device_hash}).",
        ))
    if history and subnet and subnet not in seen_subnets and ip:
        severity = "warning" if severity == "info" else severity
        alerts.append((
            "new_location", "warning",
            "Sign-in from a new network",
            f"New IP range detected: {subnet}.x.x.x.",
        ))
    if success and history and (hour < 6 or hour >= 23):
        # Compare against the user's usual hours if enough history exists
        hours = [json.loads(r["detail"] or "{}").get("hour") for r in history]
        hours = [h for h in hours if isinstance(h, int)]
        if len(hours) >= 5 and hour not in hours:
            alerts.append((
                "unusual_time", "low",
                "Unusual sign-in time",
                f"You normally sign in at other hours — this was {hour:02d}:00 UTC.",
            ))

    if not success:
        window_start = (now - timedelta(minutes=10)).isoformat()
        recent_fails = query(
            "SELECT COUNT(*) AS c FROM security_events WHERE user_id = ? AND event_type = 'login_failed'"
            " AND created_at >= ?",
            (user_id, window_start),
        )[0]["c"]
        if recent_fails >= 4:  # this failure makes 5+
            severity = "critical"
            alerts.append((
                "brute_force", "critical",
                "Repeated failed sign-ins",
                f"{recent_fails + 1} failed attempts in the last 10 minutes. "
                "If this wasn't you, change your master password.",
            ))
    else:
        window_start = (now - timedelta(minutes=10)).isoformat()
        recent_fails = query(
            "SELECT COUNT(*) AS c FROM security_events WHERE user_id = ? AND event_type = 'login_failed'"
            " AND created_at >= ?",
            (user_id, window_start),
        )[0]["c"]
        if recent_fails >= 3:
            severity = "warning"
            alerts.append((
                "success_after_fails", "warning",
                "Successful sign-in after failures",
                f"Signed in successfully after {recent_fails} recent failed attempts.",
            ))

    event_id = _insert_event(user_id, _event_payload(event_type, severity, ip, agent, detail))
    for kind, sev, title, message in alerts:
        create_alert(user_id, kind, sev, title, message, {"event_id": event_id, "ip": ip})

    return {"event_id": event_id, "alerts_created": len(alerts)}


def list_events(user_id: str, limit: int = 50) -> list[dict]:
    rows = query(
        "SELECT * FROM security_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        (user_id, min(limit, 200)),
    )
    return [
        {
            "id": r["id"],
            "event_type": r["event_type"],
            "severity": r["severity"],
            "ip": r["ip"],
            "detail": json.loads(r["detail"] or "{}"),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def list_alerts(user_id: str, limit: int = 50, unread_only: bool = False) -> list[dict]:
    sql = "SELECT * FROM alerts WHERE user_id = ?"
    params: list = [user_id]
    if unread_only:
        sql += " AND read = 0"
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(min(limit, 200))
    rows = query(sql, tuple(params))
    return [
        {
            "id": r["id"],
            "kind": r["kind"],
            "severity": r["severity"],
            "title": r["title"],
            "message": r["message"],
            "meta": json.loads(r["meta"] or "{}"),
            "read": bool(r["read"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def mark_alert_read(user_id: str, alert_id: str) -> bool:
    row = query("SELECT id FROM alerts WHERE id = ? AND user_id = ?", (alert_id, user_id))
    if not row:
        return False
    execute("UPDATE alerts SET read = 1 WHERE id = ? AND user_id = ?", (alert_id, user_id))
    return True


def unread_count(user_id: str) -> int:
    return query("SELECT COUNT(*) AS c FROM alerts WHERE user_id = ? AND read = 0", (user_id,))[0]["c"]
