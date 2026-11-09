"""Deterministic precedence rules for website-issued manual lock overrides."""
from __future__ import annotations


def manual_override(policy: dict, now_ts: int) -> str | None:
    """Return 'unlock', 'lock', or None when schedule policy should decide."""
    mode = str(policy.get("overrideMode", "") or "").lower()
    try:
        until = int(policy.get("unlockedUntil", 0) or 0)
    except (TypeError, ValueError):
        until = 0
    if mode == "unlock":
        return "unlock" if until <= 0 or until > int(now_ts) else None
    if mode == "lock":
        return "lock"
    if until > int(now_ts):
        return "unlock"
    if policy.get("paused"):
        return "lock"
    return None
