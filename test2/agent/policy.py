"""Pure policy logic for the macOS agent (no I/O, fully unit-tested).

It mirrors what the shared Admin/Parent dashboard (web/common.js) shows, so that
what a parent sees on screen is exactly what the Mac enforces.
"""
from __future__ import annotations
import datetime as dt
import re
from dataclasses import dataclass

# Admin "Lock from parent" checkboxes -> the config keys they protect.
LOCK_SECTIONS = {
    "control": ("paused", "bonus", "unlockedUntil", "overrideMode"),
    "adult": ("adult", "gambling", "social", "proxy", "ageGroup"),
    "sites": ("sites", "allowedSites"),
    "browsers": ("browsers", "safeSearch"),
    "apps": ("apps", "allowedApps"),
    "games": ("blockGames", "blockedGames", "allowedGames"),
    "time": ("limit", "limitWk", "start", "end"),
    "location": ("locationEnabled",),
}
# Lists written by the administrator are always added to the parent's lists.
LIST_KEYS = ("sites", "allowedSites", "apps", "allowedApps", "blockedGames", "allowedGames")


def merge_policy(parent: dict, admin: dict, protection_off: bool = False, suspended: bool = False) -> dict:
    p = dict(parent if isinstance(parent, dict) else {})
    admin = admin if isinstance(admin, dict) else {}
    for section in admin.get("locked", []) or []:
        for key in LOCK_SECTIONS.get(section, ()):
            if key in admin:
                p[key] = admin[key]
    for key in LIST_KEYS:
        if not isinstance(admin.get(key), list):
            continue
        # Website rules edited in the Admin Dashboard are a complete snapshot,
        # not an additive patch. Replacing these two lists is essential: an old
        # parent-side entry must not resurrect a site the administrator has
        # explicitly unblocked. Other administrator-managed lists retain their
        # historical additive behaviour.
        if key in ("sites", "allowedSites"):
            p[key] = list(dict.fromkeys(admin[key]))
        else:
            cur = p.get(key, [])
            p[key] = list(dict.fromkeys((cur if isinstance(cur, list) else []) + admin[key]))
    p["protectionOff"] = bool(protection_off)
    p["suspended"] = bool(suspended)
    return p


# ---------------------------------------------------------------- names
def norm(x) -> str:
    """'Google Chrome.app', 'chrome.exe', '/Applications/Roblox.app' -> comparable token."""
    s = str(x or "").strip().lower().replace("\\", "/").rsplit("/", 1)[-1]
    s = re.sub(r"\.(exe|app|dmg|pkg)$", "", s)
    return re.sub(r"[^a-z0-9]", "", s)


# Windows executable names offered by the dashboard's browser switches -> Mac app names.
BROWSER_MAP = {
    "chrome.exe": ("googlechrome", "chrome"),
    "msedge.exe": ("microsoftedge", "msedge"),
    "firefox.exe": ("firefox",),
    "brave.exe": ("bravebrowser", "brave"),
    "opera.exe": ("opera", "operagx"),
    "vivaldi.exe": ("vivaldi",),
    "safari.exe": ("safari",),
}
# The dashboard's "Block common games" switch, as Mac app/process names.
DEFAULT_GAMES = {
    "roblox", "robloxplayer", "robloxstudio", "minecraft", "minecraftlauncher", "steam", "steamosx",
    "epicgameslauncher", "fortnite", "leagueoflegends", "leagueclient", "riotclientservices", "riotclient",
    "valorant", "amongus", "genshinimpact", "battlenet", "ealauncher", "eaapp", "origin", "bluestacks",
    "geforcenow", "terraria", "stardewvalley", "brawlhalla", "freefire", "pubg", "dota2", "csgo", "cs2",
}
# Never touched, even if somebody typed them into a block list.
PROTECTED = {"finder", "loginwindow", "dock", "systemuiserver", "windowserver", "launchd", "kerneltask",
             "controlcenter", "python", "python3", "mfamilysafetyguard"}


def _hit(token: str, cand: str) -> bool:
    return bool(token) and (token == cand or (len(token) >= 5 and token in cand))


def _tokens(values) -> list[str]:
    return [t for t in (norm(v) for v in (values if isinstance(values, list) else [])) if t]


def app_verdict(candidates, policy: dict):
    """Return (blocked, kind, label) for one running program.

    `candidates` = normalised names the program is known by (bundle name, executable, hints).
    kind is one of 'app', 'game', 'browser'."""
    cands = {norm(c) for c in candidates if norm(c)}
    if not cands or cands & PROTECTED:
        return False, "", ""
    allow_apps, allow_games = _tokens(policy.get("allowedApps")), _tokens(policy.get("allowedGames"))
    any_hit = lambda toks: next((t for t in toks if any(_hit(t, c) for c in cands)), None)
    if any_hit(allow_apps) or any_hit(allow_games):
        return False, "", ""
    t = any_hit(_tokens(policy.get("apps")))
    if t:
        return True, "app", t
    g_tokens = _tokens(policy.get("blockedGames")) + (sorted(DEFAULT_GAMES) if policy.get("blockGames") else [])
    t = any_hit(g_tokens)
    if t:
        return True, "game", t
    for exe in policy.get("browsers", []) or []:
        for name in BROWSER_MAP.get(str(exe).lower(), (norm(exe),)):
            if any(c == name for c in cands):
                return True, "browser", name
    return False, "", ""


# ---------------------------------------------------------------- time rules
@dataclass
class Decision:
    locked: bool
    kind: str      # none | suspended | parent-lock | schedule | limit | override-unlock | timed-unlock
    reason: str


def _minutes(hhmm):
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", str(hhmm or ""))
    if not m:
        return None
    h, mi = int(m.group(1)), int(m.group(2))
    return h * 60 + mi if h < 24 and mi < 60 else None


def limit_minutes(policy: dict, today: dt.date, day_str: str):
    """Daily limit in minutes (weekend value on Sat/Sun) plus today's bonus, or None for 'no limit'."""
    weekend = today.weekday() >= 5
    base = policy.get("limitWk") if weekend and policy.get("limitWk") is not None else policy.get("limit")
    try:
        base = float(base)
    except (TypeError, ValueError):
        return None
    bonus = policy.get("bonus")
    if isinstance(bonus, dict) and bonus.get("day") == day_str:
        try:
            base += float(bonus.get("min") or 0)
        except (TypeError, ValueError):
            pass
    return base


def in_allowed_hours(policy: dict, now: dt.datetime) -> bool:
    s, e = _minutes(policy.get("start")), _minutes(policy.get("end"))
    if s is None or e is None or s == e:
        return True
    cur = now.hour * 60 + now.minute
    return (s <= cur < e) if s < e else (cur >= s or cur < e)   # window may cross midnight


def lock_decision(policy: dict, now_ts: float, used_sec: float, day_str: str, now: dt.datetime) -> Decision:
    """Same order of precedence as the dashboard's lockedNow() plus its limit/schedule rules."""
    if policy.get("suspended"):
        return Decision(True, "suspended", "This child is suspended by the administrator.")
    mode = str(policy.get("overrideMode") or "")
    try:
        until = float(policy.get("unlockedUntil") or 0)
    except (TypeError, ValueError):
        until = 0.0
    if mode == "unlock" and (not until or until > now_ts):
        return Decision(False, "override-unlock", "")
    if mode == "lock":
        return Decision(True, "parent-lock", "Locked by your parent.")
    if until > now_ts:
        return Decision(False, "timed-unlock", "")
    if policy.get("paused"):
        return Decision(True, "parent-lock", "Locked by your parent.")
    if not in_allowed_hours(policy, now):
        return Decision(True, "schedule", f"Outside allowed hours ({policy.get('start')} to {policy.get('end')}).")
    lim = limit_minutes(policy, now.date(), day_str)
    if lim is not None and used_sec >= lim * 60:
        return Decision(True, "limit", "Today's screen time is used up.")
    return Decision(False, "none", "")


def remaining_seconds(policy: dict, used_sec: float, today: dt.date, day_str: str):
    lim = limit_minutes(policy, today, day_str)
    return None if lim is None else max(0.0, lim * 60 - used_sec)


# ---------------------------------------------------------------- web rules
DOMAIN_RX = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")


def clean_domain(x) -> str:
    """'https://user@WWW.Example.com:8080/a?b#c', '*.example.com', 'example.com?x=1', ' example.com. ' -> 'example.com'."""
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(x or "").strip().lower())
    d = re.split(r"[/?#\\\s]", d, maxsplit=1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    d = re.sub(r"^(\*\.)+", "", d).strip(".")
    return d.removeprefix("www.").strip(".")


def rule_domains(policy: dict, category_domains: dict):
    """(blocked, allowed) domain sets for the website rules."""
    def good(values):
        out = set()
        for x in values if isinstance(values, list) else []:
            d = clean_domain(x)
            if DOMAIN_RX.fullmatch(d):
                out.add(d)
        return out
    blocked = good(policy.get("sites", []))
    for c in ("adult", "gambling", "social", "proxy"):
        if policy.get(c):
            blocked.update(category_domains.get(c, set()))
    return blocked, good(policy.get("allowedSites", []))
