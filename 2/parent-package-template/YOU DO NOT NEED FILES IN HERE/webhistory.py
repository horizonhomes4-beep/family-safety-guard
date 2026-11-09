"""Reads the pages a person actually opened from the browsers' own history databases.

DNS and network logs contain every background request (ads, CDNs, updates, telemetry). A browser's
history contains only pages that were really navigated to, so it is the correct source for the
"Sites visited" list and the activity timeline.

Supported: Chrome, Edge, Brave, Vivaldi, Opera / Opera GX (Chromium History file) and Firefox
(places.sqlite). Every Windows account under C:\\Users is scanned, so it works for any child account.

Private/Incognito windows do not write history; the agent turns those modes off with browser policy.
"""
from __future__ import annotations
import os, shutil, sqlite3, tempfile, time
from pathlib import Path
from urllib.parse import urlsplit

EPOCH_1601 = 11644473600
# Chromium core transition types that mean "the person navigated here" (3 and 4 are embedded frames).
CHROMIUM_OK = {0, 1, 2, 5, 6, 7, 8, 9, 10}
# Firefox visit types: 4 = embed, 7 = download, 8 = framed link are not navigations.
FIREFOX_OK = {1, 2, 3, 5, 6, 9}
SKIP_USERS = {"public", "default", "default user", "all users", "desktop.ini"}

CHROMIUM = [  # (label, base folder relative to the user profile, has profile sub-folders)
    ("Chrome", r"AppData\Local\Google\Chrome\User Data", True),
    ("Edge", r"AppData\Local\Microsoft\Edge\User Data", True),
    ("Brave", r"AppData\Local\BraveSoftware\Brave-Browser\User Data", True),
    ("Vivaldi", r"AppData\Local\Vivaldi\User Data", True),
    ("Opera", r"AppData\Roaming\Opera Software\Opera Stable", False),
    ("Opera GX", r"AppData\Roaming\Opera Software\Opera GX Stable", False),
]


def users_root() -> Path:
    return Path(os.environ.get("SystemDrive", "C:") + "\\Users")


def find_sources(root: Path | None = None) -> list[dict]:
    """Every history database that exists right now: [{key, browser, user, kind, path}]."""
    root = root or users_root()
    out: list[dict] = []
    try:
        users = [p for p in root.iterdir() if p.is_dir() and p.name.lower() not in SKIP_USERS]
    except OSError:
        return out
    for home in users:
        for label, rel, profiles in CHROMIUM:
            base = home.joinpath(*rel.split("\\"))
            if not base.is_dir():
                continue
            dirs = [base]
            if profiles:
                dirs = [d for d in base.iterdir() if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile "))]
            for d in dirs:
                hist = d / "History"
                if hist.is_file():
                    out.append({"key": str(hist), "browser": label, "user": home.name, "kind": "chromium", "path": hist})
        ff = home.joinpath("AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
        if ff.is_dir():
            for d in ff.iterdir():
                places = d / "places.sqlite"
                if places.is_file():
                    out.append({"key": str(places), "browser": "Firefox", "user": home.name, "kind": "firefox", "path": places})
    return out


def _snapshot(path: Path, tmp: Path) -> Path:
    """Copy the database (and its journal/WAL) so the browser's lock never blocks us."""
    dst = tmp / path.name
    shutil.copy2(path, dst)
    for suffix in ("-wal", "-journal"):
        side = path.with_name(path.name + suffix)
        if side.is_file():
            try:
                shutil.copy2(side, tmp / (path.name + suffix))
            except OSError:
                pass
    return dst


def clean_url(url: str) -> tuple[str, str] | None:
    """(host, short_url) for web pages; None for browser-internal pages, local files, etc."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = parts.hostname.lower().strip(".")
    if host in ("localhost",) or "." not in host:
        return None
    short = f"{parts.scheme}://{host}{parts.path}"
    return host, short[:140]


def _read(src: dict, last_id: int, since: int, limit: int, tmp: Path, first: bool = False) -> tuple[list[dict], int]:
    """New visits since `last_id`. On the first read of a source (`first`), take only visits newer than `since`
    and start tracking from the table's current maximum id so older history is never imported later."""
    snap = _snapshot(src["path"], tmp)
    con = sqlite3.connect(snap.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    chromium = src["kind"] == "chromium"
    try:
        table = "visits" if chromium else "moz_historyvisits"
        top = int(con.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0] or 0) if first else last_id
        if chromium:
            sql = ("SELECT v.id, v.visit_time, v.transition, u.url, u.title FROM visits v JOIN urls u ON u.id=v.url WHERE "
                   + ("v.visit_time>=? " if first else "v.id>? ") + "ORDER BY v.id LIMIT ?")
            arg = int((since + EPOCH_1601) * 1_000_000) if first else last_id
        else:
            sql = ("SELECT h.id, h.visit_date, h.visit_type, p.url, p.title FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id WHERE "
                   + ("h.visit_date>=? " if first else "h.id>? ") + "ORDER BY h.id LIMIT ?")
            arg = int(since * 1_000_000) if first else last_id
        rows = con.execute(sql, (arg, limit)).fetchall()
    finally:
        con.close()
    out = []
    for vid, vt, kind, url, title in rows:
        if not first:
            top = max(top, vid)
        if chromium:
            if (kind & 0xFF) not in CHROMIUM_OK:
                continue
            ts = int(vt / 1_000_000 - EPOCH_1601)
        else:
            if kind not in FIREFOX_OK:
                continue
            ts = int(vt / 1_000_000)
        c = clean_url(url)
        if not c:
            continue
        out.append({"t": ts, "host": c[0], "u": c[1], "title": " ".join((title or "").split())[:90],
                    "browser": src["browser"], "user": src["user"]})
    return out, top


def current_max_id(src: dict, tmp: Path) -> int:
    snap = _snapshot(src["path"], tmp)
    con = sqlite3.connect(snap.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    try:
        table = "visits" if src["kind"] == "chromium" else "moz_historyvisits"
        row = con.execute(f"SELECT MAX(id) FROM {table}").fetchone()
        return int(row[0] or 0)
    finally:
        con.close()


def collect(marks: dict, now: float | None = None, first_window: int = 3600, limit: int = 500,
            root: Path | None = None) -> tuple[list[dict], list[str], list[str]]:
    """Return (new_visits_oldest_first, sources_readable, errors). `marks` maps source key -> last visit id and is updated in place.

    The first time a source is seen, only the last `first_window` seconds are imported so older history is not flooded in.
    """
    now = now or time.time()
    visits: list[dict] = []
    ok: list[str] = []
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="pg-hist-") as t:
        tmp = Path(t)
        for i, src in enumerate(find_sources(root)):
            work = tmp / str(i)
            work.mkdir()
            src = {**src}
            try:
                first = src["key"] not in marks
                found, top = _read(src, int(marks.get(src["key"], 0)), int(now - first_window), limit, work, first)
                marks[src["key"]] = top
                visits += found
                ok.append(f"{src['browser']} ({src['user']})")
            except Exception as exc:  # locked, corrupt, permission: report, never crash the agent
                errors.append(f"{src['browser']} ({src['user']}): {type(exc).__name__}: {exc}")
    visits.sort(key=lambda v: v["t"])
    return visits, ok, errors
