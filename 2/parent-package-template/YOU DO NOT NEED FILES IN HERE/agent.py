"""ParentGuard Windows child-device agent.

Enforces administrator/parent policy on this Windows PC and reports acknowledged
state to Firestore. This is endpoint software, not an OS-level MDM: see README
for the permissions and bypass limitations that still apply.
"""
from __future__ import annotations
import csv, datetime as dt, hashlib, io, json, os, re, subprocess, sys, time
from pathlib import Path
from typing import Any

VERSION = "5.11.1"
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "packages"))
import requests
import blocklists as BL
import policy_rules as PR
import dnsfilter
import webhistory
LOG, STATE, CONFIG = ROOT / "agent.log", ROOT / "state.json", ROOT / "config.json"
HEALTH = ROOT / "health.json"
NOTICE = ROOT / "notice.json"
# Shared, world-readable copy of the notice. The child's pop-up helper reads this folder, so it works even
# if the Program Files copy cannot be read from the child's session.
NOTICE_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "MFamilySafetyGuard" / "notices"
NOTICE_SHARED = NOTICE_DIR / "notice.json"
# Folder where the child's interactive notice window drops requests (more time, allow site...).
# The SYSTEM agent validates each file and forwards it to Firestore + e-mail.
REQ_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "MFamilySafetyGuard" / "requests"
NOTICE_GRACE = 45  # seconds the child sees the lock notice (and can send a request) before the session is disconnected
MAIL_URL = "https://api.emailjs.com/api/v1.0/email/send"
REQ_TYPES = {"time", "site", "app", "message"}
MUTEX_NAME = "Global\\ParentGuardAgentSingleton"
HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\drivers\etc\hosts"
TICK = 10
ADULT_DOMAINS = set("pornhub.com xvideos.com xnxx.com xhamster.com redtube.com youporn.com brazzers.com onlyfans.com chaturbate.com stripchat.com spankbang.com porn.com rule34.xxx nhentai.net livejasmin.com bongacams.com".split())
BROWSER_EXES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"}
DEFAULT_GAMES = {"robloxplayerbeta.exe", "minecraft.exe", "javaw.exe", "steam.exe", "epicgameslauncher.exe", "fortniteclient-win64-shipping.exe", "leagueclient.exe", "riotclientservices.exe", "valorant.exe", "among us.exe"}
IGNORED = {"explorer.exe", "searchhost.exe", "textinputhost.exe", "applicationframehost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe", "systemsettings.exe", "ctfmon.exe", "dwm.exe", "taskmgr.exe", "runtimebroker.exe", "lockapp.exe"}


def log(message: str) -> None:
    try:
        if LOG.exists() and LOG.stat().st_size > 512_000:
            LOG.replace(LOG.with_suffix(".log.1"))
        with LOG.open("a", encoding="utf-8") as f:
            f.write(f"{dt.datetime.now().isoformat(timespec='seconds')} [{VERSION}] {message}\n")
    except OSError:
        pass


def run(args: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


cfg_file = load_json(CONFIG, {})
try:
    PROJECT, API_KEY = cfg_file["projectId"], cfg_file["apiKey"]
    DEVICE_ID, DEVICE_KEY = cfg_file["deviceId"], cfg_file["deviceKey"]
    if not all(isinstance(v, str) and v.strip() for v in (PROJECT, API_KEY, DEVICE_ID, DEVICE_KEY)):
        raise ValueError("projectId, apiKey, deviceId and deviceKey must be non-empty strings")
except KeyError as exc:
    raise SystemExit(f"Invalid config.json: missing {exc}")
DB = f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents"
state = load_json(STATE, {})
for key, value in {"reqLog": [], "mailQueue": [], "awaiting": [], "childName": "", "used": 0, "day": "", "cfg": {}, "apps": {}, "hist": {}, "events": [], "timeline": [], "sites": {}, "dyn": {}, "dnsRid": 0, "revision": "", "policyAppliedAt": 0, "policySyncError": "", "device": {}, "deviceAt": 0, "hmarks": {}, "web": {}, "upstreams": []}.items():
    state.setdefault(key, value)
session: dict[str, str] = {}
http = requests.Session()
http.headers.update({"User-Agent": f"MFamilySafetyGuard/{VERSION}", "Accept": "application/json"})
hosts_signature: str | None = None
dns_signature: bool | None = None
pending_command: dict = {}  # last admin command read from the device document (repair / uninstall)


def save_state() -> None:
    """Atomically persist local state so a power loss cannot leave half-written JSON."""
    tmp = STATE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        for attempt in range(4):  # another program (antivirus, a log reader) can hold state.json for a moment on Windows
            try:
                tmp.replace(STATE)
                break
            except PermissionError:
                if attempt == 3:
                    raise
                time.sleep(0.5)
        if os.name == "nt":
            # Directory ACLs restrict this file to SYSTEM/Administrators; hidden is not encryption.
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(STATE), 0x2)
            except Exception:
                pass
    except OSError as exc:
        log(f"state save failed: {exc}")


_notice_last: dict[str, float] = {}

def child_text(message: str, kind: str, domain: str, app: str) -> str:
    """Plain-language explanation shown to the child."""
    if kind == "block" and domain:
        return f"The website {domain} is blocked by your family safety settings."
    if kind == "block" and app:
        return f"The app {app} is blocked by your family safety settings."
    if kind == "screen":
        why = message.split(":", 1)[1].strip() if ":" in message else message
        return f"This computer is about to lock ({why})."
    return message


def device_summary() -> dict:
    """What is active on this device, shown to the child in the notice window."""
    cfg = state.get("cfg", {}) or {}
    try:
        wk = dt.datetime.now().weekday() >= 5
        base = cfg.get("limitWk", cfg.get("limit")) if wk else cfg.get("limit")
        bonus = cfg.get("bonus") or {}
        extra = int(bonus.get("min", 0)) if bonus.get("day") == state.get("day") else 0
        limit = None if base in (None, "") else int(float(base)) + extra
    except Exception:
        limit = None
    used = int(round(state.get("used", 0)))
    filters = [n for k, n in (("adult", "Adult content"), ("gambling", "Gambling"), ("social", "Social media"), ("proxy", "VPNs & proxies")) if cfg.get(k)]
    if cfg.get("safeSearch", True):
        filters.append("Safe search")
    return {
        "used": used, "limit": limit, "left": None if limit is None else max(0, limit - used),
        "hours": f"{cfg.get('start', '07:00')} - {cfg.get('end', '21:00')}",
        "sites": len(cfg.get("sites", []) or []), "apps": len(cfg.get("apps", []) or []),
        "games": bool(cfg.get("blockGames")), "filters": filters, "locked": bool(cfg.get("paused")),
    }


_helper_started = 0.0


def ensure_notice_helper() -> None:
    """Start the pop-up helper in the signed-in user's desktop if it is not already running."""
    global _helper_started
    if os.name != "nt" or time.time() - _helper_started < 45:
        return
    _helper_started = time.time()
    try:
        # The task is registered for the Users group with MultipleInstances=IgnoreNew, so this is harmless
        # when the helper is already running.
        run(["schtasks", "/run", "/tn", "MFamilySafetyGuard-Notice"], timeout=15)
    except Exception as exc:
        log(f"could not start notice helper: {exc}")


def publish_notice(message: str, kind: str, domain: str = "", app: str = "", lock_in: int = 0) -> None:
    """Publish a full-screen notice for interactive Windows users (shown by notice_client.py)."""
    if os.name != "nt" or kind not in {"block", "screen", "answer"}:
        return
    key = f"{kind}:{domain or app or message}"
    now = time.time()
    # Avoid repeatedly covering the desktop: one notice per blocked site (5 min) / app (2 min), whatever the lookups.
    if now - _notice_last.get(key, 0) < (300 if domain else 120 if app else 30):
        return
    _notice_last[key] = now
    try:
        previous = load_json(NOTICE, {})
        ttype, target = ("site", domain) if domain else (("app", app) if app else (("time", "") if kind == "screen" else ("message", "")))
        notice = {
            "id": max(int(now * 1000), int(previous.get("id", 0)) + 1),
            "at": int(now),
            "title": "@M Family Safety Guard blockage",
            "reason": child_text(message, kind, domain, app) if kind != "answer" else message,
            "kind": kind,
            "ttype": ttype,
            "target": target,
            "lockAt": int(now + lock_in) if lock_in else 0,
            "device": device_summary(),
        }
        payload = json.dumps(notice, ensure_ascii=False)
        for target in (NOTICE_SHARED, NOTICE):
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_suffix(".tmp")
                tmp.write_text(payload, encoding="utf-8")
                tmp.replace(target)
            except Exception as exc:
                log(f"notice write failed ({target}): {exc}")
        log(f"notice published: {notice['reason']}")
        ensure_notice_helper()
    except Exception as exc:
        log(f"notice publish failed: {exc}")

def event(message: str, kind: str = "sys", at: int | None = None, domain: str = "", app: str = "",
          notify: bool = True, lock_in: int = 0, extra: dict | None = None) -> None:
    """Record an activity entry. kind: web | block | app | user | screen | sys. Feeds the live timeline."""
    item: dict[str, Any] = {"at": int(at or time.time()), "message": message, "kind": kind}
    if domain:
        item["d"] = domain
    if extra:
        item.update(extra)
    state["events"] = ([item] + state["events"])[:40]
    state["timeline"] = ([item] + state.get("timeline", []))[:400]
    log(message)
    if notify:
        publish_notice(message, kind, domain, app, lock_in)


def headers() -> dict[str, str]:
    return {"Authorization": "Bearer " + session.get("token", "")}


def authenticate() -> None:
    refresh = state.get("refreshToken")
    if refresh:
        try:
            response = http.post(f"https://securetoken.googleapis.com/v1/token?key={API_KEY}",
                                     data={"grant_type": "refresh_token", "refresh_token": refresh}, timeout=20)
            if response.ok:
                data = response.json()
                session.update(token=data["id_token"], uid=data["user_id"])
                state["refreshToken"] = data["refresh_token"]
                save_state()
                return
        except requests.RequestException as exc:
            log(f"token refresh failed: {exc}")
    response = http.post(f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}",
                             json={"returnSecureToken": True}, timeout=20)
    data = response.json()
    if "idToken" not in data:
        raise RuntimeError(f"Firebase agent sign-in failed: {data}")
    session.update(token=data["idToken"], uid=data["localId"])
    state["refreshToken"] = data["refreshToken"]
    save_state()
    url = f"{DB}/devices/{DEVICE_ID}/agents/{session['uid']}"
    response = http.patch(url, headers=headers(), json={"fields": {"key": {"stringValue": DEVICE_KEY}}}, timeout=20)
    if not response.ok:
        raise RuntimeError(f"Agent registration rejected: {response.status_code} {response.text[:300]}")


def json_field(fields: dict, name: str, default: Any) -> Any:
    try:
        return json.loads(fields.get(name, {}).get("stringValue", ""))
    except (ValueError, TypeError):
        return default


def pull_policy() -> dict:
    response = http.get(f"{DB}/devices/{DEVICE_ID}", headers=headers(), timeout=20)
    if response.status_code in (401, 403):
        authenticate()
        response = http.get(f"{DB}/devices/{DEVICE_ID}", headers=headers(), timeout=20)
    response.raise_for_status()
    fields = response.json().get("fields", {})
    state["childName"] = str(fields.get("name", {}).get("stringValue", ""))[:80]
    parent = json_field(fields, "cfg", {})
    admin = json_field(fields, "adminCfg", {})
    # Admin policy overrides parent settings only for explicitly locked sections.
    policy = dict(parent)
    section_fields = {
        "control": ("paused", "bonus", "unlockedUntil", "overrideMode"), "apps": ("apps", "allowedApps"),
        "games": ("blockedGames", "allowedGames", "blockGames"), "browsers": ("browsers", "safeSearch"),
        "sites": ("sites", "allowedSites"), "adult": ("adult", "gambling", "social", "proxy", "ageGroup"),
        "time": ("limit", "limitWk", "start", "end", "child", "bedtime", "wakeTime"),
        "location": ("locationEnabled",),
    }
    for section in admin.get("locked", []):
        for field in section_fields.get(section, ()):
            if field in admin:
                policy[field] = admin[field]
    # Administrator exceptions are additive and take precedence at enforcement
    # time: an admin-approved app/game/site can override a parent's blocklist.
    for field in ("apps", "allowedApps", "blockedGames", "allowedGames", "sites", "allowedSites"):
        if isinstance(admin.get(field), list):
            policy[field] = list(dict.fromkeys(list(policy.get(field, [])) + admin[field]))
    if admin.get("blockGames") is True:
        policy["blockGames"] = True
    if "locationEnabled" in admin:
        policy["locationEnabled"] = bool(admin["locationEnabled"])
    # Admin-only switches (parents cannot write these fields; see firestore.rules).
    policy["protectionOff"] = fields.get("protection", {}).get("stringValue", "") == "off"
    global pending_command
    raw_command = json_field(fields, "command", {})
    pending_command = raw_command if isinstance(raw_command, dict) else {}
    state["revision"] = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
    return policy


def normalise_domains(values: Any) -> set[str]:
    out = set()
    for item in values if isinstance(values, list) else []:
        value = str(item).strip().lower()
        value = re.sub(r"^https?://", "", value)
        value = value.split("/", 1)[0].split(":", 1)[0].removeprefix("www.").strip(".")
        if value and re.fullmatch(r"[a-z0-9.-]+", value):
            out.add(value)
    return out


def enabled_categories(policy: dict) -> list[str]:
    return [c for c in ("adult", "gambling", "social", "proxy") if policy.get(c)]


def blocked_set(policy: dict) -> set[str]:
    """Every host the policy blocks: parent/admin list, enabled categories and hosts discovered from DNS activity."""
    cats = enabled_categories(policy)
    blocked = set(normalise_domains(policy.get("sites", [])))
    for cat in cats:
        blocked |= BL.CATEGORY_DOMAINS[cat]
    blocked |= {h for h, cat in state.get("dyn", {}).items() if cat in cats or cat == "custom"}
    allowed = normalise_domains(policy.get("allowedSites", []))
    return {d for d in blocked if not any(d == a or d.endswith("." + a) for a in allowed)}


def update_hosts(policy: dict) -> None:
    global hosts_signature
    blocked = blocked_set(policy)
    signature = json.dumps(sorted(blocked))
    if signature == hosts_signature:
        return
    try:
        original = HOSTS.read_text(encoding="utf-8", errors="ignore") if HOSTS.exists() else ""
        original = re.sub(r"(?ms)^# PARENTGUARD BEGIN\s*.*?^# PARENTGUARD END\s*\n?", "", original).rstrip()
        if blocked:
            lines = []
            for domain in sorted(blocked):
                names = [domain] if domain.startswith("www.") else [domain, "www." + domain, "m." + domain]
                for name in names:
                    lines += [f"0.0.0.0 {name}", f":: {name}"]
            original += "\n\n# PARENTGUARD BEGIN\n" + "\n".join(lines) + "\n# PARENTGUARD END\n"
        HOSTS.write_text(original + "\n", encoding="utf-8")
        run(["ipconfig", "/flushdns"])
        hosts_signature = signature
        event(f"Website policy applied ({len(blocked)} blocked domains)", "sys")
    except Exception as exc:
        log(f"hosts policy failed (run installer as administrator): {exc}")
        hosts_signature = None


BROWSER_DOH = [
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "REG_SZ", "off"),
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "BuiltInDnsClientEnabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "REG_SZ", "off"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "BuiltInDnsClientEnabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "REG_SZ", "off"),
    (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", "REG_DWORD", "1"),
]


def apply_browser_hardening() -> None:
    """Turn off DNS-over-HTTPS so the hosts file, family DNS and the DNS activity log see every lookup."""
    if os.name != "nt" or state.get("dohOff") == 1:
        return
    for key, name, kind, value in BROWSER_DOH:
        run(["reg", "add", key, "/v", name, "/t", kind, "/d", value, "/f"])
    run(["wevtutil", "sl", "Microsoft-Windows-DNS-Client/Operational", "/e:true", "/ms:16777216"])
    state["dohOff"] = 1
    save_state()
    event("Browser DNS-over-HTTPS disabled; website activity logging enabled", "sys")


def note_site(base: str, ts: int, bg: bool, blocked: bool) -> bool:
    """Aggregate one DNS lookup into the per-site record. True when it counts as a new visit / blocked attempt."""
    sites = state["sites"]
    s = sites.setdefault(base, {"n": 0, "first": ts, "last": 0, "bn": 0, "bl": 0, "v": [], "bg": bg})
    new = False
    if blocked:
        if ts - s.get("bl", 0) >= 30:
            s["bn"] += 1
            new = True
        s["bl"] = max(s.get("bl", 0), ts)
    elif ts - s["last"] >= 120:
        s["n"] += 1
        s["v"] = (s["v"] + [ts])[-12:]
        new = True
    s["last"] = max(s["last"], ts)
    if len(sites) > 400:
        for old in sorted(sites, key=lambda k: sites[k]["last"])[:50]:
            del sites[old]
    return new


def process_dns(policy: dict) -> None:
    """Read new lookups from the Windows DNS Client log: record visited sites, count blocked attempts, learn subdomains to block."""
    global hosts_signature
    if os.name != "nt":
        return
    secs = max(10, int(time.time() - state.get("dnsAt", time.time() - 30)) + 3)
    script = ("$t=(Get-Date).AddSeconds(-%d);$e=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational';Id=3006;StartTime=$t} "
              "-ErrorAction SilentlyContinue|Select-Object -First 500;@($e|ForEach-Object{[pscustomobject]@{r=$_.RecordId;t=[DateTimeOffset]::new($_.TimeCreated).ToUnixTimeSeconds();"
              "q=[string]$_.Properties[0].Value}})|ConvertTo-Json -Compress") % secs
    rows = ps_json(script)
    state["dnsAt"] = time.time()
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return
    cats = enabled_categories(policy)
    blocked = blocked_set(policy)
    last_rid = int(state.get("dnsRid", 0))
    changed = False
    for row in sorted((r for r in rows if isinstance(r, dict)), key=lambda r: int(r.get("r", 0))):
        rid = int(row.get("r", 0))
        if rid <= last_rid:
            continue
        state["dnsRid"] = last_rid = rid
        host = str(row.get("q", "")).lower().strip(".")
        if not BL.valid_host(host):
            continue
        ts, base = int(row.get("t", time.time())), BL.base_domain(host)
        hit = any(host == d or host.endswith("." + d) for d in blocked)
        cat = "" if hit else BL.classify(host, cats)
        if hit or cat:
            if cat and host not in state["dyn"]:
                state["dyn"][host] = cat
                changed = True
            elif hit and host not in blocked:
                state["dyn"][host] = "custom"
                changed = True
            if note_site(base, ts, BL.is_background(host), True):
                event(f"Blocked website: {base}", "block", ts, base, notify=not BL.is_background(host))
        else:
            # A DNS lookup is not a visit (pages load dozens of ad/CDN/tracker hosts). Real visits come from the
            # browsers' own history (process_history); lookups are kept only as 'background' records.
            note_lookup(base, ts)
    if len(state["dyn"]) > 600:
        state["dyn"] = dict(list(state["dyn"].items())[-600:])
    if changed:
        hosts_signature = None


# ---------------------------------------------------------------------------
# v5.9: real-time DNS filter + real browser history (replaces "guessing" from background DNS traffic)
# ---------------------------------------------------------------------------
NEVER_BLOCK = ("googleapis.com", "firebaseio.com", "firebaseapp.com", "emailjs.com", "ipwho.is")
FLAG_CATS = ("adult", "gambling", "proxy")  # shown to the parent as 'looks like ...' when such a site was visited unblocked
DECIDER: dict = {"cats": [], "explicit": set(), "allowed": set()}
FILTER: "dnsfilter.DnsFilter | None" = None
_filter_try = 0.0


def update_decider(policy: dict) -> None:
    """Snapshot of the rules the DNS filter threads use. Replaced atomically each cycle."""
    global DECIDER
    DECIDER = {"cats": enabled_categories(policy), "explicit": normalise_domains(policy.get("sites", [])),
               "allowed": normalise_domains(policy.get("allowedSites", []))}


def dns_decide(host: str) -> tuple[bool, str]:
    """(blocked, reason) for one DNS name. Runs on every lookup, before the name is resolved."""
    d = DECIDER
    host = host.lower().strip(".")
    if host == "use-application-dns.net":  # Firefox's DoH canary: NXDOMAIN makes Firefox keep using system DNS
        return True, "doh-canary"
    if not host or "." not in host or any(host == n or host.endswith("." + n) for n in NEVER_BLOCK):
        return False, ""
    if any(host == a or host.endswith("." + a) for a in d["allowed"]):
        return False, ""
    for dom in d["explicit"]:
        if host == dom or host.endswith("." + dom):
            return True, "list"
    for cat in d["cats"]:
        if BL.in_set(host, BL.CATEGORY_DOMAINS.get(cat, ())):
            return True, cat
    for cat in d["cats"]:
        rx = BL.KEYWORDS.get(cat)
        if rx and rx.search(host):
            return True, cat
    return False, ""


def compute_upstreams(family: bool) -> list[str]:
    """Where the local filter forwards allowed lookups. Never loops back to 127.x."""
    original = []
    public = ["1.1.1.1", "8.8.8.8"]  # last-resort resolvers so the agent can always reach Firebase
    for item in state.get("dnsOriginal") or []:
        item["Servers"] = clean_servers(item.get("Servers"))
        for server in item.get("Servers") or []:
            server = str(server)
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", server) and not server.startswith("127.") and server not in original:
                original.append(server)
    if family:
        return ["1.1.1.3", "1.0.0.3"] + original[:2] + [x for x in public if x not in original[:2]]  # originals only if Cloudflare Family is unreachable
    return original[:4] + [x for x in public if x not in original[:4]]


def ensure_dns_filter() -> bool:
    """Start (or keep) the local DNS filter. False when it cannot listen; the agent then falls back to HOSTS + event log."""
    global FILTER, _filter_try
    if FILTER and FILTER.running:
        return True
    port = int(os.environ.get("PG_DNS_PORT", "53"))
    if os.name != "nt" and "PG_DNS_PORT" not in os.environ:
        return False
    if time.time() - _filter_try < 120:
        return False
    _filter_try = time.time()
    FILTER = dnsfilter.DnsFilter(dns_decide, lambda: list(state.get("upstreams") or ["1.1.1.1", "8.8.8.8"]), log, port=port)
    ok = FILTER.start()
    state["web"]["dnsError"] = "" if ok else FILTER.error
    if ok:
        event("Real-time website filter started", "sys")
    return ok


def filter_selftest() -> bool:
    """Ask our own filter a question. True only if it answers, so Windows is never pointed at a dead resolver."""
    import socket, struct
    port = int(os.environ.get("PG_DNS_PORT", "53"))
    query = struct.pack("!HHHHHH", 0x5047, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(6)
            s.sendto(query, ("127.0.0.1", port))
            data, _ = s.recvfrom(4096)
            return data[:2] == query[:2]
    except OSError:
        return False


def clean_servers(value: Any) -> list[str]:
    """PowerShell's ConvertTo-Json writes ONE dns server as a plain string, not a list. Looping over that string split
    '192.168.18.1' into single characters, which broke both the upstream list and the DNS restore. Accepts a string, a
    list, or a list already split into characters by the older version, and never returns a loopback address."""
    if isinstance(value, str):
        value = [value]
    items = [str(x).strip() for x in (value or [])]
    if items and all(len(x) == 1 for x in items):
        items = ["".join(items)]
    return [x for x in items if x and not x.startswith("127.") and x != "::1"]


def snapshot_dns() -> bool:
    if "dnsOriginal" in state:
        for item in state["dnsOriginal"]:  # repair a snapshot saved by the older version
            item["Servers"] = clean_servers(item.get("Servers"))
        return True
    query = "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,@{Name='Servers';Expression={$_.ServerAddresses}} | ConvertTo-Json -Compress"
    result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", query])
    try:
        original = json.loads(result.stdout.strip() or "[]")
        original = [original] if isinstance(original, dict) else original
        for item in original:  # a snapshot taken while we were already routing would "restore" 127.0.0.1 = no internet
            item["Servers"] = clean_servers(item.get("Servers"))
            item["Servers"] = [x for x in (item.get("Servers") or []) if not str(x).startswith("127.") and str(x) != "::1"]
        state["dnsOriginal"] = original
        save_state()
        return True
    except Exception as exc:
        log(f"could not snapshot original DNS settings: {exc}")
        return False


def restore_original_dns() -> None:
    for item in state.get("dnsOriginal") or []:
        item["Servers"] = clean_servers(item.get("Servers"))
        index = int(item.get("InterfaceIndex", 0) or 0)
        servers = [str(x) for x in (item.get("Servers") or []) if not str(x).startswith("127.")]
        if not index:
            continue
        if servers:
            quoted = ",".join("'" + x.replace("'", "") + "'" for x in servers)
            script = f"Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses ({quoted})"
        else:
            script = f"Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"
        result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        if result.returncode:
            log(f"could not restore DNS on interface {index}: {result.stderr[:200]}")
            if servers:  # last resort: automatic (DHCP) DNS, so the PC is never left pointing at a dead local filter
                run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f"Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"])
    run(["ipconfig", "/flushdns"])


def dns_failopen_check() -> None:
    """Called after a failed policy sync. A locked PC must always be able to hear 'Unlock'. If the PC reaches the internet by
    address but cannot resolve names while Windows DNS points at our local filter, stop routing through the filter for
    10 minutes so the agent can reach Firebase again. A truly offline PC (no internet by address) is left alone."""
    if os.name != "nt":
        return
    state["syncFails"] = int(state.get("syncFails", 0)) + 1
    if state["syncFails"] < 3 or not state.get("dnsLocal"):
        return
    net = internet_state()
    if net["net"] and not net["dns"]:
        log("Internet works by address but names do not resolve through the local filter; DNS reset to automatic for 10 minutes")
        reset_loopback_dns()
        state.update(dnsLocal=False, dnsRouteSig="", dnsRouteAt=0, dnsBypassUntil=time.time() + 600, syncFails=0)
        save_state()


def apply_dns_routing(policy: dict, local_ok: bool) -> None:
    """Point every network adapter at the local filter (127.0.0.1 / ::1) so no program can look a name up around it."""
    global dns_signature
    if os.name != "nt":
        return
    family = bool(policy.get("adult"))
    if time.time() < state.get("dnsBypassUntil", 0):
        return  # fail-open window after DNS trouble: leave Windows on automatic DNS until it ends
    if not local_ok:
        if state.get("dnsLocal"):  # filter is down: never leave Windows pointing at a dead resolver
            restore_original_dns()
            state["dnsLocal"] = False
            dns_signature = None
            save_state()
        apply_family_dns(family)
        return
    if not snapshot_dns():
        return
    state["upstreams"] = compute_upstreams(family)
    sig = "local:" + ",".join(state["upstreams"])
    if state.get("dnsRouteSig") == sig and time.time() - state.get("dnsRouteAt", 0) < 300 and state.get("dnsLocal"):
        return
    if not state.get("dnsLocal"):
        ok = filter_selftest()
        state["web"]["selfTest"] = ok
        if not ok:
            log("DNS filter self-test failed; Windows DNS not redirected")
            return
    script = ("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {$i=$_.ifIndex; "
              "try {Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses ('127.0.0.1','::1') -ErrorAction Stop} "
              "catch {Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses ('127.0.0.1')}}")
    result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=40)
    if result.returncode:
        log(f"DNS redirect failed: {result.stderr[:250]}")
        return
    run(["ipconfig", "/flushdns"])
    first = not state.get("dnsLocal")
    state.update(dnsLocal=True, dnsRouteSig=sig, dnsRouteAt=time.time())
    dns_signature = None  # fallback-mode bookkeeping restarts if the filter ever stops
    save_state()
    if first:
        event("All website lookups now pass through the real-time filter", "sys")


def note_lookup(base: str, ts: int) -> None:
    """Record a DNS lookup of an allowed name as *background* activity (never a visit)."""
    sites = state["sites"]
    s = sites.setdefault(base, {"n": 0, "first": ts, "last": 0, "bn": 0, "bl": 0, "v": [], "bg": True})
    s["dn"] = s.get("dn", 0) + 1
    if s.get("bg", True):
        s["last"] = max(s["last"], ts)
    else:
        s["ll"] = max(s.get("ll", 0), ts)
    if len(sites) > 400:  # drop the oldest background-only records first; real visits are kept
        for old in sorted(sites, key=lambda k: (not sites[k].get("bg", True) or sites[k].get("bn", 0) > 0, sites[k]["last"]))[:60]:
            del sites[old]


def process_filter_log(policy: dict) -> None:
    """Turn the DNS filter's query log into blocked-attempt records (real time). Allowed lookups are background only."""
    if not FILTER:
        return
    for q in FILTER.drain():
        host, ts = q["h"], int(q["t"])
        if not BL.valid_host(host):
            continue
        base = BL.base_domain(host)
        if q["b"]:
            if q["why"] == "doh-canary" or q["q"] not in (1, 28):  # count A/AAAA only: one attempt, not one per record type
                continue
            if note_site(base, ts, True, True):
                event(f"Blocked website: {base}", "block", ts, base, notify=not BL.is_background(host))
        else:
            note_lookup(base, ts)


def process_history(policy: dict) -> None:
    """Add the pages the child really opened (browser history) to the visited-sites list and the timeline."""
    now = time.time()
    if now - state.get("histAt", 0) < 10:
        return
    state["histAt"] = now
    visits, ok, errors = webhistory.collect(state["hmarks"], now)
    state["web"].update(historySources=ok, historyErrors=errors[:5], historyAt=int(now))
    for v in visits:
        host, ts = v["host"], int(v["t"])
        if not BL.valid_host(host):
            continue
        base = BL.base_domain(host)
        s = state["sites"].setdefault(base, {"n": 0, "first": ts, "last": 0, "bn": 0, "bl": 0, "v": [], "bg": False})
        s["bg"] = False
        if not s["n"]:
            s["first"] = ts
        new = ts - s.get("lv", 0) >= 120
        s["lv"], s["last"] = max(s.get("lv", 0), ts), max(s["last"], ts)
        if not new:
            continue
        s["n"] += 1
        s["v"] = (s["v"] + [ts])[-12:]
        blocked, _why = dns_decide(host)
        title = f" — {v['title']}" if v["title"] else ""
        if blocked:
            # The page opened although the rules say it is blocked (browser cache, VPN, own DNS...). Never hide this.
            s["leak"] = ts
            event(f"Opened a blocked website that was NOT stopped: {host}{title}", "block", ts, base, extra={"u": v["u"], "br": v["browser"]})
            continue
        cat = BL.classify(host, FLAG_CATS)
        if cat:
            s["cat"] = cat
        extra = {"u": v["u"], "br": v["browser"], "w": v["user"]}
        if cat:
            extra["c"] = cat
        event(f"Visited {host}{title}", "web", ts, base, notify=False, extra=extra)


PRIVACY_POLICIES = [
    # keep browsing in a mode that is recorded and filtered (no Incognito/InPrivate/Guest/Tor, history cannot be wiped)
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "IncognitoModeAvailability", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "BrowserGuestModeEnabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "AllowDeletingBrowserHistory", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Google\Chrome", "NetworkPredictionOptions", "REG_DWORD", "2"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "InPrivateModeAvailability", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "BrowserGuestModeEnabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "AllowDeletingBrowserHistory", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "NetworkPredictionOptions", "REG_DWORD", "2"),
    (r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave", "IncognitoModeAvailability", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave", "TorDisabled", "REG_DWORD", "1"),
    (r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave", "BrowserGuestModeEnabled", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\BraveSoftware\Brave", "AllowDeletingBrowserHistory", "REG_DWORD", "0"),
    (r"HKLM\SOFTWARE\Policies\Mozilla\Firefox", "DisablePrivateBrowsing", "REG_DWORD", "1"),
]
DOT_RULE = "MFamilySafetyGuard-BlockDoT"


def apply_privacy_hardening() -> None:
    """Close the easy ways around the filter and the log. Applied once per release; failures are logged and retried."""
    if os.name != "nt" or state.get("privApplied") == VERSION:
        return
    failed = 0
    for key, name, kind, value in PRIVACY_POLICIES:
        result = run(["reg", "add", key, "/v", name, "/t", kind, "/d", value, "/f"])
        if result.returncode:
            failed += 1
            log(f"browser policy not applied: {key}\\{name}: {result.stderr[:120]}")
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={DOT_RULE}"])
    result = run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={DOT_RULE}", "dir=out", "action=block", "protocol=TCP", "remoteport=853"])
    if result.returncode:
        failed += 1
        log(f"DNS-over-TLS firewall rule not added: {result.stderr[:120]}{result.stdout[:120]}")
    state["web"]["privateOff"] = failed == 0
    if not failed:
        state["privApplied"] = VERSION
    save_state()
    event("Private browsing, guest mode and history deletion disabled in Chrome, Edge, Brave and Firefox" if not failed
          else f"Browser privacy policies partly applied ({failed} failed; see agent.log)", "sys")


def apply_safe_search(enabled: bool) -> None:
    """Apply Windows machine-level managed SafeSearch policies for Chrome/Edge."""
    if os.name != "nt" or state.get("safeSearchApplied") is enabled:
        return
    policies = [
        (r"HKLM\SOFTWARE\Policies\Google\Chrome", "ForceGoogleSafeSearch", "1"),
        (r"HKLM\SOFTWARE\Policies\Google\Chrome", "ForceYouTubeRestrict", "2"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceBingSafeSearch", "2"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceYouTubeRestrict", "2"),
    ]
    for key, name, value in policies:
        if enabled:
            result = run(["reg", "add", key, "/v", name, "/t", "REG_DWORD", "/d", value, "/f"])
        else:
            result = run(["reg", "delete", key, "/v", name, "/f"])
        if result.returncode not in (0, 1):
            log(f"SafeSearch policy update failed: {key}\\{name}")
    state["safeSearchApplied"] = enabled
    save_state()


def apply_family_dns(enabled: bool) -> None:
    """Use Cloudflare Family DNS while enabled, restoring the prior DNS on disable."""
    global dns_signature
    if dns_signature == enabled:
        return
    if enabled:
        if "dnsOriginal" not in state:
            query = "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,@{Name='Servers';Expression={$_.ServerAddresses}} | ConvertTo-Json -Compress"
            result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", query])
            try:
                original = json.loads(result.stdout.strip() or "[]")
                if isinstance(original, dict):
                    original = [original]
                state["dnsOriginal"] = original
                save_state()
            except Exception as exc:
                log(f"could not snapshot original DNS settings: {exc}")
                return
        script = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('1.1.1.3','1.0.0.3')}"
        result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        if result.returncode:
            log(f"DNS family filter failed: {result.stderr[:250]}")
            return
    else:
        original = state.get("dnsOriginal")
        if original is not None:
            for item in original:
                index = int(item.get("InterfaceIndex", 0) or 0)
                servers = item.get("Servers") or []
                if not index:
                    continue
                if servers:
                    quoted = ",".join("'" + str(x).replace("'", "") + "'" for x in servers)
                    script = f"Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses ({quoted})"
                else:
                    script = f"Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"
                result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
                if result.returncode:
                    log(f"could not restore DNS on interface {index}: {result.stderr[:200]}")
            state.pop("dnsOriginal", None)
            save_state()
    dns_signature = enabled


def cleanup_device() -> None:
    """Remove ParentGuard-owned local filtering and restore saved network settings."""
    try:
        original = HOSTS.read_text(encoding="utf-8", errors="ignore") if HOSTS.exists() else ""
        cleaned = re.sub(r"(?ms)^# PARENTGUARD BEGIN\s*.*?^# PARENTGUARD END\s*\n?", "", original).rstrip() + "\n"
        HOSTS.write_text(cleaned, encoding="utf-8")
        run(["ipconfig", "/flushdns"])
    except Exception as exc:
        log(f"hosts cleanup failed: {exc}")
    try:
        saved = state.get("dnsOriginal")
        if saved is not None:
            for item in saved:
                index = int(item.get("InterfaceIndex", 0) or 0)
                servers = [x for x in (item.get("Servers") or []) if not str(x).startswith("127.") and str(x) != "::1"]
                if not index:
                    continue
                if servers:
                    quoted = ",".join("'" + str(x).replace("'", "") + "'" for x in servers)
                    command = f"Set-DnsClientServerAddress -InterfaceIndex {index} -ServerAddresses ({quoted})"
                else:
                    command = f"Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"
                run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command])
    except Exception as exc:
        log(f"DNS cleanup failed: {exc}")
    for key, name in [
        (r"HKLM\SOFTWARE\Policies\Google\Chrome", "ForceGoogleSafeSearch"),
        (r"HKLM\SOFTWARE\Policies\Google\Chrome", "ForceYouTubeRestrict"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceBingSafeSearch"),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "ForceYouTubeRestrict"),
    ]:
        run(["reg", "delete", key, "/v", name, "/f"])
    for key, name, _kind, _value in BROWSER_DOH:
        run(["reg", "delete", key, "/v", name, "/f"])
    for key, name, _kind, _value in PRIVACY_POLICIES:
        run(["reg", "delete", key, "/v", name, "/f"])
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={DOT_RULE}"])
    try:
        if state.get("dnsLocal"):
            restore_original_dns()
            state["dnsLocal"] = False
            save_state()
    except Exception as exc:
        log(f"local DNS restore failed: {exc}")
    log("ParentGuard-owned filtering settings removed")


def process_rows() -> list[tuple[str, str, str, str, str]]:
    rows = []
    result = run(["tasklist", "/v", "/fo", "csv", "/nh"])
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row) >= 9:
            exe, pid, session_id, username, window = row[0].lower(), row[1], row[3], row[6].lower(), row[8].strip()
            if username.startswith(("nt authority", "n/a", "font")):
                continue
            rows.append((exe, pid, session_id, username.split("\\")[-1], window))
    return rows


def enforce_process_policy(policy: dict, rows: list[tuple[str, str, str, str, str]]) -> tuple[set[str], list[str]]:
    # Enforcement is device-scoped: apply policy to every interactive Windows user.
    blocked_apps = {str(x).strip().lower() for x in policy.get("apps", []) if str(x).strip()}
    allowed_apps = {str(x).strip().lower() for x in policy.get("allowedApps", []) if str(x).strip()}
    blocked_games = {str(x).strip().lower() for x in policy.get("blockedGames", []) if str(x).strip()}
    if policy.get("blockGames"):
        blocked_games |= DEFAULT_GAMES
    allowed_games = {str(x).strip().lower() for x in policy.get("allowedGames", []) if str(x).strip()}
    blocked_browsers = {str(x).strip().lower() for x in policy.get("browsers", [])}
    killed = []
    for exe, pid, _session, _user, _window in rows:
        game_denied = exe in blocked_games and exe not in allowed_games
        app_denied = exe in blocked_apps and exe not in allowed_apps
        browser_denied = exe in blocked_browsers and exe not in allowed_apps
        if (game_denied or app_denied or browser_denied) and exe not in IGNORED:
            result = run(["taskkill", "/f", "/pid", pid])
            if result.returncode == 0:
                killed.append(exe)
                event(f"Blocked application: {exe}", "block", app=exe)
    # Return session IDs represented by interactive device rows only; session 0
    # and service processes are excluded before this function is called.
    return {row[2] for row in rows}, killed


def wts_sessions() -> list[dict]:
    """All Windows sessions with owner and state, via the Terminal Services API (state 0 = active, 4 = disconnected)."""
    import ctypes
    from ctypes import wintypes

    class INFO(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR), ("State", wintypes.DWORD)]
    api = ctypes.windll.wtsapi32
    api.WTSEnumerateSessionsW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(INFO)), ctypes.POINTER(wintypes.DWORD)]
    api.WTSEnumerateSessionsW.restype = wintypes.BOOL
    api.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    api.WTSQuerySessionInformationW.restype = wintypes.BOOL
    api.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    base, count = ctypes.POINTER(INFO)(), wintypes.DWORD()
    if not api.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(base), ctypes.byref(count)):
        raise OSError("WTSEnumerateSessions failed")
    out = []
    try:
        for i in range(count.value):
            item, buf, size, user = base[i], ctypes.c_void_p(), wintypes.DWORD(), ""
            if api.WTSQuerySessionInformationW(None, item.SessionId, 5, ctypes.byref(buf), ctypes.byref(size)) and buf.value:  # 5 = WTSUserName
                user = ctypes.wstring_at(buf.value)
                api.WTSFreeMemory(buf)
            out.append({"id": int(item.SessionId), "user": user, "state": int(item.State), "name": item.pWinStationName or ""})
    finally:
        api.WTSFreeMemory(ctypes.cast(base, ctypes.c_void_p))
    return out


def lockscreen_sessions() -> set[int]:
    """Sessions currently showing the Windows lock screen (LogonUI.exe runs there)."""
    out: set[int] = set()
    try:
        for row in csv.reader(io.StringIO(run(["tasklist", "/fi", "imagename eq LogonUI.exe", "/fo", "csv", "/nh"]).stdout)):
            if len(row) >= 4 and row[3].strip().isdigit():
                out.add(int(row[3]))
    except Exception as exc:
        log(f"lock screen query failed: {exc}")
    return out


def device_sessions(check_lock: bool = True):
    """Return all interactive user sessions on this managed PC.

    No child username is required: the endpoint/device is the enforcement boundary.
    Session 0 and service/system sessions are excluded. `active` contains sessions
    with an unlocked interactive desktop; `users` also reports disconnected sessions.
    """
    if os.name != "nt":
        return None
    try:
        sessions = wts_sessions()
    except Exception as exc:
        log(f"session query failed: {exc}")
        return None
    locked = lockscreen_sessions() if check_lock else set()
    users = [x for x in sessions if x["id"] != 0 and x["user"]]
    active = [x for x in users if x["state"] == 0 and x["id"] not in locked]
    return users, active


def child_sessions(child: str, check_lock: bool = True):
    """Legacy compatibility helper; monitoring itself no longer depends on this account."""
    info = device_sessions(check_lock=check_lock)
    if info is None:
        return None
    users, active = info
    mine = [x for x in users if x["user"].lower() == str(child or "").lower()]
    live = [x for x in active if x["user"].lower() == str(child or "").lower()]
    return mine, live


def enforce_lock(child: str = "", reason: str = "") -> dict:
    """Disconnect every active interactive user session on this managed PC.

    This is device-wide and independent of the configured child's Windows username.
    Sessions are disconnected, not signed out, so work can be resumed after unlock.
    """
    rec: dict[str, Any] = {"at": int(time.time()), "reason": reason, "ok": True, "n": 0,
                           "note": "No active interactive user session to lock"}
    info = device_sessions(check_lock=False)
    if info is None:
        rec.update(ok=False, note="Could not read Windows sessions")
        return rec
    active = info[1]
    if not active:
        return rec
    import ctypes
    failed = []
    for x in active:
        try:
            ok = ctypes.windll.wtsapi32.WTSDisconnectSession(None, x["id"], False)
        except Exception:
            ok = 0
        if not ok:
            fallback = run(["tsdiscon", str(x["id"])])
            if fallback.returncode != 0:
                failed.append(x["id"])
    time.sleep(1)
    after = device_sessions(check_lock=False)
    still = after[1] if after else active
    rec.update(n=len(active), ok=not still and not failed,
               note=("All active PC user sessions disconnected and verified" if not still and not failed
                     else "Lock was sent but one or more sessions remain active or could not be disconnected"))
    return rec


def idle_wait(seconds: float) -> None:
    """Sleep between cycles, but keep re-locking every 2 s so a restricted user cannot simply sign back in."""
    end = time.time() + seconds
    while end - time.time() > 0:
        time.sleep(min(2.0, max(0.0, end - time.time())))
        try:
            cfg = state.get("cfg") or {}
            if cfg.get("protectionOff") or state.get("protectionOff"):
                continue
            if os.name == "nt" and restriction(cfg, dt.datetime.now()):
                rec = enforce_lock("", state.get("lastReason", ""))
                if rec["n"]:
                    state["lock"] = rec
                    log(f"re-lock: {rec['note']}")
        except Exception as exc:
            log(f"re-lock error: {exc}")


def write_health(ok: bool, error: str = "", phase: str = "") -> None:
    """Atomic heartbeat used by the installer and watchdog diagnostics."""
    try:
        payload = {"ok": ok, "at": int(time.time()), "version": VERSION, "error": error[:300], "phase": phase}
        tmp = HEALTH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(HEALTH)
    except OSError as exc:
        log(f"could not write installer heartbeat: {exc}")


def acquire_single_instance():
    """Hold a Windows named mutex so only one agent loop can ever run. Returns a handle, or None if another agent holds it."""
    if os.name != "nt":
        return object()
    import ctypes
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if not handle or ctypes.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return None
    return handle


def agent_running() -> bool:
    if os.name != "nt":
        return False
    import ctypes
    handle = ctypes.windll.kernel32.OpenMutexW(0x00100000, False, MUTEX_NAME)  # SYNCHRONIZE
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    return False


def ps_json(script: str, timeout: int = 25) -> Any:
    result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
    try:
        return json.loads(result.stdout.strip() or "null")
    except ValueError:
        return None


def console_user(rows: list) -> str:
    """Windows account that owns the interactive desktop (explorer.exe), if anyone is signed in."""
    names = {row[3] for row in rows if row[0] == "explorer.exe"}
    return ", ".join(sorted(names))


def collect_device_info() -> dict:
    """Identity, hardware and network details for the dashboard. Refreshed every 10 minutes."""
    info: dict[str, Any] = {"computerName": os.environ.get("COMPUTERNAME", "")}
    if os.name != "nt":
        return info
    data = ps_json("$o=Get-CimInstance Win32_OperatingSystem;$c=Get-CimInstance Win32_ComputerSystem;"
                   "[pscustomobject]@{os=$o.Caption;build=$o.BuildNumber;manufacturer=$c.Manufacturer;model=$c.Model}|ConvertTo-Json -Compress")
    if isinstance(data, dict):
        info.update({k: str(v or "") for k, v in data.items()})
    ips = ps_json("@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1'}|Select-Object -ExpandProperty IPAddress)|ConvertTo-Json -Compress")
    if isinstance(ips, str):
        ips = [ips]
    info["localIp"] = ips if isinstance(ips, list) else []
    return info


def get_ip_location() -> dict | None:
    """Approximate, IP-based location (city level). Only used when the parent enabled location reporting."""
    try:
        data = http.get("https://ipwho.is/", timeout=10).json()
        if data.get("success"):
            return {"publicIp": data.get("ip", ""), "city": data.get("city", ""), "region": data.get("region", ""),
                    "country": data.get("country", ""), "latitude": data.get("latitude"), "longitude": data.get("longitude"),
                    "approximate": True, "capturedAt": dt.datetime.now(dt.timezone.utc).isoformat()}
    except Exception as exc:
        log(f"IP location unavailable: {exc}")
    return None


def validate_config() -> None:
    """Reject incomplete, malformed, or obviously unsafe device configuration."""
    values = {"projectId": PROJECT, "apiKey": API_KEY, "deviceId": DEVICE_ID, "deviceKey": DEVICE_KEY}
    for name, value in values.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"config.json field {name} is empty")
        if any(marker in value.upper() for marker in ("PASTE_FROM_ADMIN", "YOUR_", "CHANGE_ME", "REPLACE_")):
            raise ValueError(f"config.json field {name} still contains a placeholder")
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,}[a-z0-9]", PROJECT):
        raise ValueError("config.json projectId is not a valid Firebase project identifier")
    if len(API_KEY) < 20 or len(DEVICE_ID) < 6 or len(DEVICE_KEY) < 16:
        raise ValueError("config.json credentials do not meet the minimum format requirements")
    if DEVICE_ID == DEVICE_KEY:
        raise ValueError("deviceId and deviceKey must be different values")

def self_check() -> int:
    """One-shot connection test used by the installer: sign in, register, read policy, write status."""
    try:
        validate_config()
    except Exception as exc:
        print(f"FAIL  Device configuration: {exc}")
        write_health(False, str(exc))
        return 1
    steps = [("Firebase sign-in and device registration", authenticate), ("Policy read", pull_policy),
             ("Status write", lambda: push_status({"version": VERSION, "seen": int(time.time()), "msg": "", "installCheck": True, "agentMode": "preflight"}))]
    for name, fn in steps:
        try:
            fn()
            print(f"OK    {name}")
        except Exception as exc:
            print(f"FAIL  {name}: {exc}")
            write_health(False, f"{name}: {exc}")
            return 1
    write_health(True)
    return 0



def get_location() -> dict | None:
    """Read Windows Location API only when enabled and permission is granted."""
    # WinRT location access is attempted through PowerShell. Windows Location
    # Services must be enabled; no IP-based location is fabricated as a fallback.
    script = r'''$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null=[Windows.Devices.Geolocation.Geolocator,Windows.Devices.Geolocation,ContentType=WindowsRuntime]
$op=[Windows.Devices.Geolocation.Geolocator]::new().GetGeopositionAsync()
$task=[System.WindowsRuntimeSystemExtensions]::AsTask($op); $task.Wait(12000)
$p=$task.Result.Coordinate.Point.Position
[pscustomobject]@{latitude=$p.Latitude;longitude=$p.Longitude;accuracy=$task.Result.Coordinate.Accuracy;capturedAt=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress'''
    try:
        result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=16)
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            if -90 <= float(data["latitude"]) <= 90 and -180 <= float(data["longitude"]) <= 180:
                return data
        log("Location unavailable: enable Windows Location Services and grant permission")
    except Exception as exc:
        log(f"Location unavailable: {exc}")
    return None


def screen_time(policy: dict, now: dt.datetime, active_sessions: set[str]) -> str:
    today = str(now.date())
    if state["day"] != today:
        state.update(day=today, used=0, apps={})
    if active_sessions:
        state["used"] += min(float(state.get("elapsed", TICK)), 30.0) / 60
    return restriction(policy, now)


def restriction(policy: dict, now: dt.datetime) -> str:
    """Why the device must be locked right now ('' = allowed). Pure decision: it does not change usage."""
    today = str(now.date())
    bonus = policy.get("bonus") or {}
    try:
        limit = int(policy.get("limitWk", policy.get("limit", 120)) if now.weekday() >= 5 else policy.get("limit", 120))
        if bonus.get("day") == today:
            limit += max(0, int(bonus.get("min", 0)))
    except (ValueError, TypeError):
        limit = 120
    current = now.strftime("%H:%M")
    start, end = str(policy.get("start", "07:00")), str(policy.get("end", "21:00"))
    allowed = start <= current < end if start <= end else current >= start or current < end
    # Optional bedtime window: bedtime is the enforced end; wakeTime is start.
    wake, bedtime = policy.get("wakeTime"), policy.get("bedtime")
    if wake and bedtime:
        allowed = str(wake) <= current < str(bedtime) if str(wake) <= str(bedtime) else current >= str(wake) or current < str(bedtime)
    # Website-issued manual commands have explicit priority over schedules and limits.
    # A persistent unlock stays active until the website locks again or resumes the schedule.
    override = PR.manual_override(policy, int(time.time()))
    if override == "unlock":
        return ""
    if override == "lock":
        return "locked by parent/admin"
    if state["used"] >= limit:
        return "daily screen-time limit reached"
    if not allowed:
        return "outside permitted screen-time hours / bedtime"
    return ""


# ---------------------------------------------------------------------------
# Child requests: notice window -> local request file -> Firestore + e-mail
# ---------------------------------------------------------------------------
_APP_RE = re.compile(r"^[a-z0-9][a-z0-9 ._()\-]{0,62}\.exe$")


def clean_request(raw: Any) -> dict | None:
    """Validate an untrusted request file written by a child-session process. Returns a safe dict or None."""
    if not isinstance(raw, dict):
        return None
    rtype = str(raw.get("type", "")).strip().lower()
    if rtype not in REQ_TYPES:
        return None
    target = str(raw.get("target", "")).strip().lower()[:80]
    if rtype == "site":
        target = re.sub(r"[/?#].*$", "", re.sub(r"^https?://", "", target))
        target = re.sub(r"^www\.", "", target)
        if not BL.valid_host(target):
            return None
    elif rtype == "app":
        target = target.replace("\\", "/").rsplit("/", 1)[-1]
        if not _APP_RE.fullmatch(target):
            return None
    else:
        target = ""
    try:
        minutes = int(raw.get("minutes", 0) or 0)
    except (TypeError, ValueError):
        minutes = 0
    if rtype == "time":
        minutes = minutes if minutes in (15, 30, 60) else 30
    else:
        minutes = 0
    note = re.sub(r"\s+", " ", str(raw.get("note", ""))).strip()[:300]
    reason = re.sub(r"\s+", " ", str(raw.get("reason", ""))).strip()[:200]
    user = re.sub(r"[^\w .\-@]", "", str(raw.get("user", "")))[:64]
    return {"type": rtype, "target": target, "minutes": minutes, "note": note, "reason": reason, "user": user}


def request_allowed(req: dict, now: float) -> bool:
    """Throttle so a child cannot flood the parent's inbox: 1 identical request / 2 min, 12 / hour."""
    log_ = [x for x in state.get("reqLog", []) if now - x[0] < 3600]
    state["reqLog"] = log_
    if len(log_) >= 12:
        return False
    key = f'{req["type"]}:{req["target"]}'
    if any(x[1] == key and now - x[0] < 120 for x in log_):
        return False
    log_.append([now, key])
    return True


def fs_str(value: str) -> dict:
    return {"stringValue": value}


def post_request(req: dict, rid: str, now: int) -> None:
    fields = {"type": fs_str(req["type"]), "target": fs_str(req["target"]), "minutes": {"integerValue": str(req["minutes"])},
              "note": fs_str(req["note"]), "reason": fs_str(req["reason"]), "winUser": fs_str(req["user"]),
              "createdAt": {"integerValue": str(now)}, "status": fs_str("pending"), "emailed": {"booleanValue": False}}
    url = f"{DB}/devices/{DEVICE_ID}/requests?documentId={rid}"
    response = http.post(url, headers=headers(), json={"fields": fields}, timeout=20)
    if response.status_code in (401, 403):
        authenticate()
        response = http.post(url, headers=headers(), json={"fields": fields}, timeout=20)
    response.raise_for_status()


def patch_request(rid: str, fields: dict) -> None:
    mask = "&".join(f"updateMask.fieldPaths={k}" for k in fields)
    response = http.patch(f"{DB}/devices/{DEVICE_ID}/requests/{rid}?{mask}", headers=headers(), json={"fields": fields}, timeout=20)
    response.raise_for_status()


def load_notify_config() -> dict:
    """E-mail settings the administrator saved on the Admin page (copied to this device's private/notify document)."""
    if time.time() - state.get("notifyAt", 0) < 300 and "notify" in state:
        return state["notify"]
    state["notifyAt"] = time.time()
    try:
        response = http.get(f"{DB}/devices/{DEVICE_ID}/private/notify", headers=headers(), timeout=20)
        if response.status_code == 404:
            state["notify"] = {}
        else:
            response.raise_for_status()
            state["notify"] = json_field(response.json().get("fields", {}), "json", {})
    except Exception as exc:
        log(f"notification settings unavailable: {exc}")
        state.setdefault("notify", {})
    return state["notify"]


LABEL = {"time": "More screen time", "site": "Allow a website", "app": "Allow an app", "message": "Message"}


def compose_email(req: dict, rid: str, now: int) -> tuple[str, str]:
    child = state.get("childName") or "Your child"
    asked = {"time": f"asked for {req['minutes']} more minutes of screen time",
             "site": f"asked you to allow the website {req['target']}",
             "app": f"asked you to allow the app {req['target']}",
             "message": "sent you a message"}[req["type"]]
    when = dt.datetime.fromtimestamp(now).strftime("%A %d %B %Y, %H:%M")
    lines = [f"{child} {asked}.", ""]
    if req["reason"]:
        lines.append(f"What happened: {req['reason']}")
    if req["note"]:
        lines.append(f"Their note: \"{req['note']}\"")
    lines += [f"Windows user: {req['user'] or 'unknown'}", f"Time: {when}", "",
              "Open your ParentGuard dashboard and use the Requests tab to approve or decline."]
    return f"[{LABEL[req['type']]}] {child} sent a request", "\n".join(lines)


def send_mail(cfg: dict, to: str, subject: str, message: str) -> None:
    needed = ("serviceId", "templateId", "publicKey")
    if not all(cfg.get(k) for k in needed):
        raise RuntimeError("e-mail provider is not configured on the Admin page")
    payload = {"service_id": cfg["serviceId"], "template_id": cfg["templateId"], "user_id": cfg["publicKey"],
               "template_params": {"to_email": to, "subject": subject, "message": message,
                                   "child_name": state.get("childName", ""), "from_name": "@M Family Safety Guard"}}
    if cfg.get("privateKey"):
        payload["accessToken"] = cfg["privateKey"]
    response = requests.post(MAIL_URL, json=payload, timeout=25, headers={"User-Agent": f"MFamilySafetyGuard/{VERSION}"})
    if response.status_code != 200:
        raise RuntimeError(f"mail provider answered {response.status_code}: {response.text[:120]}")


def deliver_mail_queue() -> None:
    """Send queued request e-mails; keep failures for retry (5 attempts) so a network blip does not lose them."""
    queue, keep = state.get("mailQueue", []), []
    cfg = load_notify_config() if queue else {}
    for item in queue:
        recipients = [r for r in cfg.get("recipients", []) if isinstance(r, str) and "@" in r]
        error = ""
        if not cfg.get("enabled", True) or not recipients:
            error = "no notification e-mail address is set on the Admin page"
        else:
            failed = []
            for to in [r for r in (item.get("to") or recipients) if r in recipients]:  # on retry, only those that failed
                try:
                    send_mail(cfg, to, item["subject"], item["body"])
                except Exception as exc:
                    failed.append(to); error = str(exc)
            if failed:
                item["to"] = failed
        item["tries"] = item.get("tries", 0) + 1
        done = not error
        if done or item["tries"] >= 5:
            try:
                patch_request(item["rid"], {"emailed": {"booleanValue": done}, "emailError": fs_str("" if done else error[:200]),
                                            "emailedAt": {"integerValue": str(int(time.time()))}})
            except Exception as exc:
                log(f"could not record e-mail result: {exc}")
            if not done:
                log(f"request e-mail abandoned: {error}")
        else:
            keep.append(item)
    state["mailQueue"] = keep


def process_requests() -> None:
    """Collect request files from the child notice window and forward them. Never raises into the main loop."""
    try:
        REQ_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for path in sorted(REQ_DIR.glob("*.json"))[:10]:
        try:
            if path.stat().st_size > 8192:
                req = None
            else:
                req = clean_request(load_json(path, None))
        except OSError:
            continue
        try:
            path.unlink()
        except OSError:
            continue
        now = int(time.time())
        if not req or not request_allowed(req, now):
            log("child request ignored (invalid or rate-limited)")
            continue
        rid = hashlib.sha256(f"{DEVICE_ID}{now}{req}{os.urandom(4).hex()}".encode()).hexdigest()[:20]
        try:
            post_request(req, rid, now)
        except Exception as exc:
            log(f"child request could not be stored: {exc}")
            state["reqLog"] = state["reqLog"][:-1]
            continue
        subject, body = compose_email(req, rid, now)
        state["mailQueue"].append({"rid": rid, "subject": subject, "body": body, "tries": 0})
        state["awaiting"].append({"id": rid, "type": req["type"], "target": req["target"], "at": now})
        event(f"Request sent to parent: {LABEL[req['type']]}" + (f" ({req['target']})" if req["target"] else ""), "user")
    deliver_mail_queue()
    check_answers()


def check_answers() -> None:
    """Tell the child when a parent has answered a request."""
    keep = []
    for item in state.get("awaiting", [])[:5]:
        if time.time() - item["at"] > 86400:
            continue
        try:
            response = http.get(f"{DB}/devices/{DEVICE_ID}/requests/{item['id']}", headers=headers(), timeout=20)
            status = response.json().get("fields", {}).get("status", {}).get("stringValue", "pending") if response.ok else "pending"
        except Exception:
            status = "pending"
        if status == "pending":
            keep.append(item)
            continue
        what = {"time": "more screen time", "site": f"the website {item['target']}", "app": f"the app {item['target']}", "message": "your message"}[item["type"]]
        text = (f"Your parent approved your request for {what}." if status == "approved"
                else f"Your parent declined your request for {what}." if status == "denied"
                else f"Your parent saw your request for {what}.")
        _notice_last.pop(f"answer:{text}", None)
        publish_notice(text, "answer")
    state["awaiting"] = keep + state.get("awaiting", [])[5:]


def prepare_request_folder() -> None:
    """Create the shared drop folder: children may add files, only SYSTEM/Administrators own it."""
    if os.name != "nt":
        return
    try:
        NOTICE_DIR.mkdir(parents=True, exist_ok=True)
        run(["icacls", str(NOTICE_DIR), "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX"])
        REQ_DIR.mkdir(parents=True, exist_ok=True)
        run(["icacls", str(REQ_DIR), "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "Administrators:(OI)(CI)F", "Users:(OI)(CI)M"])
    except Exception as exc:
        log(f"request folder setup failed: {exc}")


def push_status(data: dict) -> None:
    payload = {"fields": {"status": {"stringValue": json.dumps(data, separators=(",", ":"))}}}
    url = f"{DB}/devices/{DEVICE_ID}?updateMask.fieldPaths=status"
    response = http.patch(url, headers=headers(), json=payload, timeout=20)
    if response.status_code in (401, 403):
        authenticate()
        response = http.patch(url, headers=headers(), json=payload, timeout=20)
    response.raise_for_status()


def site_rows() -> list[dict]:
    """Sites for the dashboard: everything really visited or blocked first, then a bounded number of background hosts."""
    items = list(state["sites"].items())
    real = [kv for kv in items if not kv[1].get("bg", True) or kv[1].get("bn")]
    back = [kv for kv in items if kv not in real]
    pick = sorted(real, key=lambda kv: -kv[1]["last"])[:220] + sorted(back, key=lambda kv: -kv[1]["last"])[:60]
    return [{"d": d, "n": v["n"], "f": v["first"], "l": v["last"], "b": v["bn"], "bl": v.get("bl", 0), "v": v["v"],
             "g": bool(v.get("bg", True)) and not v.get("bn"), "c": v.get("cat", ""), "k": v.get("leak", 0), "dn": v.get("dn", 0)}
            for d, v in pick]


def web_status() -> dict:
    """Honest health of web monitoring, shown on the dashboard so nothing has to be guessed."""
    w = dict(state.get("web", {}))
    w.update(dnsFilter=bool(FILTER and FILTER.running), dnsRouted=bool(state.get("dnsLocal")),
             dnsQueries=FILTER.stats["queries"] if FILTER else 0, dnsBlocked=FILTER.stats["blocked"] if FILTER else 0,
             upstream=(state.get("upstreams") or [])[:2], mode="real-time-filter" if FILTER and FILTER.running and state.get("dnsLocal") else "fallback-hosts-only")
    return w


# ---------------------------------------------------------------------------
# v5.11 - safe network reset, repair ("refresh"), stop protection, remote self-destruct
# Everything below only touches things @M Family Safety Guard itself created: its folder, its scheduled tasks,
# its hosts-file block, its DNS redirect and its browser policy values. Other programs, the user's files,
# Wi-Fi/network profiles, firewall rules and other DNS settings are never reset.
# ---------------------------------------------------------------------------
TASK_AGENT, TASK_WATCH, TASK_NOTICE = "MFamilySafetyGuard-Agent", "MFamilySafetyGuard-Watchdog", "MFamilySafetyGuard-Notice"
LEGACY_TASKS = ("ParentGuardAgent", "ParentGuardWatchdog")
UNINSTALL_KEY = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MFamilySafetyGuard"
DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "MFamilySafetyGuard"
SYS_TEMP = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"
REMOVING_FLAG = ROOT / ".removing"
COMMAND_TYPES = {"repair", "uninstall"}
REQUIRED_FILES = ("agent.py", "policy_rules.py", "notice_client.py", "blocklists.py", "dnsfilter.py", "webhistory.py", "config.json")


def python_exe(windowless: bool = False) -> str:
    """Interpreter recorded by the installer (machine-wide Python)."""
    exe = ""
    try:
        exe = (ROOT / "python.txt").read_text(encoding="utf-8-sig").strip()
    except OSError:
        pass
    exe = exe or sys.executable
    base = exe.replace("pythonw.exe", "python.exe")
    return base.replace("python.exe", "pythonw.exe") if windowless else base


def q_ps(value: Any) -> str:
    return str(value).replace("'", "''")


def task_exists(name: str) -> bool:
    return run(["schtasks", "/query", "/tn", name], timeout=15).returncode == 0


def internet_state() -> dict:
    """Plain facts: can this PC reach the internet by address, and can it resolve names?"""
    import socket
    result = {"net": False, "dns": False}
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=4).close()
        result["net"] = True
    except OSError:
        pass
    try:
        socket.getaddrinfo("firestore.googleapis.com", 443)
        result["dns"] = True
    except OSError:
        pass
    return result


def loopback_dns_adapters() -> list[int]:
    """Network adapters whose DNS points at 127.0.0.1 / ::1 (our own local filter)."""
    if os.name != "nt":
        return []
    query = ("Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses -contains '127.0.0.1' -or $_.ServerAddresses -contains '::1'} "
             "| Select-Object -ExpandProperty InterfaceIndex | ConvertTo-Json -Compress")
    result = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", query], timeout=30)
    try:
        data = json.loads(result.stdout.strip() or "[]")
    except ValueError:
        return []
    return sorted({int(x) for x in (data if isinstance(data, list) else [data])})


def reset_loopback_dns() -> int:
    """Give internet back: only adapters pointing at our own loopback resolver go back to automatic (DHCP) DNS."""
    fixed = 0
    for index in loopback_dns_adapters():
        r = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"], timeout=30)
        fixed += 0 if r.returncode else 1
    if fixed:
        log(f"DNS reset to automatic on {fixed} adapter(s) that still pointed at the local filter")
    run(["ipconfig", "/flushdns"])
    return fixed


def stop_local_filter() -> None:
    global FILTER, _filter_try
    try:
        if FILTER:
            FILTER.stop()
    except Exception as exc:
        log(f"filter stop failed: {exc}")
    FILTER = None
    _filter_try = time.time()  # do not restart it while protection is stopped / being repaired


def restore_network_safely() -> list[str]:
    """Stop our filter, undo every ParentGuard-owned network change, and prove the internet still works."""
    notes = []
    stop_local_filter()
    cleanup_device()
    n = reset_loopback_dns()
    state.update(dnsLocal=False, dnsRouteSig="", dnsRouteAt=0, privApplied="")
    state.pop("dnsOriginal", None)  # re-taken from the clean, restored settings
    snapshot_dns()
    net = internet_state()
    notes.append(f"internet reachable: {'yes' if net['net'] else 'NO'}; name lookup: {'ok' if net['dns'] else 'FAILED'}")
    if n:
        notes.append(f"{n} adapter(s) taken off the local filter")
    return notes


def ps_file_run(script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    SYS_TEMP.mkdir(parents=True, exist_ok=True)
    path = SYS_TEMP / f"mfsg-{os.getpid()}-{int(time.time())}.ps1"
    path.write_text(script, encoding="utf-8-sig")
    try:
        return run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)], timeout=timeout)
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def ensure_tasks(force: bool = False) -> list[str]:
    """Re-create any missing scheduled task (same definitions as install.ps1). Returns what was (re)created."""
    if os.name != "nt":
        return []
    want_agent = force or not task_exists(TASK_AGENT)
    want_watch = force or not task_exists(TASK_WATCH)
    want_notice = force or not task_exists(TASK_NOTICE)
    if not (want_agent or want_watch or want_notice):
        return []
    py, pyw = python_exe(), python_exe(True)
    if not Path(pyw).exists():
        pyw = py
    script = f"""$ErrorActionPreference = 'Stop'
$T = '{q_ps(ROOT)}'; $py = '{q_ps(py)}'; $pyw = '{q_ps(pyw)}'
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$system = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
function Drop([string]$n) {{ if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {{ Unregister-ScheduledTask -TaskName $n -Confirm:$false }} }}
if ({'$true' if want_agent else '$false'}) {{
  Drop '{TASK_AGENT}'
  $a = New-ScheduledTaskAction -Execute $pyw -Argument ('"{{0}}"' -f (Join-Path $T 'agent.py')) -WorkingDirectory $T
  Register-ScheduledTask -TaskName '{TASK_AGENT}' -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -Principal $system -Description '@M Family Safety Guard Windows child-device client' -Force | Out-Null
}}
if ({'$true' if want_watch else '$false'}) {{
  Drop '{TASK_WATCH}'
  $w = New-ScheduledTaskAction -Execute $py -Argument ('"{{0}}" --watchdog' -f (Join-Path $T 'agent.py')) -WorkingDirectory $T
  $wt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
  Register-ScheduledTask -TaskName '{TASK_WATCH}' -Action $w -Trigger $wt -Settings $settings -Principal $system -Description '@M Family Safety Guard agent health watchdog' -Force | Out-Null
}}
if ({'$true' if want_notice else '$false'}) {{
  try {{
    Drop '{TASK_NOTICE}'
    $n = New-ScheduledTaskAction -Execute $pyw -Argument ('"{{0}}"' -f (Join-Path $T 'notice_client.py')) -WorkingDirectory $T
    Register-ScheduledTask -TaskName '{TASK_NOTICE}' -Action $n -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Settings $settings -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited) -Description '@M Family Safety Guard full-screen user notice' -Force | Out-Null
  }} catch {{ Write-Output ('notice task: ' + $_.Exception.Message) }}
}}
"""
    result = ps_file_run(script, timeout=90)
    made = [name for flag, name in ((want_agent, "agent task"), (want_watch, "watchdog task"), (want_notice, "notice task")) if flag]
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "task registration failed")[:240])
    return made


def kill_other_agents() -> None:
    """Stop every other ParentGuard python process (never this one, never unrelated Python programs)."""
    script = (f"Get-CimInstance Win32_Process | Where-Object {{ $_.Name -match '^pythonw?\\.exe$' -and $_.ProcessId -ne {os.getpid()} "
              "-and $_.CommandLine -like '*M Family Safety Guard*' }} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }")
    run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=40)


def run_detached_script(label: str, body: str) -> str:
    """Run a PowerShell script as SYSTEM in its own one-shot scheduled task, so it survives this process exiting."""
    SYS_TEMP.mkdir(parents=True, exist_ok=True)
    tag = f"{int(time.time())}{os.getpid()}"
    script, task = SYS_TEMP / f"mfsg-{label}-{tag}.ps1", f"MFSG-{label}-{tag}"
    script.write_text(body.replace("@@TASK@@", task), encoding="utf-8-sig")
    run(["icacls", str(script), "/inheritance:r", "/grant:r", "SYSTEM:F", "Administrators:F"], timeout=20)
    command = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}"'
    created = run(["schtasks", "/create", "/tn", task, "/tr", command, "/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"], timeout=30)
    if created.returncode == 0 and run(["schtasks", "/run", "/tn", task], timeout=30).returncode == 0:
        return task
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", str(script)], creationflags=flags)
    return "direct"


def set_ack(cmd: dict | None, stage: str, ok: bool, note: str, steps: list | None = None) -> None:
    state["commandAck"] = {"id": str((cmd or {}).get("id", "local")), "type": str((cmd or {}).get("type", "repair")),
                           "stage": stage, "ok": bool(ok), "note": note[:400], "steps": steps or [], "at": int(time.time())}
    save_state()


def repair_core(local: bool = False) -> tuple[bool, list[dict]]:
    """Fix what commonly breaks, in an order that keeps internet working at every step."""
    steps: list[dict] = []

    def step(name: str, fn) -> None:
        try:
            note = fn()
            steps.append({"n": name, "ok": True, "t": ", ".join(note) if isinstance(note, list) else str(note or "ok")})
        except Exception as exc:
            steps.append({"n": name, "ok": False, "t": f"{type(exc).__name__}: {exc}"[:200]})
            log(f"repair step '{name}' failed: {exc}")

    if local:
        step("Stop other agent copies", lambda: kill_other_agents() or "done")
    step("Restore safe network settings", restore_network_safely)

    def files():
        missing = [f for f in REQUIRED_FILES if not (ROOT / f).exists()]
        if missing:
            raise RuntimeError("missing " + ", ".join(missing) + " - re-run install.bat from the original folder")
        if not (ROOT / "packages" / "requests").exists():
            result = run([python_exe(), "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "--target", str(ROOT / "packages"),
                          "-r", str(ROOT / "requirements.txt")], timeout=240)
            if result.returncode:
                raise RuntimeError("could not reinstall components: " + (result.stderr or "")[-160:])
            return "components reinstalled"
        return "program files and components present"
    step("Check program files", files)

    def tasks():
        made = ensure_tasks(force=True)
        return "re-created " + ", ".join(made) if made else "ok"
    step("Re-create startup and watchdog tasks", tasks)

    def clean_state():
        for key in ("lock", "lastReason", "liveProcesses", "upstreams", "lockEventAt", "locationAt", "ipLocationAt", "deviceAt", "policySyncError"):
            state.pop(key, None)
        state["web"] = {}
        for f in (NOTICE, NOTICE_SHARED):
            try:
                f.unlink()
            except OSError:
                pass
        return "stale notices, lock and filter state cleared (screen-time usage kept)"
    step("Clear stale local state", clean_state)

    def reconnect():
        old_refresh, old_session = state.get("refreshToken"), dict(session)
        state.pop("refreshToken", None)
        session.clear()
        try:
            authenticate()
            pull_policy()
        except Exception:
            if old_refresh:
                state["refreshToken"] = old_refresh
            session.update(old_session)
            raise
        return "signed in again and policy read"
    step("Reconnect to the family dashboard", reconnect)
    ok = all(x["ok"] for x in steps)
    save_state()
    return ok, steps


def restart_agent() -> None:
    """Start a fresh agent process: a helper task waits for this one to exit, then starts the agent task."""
    body = (f"$ErrorActionPreference='SilentlyContinue'\nStart-Sleep -Seconds 4\nStart-ScheduledTask -TaskName '{TASK_AGENT}'\n"
            "Start-Sleep -Seconds 3\nUnregister-ScheduledTask -TaskName '@@TASK@@' -Confirm:$false\nRemove-Item -LiteralPath $PSCommandPath -Force\n")
    run_detached_script("restart", body)


def repair_device(cmd: dict) -> None:
    log("Repair requested from the dashboard")
    ok, steps = repair_core(local=False)
    bad = [x["n"] for x in steps if not x["ok"]]
    set_ack(cmd, "done", ok, "Device refreshed. Internet and your other programs were not touched." if ok
            else "Refreshed with problems in: " + "; ".join(bad), steps)
    event("Device refreshed from the dashboard" + ("" if ok else " (some steps failed)"), "sys", notify=False)
    save_state()
    try:
        restart_agent()
    except Exception as exc:
        log(f"restart helper failed (watchdog will restart the agent): {exc}")
    os._exit(0)


def removal_script(cmd_id: str) -> str:
    target, pf = str(ROOT), os.environ.get("ProgramFiles", r"C:\Program Files")
    return f"""$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$target = '{q_ps(target)}'; $data = '{q_ps(DATA_DIR)}'; $pf = '{q_ps(pf)}'
$key = '{q_ps(UNINSTALL_KEY)}'
$tasks = @('{TASK_WATCH}','{TASK_NOTICE}','{TASK_AGENT}','{LEGACY_TASKS[1]}','{LEGACY_TASKS[0]}')
function Guard-Procs {{ Get-CimInstance Win32_Process | Where-Object {{ $_.Name -match '^pythonw?\\.exe$' -and $_.CommandLine -like '*M Family Safety Guard*' }} }}
foreach ($t in $tasks) {{ Stop-ScheduledTask -TaskName $t; Unregister-ScheduledTask -TaskName $t -Confirm:$false }}
for ($i = 0; $i -lt 10; $i++) {{ if (-not (Guard-Procs)) {{ break }}; Start-Sleep -Seconds 2 }}
Guard-Procs | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}
Start-Sleep -Seconds 1
& netsh.exe advfirewall firewall delete rule name=MFamilySafetyGuard-BlockDoT | Out-Null
$h = Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'
if (Select-String -Path $h -Pattern 'PARENTGUARD BEGIN' -Quiet) {{
  $c = [IO.File]::ReadAllText($h)
  $c = [regex]::Replace($c, '(?ms)^# PARENTGUARD BEGIN\\s*.*?^# PARENTGUARD END\\s*\\r?\\n?', '')
  [IO.File]::WriteAllText($h, $c.TrimEnd() + "`r`n")
}}
Remove-Item -LiteralPath $key -Recurse -Force
for ($i = 0; $i -lt 12; $i++) {{
  if (-not (Test-Path -LiteralPath $target)) {{ break }}
  Guard-Procs | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}
  Remove-Item -LiteralPath $target -Recurse -Force
  if (Test-Path -LiteralPath $target) {{ & cmd.exe /c rd /s /q $target }}
  if ((Test-Path -LiteralPath $target) -and $i -eq 4) {{ & takeown.exe /f $target /r /d y | Out-Null; & icacls.exe $target /grant Administrators:F /t /c | Out-Null }}
  if (Test-Path -LiteralPath $target) {{ Start-Sleep -Seconds 2 }}
}}
Get-ChildItem -LiteralPath $pf -Directory -Filter 'M Family Safety Guard.backup-*' | ForEach-Object {{ Remove-Item -LiteralPath $_.FullName -Recurse -Force }}
Remove-Item -LiteralPath $data -Recurse -Force
$left = @()
foreach ($t in $tasks) {{ if (Get-ScheduledTask -TaskName $t) {{ $left += "task $t" }} }}
if (Test-Path -LiteralPath $target) {{ $left += 'install folder' }}
if (Test-Path -LiteralPath $key) {{ $left += 'Apps and Features entry' }}
if (Get-ChildItem -LiteralPath $pf -Directory -Filter 'M Family Safety Guard.backup-*') {{ $left += 'backup folder' }}
if (Test-Path -LiteralPath $data) {{ $left += 'data folder' }}
if (Guard-Procs) {{ $left += 'running process' }}
if (Select-String -Path $h -Pattern 'PARENTGUARD BEGIN' -Quiet) {{ $left += 'hosts entries' }}
$ok = ($left.Count -eq 0)
$note = if ($ok) {{ 'Completely removed and verified: tasks, program files, backups, data, filters and settings' }} else {{ 'Removal incomplete, still present: ' + ($left -join ', ') }}
try {{
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $status = @{{ version = '{VERSION}'; product = '@M Family Safety Guard'; seen = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); removed = $ok; msg = $note;
    commandAck = @{{ id = '{q_ps(cmd_id)}'; type = 'uninstall'; stage = 'removed'; ok = $ok; note = $note; steps = @(); at = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }} }} | ConvertTo-Json -Depth 6 -Compress
  $tok = Invoke-RestMethod -Method Post -Uri 'https://securetoken.googleapis.com/v1/token?key={q_ps(API_KEY)}' -Body @{{ grant_type = 'refresh_token'; refresh_token = '{q_ps(state.get("refreshToken", ""))}' }}
  $body = @{{ fields = @{{ status = @{{ stringValue = $status }} }} }} | ConvertTo-Json -Depth 6
  Invoke-RestMethod -Method Patch -Uri 'https://firestore.googleapis.com/v1/projects/{q_ps(PROJECT)}/databases/(default)/documents/devices/{q_ps(DEVICE_ID)}?updateMask.fieldPaths=status' -Headers @{{ Authorization = 'Bearer ' + $tok.id_token }} -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
}} catch {{ }}
if (-not $ok) {{ Set-Content -Path (Join-Path $env:SystemRoot 'Temp\\mfsg-removal.log') -Value $note }}
Unregister-ScheduledTask -TaskName '@@TASK@@' -Confirm:$false
Remove-Item -LiteralPath $PSCommandPath -Force
"""


def self_destruct(cmd: dict) -> None:
    """Remove ParentGuard completely from this PC. The detached script reports the verified result to the dashboard."""
    cid = str(cmd.get("id", ""))
    pf = os.environ.get("ProgramFiles", r"C:\Program Files").lower()
    if os.name != "nt" or ROOT.name != "M Family Safety Guard" or not str(ROOT).lower().startswith(pf):
        set_ack(cmd, "failed", False, "This agent is not running from the installed folder, so it will not delete anything. Use uninstall.bat.")
        return
    log("Removal requested from the dashboard: restoring network settings and uninstalling")
    try:
        REMOVING_FLAG.write_text(str(int(time.time())), encoding="utf-8")  # watchdog must not restart anything now
    except OSError:
        pass
    for name in (TASK_WATCH, *LEGACY_TASKS):
        run(["schtasks", "/delete", "/tn", name, "/f"], timeout=20)
    stop_local_filter()
    try:
        cleanup_device()
        reset_loopback_dns()
    except Exception as exc:
        log(f"cleanup before removal failed: {exc}")
    set_ack(cmd, "removing", True, "Removal started on the device")
    try:
        push_status({"version": VERSION, "product": "@M Family Safety Guard", "seen": int(time.time()), "msg": "Removing from this device...",
                     "commandAck": state["commandAck"]})
    except Exception as exc:
        log(f"could not announce removal: {exc}")
    run_detached_script("remove", removal_script(cid))
    os._exit(0)


def handle_command() -> None:
    cmd = pending_command or {}
    cid, ctype = str(cmd.get("id", "")), cmd.get("type")
    if not cid or ctype not in COMMAND_TYPES or cid == state.get("lastCommandId"):
        return
    try:
        issued = float(cmd.get("at", 0) or 0) / 1000
    except (TypeError, ValueError):
        issued = 0
    state["lastCommandId"] = cid
    if issued and issued < float(state.get("installedAt", 0) or 0) - 120:
        log(f"ignoring command {cid}: issued before this installation")  # an old uninstall must not hit a fresh install
        save_state()
        return
    save_state()
    if ctype == "repair":
        repair_device(cmd)
    else:
        self_destruct(cmd)


def protection_off_cycle() -> None:
    """Admin stopped protection for this device: undo every ParentGuard setting, enforce and monitor nothing, keep the heartbeat."""
    now = dt.datetime.now()
    if not state.get("protectionOff"):
        log("Protection stopped by administrator")
        stop_local_filter()
        cleanup_device()
        reset_loopback_dns()
        for f in (NOTICE, NOTICE_SHARED):
            try:
                f.unlink()
            except OSError:
                pass
        state.update(protectionOff=True, dnsLocal=False, dnsRouteSig="", privApplied="", lock=None, lastReason="", liveProcesses=[])
        event("Protection stopped by the administrator - nothing is restricted or monitored on this device", "sys", notify=False)
    state["lastTickAt"] = time.time()
    state["childState"] = "protection-stopped"
    status = {
        "version": VERSION, "product": "@M Family Safety Guard", "day": str(now.date()), "used": round(state["used"]), "usedSec": int(state["used"] * 60),
        "agentMode": "protection-stopped", "protection": "off", "active": False, "seen": int(time.time()),
        "msg": "Protection stopped by the administrator", "paused": False, "unlockedUntil": 0, "hist": state["hist"], "apps": {},
        "events": state["events"][:20], "blockedProcesses": [], "policyAppliedAt": int(state.get("policyAppliedAt", 0) or 0),
        "policyRevision": state.get("revision", ""), "lastSyncAt": int(state.get("policyAppliedAt", 0) or 0),
        "policySyncError": state.get("policySyncError", ""), "agentStartedAt": int(state.setdefault("agentStartedAt", time.time())),
        "location": None, "locationEnabled": False, "device": {**state.get("device", {}), "monitoringScope": "stopped"}, "ipLocation": None,
        "childState": "protection-stopped", "lock": None, "accounts": [], "activeUsers": [], "timeline": state.get("timeline", [])[:250],
        "sites": [], "web": {"mode": "stopped"}, "siteHits": {}, "filters": {}, "commandAck": state.get("commandAck"),
    }
    push_status(status)
    write_health(True, phase="protection-stopped")
    save_state()


def resume_protection() -> None:
    global _filter_try
    if not state.get("protectionOff"):
        return
    state.update(protectionOff=False, privApplied="", dnsRouteSig="", dnsLocal=False)
    _filter_try = 0
    event("Protection resumed by the administrator", "sys", notify=False)
    save_state()


def tick() -> None:
    try:
        policy = pull_policy()
        state["cfg"] = policy
        state["policyAppliedAt"] = int(time.time())
        state["policySyncError"] = ""
        state["syncFails"] = 0
        # Confirm the SYSTEM background task has authenticated and fetched the
        # current Firebase policy before slower Windows enforcement operations
        # (DNS setup, process enumeration, session checks) run. A later cycle
        # failure overwrites this with a failed heartbeat.
        write_health(True, phase="policy-sync")
    except Exception as exc:
        policy = state.get("cfg", {})
        state["policySyncError"] = f"{type(exc).__name__}: {exc}"[:240]
        log(f"policy sync failed; using last known policy: {exc}")
        try:
            dns_failopen_check()
        except Exception as exc2:
            log(f"dns fail-open check failed: {exc2}")
    try:
        handle_command()
    except Exception as exc:
        log(f"command failed: {type(exc).__name__}: {exc}")
    if policy.get("protectionOff"):
        protection_off_cycle()
        return
    resume_protection()
    process_requests()
    now = dt.datetime.now()
    clock = time.time()
    state["elapsed"] = min(max(clock - state.get("lastTickAt", clock - TICK), 0.0), 30.0)
    state["lastTickAt"] = clock
    local_ok = False

    def step(name, fn):
        try:
            return fn()
        except Exception as exc:
            log(f"web filter step '{name}' failed: {type(exc).__name__}: {exc}")

    step("browser hardening", apply_browser_hardening)
    step("privacy hardening", apply_privacy_hardening)
    step("rules", lambda: update_decider(policy))
    local_ok = bool(step("dns filter", ensure_dns_filter))
    if local_ok:
        step("dns log", lambda: process_filter_log(policy))
    else:
        step("dns event log (fallback)", lambda: process_dns(policy))
    step("browser history", lambda: process_history(policy))
    step("hosts file", lambda: update_hosts(policy))
    step("dns routing", lambda: apply_dns_routing(policy, local_ok))
    step("safe search", lambda: apply_safe_search(bool(policy.get("safeSearch", True))))
    rows = process_rows()
    # The installed PC is the enforcement boundary. Include every interactive
    # Windows user session regardless of its account name.
    info = device_sessions()
    if info is None:
        user_sessions, active_sessions = [], []
        interactive_ids = set()
    else:
        user_sessions, active_sessions = info
        interactive_ids = {str(x["id"]) for x in user_sessions}
    device_rows = [r for r in rows if r[2] in interactive_ids]
    sessions, killed = enforce_process_policy(policy, device_rows)
    app_names = {r[0] for r in device_rows if r[0] not in IGNORED}
    # Report newly observed applications for every interactive device user.
    # Keep only the current session/user/process set locally to bound the feed.
    previous_apps = set(state.get("liveProcesses", []))
    current_processes = {f"{r[2]}:{r[3]}:{r[0]}": (r[0], r[3]) for r in device_rows if r[0] not in IGNORED}
    for key in sorted(set(current_processes) - previous_apps):
        name, username = current_processes[key]
        event(f"Application started: {name} · Windows user: {username}", "app")
    state["liveProcesses"] = sorted(current_processes)
    current_users = sorted({x["user"] for x in active_sessions})
    previous_users = sorted(state.get("activeUsers", []))
    if current_users != previous_users:
        if current_users:
            event("Active Windows user session: " + ", ".join(current_users), "user")
        elif previous_users:
            event("No Windows user desktop is currently active", "user")
        state["activeUsers"] = current_users
    for name in app_names:
        state["apps"][name] = round(state["apps"].get(name, 0) + float(state.get("elapsed", TICK)) / 60, 2)
    # Any unlocked interactive desktop means the PC is actively in use.
    active = {str(x["id"]) for x in active_sessions}
    child_state = "active" if active else ("locked" if user_sessions else "no-user-session")
    state["childState"] = child_state
    reason = screen_time(policy, now, active)
    if reason:
        if state.get("lastReason") != reason:
            event("Screen session restricted: " + reason, "screen", lock_in=NOTICE_GRACE)
            # The agent runs as SYSTEM; allow the interactive-user notice helper
            # to display the explanation before Windows sessions are disconnected.
            if os.name == "nt":
                time.sleep(NOTICE_GRACE)
        rec = enforce_lock("", reason)
        if rec["n"] or not state.get("lock"):
            state["lock"] = rec
        else:
            state["lock"] = {**state["lock"], "checked": int(time.time())}
        if rec["n"] and time.time() - state.get("lockEventAt", 0) > 60:
            state["lockEventAt"] = time.time()
            event(("Device locked: " if rec["ok"] else "LOCK FAILED: ") + reason + " (" + rec["note"] + ")", "screen", notify=False)
    else:
        state["lock"] = None
    state["lastReason"] = reason
    state["hist"][str(now.date())] = round(state["used"])
    for key in sorted(state["hist"])[:-14]:
        del state["hist"][key]
    location = None
    if policy.get("locationEnabled"):
        last = state.get("locationAt", 0)
        if time.time() - last >= 300:
            state["locationAt"] = time.time()  # retry in 5 min even on failure; a failed lookup can block ~15 s
            location = get_location()
            if location:
                state["lastLocation"] = location
                state["locationAt"] = time.time()
    if time.time() - state.get("deviceAt", 0) >= 600:
        try:
            device = collect_device_info()
            if device:
                state["device"] = device
                state["deviceAt"] = time.time()
        except Exception as exc:
            log(f"device info failed: {exc}")
    ip_location = None
    if policy.get("locationEnabled"):
        if time.time() - state.get("ipLocationAt", 0) >= 900:
            state["ipLocationAt"] = time.time()
            found = get_ip_location()
            if found:
                state["ipLocation"] = found
                state["ipLocationAt"] = time.time()
        ip_location = state.get("ipLocation")
    try:
        all_sessions = wts_sessions() if os.name == "nt" else []
        accounts = sorted({x["user"] for x in all_sessions if x["id"] != 0 and x["user"]})
        active_users = sorted({x["user"] for x in active_sessions})
    except Exception:
        accounts = sorted({r[3] for r in rows if r[0] == "explorer.exe"})
        active_users = sorted({r[3] for r in rows if r[0] == "explorer.exe"})
    apps = dict(sorted(state["apps"].items(), key=lambda item: -item[1])[:15])
    status = {
        "version": VERSION, "product": "@M Family Safety Guard", "day": str(now.date()), "used": round(state["used"]),
        "agentMode": "device-wide-enforcing",
        "active": bool(active), "seen": int(time.time()), "msg": reason,
        "paused": bool(policy.get("paused")), "unlockedUntil": int(policy.get("unlockedUntil", 0) or 0), "hist": state["hist"],
        "apps": apps, "events": state["events"][:20], "blockedProcesses": killed,
        "policyAppliedAt": int(state.get("policyAppliedAt", 0) or 0), "policyRevision": state.get("revision", ""),
        "lastSyncAt": int(state.get("policyAppliedAt", 0) or 0), "policySyncError": state.get("policySyncError", ""), "agentStartedAt": int(state.setdefault("agentStartedAt", time.time())),
        "location": location or state.get("lastLocation"),
        "locationEnabled": bool(policy.get("locationEnabled")),
        "device": {**state.get("device", {}), "windowsUser": console_user(rows),
                   "activeUsers": active_users, "monitoringScope": "all-users-on-this-device"},
        "ipLocation": ip_location,
        "usedSec": int(state["used"] * 60), "childState": state.get("childState", ""), "lock": state.get("lock"),
        "accounts": accounts, "activeUsers": active_users,
        "timeline": state.get("timeline", [])[:250],
        "sites": site_rows(),
        "web": web_status(),
        "siteHits": {d: {"n": v["bn"], "last": v.get("bl", 0)} for d, v in state["sites"].items() if v.get("bn")},
        "filters": {c: bool(policy.get(c)) for c in ("adult", "gambling", "social", "proxy")},
        "protection": "on", "commandAck": state.get("commandAck"),
    }
    push_status(status)
    write_health(True, phase="cycle-complete")
    save_state()


def diagnose() -> int:
    """Print exactly what the agent sees, so lock and timer behaviour can be verified instead of guessed."""
    print(f"Agent v{VERSION}")
    try:
        authenticate()
        policy = pull_policy()
    except Exception as exc:
        print(f"FAIL  cannot read policy: {exc}")
        return 1
    print("Monitoring scope                : ALL interactive users on this device")
    if os.name == "nt":
        try:
            for x in wts_sessions():
                if x["id"] == 0:
                    continue
                print(f"  session {x['id']:>2}  user={x['user'] or '-':<18} state={x['state']} ({'ACTIVE' if x['state'] == 0 else 'disconnected' if x['state'] == 4 else 'other'}) {x['name']}")
        except Exception as exc:
            print(f"  could not list sessions: {exc}")
        print(f"Lock-screen sessions            : {sorted(lockscreen_sessions()) or 'none'}")
        info = device_sessions()
        print(f"Any user actively using the PC  : {bool(info and info[1]) if info else 'unknown'}")
    if os.name == "nt":
        print("--- Web monitoring ---")
        srcs = webhistory.find_sources()
        print(f"Browser history sources found   : {len(srcs)}")
        for x in srcs:
            print(f"  {x['browser']:<9} user={x['user']:<16} {x['path']}")
        update_decider(policy)
        for host in ("pornhub.com", "www.xvideos.com", "example.com"):
            print(f"  would block {host:<20}: {dns_decide(host)}")
        print(f"Windows DNS points at filter    : {state.get('dnsLocal')}")
    now = dt.datetime.now()
    print(f"Used today                      : {state['used']:.2f} min")
    print(f"Decision                        : {restriction(policy, now) or 'ALLOWED'}")
    print(f"paused={policy.get('paused')} unlockedUntil={policy.get('unlockedUntil')} limit={policy.get('limit')} weekend={policy.get('limitWk')} hours={policy.get('start')}-{policy.get('end')}")
    return 0


def watchdog() -> None:
    """Runs every minute as SYSTEM. Starts the agent when it is not running, re-creates missing tasks, and never leaves
    Windows pointing at a dead local DNS filter (the usual reason the internet 'stops working' after a crash)."""
    try:
        if REMOVING_FLAG.exists():
            return  # a remote removal is in progress
        running = agent_running()
        if not running and loopback_dns_adapters() and not filter_selftest():
            reset_loopback_dns()
            log("Watchdog: agent not running and DNS pointed at a dead local filter - DNS reset to automatic")
        try:
            made = ensure_tasks()
            if made:
                log("Watchdog re-created: " + ", ".join(made))
        except Exception as exc:
            log(f"Watchdog could not re-create tasks: {exc}")
        if running:
            return
        exe = python_exe(True)
        subprocess.Popen([exe, str(ROOT / "agent.py")], cwd=str(ROOT), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        log("Watchdog restarted agent")
    except Exception as exc:
        log(f"Watchdog failed: {exc}")


if __name__ == "__main__":
    if "--reset-network" in sys.argv:
        stop_local_filter()
        print(f"Adapters taken off the local filter: {reset_loopback_dns()}")
        print("Internet check:", internet_state())
        raise SystemExit(0)
    if "--repair-now" in sys.argv:
        good, results = repair_core(local=True)
        for item in results:
            print(("[OK]   " if item["ok"] else "[FAIL] ") + item["n"] + " - " + item["t"])
        try:
            run(["schtasks", "/run", "/tn", TASK_AGENT], timeout=30)
            print("Agent restarted.")
        except Exception as exc:
            print(f"Could not start the agent task: {exc}")
        raise SystemExit(0 if good else 1)
    if "--uninstall" in sys.argv:
        cleanup_device()
        reset_loopback_dns()
        raise SystemExit(0)
    if "--watchdog" in sys.argv:
        watchdog()
        raise SystemExit(0)
    if "--diagnose" in sys.argv:
        raise SystemExit(diagnose())
    if "--check" in sys.argv:
        raise SystemExit(self_check())
    validate_config()
    instance = acquire_single_instance()
    if instance is None:
        log("Another agent instance is already running; exiting")
        raise SystemExit(0)
    state.setdefault("agentStartedAt", int(time.time()))
    state.setdefault("installedAt", int(time.time()))
    state["lastTickAt"] = time.time()
    try:  # never start with Windows pointing at a resolver that is not running yet; the filter is re-attached once it answers
        if os.name == "nt":
            reset_loopback_dns()
        state.update(dnsLocal=False, dnsRouteSig="", dnsRouteAt=0)
    except Exception as exc:
        log(f"startup DNS guard failed: {exc}")
    prepare_request_folder()
    save_state()
    log(f"Agent v{VERSION} started; Windows={os.name}; device={DEVICE_ID}")
    failures = 0
    while True:
        try:
            if not session.get("token"):
                authenticate()
            tick()
            failures = 0
        except requests.RequestException as exc:
            failures += 1
            write_health(False, f"network/Firebase error: {exc}")
            log(f"network/Firebase error: {exc}")
        except Exception as exc:
            failures += 1
            write_health(False, f"{type(exc).__name__}: {exc}")
            log(f"agent cycle error: {type(exc).__name__}: {exc}")
        idle_wait(min(TICK * (2 ** min(failures, 4)), 30) if failures else TICK)
