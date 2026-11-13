#!/usr/bin/env python3
"""Visible, consent-based macOS companion for @M Family Safety Guard 5.12.4 (mac10).

What it does, all reported live to the Admin/Parent dashboards through Firestore:
  * heartbeat + status (status.seen drives Online/Offline)
  * website rules: real-time local DNS filter (blocked-attempt telemetry, wildcards, keyword rules) with a
    marked /etc/hosts fallback; safe-search enforcement
  * screen-time accounting, daily limits, allowed hours, lock / unlock / add time / resume, suspend
  * app, game and browser blocking, app usage and launch events, user and screen events
  * child requests (pop-up -> Firestore request -> e-mail) and parent decisions shown back to the child
  * browser private/guest/history-deletion policies, browser history, approximate location
  * repair, stop/resume protection and remote uninstall
"""
from __future__ import annotations
import datetime as dt, hashlib, json, os, platform, re, signal, socket, subprocess, sys, threading, time
from pathlib import Path
import requests
import blocklists as BL
import webhistory_mac as WH
import policy as P
import macsys
import browserpolicy
import dnsfilter
import childreq
from guard import Guard

ROOT = Path(__file__).resolve().parent
CONFIG = Path(os.environ.get("MFG_CONFIG") or ROOT / "config.json")
BASE = Path(os.environ.get("MFG_HOME") or "/Library/Application Support/MFamilySafetyGuard")
STATE = BASE / "state.json"
LOG = Path(os.environ.get("MFG_LOGDIR") or "/Library/Logs/MFamilySafetyGuard") / "agent.log"
HOSTS = Path(os.environ.get("MFG_HOSTS") or "/etc/hosts")
VERSION = "5.12.4-mac10"
PRODUCT = "@M Family Safety Guard"
TICK = 5                 # seconds between local enforcement passes (blocking, lock, usage)
SYNC_EVERY = 10          # seconds between Firebase policy reads
PUSH_EVERY = 25          # status write at least this often (dashboard treats > 90 s as offline)
HISTORY_EVERY = 30
NOTIFY_EVERY = 300
EFFECT_EVERY = 300       # re-assert hosts / DNS / browser policies even when nothing changed
LOCATION_EVERY = 900
STATUS_MAX = 700_000     # a Firestore document may not exceed 1 MiB
TOKEN_MAX_AGE = 50 * 60  # refresh the Firebase ID token before its 1 h expiry
LOG_MAX = 1_000_000
try:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    PROJECT, API_KEY = (str(cfg[k]).strip() for k in ("projectId", "apiKey"))
    DEVICE_ID, DEVICE_KEY = (str(cfg[k]).strip() for k in ("deviceId", "deviceKey"))
    if not all((PROJECT, API_KEY, DEVICE_ID, DEVICE_KEY)):
        raise ValueError("config.json contains an empty required value")
except Exception as exc:
    raise SystemExit(f"Invalid or missing {CONFIG}: {exc}")
DB = f"https://firestore.googleapis.com/v1/projects/{PROJECT}/databases/(default)/documents"
TOKEN_URL = f"https://securetoken.googleapis.com/v1/token?key={API_KEY}"
SIGNUP_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
http = requests.Session()
http.headers.update({"User-Agent": f"MFamilySafetyGuard/{VERSION}", "Accept": "application/json"})
state: dict = {}
guard: Guard | None = None
prompter: childreq.Prompter | None = None
reqs: childreq.Requests | None = None
dnsf: dnsfilter.DnsFilter | None = None
notify_cache: dict = {}
dns_error = ""
browser_result: dict = {}
location_cache: dict = {"at": 0, "ip": None}
token = ""
token_at = 0.0
last_policy: dict | None = None
last_name = ""
policy_applied_at = 0
agent_started_at = int(time.time())
heartbeat_verified = False
command_ack: dict | None = None
removed = False
last_log_line, last_log_at = "", 0.0
MARK_BEGIN, MARK_END = "# MFAMILY SAFETY GUARD BEGIN", "# MFAMILY SAFETY GUARD END"


def log(msg, force=False):
    """Write a log line. Identical repeated lines are throttled to one per 10 minutes."""
    global last_log_line, last_log_at
    if not force and msg == last_log_line and time.time() - last_log_at < 600:
        return
    last_log_line, last_log_at = msg, time.time()
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        if LOG.exists() and LOG.stat().st_size > LOG_MAX:
            tail = LOG.read_bytes()[-200_000:]
            LOG.write_bytes(tail[tail.find(b"\n") + 1:])
        with LOG.open("a", encoding="utf-8") as f:
            f.write(f"{dt.datetime.now().astimezone().isoformat(timespec='seconds')} [{VERSION}] {msg}\n")
    except Exception:
        pass


def run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=15)
    except Exception:
        return subprocess.CompletedProcess(args, 1, "", "")


def headers():
    return {"Authorization": "Bearer " + token}


def save():
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    os.chmod(tmp, 0o600); tmp.replace(STATE); os.chmod(STATE, 0o600)


def auth(force_new=False):
    """Refresh the current identity, or create/register a fresh agent identity."""
    global token, token_at
    refresh = None if force_new else state.get("refreshToken")
    if refresh:
        r = http.post(TOKEN_URL, data={"grant_type": "refresh_token", "refresh_token": refresh}, timeout=20)
        if r.ok:
            j = r.json()
            token = j["id_token"]; token_at = time.time()
            state["refreshToken"] = j.get("refresh_token", refresh); save()
            return
    r = http.post(SIGNUP_URL, json={"returnSecureToken": True}, timeout=20)
    r.raise_for_status(); j = r.json()
    token = j["idToken"]; token_at = time.time()
    state["refreshToken"] = j["refreshToken"]; save()
    reg = http.patch(f"{DB}/devices/{DEVICE_ID}/agents/{j['localId']}", headers=headers(),
                     json={"fields": {"key": {"stringValue": DEVICE_KEY}}}, timeout=20)
    reg.raise_for_status()
    log("Registered this Mac with the device key", force=True)


def request(method, url, **kw):
    """HTTP call that re-authenticates once on 401/403."""
    r = http.request(method, url, headers=headers(), timeout=20, **kw)
    if r.status_code == 401:
        auth()
        r = http.request(method, url, headers=headers(), timeout=20, **kw)
    if r.status_code == 403:
        # Admin key rotation deletes the old agents/{uid} record. A refreshed token
        # keeps that UID and cannot recreate it; register a fresh anonymous identity.
        auth(force_new=True)
        r = http.request(method, url, headers=headers(), timeout=20, **kw)
    return r


def json_field(fields, key, default):
    try:
        return json.loads(fields.get(key, {}).get("stringValue", ""))
    except Exception:
        return default


def pull():
    """Read this device's document -> (effective policy, child name, pending command)."""
    r = request("GET", f"{DB}/devices/{DEVICE_ID}")
    r.raise_for_status()
    f = r.json().get("fields", {})
    p = P.merge_policy(json_field(f, "cfg", {}), json_field(f, "adminCfg", {}),
                       protection_off=f.get("protection", {}).get("stringValue", "") == "off",
                       suspended=bool(f.get("suspended", {}).get("booleanValue", False)))
    raw_command = f.get("command", {}).get("stringValue", "")
    try:
        command = json.loads(raw_command) if raw_command else None
    except (TypeError, ValueError):
        command = None
    return p, str(f.get("name", {}).get("stringValue", ""))[:80], command


# ------------------------------------------------------------------ website rules
clean_domain = P.clean_domain


def domains(policy):
    """Blocked domains after the 'always allow' exemptions (sorted list)."""
    blocked, allowed = P.rule_domains(policy, BL.CATEGORY_DOMAINS)
    return sorted(d for d in blocked if not any(d == a or d.endswith("." + a) for a in allowed))


GOOGLE_SAFE = ["www.google.com", "google.com", "www.google.com.ng", "www.google.co.uk", "www.google.ca", "www.google.com.au",
               "www.google.co.za", "www.google.co.in", "www.google.de", "www.google.fr", "www.google.es", "www.google.it"]
SAFE_TARGETS = {"forcesafesearch.google.com": GOOGLE_SAFE,
                "restrict.youtube.com": ["www.youtube.com", "m.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com", "www.youtube-nocookie.com"],
                "strict.bing.com": ["www.bing.com"]}


def safe_search_lines():
    """hosts lines that send Google, YouTube and Bing to their official restricted-mode servers."""
    cache, now, lines = state.setdefault("safeIps", {}), time.time(), []
    for target, names in SAFE_TARGETS.items():
        ent = cache.get(target)
        if not ent or now - ent.get("t", 0) > 86400:
            ips = []
            for fam in (socket.AF_INET, socket.AF_INET6):
                try:
                    ips.append(socket.getaddrinfo(target, None, fam)[0][4][0])
                except OSError:
                    pass
            ent = cache[target] = {"ips": ips, "t": now if ips else now - 86400 + 600}   # failed lookups retry in 10 min
        for ip in (ent or {}).get("ips", []):
            lines += [f"{ip} {n}" for n in names]
    return lines


SUB_PREFIXES = ("www", "m", "mobile", "web", "amp")


def learned_hosts(policy, blocked):
    """Hosts seen in the browser history that belong to a blocked site (hosts files have no wildcards)."""
    out = set()
    for row in state.get("sites", []):
        host = str(row.get("d", "")).lower()
        if host and any(host == b or host.endswith("." + b) for b in blocked):
            out.add(host)
    return sorted(out)


def apply_hosts(policy, dns_active=False):
    """Rewrite only our marked section of /etc/hosts. With the DNS filter running, site blocks move to DNS
    (so every blocked attempt can be seen); safe-search lines always live here."""
    off = bool(policy.get("protectionOff"))
    blocked = [] if (off or dns_active) else domains(policy)
    safe = [] if off or policy.get("safeSearch") is False else safe_search_lines()
    old = HOSTS.read_text(encoding="utf-8", errors="ignore") if HOSTS.exists() else ""
    old = re.sub(r"(?ms)^" + re.escape(MARK_BEGIN) + r"\s*.*?^" + re.escape(MARK_END) + r"\s*\n?", "", old).rstrip()
    names = []
    for d in blocked:
        names += [d] + [p + "." + d for p in SUB_PREFIXES]
    names += learned_hosts(policy, blocked)
    if blocked:
        names += list(dnsfilter.FORCE_NXDOMAIN)          # Private Relay / encrypted-DNS canary
    lines = []
    for host in dict.fromkeys(names):
        lines += ["0.0.0.0 " + host, ":: " + host]
    lines += safe
    section = "\n\n" + MARK_BEGIN + "\n" + "\n".join(lines) + "\n" + MARK_END + "\n" if lines else ""
    new = old + section + ("\n" if old and not section else "")
    current = HOSTS.read_text(encoding="utf-8", errors="ignore") if HOSTS.exists() else ""
    if new != current:
        HOSTS.write_text(new, encoding="utf-8")
        flush_dns()
    return len(blocked)


def upstream_servers():
    orig = [s for v in state.get("dnsOrig", {}).values() for s in v if not s.startswith("127.")]
    live = [s for svc in macsys.network_services() for s in macsys.get_dns(svc) if not s.startswith("127.")]
    return list(dict.fromkeys(orig + live + macsys.dhcp_dns() + ["1.1.1.1", "8.8.8.8"]))


def route_dns():
    """Point every network service at the local filter (remembering what it had) and verify it stuck."""
    orig, changed, ok = state.setdefault("dnsOrig", {}), False, True
    for svc in macsys.network_services():
        cur = macsys.get_dns(svc)
        if cur != ["127.0.0.1"]:
            orig.setdefault(svc, [x for x in cur if not x.startswith("127.")])
            ok = macsys.set_dns(svc, ["127.0.0.1"]) and ok
            changed = True
    if changed:
        save()
        flush_dns()
    return ok


def restore_dns():
    """Restore each service independently; retain failed restores for the next retry."""
    original = state.get("dnsOrig", {})
    if not isinstance(original, dict) or not original:
        return True
    remaining = {}
    for svc, servers in list(original.items()):
        try:
            ok = bool(macsys.set_dns(svc, servers))
        except Exception as exc:
            ok = False
            log(f"DNS restore failed for {svc}: {exc!r}"[:180], force=True)
        if not ok:
            remaining[svc] = servers
            log(f"DNS restore failed for network service {svc}; will retry", force=True)
    state["dnsOrig"] = remaining
    save()
    flush_dns()
    return not remaining


def stop_dns():
    global dnsf
    if dnsf:
        dnsf.stop()
        dnsf = None
    restore_dns()


def ensure_dns(matcher):
    """Start/refresh the local DNS filter. Returns True when it is running and the Mac uses it."""
    global dnsf, dns_error
    if dnsf is None or not dnsf.running:
        if dnsf:
            dnsf.stop()
        dnsf = dnsfilter.DnsFilter(("127.0.0.1", 53), upstream_servers(), on_block=guard.on_dns_block if guard else None)
        try:
            dnsf.start()
        except OSError as exc:
            dns_error, dnsf = str(exc)[:160], None
            log("DNS filter could not start: " + dns_error, force=True)
            restore_dns()
            return False
    sig = matcher.signature()
    dnsf.set_matcher(matcher)
    dnsf.set_upstreams(upstream_servers())
    if getattr(dnsf, "rules_sig", None) != sig:
        dnsf.rules_sig = sig
        flush_dns()
    dns_error = "" if route_dns() else "could not change the Mac's DNS settings"
    return not dns_error


selftest_cache: tuple = (0.0, None)
bypass = {"layer": False, "strikes": 0, "seen_at": 0.0}     # hosts file used as a second layer when the Mac routes around the filter


def check_bypass(policy):
    """If the filter blocks a site but the Mac's own resolver still reaches it (VPN, custom DNS profile, Private Relay),
    add the hosts file as a second layer. Needs two consecutive fresh failures so one stale cache entry cannot trigger it."""
    if not (dnsf and dnsf.running):
        bypass.update(layer=False, strikes=0)
        return
    if bypass["layer"]:
        return
    res = selftest()
    at = selftest_cache[0]
    if not res or at == bypass["seen_at"]:
        return
    bypass["seen_at"] = at
    bypass["strikes"] = bypass["strikes"] + 1 if (res["filter"] == "blocked" and res["system"] == "resolves") else 0
    if bypass["strikes"] >= 2:
        bypass["layer"] = True
        apply_hosts(policy, dns_active=False)
        log(f"Mac still resolves {res['domain']} around the DNS filter; hosts file enabled as a second layer", force=True)


def selftest(force=False):
    """Proves blocking works on THIS Mac: the filter blocks a listed site and a made-up subdomain of it, and the
    Mac's own resolver agrees. Cached for 60 s. -> dict or None when there is nothing to test."""
    global selftest_cache
    at, cached = selftest_cache
    if not force and time.time() - at < 60:
        return cached
    res = None
    if dnsf and dnsf.running:
        blocked = sorted(dnsf.matcher.blocked - dnsf.matcher.allowed)
        if blocked:
            d = blocked[0]
            res = {"domain": d, "filter": dnsfilter.probe(d, port=dnsf.port), "subdomain": dnsfilter.probe("mfg-check." + d, port=dnsf.port),
                   "system": dnsfilter.system_lookup(d), "relay": dnsfilter.probe("mask.icloud.com", port=dnsf.port)}
    selftest_cache = (time.time(), res)
    return res


def apply_effects(policy, rules_changed=False):
    """Make the Mac match the policy: DNS filter, hosts file, safe search, browser policies. -> blocked-domain count."""
    global browser_result
    if rules_changed:
        bypass.update(layer=False, strikes=0)
    off = bool(policy.get("protectionOff"))
    blocked, allowed = P.rule_domains(policy, BL.CATEGORY_DOMAINS)
    keywords = {c: BL.KEYWORDS[c] for c in ("adult", "gambling", "proxy") if policy.get(c) and c in BL.KEYWORDS}
    dns_on = False
    if not off and (blocked or keywords):
        dns_on = ensure_dns(dnsfilter.Matcher(blocked, allowed, keywords))
    else:
        stop_dns()
    selftest_cache_reset()
    n = apply_hosts(policy, dns_active=dns_on and not bypass["layer"])
    browser_result = browserpolicy.apply(not off)
    return len(domains(policy)) if not off else 0


def flush_dns():
    macsys.flush_dns()


def selftest_cache_reset():
    global selftest_cache
    selftest_cache = (0.0, None)


def remove_own_hosts_entries():
    old = HOSTS.read_text(encoding="utf-8", errors="ignore") if HOSTS.exists() else ""
    new = re.sub(r"(?ms)^" + re.escape(MARK_BEGIN) + r"\s*.*?^" + re.escape(MARK_END) + r"\s*\n?", "", old).rstrip() + "\n"
    if new != old:
        HOSTS.write_text(new, encoding="utf-8")
        flush_dns()


def undo_everything():
    """Remove every change this agent made to the Mac (hosts, DNS, browser policies)."""
    stop_dns()
    remove_own_hosts_entries()
    return browserpolicy.apply(False)


def remote_cleanup():
    """Remove this product's launchd service, files and settings.

    Stopping the service kills this very process, so the final steps run in a detached shell
    (the LaunchDaemon plist sets AbandonProcessGroup so that shell survives the stop)."""
    undo_everything()
    script = ("sleep 3; /bin/launchctl bootout system/com.mfamily.safetyguard.agent; "
              "/bin/rm -f /Library/LaunchDaemons/com.mfamily.safetyguard.agent.plist; "
              "/bin/rm -rf '/Library/Application Support/MFamilySafetyGuard' /Library/Logs/MFamilySafetyGuard")
    subprocess.Popen(["/bin/sh", "-c", script], start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ------------------------------------------------------------------ device facts
console_user = lambda: macsys.session()["user"]


def users():
    names = {line.split()[0] for line in macsys.run(["/usr/bin/who"]).stdout.splitlines() if line.split()}
    cu = console_user()
    if cu:
        names.add(cu)
    return sorted(names)


def computer_name():
    n = macsys.run(["/usr/sbin/scutil", "--get", "ComputerName"]).stdout.strip()
    return n or platform.node()


def device_info(active_users):
    return {"computerName": computer_name(), "platform": "macOS", "os": platform.mac_ver()[0], "osName": "macOS",
            "architecture": platform.machine(), "model": macsys.run(["/usr/sbin/sysctl", "-n", "hw.model"]).stdout.strip(),
            "hostname": platform.node(), "consoleUser": console_user(), "activeUsers": active_users,
            "monitoringScope": "all-local-accounts (website rules device-wide; apps and screen time for the signed-in user)",
            "agentVersion": VERSION}


def ip_location():
    """Approximate (city-level) location from the public IP. Precise GPS location is not available to a background service."""
    for url in ("https://ipwho.is/", "https://ipapi.co/json/"):
        try:
            j = http.get(url, timeout=10).json()
            if j.get("success") is False or j.get("error"):
                continue
            city, region = j.get("city"), j.get("region") or j.get("region_name")
            country = j.get("country") or j.get("country_name")
            if city or country:
                return {"city": city or "", "region": region or "", "country": country or ""}
        except Exception:
            continue
    return None


def classify(host):
    for c in ("adult", "gambling", "social", "proxy"):
        if BL.in_set(host, BL.CATEGORY_DOMAINS.get(c, set())) or (c in BL.KEYWORDS and BL.KEYWORDS[c].search(host)):
            return c
    return ""


# ------------------------------------------------------------------ status
def build_status(policy, n_blocked, sync_error):
    now = int(time.time())
    us = users()
    pol = policy or {}
    rev = hashlib.sha256(json.dumps(pol, sort_keys=True).encode()).hexdigest()[:16]
    g = guard.status_fields() if guard else {"day": str(dt.date.today()), "used": 0, "usedSec": 0, "hist": {}, "apps": {}, "events": [], "timeline": [],
                                           "sites": [], "siteHits": {}, "blockedProcesses": [], "lock": None, "msg": "", "active": bool(console_user()),
                                           "childState": "active" if console_user() else "no-user-session"}
    running = bool(dnsf and dnsf.running)
    st_res = selftest() if running else None
    live = running and not bypass["layer"]       # the dashboard shows "Real-time blocking is on" only for this
    dns_msg = dns_error or ("This Mac still reached a blocked site around the DNS filter (VPN, custom DNS profile or Private Relay), so the hosts file is also being used as a second layer. Restart the browser; run diagnose.command for details." if bypass["layer"] else "")
    loc_on = bool(pol.get("locationEnabled"))
    status = {
        "version": VERSION, "product": PRODUCT, "seen": now,
        "protection": "off" if pol.get("protectionOff") else "on",
        "agentMode": "macOS-agent", "paused": bool(pol.get("paused")),
        "unlockedUntil": int(pol.get("unlockedUntil", 0) or 0),
        "policyAppliedAt": policy_applied_at, "lastSyncAt": policy_applied_at, "commandAck": command_ack, "removed": removed,
        "policyRevision": rev, "policySyncError": sync_error, "agentStartedAt": agent_started_at,
        "accounts": us, "activeUsers": us, "device": device_info(us),
        "monitoringScope": "all-local-accounts (website rules device-wide; apps and screen time for the signed-in user)",
        "filters": {c: bool(pol.get(c)) for c in ("adult", "gambling", "social", "proxy")},
        "blockedDomains": n_blocked,
        "location": None, "locationEnabled": loc_on, "ipLocation": location_cache["ip"] if loc_on else None,
        "web": {"mode": "real-time-filter" if live else "hosts-file-domain-filter", "dnsFilter": live,
                "dnsRouted": running and not dns_error, "dnsError": dns_msg, "selfTest": st_res,
                "dnsQueries": dnsf.queries if running else 0, "dnsBlocked": dnsf.blocked if running else 0,
                "privateOff": bool(browser_result.get("privateOff")) and not pol.get("protectionOff"),
                "browserPolicy": {k: browser_result.get(k, []) for k in ("ok", "skipped", "errors")},
                "historySources": state.get("historySources", []), "historyErrors": state.get("historyErrors", [])[:8],
                "historyAt": int(state.get("historyAt", 0) or 0),
                "note": "Website rules run in a local DNS filter. Browser history is read from supported browsers when macOS permissions allow. Safari cannot be restricted for private browsing without MDM; block it with the Browsers switch."},
    }
    status.update(g)
    return status


def shrink(status):
    """Keep the status document well under Firestore's 1 MiB limit by trimming the largest, oldest lists."""
    for _ in range(8):
        text = json.dumps(status, separators=(",", ":"))
        if len(text) <= STATUS_MAX:
            return text
        status["timeline"] = status["timeline"][:max(50, len(status["timeline"]) // 2)]
        status["sites"] = [dict(x, v=(x.get("v") or [])[-20:]) for x in status["sites"][:max(50, len(status["sites"]) // 2)]]
    return text


def push_status(data):
    body = {"fields": {"status": {"stringValue": shrink(data)}}}
    r = request("PATCH", f"{DB}/devices/{DEVICE_ID}?updateMask.fieldPaths=status", json=body)
    if not r.ok:
        raise RuntimeError(f"status write rejected: HTTP {r.status_code} {r.text[:300]}")


def read_back_seen():
    r = request("GET", f"{DB}/devices/{DEVICE_ID}")
    r.raise_for_status()
    st = json.loads(r.json().get("fields", {}).get("status", {}).get("stringValue", "{}") or "{}")
    return int(st.get("seen", 0) or 0)


# ------------------------------------------------------------------ commands
def process_command(command, policy):
    """Handle only explicit administrator commands from this device document."""
    global command_ack, removed
    if not isinstance(command, dict) or not command.get("id"):
        return False
    cid, kind = str(command.get("id", ""))[:80], command.get("type")
    if command_ack and command_ack.get("id") == cid:
        return False
    if kind == "repair":
        try:
            count = apply_effects(policy or {})
            steps = [{"n": "Reapply website rules", "ok": True, "t": f"{count} blocked domains"
                      + (" (real-time DNS filter)" if dnsf and dnsf.running else " (hosts file)")},
                     {"n": "Browser policies", "ok": not browser_result.get("errors"),
                      "t": ", ".join(browser_result.get("ok", [])) or "no supported browser found"},
                     {"n": "Flush DNS cache", "ok": True, "t": "macOS DNS cache refreshed"}]
            if dns_error:
                steps.append({"n": "DNS filter", "ok": False, "t": dns_error})
            flush_dns()
            command_ack = {"id": cid, "type": kind, "stage": "done", "ok": all(x["ok"] for x in steps),
                           "note": "Agent re-applied its rules and refreshed the DNS cache.", "at": int(time.time()), "steps": steps}
        except Exception as e:
            command_ack = {"id": cid, "type": kind, "stage": "done", "ok": False, "note": repr(e)[:200], "at": int(time.time())}
        state["commandAck"] = command_ack
        save()
        return False
    if kind == "uninstall":
        undo_everything()
        removed = True
        command_ack = {"id": cid, "type": kind, "stage": "removed", "ok": True,
                       "note": "ParentGuard agent, launchd service, DNS filter, browser policies and hosts-file rules were removed.",
                       "at": int(time.time()), "steps": [
                           {"n": "Restore DNS settings and remove website rules", "ok": True, "t": "Only ParentGuard's own entries removed"},
                           {"n": "Remove launchd service and program files", "ok": True, "t": "Cleanup started"}]}
        state["commandAck"] = command_ack
        save()
        return True
    command_ack = {"id": cid, "type": str(kind or "unknown"), "stage": "done", "ok": False,
                   "note": "Unsupported command on this Mac agent.", "at": int(time.time())}
    state["commandAck"] = command_ack
    save()
    return False


# ------------------------------------------------------------------ browser history
def collect_browser_history():
    """Collect recent navigations from the active console user's supported browsers."""
    cu = console_user()
    if not cu:
        return
    marks = state.setdefault("hmarks", {})
    visits, sources, errors = WH.collect(marks, home=Path("/Users") / cu)
    state["historySources"], state["historyErrors"], state["historyAt"] = sources, errors, int(time.time())
    sites = {x.get("d"): x for x in state.get("sites", []) if isinstance(x, dict) and x.get("d")}
    for v in visits:
        host = v["host"]
        row = sites.setdefault(host, {"d": host, "n": 0, "l": 0, "b": 0, "bl": 0, "g": BL.is_background(host), "c": classify(host), "k": 0})
        row["n"] = int(row.get("n", 0)) + 1
        row["l"] = max(int(row.get("l", 0)), int(v["t"]))
        row["v"] = (list(row.get("v", [])) + [int(v["t"])])[-100:]
        if guard:
            guard.event_at(int(v["t"]), "Visited " + host, "web", d=host, u=v.get("u", ""), browser=v.get("browser", ""), user=v.get("user", ""))
    state["sites"] = sorted(sites.values(), key=lambda x: int(x.get("l", 0)), reverse=True)[:300]
    save()
    if errors:
        log("Browser history access warnings: " + "; ".join(errors[:3]))
    if visits:
        log(f"Collected {len(visits)} browser navigation(s) from {', '.join(sources) or 'supported browsers'}")


# ------------------------------------------------------------------ main loop
sched = {"sync": 0.0, "push": 0.0, "hist": 0.0, "notify": 0.0, "effects": 0.0, "loc": 0.0, "reqs": 0.0, "sig": "", "web": "", "dnscheck": 0.0}
n_blocked = 0
sync_error = ""


def web_signature(policy):
    keys = ("sites", "allowedSites", "adult", "gambling", "social", "proxy", "safeSearch", "protectionOff")
    return json.dumps({k: policy.get(k) for k in keys}, sort_keys=True, default=str)


def do_sync(now):
    """One Firebase round trip: read policy, apply it, run commands. Returns True when the agent must remove itself."""
    global last_policy, last_name, policy_applied_at, n_blocked, sync_error, dns_error
    if not token or time.time() - token_at > TOKEN_MAX_AGE:
        auth()
    should_remove = False
    try:
        policy, last_name, command = pull()
        signature = web_signature(policy)
        changed = signature != sched["web"]
        last_policy = policy
        guard.set_policy(policy)
        if changed or now - sched["effects"] >= EFFECT_EVERY:
            # Commit the signature only after every enforcement layer succeeds. If
            # DNS/hosts/browser policy application raises, the next sync retries it.
            n_blocked = apply_effects(policy, rules_changed=changed)
            sched["web"] = signature
            sched["effects"] = now
        elif dnsf and not dnsf.running:
            n_blocked = apply_effects(policy)
        if not policy.get("protectionOff") and now - sched["hist"] >= HISTORY_EVERY:
            sched["hist"] = now
            collect_browser_history()
        if now - sched["notify"] >= NOTIFY_EVERY:
            sched["notify"] = now
            try:
                notify_cache.clear(); notify_cache.update(reqs.notify_config())
            except Exception as e:
                log("notify settings: " + repr(e)[:120])
        if policy.get("locationEnabled") and now - location_cache["at"] >= LOCATION_EVERY:
            location_cache.update(at=now, ip=ip_location())
        check_bypass(policy)
        if dnsf and dnsf.running and now - sched["dnscheck"] >= 30:
            sched["dnscheck"] = now
            dns_error = "" if route_dns() else "could not change the Mac's DNS settings"
        elif not (dnsf and dnsf.running) and state.get("dnsOrig") and now - sched["dnscheck"] >= 30:
            # A failed restore must remain recoverable even after the DNS daemon stops.
            sched["dnscheck"] = now
            if restore_dns():
                dns_error = ""
            else:
                dns_error = "could not restore the Mac's original DNS settings"
        if state.get("policy") != policy:
            state["policy"] = policy              # lets the Mac enforce its rules at boot before the network is up
            save()
        guard.tick()
        policy_applied_at = int(time.time())
        should_remove = process_command(command, policy)
        sync_error = ""
    except Exception as e:                  # keep reporting a heartbeat even when the policy step fails
        sync_error = repr(e)[:200]
        log("policy step failed: " + sync_error)
    if should_remove:
        n_blocked = 0
    return should_remove


def status_signature(st):
    keys = ("lock", "msg", "active", "childState", "protection", "paused", "policyRevision", "removed", "policySyncError", "commandAck")
    top = (st["timeline"][0]["at"], st["timeline"][0]["message"]) if st["timeline"] else None
    return json.dumps([[st.get(k) for k in keys], top, len(st["sites"]), st["web"]["mode"], st["web"]["privateOff"]], sort_keys=True, default=str)


def step():
    """One 5-second pass. Returns True when the agent should exit."""
    global heartbeat_verified
    now = time.time()
    should_remove = False
    if now - sched["sync"] >= SYNC_EVERY:
        sched["sync"] = now
        should_remove = do_sync(now)
    else:
        guard.tick()
    if prompter and now - sched["reqs"] >= 15 and prompter.pending:
        sched["reqs"] = now
        try: prompter.poll()
        except Exception as e: log("request poll: " + repr(e)[:120])
    status = build_status(last_policy, n_blocked, sync_error)
    sig = status_signature(status)
    changed, since = sig != sched["sig"], now - sched["push"]
    if should_remove or since >= PUSH_EVERY or (changed and since >= 3):
        push_status(status)
        sched["push"], sched["sig"] = now, sig
        if should_remove:
            remote_cleanup()
            return True
        if not heartbeat_verified:
            seen = read_back_seen()
            if seen == status["seen"]:
                heartbeat_verified = True
                log(f"HEARTBEAT VERIFIED: Firestore devices/{DEVICE_ID} status.seen={seen}; the dashboard will show this Mac Online", force=True)
            else:
                log(f"HEARTBEAT NOT VERIFIED: wrote seen={status['seen']} but read back {seen}", force=True)
        log(f"Heartbeat OK for {last_name or DEVICE_ID}; blockedDomains={n_blocked}; dns={'on' if dnsf and dnsf.running else 'off'}; "
            f"locked={bool(guard.lock_info)}; users={','.join(status['accounts']) or 'none'}")
    return False


def build_runtime():
    """Create the guard, request prompter and Firestore client (also used by --diagnose)."""
    global guard, prompter, reqs
    reqs = childreq.Requests(request, DB, DEVICE_ID)
    guard = Guard(state, macsys, None, save, log)
    prompter = childreq.Prompter(reqs, macsys.show_dialog, lambda: last_name, lambda: guard.session, lambda: notify_cache, log)
    guard.prompter = prompter


def shutdown(*_):
    log("Agent stopping; restoring DNS settings", force=True)
    try:
        stop_dns()
    finally:
        os._exit(0)


def apply_cached_policy():
    """At boot: enforce the last rules this Mac received, before (and without) any network access."""
    global last_policy, n_blocked
    cached = state.get("policy")
    if not (isinstance(cached, dict) and cached):
        return False
    try:
        last_policy = cached
        guard.set_policy(cached)
        sched["web"] = web_signature(cached)
        n_blocked = apply_effects(cached)
        sched["effects"] = time.time()
        log("Applied the last known rules from this Mac's cache", force=True)
        return True
    except Exception as e:
        log("cached rules could not be applied: " + repr(e)[:160], force=True)
        return False


def main():
    global command_ack
    STATE.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    if STATE.exists():
        try: state.update(json.loads(STATE.read_text()))
        except Exception: pass
    command_ack = state.get("commandAck")
    build_runtime()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    apply_cached_policy()
    log(f"Agent started (device {DEVICE_ID}, project {PROJECT})", force=True)
    while True:
        t0 = time.time()
        try:
            if step():
                raise SystemExit(0)
        except SystemExit:
            raise
        except Exception as e:
            log("heartbeat error: " + repr(e)[:300])
        time.sleep(max(1, TICK - (time.time() - t0)))


def diagnose():
    """One visible pass with plain output:  sudo <venv>/bin/python agent.py --diagnose [--lock-test] [--dialog-test]"""
    global command_ack
    if STATE.exists():
        try: state.update(json.loads(STATE.read_text()))
        except Exception: pass
    command_ack = state.get("commandAck")
    build_runtime()
    ok_all = True
    def line(ok, text):
        nonlocal ok_all
        ok_all = ok_all and ok
        print(("PASS  " if ok else "FAIL  ") + text)
    print(f"Agent {VERSION}\nProject  : {PROJECT}\nDevice ID: {DEVICE_ID}")
    try:
        auth(); line(True, "Firebase sign-in")
        pol, name, command = pull(); line(True, f"policy read (device name: {name or '-'}, protection {'OFF' if pol.get('protectionOff') else 'on'})")
        n = len(domains(pol))
        print(f"      effective rules: {n} blocked domains, {len(pol.get('apps', []))} blocked apps, limit={pol.get('limit')} weekend={pol.get('limitWk')} hours={pol.get('start')}-{pol.get('end')}")
        s = macsys.session()
        line(s["present"], f"session: user={s['user'] or '-'} uid={s['uid']} screenLocked={s['locked']}  (needs a signed-in user)")
        procs = macsys.processes()
        apps = sorted({macsys.top_app(p["path"])[0] for p in procs if p["uid"] == s["uid"] and macsys.is_user_app_main(p["path"])})
        line(bool(procs), f"process list: {len(procs)} processes; running apps: {', '.join(apps[:8]) or 'none'}")
        if s["present"]:
            fa = macsys.frontmost_app(s["uid"])
            line(bool(fa), f"frontmost app: {fa or 'not detected'}")
        line(bool(macsys.network_services()), f"network services: {', '.join(macsys.network_services()[:4])}")
        try:
            probe = dnsfilter.DnsFilter(("127.0.0.1", 0)); probe.start(); probe.stop(); line(True, "DNS filter can start (test port)")
        except OSError as exc:
            line(False, f"DNS filter cannot start: {exc}")
        blocked_now = sorted(P.rule_domains(pol, BL.CATEGORY_DOMAINS)[0] - P.rule_domains(pol, BL.CATEGORY_DOMAINS)[1])
        if blocked_now:
            d = blocked_now[0]
            line(dnsfilter.probe(d) == "blocked", f"running DNS filter (127.0.0.1:53) blocks {d}: {dnsfilter.probe(d)}")
            line(dnsfilter.probe("mfg-check." + d) == "blocked", f"...and a made-up subdomain of it: {dnsfilter.probe('mfg-check.' + d)}")
            line(dnsfilter.system_lookup(d) == "blocked", f"this Mac's own resolver cannot reach {d}: {dnsfilter.system_lookup(d)}  (if it resolves: another DNS/VPN/Private Relay is bypassing the filter; restart the browser)")
            line(dnsfilter.system_lookup("mask.icloud.com") == "blocked", "iCloud Private Relay is switched off for this network (mask.icloud.com does not resolve)")
        else:
            print("      no blocked sites in the current rules, so the website filter has nothing to prove")
        installed = [k for k, v in browserpolicy.TARGETS.items() if browserpolicy.installed(v[0])]
        print(f"      browsers found for private-mode policy: {', '.join(installed) or 'none'} (Safari cannot be restricted this way)")
        collect_browser_history()
        print("History sources: " + (", ".join(state.get("historySources", [])) or "none detected"))
        for warning in state.get("historyErrors", []): print("HISTORY WARNING: " + warning)
        if pol.get("locationEnabled"):
            loc = ip_location(); line(bool(loc), f"approximate location: {loc}")
        if "--lock-test" in sys.argv and s["present"]:
            print("      LOCK TEST: locking the screen in 3 seconds...")
            time.sleep(3); ok, how = macsys.lock_screen(s["uid"]); line(ok, f"lock screen via {how}")
        if "--dialog-test" in sys.argv and s["present"]:
            r = macsys.show_dialog(s["uid"], s["user"], "ParentGuard test pop-up. Press OK.", ["OK"], "OK", 30, icon="note"); line(bool(r), f"pop-up on the child's screen: {r}")
        st = build_status(pol, n, ""); push_status(st); line(True, "status write")
        seen = read_back_seen(); ok = seen == st["seen"]
        line(ok, f"read-back status.seen={seen} (age {int(time.time()) - seen}s)")
        print("RESULT: dashboard should show ONLINE" if ok_all else "RESULT: at least one check failed (see FAIL lines above)")
        return 0 if ok_all else 1
    except Exception as e:
        print("FAIL ", repr(e)); return 1


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run through install.command; the service requires administrator approval.")
    if "--restore-dns" in sys.argv:
        if STATE.exists():
            try: state.update(json.loads(STATE.read_text()))
            except Exception: pass
        restore_dns(); print("DNS settings restored to what they were before ParentGuard."); raise SystemExit(0)
    if "--cleanup" in sys.argv:
        if STATE.exists():
            try: state.update(json.loads(STATE.read_text()))
            except Exception: pass
        res = undo_everything(); print("Removed ParentGuard hosts entries, DNS routing and browser policies.", res.get("errors") or ""); raise SystemExit(0)
    if "--diagnose" in sys.argv:
        raise SystemExit(diagnose())
    main()
