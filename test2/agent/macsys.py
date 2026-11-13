"""Thin, replaceable wrappers around macOS commands used by the agent.

Everything that touches the operating system lives here so the rest of the agent can be unit-tested with fakes.
The agent runs as root (LaunchDaemon); anything that must happen inside the child's desktop session is run
through `launchctl asuser <uid>`.
"""
from __future__ import annotations
import os, plistlib, re, signal, subprocess, sys, time

NO_USER = {"", "root", "loginwindow", "_mbsetupuser"}
LOCK_CODE = ("import ctypes;ctypes.CDLL('/System/Library/PrivateFrameworks/login.framework/Versions/Current/login')"
             ".SACLockScreenImmediate()")
APP_DIRS = ("/Applications/", "/System/Applications/", "/Users/")


def run(args, timeout=15, binary=False):
    try:
        return subprocess.run(args, capture_output=True, text=not binary, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(args, 1, b"" if binary else "", str(exc))


def asuser(uid, cmd):
    return ["/bin/launchctl", "asuser", str(uid)] + list(cmd)


# ------------------------------------------------------------------ session
def session() -> dict:
    """Who is at the screen right now: {'present','user','uid','locked'}."""
    cp = run(["/usr/sbin/ioreg", "-n", "Root", "-d1", "-a"], binary=True)
    try:
        data = plistlib.loads(cp.stdout)
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            for u in entry.get("IOConsoleUsers") or []:
                if not u.get("kCGSSessionOnConsoleKey"):
                    continue
                user = str(u.get("kCGSSessionUserNameKey") or "")
                if user in NO_USER:
                    continue
                return {"present": True, "user": user, "uid": int(u.get("kCGSSessionUserIDKey", -1)),
                        "locked": bool(u.get("CGSSessionScreenIsLocked"))}
    except Exception:
        pass
    # Fallback when ioreg gives nothing usable: owner of /dev/console (cannot tell if the screen is locked).
    user = run(["/usr/bin/stat", "-f%Su", "/dev/console"]).stdout.strip()
    if user in NO_USER:
        return {"present": False, "user": "", "uid": -1, "locked": False}
    uid = run(["/usr/bin/id", "-u", user]).stdout.strip()
    return {"present": True, "user": user, "uid": int(uid) if uid.isdigit() else -1, "locked": False}


# ------------------------------------------------------------------ processes
def parse_ps(text: str):
    rows = []
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            rows.append({"pid": int(parts[0]), "uid": int(parts[1]), "path": parts[2]})
    return rows


def processes():
    rows = parse_ps(run(["/bin/ps", "-axo", "pid=,uid=,comm="]).stdout)
    java = [r["pid"] for r in rows if os.path.basename(r["path"]) == "java"]
    if java:   # Minecraft (Java Edition) runs as plain "java"; its command line identifies it
        args = {}
        for line in run(["/bin/ps", "-o", "pid=,args=", "-p", ",".join(map(str, java))]).stdout.splitlines():
            p = line.strip().split(None, 1)
            if len(p) == 2 and p[0].isdigit():
                args[int(p[0])] = p[1][:400]
        for r in rows:
            if r["pid"] in args:
                r["args"] = args[r["pid"]]
    return rows


def top_app(path: str):
    """'/Applications/Google Chrome.app/Contents/Frameworks/.../Helper.app/Contents/MacOS/x' -> ('Google Chrome', path-of-app)."""
    m = re.match(r"^(.*?/([^/]+)\.app)(?:/|$)", path)
    return (m.group(2), m.group(1)) if m else (None, None)


def is_user_app_main(path: str) -> bool:
    """True for the main executable of a normal app (not helpers, not system UI agents)."""
    if path.count(".app/") != 1 or ".app/Contents/MacOS/" not in path:
        return False
    return path.startswith(APP_DIRS) and "MFamilySafetyGuard" not in path


def kill_pids(pids, grace=0.6):
    live = []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            live.append(pid)
        except (ProcessLookupError, PermissionError):
            pass
    if live:
        time.sleep(grace)
    for pid in live:
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def frontmost_app(uid: int):
    asn = run(asuser(uid, ["/usr/bin/lsappinfo", "front"])).stdout.strip()
    if not asn:
        return None
    out = run(asuser(uid, ["/usr/bin/lsappinfo", "info", "-only", "name", asn])).stdout
    m = re.search(r'=\s*"(.+?)"\s*$', out.strip())
    return m.group(1) if m else None


# ------------------------------------------------------------------ screen lock and pop-ups
def lock_screen(uid: int):
    """Lock the child's screen. Returns (ok, method-or-error). Tries three methods in order."""
    if run(asuser(uid, [sys.executable, "-c", LOCK_CODE]), timeout=10).returncode == 0:
        return True, "SACLockScreenImmediate"
    cg = "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession"
    if os.path.exists(cg) and run(asuser(uid, [cg, "-suspend"]), timeout=10).returncode == 0:
        return True, "CGSession -suspend"
    run(["/usr/bin/pmset", "displaysleepnow"])
    return False, "Only the display was switched off; this macOS version refused to lock the screen."


def _q(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def dialog_script(text, buttons, default, timeout, title, answer=False, icon="caution"):
    btns = ", ".join(f'"{_q(b)}"' for b in buttons)
    return (f'display dialog "{_q(text)}" with title "{_q(title)}" buttons {{{btns}}} default button "{_q(default or buttons[-1])}"'
            f' giving up after {int(timeout)} with icon {icon}' + (' default answer ""' if answer else ""))


def parse_dialog(out: str):
    m = re.search(r"button returned:(?P<b>.*?)(?:, text returned:(?P<t>.*?))?, gave up:(?P<g>true|false)\s*$", out.strip(), re.S)
    if not m:
        return None
    return {"button": m.group("b"), "text": m.group("t") or "", "gave_up": m.group("g") == "true"}


def show_dialog(uid, user, text, buttons, default=None, timeout=60, title="ParentGuard", answer=False, icon="caution"):
    """Show a dialog on the child's screen. Blocks until answered; returns {'button','text','gave_up'} or None."""
    script = dialog_script(text, buttons, default, timeout, title, answer, icon)
    cp = run(asuser(uid, ["/usr/bin/sudo", "-u", user, "/usr/bin/osascript", "-e", script]), timeout=timeout + 15)
    return parse_dialog(cp.stdout) if cp.returncode == 0 else None


# ------------------------------------------------------------------ DNS
def network_services():
    out = run(["/usr/sbin/networksetup", "-listallnetworkservices"]).stdout.splitlines()
    return [s.strip() for s in out[1:] if s.strip() and not s.startswith("*")]


def get_dns(service):
    out = run(["/usr/sbin/networksetup", "-getdnsservers", service]).stdout.strip()
    return [] if (not out or "aren't any" in out) else out.split()


def set_dns(service, servers):
    cp = run(["/usr/sbin/networksetup", "-setdnsservers", service] + (list(servers) or ["Empty"]))
    return cp.returncode == 0


def dhcp_dns():
    """Resolvers handed out by the router (DHCP), used as the filter's upstream when no DNS is set by hand."""
    found = []
    for line in run(["/usr/sbin/networksetup", "-listallhardwareports"]).stdout.splitlines():
        if line.startswith("Device:"):
            dev = line.split(":", 1)[1].strip()
            out = run(["/usr/sbin/ipconfig", "getoption", dev, "domain_name_server"]).stdout
            found += [ip for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", out) if not ip.startswith("127.")]
    return list(dict.fromkeys(found))


def flush_dns():
    run(["/usr/bin/dscacheutil", "-flushcache"])
    run(["/usr/bin/killall", "-HUP", "mDNSResponder"])
