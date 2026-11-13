"""Disable private/incognito/guest browsing, history deletion and encrypted-DNS bypass in installed browsers.

Chromium-family browsers read /Library/Managed Preferences/<bundle-id>.plist, Firefox reads
/Library/Preferences/org.mozilla.firefox.plist. Every file we write carries a marker key; files without it
(for example from an MDM profile) are never overwritten or deleted. Browsers must be restarted to pick the
policy up. Safari has no such policy outside MDM/Screen Time: block it with the Browsers switch instead.
"""
from __future__ import annotations
import os, plistlib
from pathlib import Path

MARK = "MFamilySafetyGuardManaged"
MANAGED = Path("/Library/Managed Preferences")
PREFS = Path("/Library/Preferences")
APPS = (Path("/Applications"), Path("/Users"))

# label -> (app bundle name, plist file, policy dict)
CHROMIUM_POLICY = {"IncognitoModeAvailability": 1, "BrowserGuestModeEnabled": False,
                   "AllowDeletingBrowserHistory": False, "DnsOverHttpsMode": "off"}
EDGE_POLICY = {"InPrivateModeAvailability": 1, "BrowserGuestModeEnabled": False,
               "AllowDeletingBrowserHistory": False, "DnsOverHttpsMode": "off"}
TARGETS = {
    "Chrome": ("Google Chrome.app", "com.google.Chrome.plist", CHROMIUM_POLICY, MANAGED),
    "Edge": ("Microsoft Edge.app", "com.microsoft.Edge.plist", EDGE_POLICY, MANAGED),
    "Brave": ("Brave Browser.app", "com.brave.Browser.plist", CHROMIUM_POLICY, MANAGED),
    "Vivaldi": ("Vivaldi.app", "com.vivaldi.Vivaldi.plist", CHROMIUM_POLICY, MANAGED),
    "Firefox": ("Firefox.app", "org.mozilla.firefox.plist",
                {"EnterprisePoliciesEnabled": True, "DisablePrivateBrowsing": True,
                 "DNSOverHTTPS": {"Enabled": False, "Locked": True}}, PREFS),
}


def installed(app_name: str, roots=APPS) -> bool:
    for root in roots:
        if root == Path("/Users"):
            if root.is_dir() and any((u / "Applications" / app_name).exists() for u in root.iterdir() if u.is_dir()):
                return True
        elif (root / app_name).exists():
            return True
    return False


def _ours(path: Path) -> bool:
    try:
        return bool(plistlib.loads(path.read_bytes()).get(MARK))
    except Exception:
        return False


def apply(enabled: bool, targets=TARGETS, roots=APPS) -> dict:
    """Write (enabled=True) or remove (False) our policy files. Returns
    {'ok': [...], 'skipped': [...], 'errors': [...], 'privateOff': bool}."""
    res = {"ok": [], "skipped": [], "errors": []}
    for label, (app, fname, policy, folder) in targets.items():
        path = folder / fname
        try:
            if not enabled:
                if path.exists() and _ours(path):
                    path.unlink()
                    res["ok"].append(label)
                continue
            if not installed(app, roots):
                continue
            if path.exists() and not _ours(path):
                res["skipped"].append(f"{label}: a policy file from another source exists and was left unchanged")
                continue
            data = dict(policy)
            data[MARK] = True
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(plistlib.dumps(data))
            os.chmod(tmp, 0o644)
            tmp.replace(path)
            back = plistlib.loads(path.read_bytes())
            if all(back.get(k) == v for k, v in data.items()):
                res["ok"].append(label)
            else:
                res["errors"].append(f"{label}: policy file did not read back correctly")
        except Exception as exc:
            res["errors"].append(f"{label}: {type(exc).__name__}: {exc}")
    res["privateOff"] = bool(enabled and res["ok"] and not res["errors"] and not res["skipped"])
    return res
