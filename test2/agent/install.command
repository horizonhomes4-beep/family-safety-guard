#!/bin/bash
# @M Family Safety Guard - macOS installer (5.12.3-mac9)
# Works on Apple Silicon and Intel Macs (MacBook Air/Pro, iMac, Mac mini, Mac Studio), macOS 11 Big Sur to macOS 26 Tahoe.
#
# Usage:   bash install.command                      (uses config.json next to this script, or the one already installed)
#          bash install.command /path/to/config.json
# Running it with "bash" also avoids the macOS "cannot be opened / unidentified developer" block on downloaded files.
set -euo pipefail
VERSION="5.12.3-mac9"
# Every program file the service needs. The Admin page packs exactly these (see macos/sync-agent-files.sh).
MODULES="agent.py blocklists.py webhistory_mac.py policy.py macsys.py guard.py dnsfilter.py browserpolicy.py childreq.py"
TOOLS="diagnose.command"
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="/Library/Application Support/MFamilySafetyGuard"
LOGDIR="/Library/Logs/MFamilySafetyGuard"
PLIST="/Library/LaunchDaemons/com.mfamily.safetyguard.agent.plist"
PY_PKG_URL="https://www.python.org/ftp/python/3.12.10/python-3.12.10-macos11.pkg"
PY_PKG_BIN="/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
TTY=0; [[ -t 0 ]] && TTY=1

say() { printf '%s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

say "@M FAMILY SAFETY GUARD - macOS installer ($VERSION)"
say "This installs a visible system service. It blocks websites (a local DNS filter covering every subdomain, plus /etc/hosts), enforces screen time, locks the screen,"
say "blocks apps/games/browsers you choose, shows request pop-ups to the child, and sets browser private-mode policies."
say "While it runs, this Mac's DNS settings point to 127.0.0.1 (restored automatically on stop or uninstall). It does not hide itself."
say "It reads supported browser history for the signed-in Mac user when macOS permissions allow."
[[ "$(uname -s)" == "Darwin" ]] || die "This installer is for macOS only."
ARCH="$(uname -m)"
OSV="$(sw_vers -productVersion)"
say "Detected macOS $OSV / $ARCH"
[[ "$ARCH" == "arm64" || "$ARCH" == "x86_64" ]] || die "Unsupported processor type: $ARCH"
OSMAJOR="${OSV%%.*}"; OSMINOR="${OSV#*.}"; OSMINOR="${OSMINOR%%.*}"
if [[ "$OSMAJOR" -lt 10 || ( "$OSMAJOR" -eq 10 && "$OSMINOR" -lt 15 ) ]]; then
  die "macOS $OSV is too old. Update to macOS 11 (Big Sur) or newer."
fi
# Files downloaded in a browser carry a quarantine flag that can block the helper scripts; clear it for this folder.
xattr -dr com.apple.quarantine "$HERE" 2>/dev/null || true

# ---------------------------------------------------------------- 1. device config.json
# Every Mac needs its OWN device record + key (Admin dashboard > add a child device > Copy config.json).
CONFIG_SRC=""; CONFIG_TMP=""
if [[ $# -ge 1 && -f "$1" ]]; then CONFIG_SRC="$1"
elif [[ -f "$HERE/config.json" ]]; then CONFIG_SRC="$HERE/config.json"
elif [[ -f "$TARGET/config.json" ]]; then CONFIG_SRC="$TARGET/config.json"; say "Upgrading in place: keeping this Mac's existing config."
elif [[ -f "$HOME/Downloads/macos/config.json" ]]; then CONFIG_SRC="$HOME/Downloads/macos/config.json"
fi
if [[ -z "$CONFIG_SRC" ]]; then
  [[ $TTY -eq 1 ]] || die "config.json not found. Put this Mac's config.json next to install.command, or run: bash install.command /full/path/to/config.json"
  CONFIG_TMP="$(mktemp -t mfgconfig)"; trap 'rm -f "$CONFIG_TMP"' EXIT
  say
  say "config.json was not found next to this script."
  say "In the Admin dashboard open this Mac's device, press 'Copy config.json', then paste it below."
  say "When it is pasted, press Return, then Control-D."
  cat > "$CONFIG_TMP"
  CONFIG_SRC="$CONFIG_TMP"
fi
[[ -r "$CONFIG_SRC" ]] || sudo test -r "$CONFIG_SRC" || die "Cannot read $CONFIG_SRC"

# ---------------------------------------------------------------- 2. find (or install) a usable Python 3.9+
py_ok() { [[ -x "$1" ]] && "$1" -c 'import sys, ssl, venv, sqlite3, ctypes; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; }
CLT_PRESENT=0; xcode-select -p >/dev/null 2>&1 && CLT_PRESENT=1
find_python() {
  local v p
  for v in 3.13 3.12 3.11 3.10 3.9; do
    for p in "/Library/Frameworks/Python.framework/Versions/$v/bin/python$v" "/opt/homebrew/bin/python$v" "/usr/local/bin/python$v"; do
      if py_ok "$p"; then echo "$p"; return 0; fi
    done
  done
  for v in python3.13 python3.12 python3.11 python3.10 python3.9; do
    p="$(command -v "$v" 2>/dev/null || true)"
    if [[ -n "$p" ]] && py_ok "$p"; then echo "$p"; return 0; fi
  done
  # /usr/bin/python3 is only a stub until the Xcode Command Line Tools exist; calling it would pop up an installer.
  if [[ $CLT_PRESENT -eq 1 ]] && py_ok /usr/bin/python3; then echo /usr/bin/python3; return 0; fi
  return 1
}
PYTHON="$(find_python || true)"
if [[ -z "$PYTHON" ]]; then
  say
  say "No Python 3.9+ was found on this Mac. The agent needs one."
  say "I can install the official Python 3.12 from python.org (about 45 MB, signed by the Python Software Foundation)."
  if [[ $TTY -eq 1 ]]; then
    read -r -p "Install it now? [Y/n] " ans
    [[ -z "$ans" || "$ans" =~ ^[Yy] ]] || die "Cancelled. Install Python 3.9+ from https://www.python.org/downloads/macos/ and run this again."
  fi
  PKGDIR="$(mktemp -d -t mfgpython)"
  say "Downloading Python..."
  curl -fL --retry 3 --connect-timeout 20 -o "$PKGDIR/python.pkg" "$PY_PKG_URL" || die "Download failed. Check the internet connection, or install Python from https://www.python.org/downloads/macos/"
  SIG="$(pkgutil --check-signature "$PKGDIR/python.pkg" 2>&1 || true)"
  if ! grep -q "Python Software Foundation" <<<"$SIG"; then rm -rf "$PKGDIR"; die "The downloaded Python installer is not signed by the Python Software Foundation. Not installing it."; fi
  sudo -v
  sudo installer -pkg "$PKGDIR/python.pkg" -target / >/dev/null || die "The Python installer failed."
  rm -rf "$PKGDIR"
  py_ok "$PY_PKG_BIN" || die "Python was installed but does not run. Restart the Mac and try again."
  PYTHON="$PY_PKG_BIN"
fi
say "Using Python: $PYTHON ($("$PYTHON" -c 'import sys; print(sys.version.split()[0])'))"

"$PYTHON" - "$CONFIG_SRC" <<'PY'
import json, sys
try:
    c = json.load(open(sys.argv[1]))
except Exception as e:
    raise SystemExit("config.json is not valid JSON: %s" % e)
missing = [k for k in ("projectId", "apiKey", "deviceId", "deviceKey")
           if not str(c.get(k, "")).strip() or str(c[k]).upper().startswith(("YOUR", "THE-", "CHANGE_ME", "GENERATE"))]
if missing:
    raise SystemExit("config.json is incomplete or still the example. Missing/placeholder: " + ", ".join(missing))
print("Config  :", sys.argv[1])
print("Project :", c["projectId"])
print("Device  :", c["deviceId"])
PY
for m in $MODULES; do
  [[ -s "$HERE/$m" ]] || die "The installer is incomplete: $m is missing. Download the installer again from the Admin page."
  "$PYTHON" -m py_compile "$HERE/$m" || die "$m has an error and cannot be installed."
done
for t in $TOOLS; do
  [[ -s "$HERE/$t" ]] || die "The installer is incomplete: $t is missing. Download the installer again from the Admin page."
  bash -n "$HERE/$t" || die "$t has a shell syntax error."
done
rm -rf "$HERE/__pycache__"

# ---------------------------------------------------------------- 3. install
say "The next step requests administrator permission to install the service."
sudo -v
sudo launchctl bootout system/com.mfamily.safetyguard.agent >/dev/null 2>&1 || true
sudo mkdir -p "$TARGET" "$LOGDIR"
sudo rm -f "$LOGDIR/agent.log"          # so verification below only sees THIS install
for m in $MODULES; do sudo cp "$HERE/$m" "$TARGET/"; done
for t in $TOOLS; do sudo cp "$HERE/$t" "$TARGET/"; done
sudo chmod 755 "$TARGET/diagnose.command"
if [[ "$CONFIG_SRC" != "$TARGET/config.json" ]]; then sudo cp "$CONFIG_SRC" "$TARGET/config.json"; fi
sudo rm -rf "$TARGET/__pycache__"
sudo chmod 700 "$TARGET"
sudo chmod 600 "$TARGET/config.json"
# Rebuild the virtual environment when it is missing/broken, or was built for a different processor or Python.
WANT="$("$PYTHON" -c 'import sys, platform; print(platform.machine(), sys.version_info[0], sys.version_info[1])')"
HAVE=""
if [[ -x "$TARGET/.venv/bin/python" ]]; then
  HAVE="$(sudo "$TARGET/.venv/bin/python" -c 'import sys, platform; print(platform.machine(), sys.version_info[0], sys.version_info[1])' 2>/dev/null || true)"
fi
if [[ "$HAVE" != "$WANT" ]] || ! sudo "$TARGET/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
  sudo rm -rf "$TARGET/.venv"
  sudo "$PYTHON" -m venv "$TARGET/.venv" || die "Could not create the Python environment."
fi
sudo "$TARGET/.venv/bin/python" -m pip install --upgrade --quiet --disable-pip-version-check pip \
  || say "(pip upgrade skipped: continuing with the bundled pip)"
sudo "$TARGET/.venv/bin/python" -m pip install --quiet --disable-pip-version-check -r "$HERE/requirements.txt" \
  || die "Could not download the 'requests' package. Check the internet connection and run this again."
sudo "$TARGET/.venv/bin/python" -c 'import requests' || die "The 'requests' package did not install correctly."
sudo chmod 755 "$TARGET/agent.py"
sudo chown -R root:wheel "$TARGET" "$LOGDIR"
sudo chmod 700 "$TARGET"; sudo chmod 600 "$TARGET/config.json"
sudo mkdir -p /Library/LaunchDaemons
sudo cp "$HERE/com.mfamily.safetyguard.agent.plist" "$PLIST"
sudo chown root:wheel "$PLIST"
sudo chmod 644 "$PLIST"
sudo plutil -lint "$PLIST" >/dev/null
sudo launchctl bootstrap system "$PLIST"
sudo launchctl kickstart -k "system/com.mfamily.safetyguard.agent"

# ---------------------------------------------------------------- 4. verify + one-time permission help
REAL="$(sudo "$TARGET/.venv/bin/python" -c 'import os, sys; print(os.path.realpath(getattr(sys, "_base_executable", sys.executable)))' 2>/dev/null || true)"
APPPY=""
if [[ -n "$REAL" ]]; then
  CAND="$(dirname "$REAL")/../Resources/Python.app/Contents/MacOS/Python"
  [[ -f "$CAND" ]] && APPPY="$(cd "$(dirname "$CAND")" && pwd)/Python"
fi
say "Waiting for the first verified heartbeat (up to 90 s)..."
OK=0
for i in {1..45}; do
  if sudo grep -q "HEARTBEAT VERIFIED" "$LOGDIR/agent.log" 2>/dev/null; then OK=1; break; fi
  sleep 2
done
say
if [[ $OK -eq 1 ]]; then
  say "INSTALLATION VERIFIED - Firestore now holds a fresh status.seen for this Mac."
  say "Refresh the Admin page: this Mac should show Online within a few seconds."
else
  say "Service installed but a verified heartbeat was NOT seen. Latest log lines:"
  sudo tail -15 "$LOGDIR/agent.log" 2>/dev/null || true
  say "Run:  bash \"$TARGET/diagnose.command\"   and read the first FAIL line."
fi
say
say "ONE-TIME PERMISSIONS (needed so Safari history and the lock screen work):"
say " 1. System Settings > Privacy & Security > Full Disk Access > '+' > add this program (Cmd-Shift-G, paste the path):"
say "      ${APPPY:-$REAL}"
[[ -n "$APPPY" && -n "$REAL" ]] && say "    (if that does not work, add:  $REAL )"
say "    then run:  sudo launchctl kickstart -k system/com.mfamily.safetyguard.agent"
say " 2. System Settings > Lock Screen > 'Require password after screen saver begins or display is turned off' = Immediately."
say " 3. The child should use a Standard (non-administrator) account."
say " 4. Restart Chrome/Edge/Brave/Firefox/Safari once so the private-browsing and secure-DNS policies load."
say " 5. To prove screen locking and pop-ups work on THIS Mac (child account signed in):  bash diagnose.command --lock-test --dialog-test"
if [[ $TTY -eq 1 && $OK -eq 1 ]]; then
  read -r -p "Open the Full Disk Access settings page now? [y/N] " a2
  if [[ "$a2" =~ ^[Yy] ]]; then
    [[ -n "${APPPY:-$REAL}" ]] && open -R "${APPPY:-$REAL}" 2>/dev/null || true
    open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
  fi
fi
[[ $OK -eq 1 ]] && exit 0 || exit 2
