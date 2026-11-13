#!/bin/bash
# Visible diagnostic entry point for the installed macOS agent.
set -euo pipefail
TARGET="/Library/Application Support/MFamilySafetyGuard"
PY="$TARGET/.venv/bin/python"
AGENT="$TARGET/agent.py"
if [[ ! -x "$PY" || ! -f "$AGENT" ]]; then
  echo "ParentGuard is not installed completely at: $TARGET" >&2
  exit 2
fi
exec sudo "$PY" "$AGENT" --diagnose "$@"
