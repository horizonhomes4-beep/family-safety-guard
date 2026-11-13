#!/bin/bash
# Friendly launcher: double-click this file (first time: right-click > Open > Open) to install ParentGuard on this Mac.
cd "$(dirname "$0")/macos" || exit 1
clear
echo "ParentGuard installer - when asked, type this Mac's login password (nothing shows while you type) and press Return."
echo
bash ./install.command
RC=$?
echo
read -r -p "Press Return to close this window." _
exit $RC
