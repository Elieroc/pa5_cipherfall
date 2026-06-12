#!/usr/bin/env bash
# =============================================================================
# Phantom Eye (recon.sh) — Collecte d'informations système sur une ligne (séparateur ;)
# Colonnes : Distro;Version;Kernel;SMB_Shares;NFS_Exports;S3_Buckets;
#            MariaDB_DBs;PostgreSQL_DBs;MongoDB_DBs;GitLab_Version
# =============================================================================

# ---------- helpers ----------------------------------------------------------
cmd_exists() { command -v "$1" &>/dev/null; }
trim()        { echo "$1" | tr -d '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
na()          { echo "N/A"; }

# ---------- Distro & Version -------------------------------------------------
get_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${NAME:-Unknown}"
    elif cmd_exists lsb_release; then
        lsb_release -si
    else
        na
    fi
}

get_version() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "${VERSION_ID:-${VERSION:-Unknown}}"
    elif cmd_exists lsb_release; then
        lsb_release -sr
    else
        na
    fi
}

# ---------- Kernel -----------------------------------------------------------
get_kernel() {
    uname -r 2>/dev/null || na
}

# ---------- SMB (Samba) shares -----------------------------------------------
get_smb() {
    local shares=""
    # Depuis la config Samba
    if cmd_exists testparm; then
        shares=$(testparm -s 2>/dev/null \
            | awk '/^\[/ && !/^\[(global|printers|print\$)\]/ {
                    gsub(/[\[\]]/,"",$0); printf "%s,", $0 }')
    elif [[ -f /etc/samba/smb.conf ]]; then
        shares=$(grep -oP '(?<=^\[)[^\]]+(?=\])' /etc/samba/smb.conf \
            | grep -viE '^(global|printers|print\$)' \
            | paste -sd, -)
    fi
    [[ -z "$shares" ]] && shares=$(na)
    trim "${shares%,}"
}

# ---------- NFS exports -------------------------------------------------------
get_nfs() {
    local exports=""
    if [[ -f /etc/exports ]]; then
        exports=$(grep -vE '^\s*#|^\s*$' /etc/exports \
            | awk '{print $1}' \
            | paste -sd, -)
    elif cmd_exists showmount; then
        exports=$(showmount -e localhost 2>/dev/null \
            | tail -n +2 \
            | awk '{print $1}' \
            | paste -sd, -)
    fi
    [[ -z "$exports" ]] && exports=$(na)
    trim "$exports"
}

# ---------- S3 buckets (AWS CLI) ----------------------------------------------
get_s3() {
    local buckets=""
    if cmd_exists aws; then
        buckets=$(aws s3 ls 2>/dev/null \
            | awk '{print $3}' \
            | paste -sd, -)
    fi
    [[ -z "$buckets" ]] && buckets=$(na)
    trim "$buckets"
}

# ---------- MariaDB / MySQL databases ----------------------------------------
get_mariadb() {
    local dbs=""
    local mysql_cmd=""
    cmd_exists mariadb && mysql_cmd="mariadb"
    cmd_exists mysql   && mysql_cmd="${mysql_cmd:-mysql}"

    if [[ -n "$mysql_cmd" ]]; then
        # Essaie d'abord sans mot de passe (socket Unix / root local)
        dbs=$($mysql_cmd -N -e "SHOW DATABASES;" 2>/dev/null \
            | grep -viE '^(information_schema|performance_schema|mysql|sys)$' \
            | paste -sd, -)
    fi
    [[ -z "$dbs" ]] && dbs=$(na)
    trim "$dbs"
}

# ---------- PostgreSQL databases ---------------------------------------------
get_postgresql() {
    local dbs=""
    if cmd_exists psql; then
        dbs=$(sudo -u postgres psql -Atc \
            "SELECT datname FROM pg_database WHERE datistemplate = false;" \
            2>/dev/null \
            | grep -viE '^postgres$' \
            | paste -sd, -)
    fi
    [[ -z "$dbs" ]] && dbs=$(na)
    trim "$dbs"
}

# ---------- MongoDB databases -------------------------------------------------
get_mongodb() {
    local dbs=""
    local mongo_cmd=""
    cmd_exists mongosh && mongo_cmd="mongosh"
    cmd_exists mongo   && mongo_cmd="${mongo_cmd:-mongo}"

    if [[ -n "$mongo_cmd" ]]; then
        dbs=$($mongo_cmd --quiet --eval \
            "db.adminCommand({listDatabases:1}).databases.map(d=>d.name).join(',')" \
            2>/dev/null \
            | grep -v '^$' \
            | tail -1)
    fi
    [[ -z "$dbs" ]] && dbs=$(na)
    trim "$dbs"
}

# ---------- GitLab version ---------------------------------------------------
get_gitlab() {
    local ver=""
    # Paquet système
    if cmd_exists gitlab-rake; then
        ver=$(gitlab-rake gitlab:env:info 2>/dev/null \
            | grep -i "GitLab version" \
            | awk '{print $NF}')
    fi
    # Fichier VERSION dans l'installation omnibus
    if [[ -z "$ver" && -f /opt/gitlab/version-manifest.txt ]]; then
        ver=$(head -1 /opt/gitlab/version-manifest.txt | awk '{print $2}')
    fi
    # API locale (si GitLab tourne)
    if [[ -z "$ver" ]]; then
        ver=$(curl -sf http://localhost/api/v4/version 2>/dev/null \
            | grep -oP '"version"\s*:\s*"\K[^"]+')
    fi
    [[ -z "$ver" ]] && ver=$(na)
    trim "$ver"
}

# =============================================================================
# Assemblage final sur une seule ligne
# =============================================================================
DISTRO=$(get_distro)
VERSION=$(get_version)
KERNEL=$(get_kernel)
SMB=$(get_smb)
NFS=$(get_nfs)
S3=$(get_s3)
MARIADB=$(get_mariadb)
POSTGRESQL=$(get_postgresql)
MONGODB=$(get_mongodb)
GITLAB=$(get_gitlab)

printf '%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n' \
    "$DISTRO" "$VERSION" "$KERNEL" \
    "$SMB" "$NFS" "$S3" \
    "$MARIADB" "$POSTGRESQL" "$MONGODB" \
    "$GITLAB"