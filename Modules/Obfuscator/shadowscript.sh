#!/usr/bin/env bash
# =============================================================================
# ShadowScript (obfuscator_v2.sh) — Obfuscateur bash avancé (technique unique combinée)
# Usage: ./obfuscator_v2.sh <script.sh>
# Techniques :
#   1. Payload   : strip des commentaires (#) et lignes vides, puis gzip + base64 + ROT13
#   2. Chunks    : nombre fixe cible (30-60) INDÉPENDANT de la taille du source ;
#                  chunk_size est calculé dynamiquement (ceil(payload/N)) pour que
#                  la taille du payload ne se lise pas dans le nombre de lignes.
#   3. Noms      : variables aléatoires pour le payload, les commandes, les leurres
#   4. base64 / gunzip : encodage hex $'\x..'
#   5. eval      : reconstruit via printf + codes octaux (jamais en clair)
#   6. tr args   : charset ROT13 encodés en hex
#   7. Leurres   : 40-100 variables au même charset et à la même longueur que les
#                  vrais chunks, insérées à des positions aléatoires parmi eux ;
#                  les définitions de commandes (b64, gunzip, etc.) sont également
#                  mélangées aléatoirement dans ce bloc.
#
# Propriété de sortie :
#   Nombre total de lignes ≈ constante ∈ [70, 170], non corrélée à l'entrée.
#   Seule la longueur des strings de chunk varie avec la taille du payload.
# =============================================================================

set -euo pipefail

[[ $# -lt 1 ]] && { echo "Usage: $0 <script.sh>"; exit 1; }

INPUT="$1"
OUTPUT="${INPUT%.sh}_obfv2.sh"
[[ ! -f "$INPUT" ]] && { echo "Erreur: fichier '$INPUT' introuvable."; exit 1; }

# ── Générateur de nom de variable (préfixe _, 5-12 chars aléatoires) ──────────
rand_var() {
    local chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local len=$(( RANDOM % 8 + 5 )) v="_" i
    for (( i=0; i<len; i++ )); do
        v+="${chars:$(( RANDOM % ${#chars} )):1}"
    done
    echo "$v"
}

# ── Encodage hex bash : "abc" → $'\x61\x62\x63' ───────────────────────────────
to_hex() {
    local s="$1" r="\$'" i h
    for (( i=0; i<${#s}; i++ )); do
        printf -v h '%02x' "'${s:$i:1}"
        r+="\\x${h}"
    done
    echo "${r}'"
}

# ── Encodage octal : "eval" → printf '\145\166\141\154' ───────────────────────
to_octal_printf() {
    local s="$1" cmd="printf '" i o
    for (( i=0; i<${#s}; i++ )); do
        printf -v o '%03o' "'${s:$i:1}"
        cmd+="\\${o}"
    done
    echo "${cmd}'"
}

# ── Générateur de leurre : même charset que le payload (base64+ROT13) ─────────
# Longueur calquée sur chunk_size pour être indiscernable visuellement.
gen_fake_line() {
    local ref_len="${1:-20}"
    local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    local fv g i
    local spread=$(( ref_len / 4 + 1 ))
    local len=$(( RANDOM % (spread * 2 + 1) + ref_len - spread ))
    [[ $len -lt 4 ]] && len=4
    fv=$(rand_var)
    g=""
    for (( i=0; i<len; i++ )); do
        g+="${chars:$(( RANDOM % ${#chars} )):1}"
    done
    printf '%s\n' "${fv}='${g}'"
}

# ── Étape 1 : strip commentaires/blancs, gzip + base64 + ROT13 ───────────────
payload=$(grep -Ev '^\s*#|^\s*$' "$INPUT" | gzip -c | base64 -w 0 | tr 'A-Za-z' 'N-ZA-Mn-za-m')

# ── Étape 2 : nombre de chunks FIXE, indépendant de la taille du payload ──────
TARGET_CHUNKS=$(( RANDOM % 31 + 30 ))
if [[ ${#payload} -le $TARGET_CHUNKS ]]; then
    nchunks=${#payload}
    chunk_size=1
else
    nchunks=$TARGET_CHUNKS
    chunk_size=$(( (${#payload} + nchunks - 1) / nchunks ))
fi

declare -a vnames=()
declare -a chunks=()
i=0
while [[ $i -lt ${#payload} ]]; do
    vnames+=( "$(rand_var)" )
    chunks+=( "${payload:$i:$chunk_size}" )
    i=$(( i + chunk_size ))
done
nchunks=${#vnames[@]}

# ── Étape 3 : noms aléatoires pour les commandes clés ─────────────────────────
v_b64=$(rand_var)
v_gz=$(rand_var)
v_ev=$(rand_var)
v_pay=$(rand_var)
v_rk=$(rand_var)
v_rv=$(rand_var)

hex_b64=$(to_hex "base64")
hex_gz=$(to_hex "gunzip")
oct_ev=$(to_octal_printf "eval")
hex_rk=$(to_hex "A-Za-z")
hex_rv=$(to_hex "N-ZA-Mn-za-m")

# ── Étape 4 : mélange Fisher-Yates sur les indices des chunks ─────────────────
declare -a idx=()
for (( j=0; j<nchunks; j++ )); do idx+=("$j"); done
for (( j=nchunks-1; j>0; j-- )); do
    k=$(( RANDOM % (j+1) ))
    tmp="${idx[$j]}"; idx[$j]="${idx[$k]}"; idx[$k]="$tmp"
done

# ── Étape 5 : construction de la ligne de concaténation et d'exécution ────────
concat=""
for (( j=0; j<nchunks; j++ )); do
    concat+="\${${vnames[$j]}}"
done
exec_line="\${${v_ev}} \"\$(printf '%s' \"\${${v_pay}}\" | tr \"\${${v_rk}}\" \"\${${v_rv}}\" | \${${v_b64}} -d | \${${v_gz}})\""

# ── Étape 6 : construction du pool de lignes à mélanger ───────────────────────
# On place dans un tableau toutes les lignes "variables" (chunks + commandes),
# puis on insère 40-100 leurres à des positions aléatoires dans ce tableau.
declare -a pool=()

for j in "${idx[@]}"; do
    pool+=( "${vnames[$j]}='${chunks[$j]}'" )
done

pool+=( "${v_b64}=${hex_b64}" )
pool+=( "${v_gz}=${hex_gz}" )
pool+=( "${v_ev}=\$(${oct_ev})" )
pool+=( "${v_rk}=${hex_rk}" )
pool+=( "${v_rv}=${hex_rv}" )

N_DECOYS=$(( RANDOM % 61 + 40 ))
for (( d=0; d<N_DECOYS; d++ )); do
    pos=$(( RANDOM % (${#pool[@]} + 1) ))
    fake=$(gen_fake_line "$chunk_size")
    pool=( "${pool[@]:0:$pos}" "$fake" "${pool[@]:$pos}" )
done

# ── Écriture du stub ───────────────────────────────────────────────────────────
{
    printf '#!/usr/bin/env bash\n'
    printf '%s\n' "${pool[@]}"
    printf '%s="%s"\n' "$v_pay" "$concat"
    printf '%s\n' "$exec_line"
} > "$OUTPUT"

chmod +x "$OUTPUT"

SIZE_IN=$(wc -c < "$INPUT")
SIZE_OUT=$(wc -c < "$OUTPUT")
TOTAL_LINES=$(wc -l < "$OUTPUT")
printf '\n\033[0;32m✓ Obfuscation terminée\033[0m : %s\n' "$OUTPUT"
printf '  Original  : %d octets\n' "$SIZE_IN"
printf '  Obfusqué  : %d octets\n' "$SIZE_OUT"
printf '  Chunks    : %d  (taille ~%d chars)\n' "$nchunks" "$chunk_size"
printf '  Leurres   : %d lignes\n' "$N_DECOYS"
printf '  Total     : %d lignes\n' "$TOTAL_LINES"
