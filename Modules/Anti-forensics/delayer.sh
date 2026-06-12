#!/bin/bash
# =============================================================================
# EchoErase (delayer.sh) — Injection de délais aléatoires entre les lignes d'un script
# =============================================================================

INPUT_FILE=$1
FIXED_DELAY=$2
JITTER=$3

while IFS= read -r line; do
    # On affiche d'abord la ligne originale du script de recon
    echo "$line"

    # Nettoyage pour l'analyse (enlève les espaces au début et à la fin)
    trimmed=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    # --- LOGIQUE DE FILTRAGE ---
    # On n'ajoute PAS de sleep si :
    # 1. La ligne est vide
    # 2. C'est un commentaire (#)
    # 3. La ligne se termine par un backslash (continuation de commande)
    # 4. La ligne commence par un pipe (suite d'un pipe)
    # 5. C'est un mot-clé de structure (if, then, else, etc.)
    
    if [[ ! -z "$trimmed" && \
          "$trimmed" != "#"* && \
          "$trimmed" != "|"* && \
          "$trimmed" != *"\\" && \
          "$trimmed" != "if"* && \
          "$trimmed" != "then"* && \
          "$trimmed" != "else"* && \
          "$trimmed" != "elif"* && \
          "$trimmed" != "fi"* && \
          "$trimmed" != "do"* && \
          "$trimmed" != "done"* && \
          "$trimmed" != "{"* && \
          "$trimmed" != "}"* ]]; then
        
        # Calcul du délai avec une graine aléatoire (RANDOM) pour varier à chaque ligne
        TOTAL_SLEEP=$(awk -v f="$FIXED_DELAY" -v j="$JITTER" -v seed="$RANDOM" 'BEGIN {
            "date +%N" | getline nano; 
            srand(nano + seed); 
            r = (rand() * 2 * j) - j;
            res = f + r;
            if (res < 0) res = 0;
            printf "%.5f", res
        }')

        echo "    sleep $TOTAL_SLEEP"
    fi
done < "$INPUT_FILE"