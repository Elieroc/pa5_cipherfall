#!/usr/bin/env bash
# Start full local test environment: wrangler dev + NullRelay + ClockVenom + Docker agents
set -euo pipefail
cd "$(dirname "$0")"

PSK=testkey123
WORKER_SECRET=$(python3 -c "
import hmac, hashlib
print(hmac.new(b'${PSK}', b'worker_token', hashlib.sha256).hexdigest()[:32])
")

echo "[1/6] Writing .dev.vars for wrangler dev..."
echo "WORKER_SECRET=${WORKER_SECRET}" > ../cloudflare-worker/.dev.vars

echo "[2/6] Initialising D1 local tables..."
(cd ../cloudflare-worker && wrangler d1 execute cipherfall-c2-db --local --command "
CREATE TABLE IF NOT EXISTS tasks (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS results (task_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS heartbeats (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);
" 2>&1) | tail -3

echo "[3/6] Starting wrangler dev on :8787..."
(cd ../cloudflare-worker && wrangler dev --local --port 8787 --ip 0.0.0.0) > /tmp/wrangler-dev.log 2>&1 &
echo "  PID=$!"
sleep 3

echo "[4/6] Starting NullRelay server on :1337..."
(cd .. && WORKER_URL=http://localhost:8787 C2_PSK=$PSK C2_POLL=2 C2_ADMIN=1337 python3 cloudflare-worker/server.py) > /tmp/nullrelay-server.log 2>&1 &
echo "  PID=$!"
sleep 1

echo "[5/6] Starting ClockVenom server on UDP/123 (sudo)..."
(cd .. && sudo C2_PSK=$PSK C2_POLL=2 C2_ADMIN=1338 python3 ntp/server.py) > /tmp/clockvenom-server.log 2>&1 &
echo "  PID=$!"
sleep 1

echo "[6/6] Starting Docker agents..."
docker compose up -d --build

echo ""
echo "Environment ready."
echo "  TUI:    cd Modules/C2 && C2_ADMIN_PORTS=1338,1337 C2_HOST=127.0.0.1 python3 tui.py"
echo "  Logs:   /tmp/wrangler-dev.log | /tmp/nullrelay-server.log | /tmp/clockvenom-server.log"
echo "  Stop:   bash stop.sh"
