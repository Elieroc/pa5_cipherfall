#!/usr/bin/env bash
# Tear down local test environment
set -euo pipefail
cd "$(dirname "$0")"

docker compose down --remove-orphans

pkill -f "wrangler dev" 2>/dev/null && echo "wrangler dev stopped" || true
pkill -f "cloudflare-worker/server.py" 2>/dev/null && echo "NullRelay stopped" || true
sudo pkill -f "ntp/server.py" 2>/dev/null && echo "ClockVenom stopped" || true

rm -f /tmp/wrangler-dev.log /tmp/nullrelay-server.log /tmp/clockvenom-server.log
echo "Done."
