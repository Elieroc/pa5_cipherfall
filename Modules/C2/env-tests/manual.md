# Local C2 Test Environment — Manual

## Purpose

Run the full C2 stack locally without VPS or live Cloudflare Worker.
- NullRelay server + ClockVenom server: host machine
- Cloudflare Worker mock: `wrangler dev --local` (port 8787, D1 simulated)
- Agents: Docker containers with 1s beacon interval

## Architecture

```
[host machine]
  wrangler dev :8787          ← CF Worker mock (D1 in local SQLite)
  NullRelay server :1337      ← polls localhost:8787
  ClockVenom server UDP/123   ← needs root
  TUI / operator_cli          ← talks to :1337 and :1338

[Docker containers via host.docker.internal]
  nr-agent-1, nr-agent-2     → WORKER_URL=http://host.docker.internal:8787
  cv-agent-1, cv-agent-2     → C2_DIRECT=host.docker.internal
```

## Prerequisites

- `node` + `wrangler` in PATH (`npm i -g wrangler` if missing)
- `docker` + `docker compose` in PATH
- `python3` with `pycryptodome` + `fastapi` + `uvicorn` installed (from Modules/C2/cloudflare-worker/requirements.txt and Modules/C2/ntp/requirements.txt)
- `sudo` access (ClockVenom needs UDP/123)

## Quick start

```bash
cd Modules/C2/env-tests
bash start.sh
```

Then open TUI from project root:
```bash
cd Modules/C2
C2_ADMIN_PORTS=1338,1337 C2_HOST=127.0.0.1 python3 tui.py
```

Or create `.env` in Modules/C2/ pointing at local infra:
```
WORKER_URL=http://localhost:8787
C2_PSK=testkey123
C2_ADMIN_PORTS=1338,1337
C2_HOST=127.0.0.1
```

## Tear down

```bash
bash stop.sh
```

## What start.sh does (step by step)

1. Computes `WORKER_SECRET = HMAC-SHA256("testkey123", "worker_token").hexdigest()[:32]`
2. Writes `cloudflare-worker/.dev.vars` with that secret (wrangler dev reads it)
3. Initialises D1 local tables via `wrangler d1 execute --local`
4. Starts `wrangler dev --local --port 8787 --ip 0.0.0.0` in background → `/tmp/wrangler-dev.log` (must bind 0.0.0.0, not 127.0.0.1, so Docker containers can reach it via host.docker.internal)
5. Starts `cloudflare-worker/server.py` with `WORKER_URL=http://localhost:8787` → `/tmp/nullrelay-server.log`
6. Starts `ntp/server.py` with sudo → `/tmp/clockvenom-server.log`
7. Runs `docker compose up -d --build` (builds image from `Modules/C2/`, 2 NullRelay + 2 ClockVenom agents)

## Checking health

```bash
# NullRelay admin API
curl http://127.0.0.1:1337/admin/agents

# ClockVenom admin API
curl http://127.0.0.1:1338/admin/agents

# wrangler dev direct
curl http://127.0.0.1:8787/agents \
  -H "Authorization: Bearer $(python3 -c "import hmac,hashlib; print(hmac.new(b'testkey123', b'worker_token', hashlib.sha256).hexdigest()[:32])")"

# Docker container logs
docker compose -f Modules/C2/env-tests/docker-compose.yml logs -f nr-agent-1
docker compose -f Modules/C2/env-tests/docker-compose.yml logs -f cv-agent-1
```

Agents appear in TUI within ~5s (beacon interval = 1s).

## Key constants

| Variable | Test value | Notes |
|---|---|---|
| `C2_PSK` | `testkey123` | must match across server, worker, agents |
| `WORKER_URL` (server) | `http://localhost:8787` | wrangler dev |
| `WORKER_URL` (Docker agents) | `http://host.docker.internal:8787` | reaches host from container |
| `C2_DIRECT` (ClockVenom agents) | `host.docker.internal` | bypasses DNS, goes direct to host |
| `C2_INT` / `C2_JITTER` | `1` / `1` | fast beacon for testing |
| NullRelay admin port | `1337` | |
| ClockVenom admin port | `1338` | |

## Adding more agents

Scale up in docker-compose.yml — copy any service block, rename it, same env vars. Rebuild with:
```bash
docker compose up -d --build --scale nr-agent-1=3
```
Or duplicate blocks manually for different configs.

## Troubleshooting

**`wrangler dev` fails immediately**: check `cloudflare-worker/.dev.vars` exists; run `wrangler dev --local` manually from `cloudflare-worker/` to see the error.

**Agents registered in NullRelay but not showing**: NullRelay server may not have started. Check `/tmp/nullrelay-server.log`. Missing `pycryptodome`? `pip install pycryptodome`.

**ClockVenom agents not showing**: ClockVenom server needs UDP/123. Check `/tmp/clockvenom-server.log` for permission error. Run `sudo python3 ntp/server.py` manually to confirm.

**`host.docker.internal` not resolving in containers**: The `extra_hosts: host.docker.internal:host-gateway` line in docker-compose.yml handles this on Linux. If it fails, replace with the Docker bridge IP: `ip route | awk '/docker/{print $9}'` then hardcode that IP in compose.

**D1 tables not found in wrangler dev**: Re-run step 3 manually:
```bash
cd Modules/C2/cloudflare-worker
wrangler d1 execute cipherfall-c2-db --local --command "CREATE TABLE IF NOT EXISTS tasks (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS results (task_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS heartbeats (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);"
```

**Port 8787 in use**: Kill the old wrangler dev: `pkill -f "wrangler dev"`.

## File map

```
Modules/C2/env-tests/
├── Dockerfile          # agent image (copies nullrelay.py + clockvenom.py from parent context)
├── docker-compose.yml  # 2x NullRelay agents + 2x ClockVenom agents
├── .env.test           # reference for all test constants (not loaded automatically)
├── start.sh            # one-command spin-up
├── stop.sh             # tear down everything
└── manual.md           # this file
```
