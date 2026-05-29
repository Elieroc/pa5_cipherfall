# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

Cipherfall is an ESGI annual project simulating the reconstruction of an APT's tooling arsenal. The modules cover the full attack lifecycle: reconnaissance, obfuscation, C2, dropping payloads, phishing, privilege escalation, rootkits, and anti-forensics. All code is for authorized security research and educational purposes.

## Module execution

```bash
# Recon — single semicolon-delimited output line
bash Modules/Recon/recon.sh

# Obfuscate a bash script (advanced: ROT13+chunks+random vars+decoys)
bash Modules/Obfuscator/obfuscator_v2.sh <script.sh>

# Obfuscate a Python script (same technique as obfuscator_v2 but for .py)
python3 Modules/Obfuscator/obfuscator_py.py <script.py>

# Anti-forensics: ghost shell (root recommended for full coverage)
sudo bash Modules/Anti-forensics/ghost-shell.sh

# Anti-forensics: inject randomized sleep delays between lines of a script
bash Modules/Anti-forensics/delayer.sh <script.sh> <fixed_delay_s> <jitter_s>

# Anti-forensics: rename a file (base64 stem by default, or random/ext options)
python3 Modules/Anti-forensics/renamer.py [--no-recover] [--ext] [--view] <file>

# C2: start server (requires WORKER_URL env var pointing to Cloudflare Worker)
cd Modules/C2 && pip install -r requirements.txt
WORKER_URL=https://... C2_PSK=... python3 server.py

# C2: interactive TUI dashboard (talks to server admin API)
cd Modules/C2 && WORKER_URL=https://... C2_PSK=... python3 tui.py

# C2: deploy Cloudflare Worker dead-drop
cd Modules/C2 && wrangler secret put WORKER_SECRET && wrangler deploy

# Dropper: fileless binary execution via memfd_create
python3 Modules/Dropper/net_bin_dropper.py

# Dropper: fileless bash script execution via memfd_create
python3 Modules/Dropper/net_sh_dropper.py

# Dropper: fileless Python script execution via memfd_create + exec
python3 Modules/Dropper/net_py_dropper.py

# Phishing: Microsoft device flow 2FA bypass (serves phishing page)
cd Modules/Phishing/deviceflowbypass2fa && pip install -r req.txt && python3 server.py

# Rootkit: build and load LKM
cd Modules/Rootkits && make && sudo insmod rootkit.ko

# Privesc: DirtyFrag exploit (CVE)
cd Modules/Privesc/dirtyfrag && ./exp

# Privesc: ssh-keysign privilege escalation
cd Modules/Privesc/ssh-keysign-pwn && make && ./sshkeysign_pwn

# Privesc: Fragnesia namespace wrapper (CVE-2026-46300)
bash Modules/Privesc/fragnesia.sh
```

## Architecture

Full attack pipeline: recon target → obfuscate payload → drop via fileless dropper → beacon to C2 via Cloudflare dead-drop → escalate privileges → persist with rootkit → cover tracks with anti-forensics.

**Recon** (`recon.sh`): Collects system fingerprint data using only built-in tools and standard binaries (`testparm`, `aws`, `psql`, `mongosh`, `gitlab-rake`, etc.). Falls back gracefully to `N/A` for each unavailable data source. Output is always exactly one line: `Distro;Version;Kernel;SMB_Shares;NFS_Exports;S3_Buckets;MariaDB_DBs;PostgreSQL_DBs;MongoDB_DBs;GitLab_Version`.

**Obfuscator** (`obfuscator_v2.sh`, `obfuscator_py.py`): Stacks gzip → base64 → ROT13, then splits into variable-size chunks, shuffles chunk definition order (Fisher-Yates), encodes all command names in hex (`$'\x..'`) or chr() sequences, and injects decoy variables from a hardcoded fake-pool. The final stub never contains any readable string like `eval`, `base64`, or `gunzip`.

**C2** (`server.py`, `agent.py`, `worker.js`, `tui.py`, `operator_cli.py`): Three-tier architecture — C2 server (operator-side, no public port) ↔ Cloudflare Worker KV dead-drop ↔ agent (victim-side). Server and agent never connect directly; all traffic is HTTPS/443 to Cloudflare edge.

_Dead-drop flow:_ (1) operator queues task → stored in SQLite as `pending`; (2) server dispatch loop PUTs encrypted task to Worker `PUT /task/{agent_id}` → marked `sent` on HTTP 200; (3) agent beacons: PUTs heartbeat to `/hb/{agent_id}`, GETs `/task/{agent_id}` (204 = nothing, 200 = execute), PUTs result to `/result/{task_id}`; (4) server collect loop GETs `/result/{task_id}` → decrypts, stores in SQLite, marks `done`.

_Encryption:_ AES-256-GCM. Key = PBKDF2-SHA256(PSK, `cipherfall_c2_v1`, 32 bytes, 100k iterations). Wire = `base64(nonce[12] ‖ ciphertext ‖ GCM-tag[16])`. Server uses pycryptodome; agent implements AES-256-GCM from scratch in pure Python stdlib (no pip on target).

_Authentication:_ `Authorization: Bearer <token>` where token = `HMAC-SHA256(PSK, b"worker_token").hexdigest()[:32]`, derived identically on server and agent. Worker returns 404 on bad token to avoid fingerprinting.

_Agent identity:_ SHA-256 of `/etc/machine-id` (fallback: hostname), truncated to 32 hex chars. Deterministic across reboots. Print with `python3 agent.py --id`. Agent spoofs `User-Agent: Mozilla/5.0 … Chrome/124`.

_Agent commands:_ any shell string (executed via `/bin/sh`, stdout+stderr returned); `UPLOAD:/path` (file read binary, returned as base64).

_Worker KV TTLs:_ task 1h, result 24h, heartbeat 10min. Task GET is one-time read (`ctx.waitUntil` delete). `GET /agents` lists all `hb:` keys for auto-discovery (max 1000).

_Server env vars:_ `WORKER_URL` (required), `C2_PSK` (default: `changeme`), `C2_DB` (`c2.db`), `C2_ADMIN` (port, default `1337`), `C2_POLL` (interval s, default `10`).

_Agent env vars (bake before obfuscating):_ `WORKER_URL` (required), `C2_PSK` (`changeme`), `C2_INT` (beacon interval s, `30`), `C2_JITTER` (±jitter s, `10`).

_Server admin API (127.0.0.1 only):_ `GET /admin/agents`, `GET /admin/tasks`, `POST /admin/register {agent_id, label?}`, `POST /admin/task {agent_id, command}`, `GET /admin/result/<task_id>`.

_TUI_ (`tui.py`, Textual + Rich): two tabs — **Agents** (list agents, browse tasks, dispatch commands, auto-refresh every 5s) and **Payload** (bakes `agent.py` via regex substitution of constants, optionally calls `obfuscator_py.py`). Reads `C2_ADMIN_PORT` (default `1337`), `WORKER_URL`, `C2_PSK`.

_Operator CLI_ (`operator_cli.py`, stdlib only): `agents`, `register <id> [label]`, `tasks`, `task <id_prefix> <cmd>` (prefix min 4 chars), `result <task_id>`, `wait <task_id>` (polls every 5s).

_Worker deployment:_ `wrangler kv:namespace create "C2_KV"` → paste id in `wrangler.toml`; `wrangler secret put WORKER_SECRET` (paste derived token); `wrangler deploy`.

_Limitations:_ task lost if agent crashes after GET before PUT result (re-queue manually); one pending task per agent at a time; SQLite not suitable for large deployments; agent has no persistence (pair with dropper).

**Dropper** (`net_bin_dropper.py`, `net_sh_dropper.py`, `net_py_dropper.py`): Fileless execution via `memfd_create(2)` — payload downloaded over HTTP(S) never touches disk. Binary dropper: `MFD_CLOEXEC` set, kernel execs the fd directly. Shell dropper: no `MFD_CLOEXEC` (fd must stay open for bash), exec via `/proc/self/fd/<n>`. Python dropper: similar to shell but invokes `python3`. All three support `DAEMON_MODE` for double-fork daemonization.

**Phishing** (`deviceflowbypass2fa/`): Microsoft OAuth 2.0 device authorization flow abuse. Flask server proxies requests to `login.microsoftonline.com/common/oauth2/v2.0/devicecode`, displays the user code via `outlook.html` phishing page, then polls for token completion to capture access + refresh tokens. Scope includes `offline_access` to obtain long-lived refresh tokens.

**Rootkit** (`rootkit.c`): Linux LKM rootkit. Hooks `__NR_getdents64`, `__NR_getdents`, `__NR_kill` via syscall table patching (CR0.WP bypass with inline asm). Hides files prefixed `rootkit_`, runtime-controlled files/PIDs via `/proc/rootkit_ctrl` write-only interface. Self-hides from `lsmod` and `/sys/module/` at init. Supports kernels ≥ 4.17 (pt_regs ABI) and ≥ 5.7 (`kallsyms_lookup_name` via kprobe). No persistence across reboot; `rmmod` unavailable after self-hide by design.

**Privesc** (`dirtyfrag/`, `ssh-keysign-pwn/`, `fragnesia.sh`): Three exploits. `dirtyfrag` targets CVE via fragmented memory. `ssh-keysign-pwn` abuses `ssh-keysign` SUID binary. `fragnesia.sh` is a user+network namespace wrapper for CVE-2026-46300 that sets up the unprivileged namespace environment before running the compiled exploit.

**Anti-forensics — ghost-shell** (`ghost-shell.sh`): Five phases: (1) disable kernel auditing (`auditctl -e 0`) + stop auditbeat; (2) erase utmp/wtmp entries for current TTY via `utmpdump -r`; (3) zero lastlog for current UID via `dd` (seek to `uid * 292`); (4) scrub environment variables (SSH_*, SUDO_*, terminal fingerprints); (5) exec shell spoofed as `[kworker/u:0]` via `exec -a`. `trap EXIT` restores audit rules. Limitation: `/proc/<PID>/exe` still points to real bash.

**Anti-forensics — delayer** (`delayer.sh`): Injects `sleep <N>` after each substantive line, skipping comments, blank lines, backslash/pipe continuations, and shell control keywords. Delay randomized via awk with nanosecond seed.

**Anti-forensics — renamer** (`renamer.py`): Renames files using base64 URL-safe stem encoding (RFC 4648 §5, no padding, reversible via `--view`). `--no-recover`: random 6-char alphanumeric stem (CSPRNG, irreversible). `--ext`: replaces extension with a plausible alternative from a family table. All modes combinable except `--view` + `--ext`.

## Coding conventions

- Each file starts with a detailed header block explaining what the module does, all techniques used, and known limitations (see existing files as reference).
- No inline or explanatory comments anywhere else in the code — only the header.
- When adding a new module, test it before reporting it complete; if a live test is not possible, explicitly say so.
- Variable names in obfuscated stubs are always randomly generated at obfuscation time, not hardcoded.
