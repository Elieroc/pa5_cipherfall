# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

Cipherfall is an ESGI annual project simulating the reconstruction of an APT's tooling arsenal. The modules cover the three core phases: reconnaissance, obfuscation, and anti-forensics. All code is for authorized security research and educational purposes.

## Module execution

```bash
# Recon — single semicolon-delimited output line
bash Modules/Recon/recon.sh

# Obfuscate a bash script (level 1=base64, 2=base64+gzip, 3=multi-layer; default 2)
bash Modules/Obfuscator/obfuscator.sh <script.sh> [1|2|3]

# Obfuscate bash with advanced technique (ROT13+chunks+random vars+decoys)
bash Modules/Obfuscator/obfuscator_v2.sh <script.sh>

# Obfuscate a Python script (same technique as obfuscator_v2 but for .py)
python3 Modules/Obfuscator/obfuscator_py.py <script.py>

# Anti-forensics: ghost shell (root recommended for full coverage)
sudo bash Modules/Anti-forensics/ghost-shell.sh

# Anti-forensics: add randomized sleep delays between lines of a script
bash Modules/Anti-forensics/delayer.sh <script.sh> <fixed_delay_s> <jitter_s>
```

Obfuscators write output to `<input_basename>_obfuscated.sh` / `<input_basename>_obfv2.sh` / `<input_basename>_obf.py` in the same directory as the input file.

## Architecture

The modules are designed to be used in pipeline: write a recon/payload script → obfuscate it → deploy under ghost-shell cover.

**Recon** (`recon.sh`): Collects system fingerprint data using only built-in tools and standard binaries (`testparm`, `aws`, `psql`, `mongosh`, `gitlab-rake`, etc.). Falls back gracefully to `N/A` for each unavailable data source. Output is always exactly one line: `Distro;Version;Kernel;SMB_Shares;NFS_Exports;S3_Buckets;MariaDB_DBs;PostgreSQL_DBs;MongoDB_DBs;GitLab_Version`.

**Obfuscator** (`obfuscator_v2.sh`, `obfuscator_py.py`): The v2 technique stacks gzip → base64 → ROT13, then splits into variable-size chunks, shuffles chunk definition order (Fisher-Yates), encodes all command names in hex (`$'\x..'`) or chr() sequences, and injects decoy variables using pool values from a hardcoded fake-pool. The final stub never contains any readable string like `eval`, `base64`, or `gunzip`.

**Anti-forensics — ghost-shell** (`ghost-shell.sh`): Operates in five sequential phases: (1) blackout kernel auditing (`auditctl -e 0`) and stop auditbeat before generating any artifacts; (2) erase utmp/wtmp entries for the current TTY via `utmpdump -r`; (3) zero lastlog entry for the current UID via `dd` seeking to `uid * 292` bytes; (4) clean environment variables (SSH_*, SUDO_*, terminal fingerprints); (5) exec a shell spoofed as `[kworker/u:0]` via `exec -a`. A `trap EXIT` restores audit rules on session close. Known limitation: `/proc/<PID>/exe` still points to the real bash binary.

**Anti-forensics — delayer** (`delayer.sh`): Reads a script line-by-line and injects `sleep <N>` after each substantive line, skipping comments, blank lines, backslash continuations, pipe continuations, and shell control keywords. Delay is randomized with awk using nanosecond seeding.

## Coding conventions

- Each file starts with a detailed header block explaining what the module does, all techniques used, and known limitations (see existing files as reference).
- No inline or explanatory comments anywhere else in the code — only the header.
- When adding a new module, test it before reporting it complete; if a live test is not possible, explicitly say so.
- Variable names in obfuscated stubs are always randomly generated at obfuscation time, not hardcoded.
