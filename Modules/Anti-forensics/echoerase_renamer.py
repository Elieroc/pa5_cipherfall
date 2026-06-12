#!/usr/bin/env python3
# =============================================================================
# EchoErase (renamer.py) — Renommage anti-forensique de fichiers par encodage base64
# Usage:
#   python3 renamer.py <fichier>                       → stem en base64 URL-safe
#   python3 renamer.py --view <fichier>                → affiche le nom d'origine
#   python3 renamer.py --no-recover <fichier>          → stem de 6 chars aléatoires
#   python3 renamer.py --ext <fichier>                 → extension aléatoire valide
#   python3 renamer.py --no-recover --ext <fichier>    → stem aléatoire + ext aléatoire
# =============================================================================
# Technique :
#   Mode par défaut : le stem du fichier (nom sans extension) est encodé en
#   base64 URL-safe (RFC 4648 §5) : utilise '-' et '_' à la place de '+' et '/',
#   sans padding '=' final — tous les caractères produits sont valides sur tout
#   système de fichiers Linux/POSIX. L'extension est préservée telle quelle.
#   Le décodage restaure le padding manquant avant d'appeler b64decode.
#
#   Mode --no-recover : génère un stem de 6 caractères alphanumériques
#   (a-z, A-Z, 0-9) tirés via os.urandom (CSPRNG). Irréversible.
#
#   Option --ext : remplace l'extension par une extension liée au type du fichier
#   d'origine, choisie aléatoirement via secrets.choice dans une table de familles.
#   Si l'extension d'origine n'est pas dans la table, une extension générique est
#   choisie (.tmp, .bak, .dat…). Combinable avec --no-recover. Incompatible avec
#   --view (qui n'effectue aucun renommage).
#
#   Exemples :
#     recon.sh      →  cmVjb24.sh            (défaut)
#     recon.sh      →  cmVjb24.bash          (défaut + --ext)
#     recon.sh      →  k9Xp2T.env            (--no-recover + --ext)
#     payload.py    →  cGF5bG9hZA.pyc        (défaut + --ext)
#
# Limitations :
#   Un stem déjà base64 URL-safe valide par coïncidence sera mal interprété par
#   --view. Le script ne tient pas de registre des fichiers renommés.
# =============================================================================

import argparse
import base64
import os
import secrets
import sys

_ALPHANUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

_EXT_FAMILIES: dict[str, list[str]] = {
    ".sh":    [".bash", ".bsh", ".env", ".rc", ".profile"],
    ".bash":  [".sh", ".bsh", ".env", ".rc"],
    ".py":    [".pyc", ".pyo", ".pyi"],
    ".pyc":   [".py", ".pyo", ".pyi"],
    ".js":    [".mjs", ".cjs", ".jsx"],
    ".ts":    [".mts", ".cts", ".tsx"],
    ".c":     [".h", ".cc", ".cpp", ".cxx"],
    ".cpp":   [".cc", ".cxx", ".h", ".hpp"],
    ".h":     [".hpp", ".hh", ".hxx"],
    ".go":    [".mod", ".sum"],
    ".rs":    [".toml"],
    ".rb":    [".rbx", ".rake"],
    ".pl":    [".pm", ".t"],
    ".php":   [".phtml", ".php5", ".php7"],
    ".java":  [".class", ".jar"],
    ".class": [".java", ".jar"],
    ".txt":   [".log", ".bak", ".tmp", ".dat", ".out"],
    ".log":   [".txt", ".bak", ".tmp", ".out"],
    ".conf":  [".cfg", ".ini", ".config", ".env", ".toml"],
    ".cfg":   [".conf", ".ini", ".config", ".toml"],
    ".ini":   [".conf", ".cfg", ".config"],
    ".json":  [".jsonc", ".json5", ".geojson"],
    ".yaml":  [".yml"],
    ".yml":   [".yaml"],
    ".xml":   [".xsl", ".xsd", ".xhtml", ".svg"],
    ".html":  [".htm", ".xhtml", ".shtml"],
    ".md":    [".markdown", ".rst", ".txt"],
    ".sql":   [".db", ".sqlite", ".sqlite3"],
    ".gz":    [".bz2", ".xz", ".zst", ".lz4"],
    ".bz2":   [".gz", ".xz", ".zst"],
    ".zip":   [".jar", ".war", ".ear", ".apk"],
    ".tar":   [".cpio", ".shar"],
    ".so":    [".o", ".a", ".dylib"],
    ".exe":   [".dll", ".sys", ".com"],
    ".bin":   [".dat", ".raw", ".img"],
    ".pem":   [".crt", ".key", ".cer", ".der"],
    ".crt":   [".pem", ".cer", ".der"],
    ".key":   [".pem", ".ppk", ".priv"],
}

_GENERIC_EXTS = [".tmp", ".bak", ".dat", ".log", ".cache", ".out", ".swp"]


def encode_stem(stem: str) -> str:
    return base64.urlsafe_b64encode(stem.encode()).decode().rstrip("=")


def decode_stem(encoded: str) -> str:
    padding = (4 - len(encoded) % 4) % 4
    return base64.urlsafe_b64decode((encoded + "=" * padding).encode()).decode()


def random_stem(length: int = 6) -> str:
    return "".join(_ALPHANUM[b % len(_ALPHANUM)] for b in os.urandom(length))


def random_ext(original_ext: str) -> str:
    candidates = _EXT_FAMILIES.get(original_ext.lower(), _GENERIC_EXTS)
    return secrets.choice(candidates)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="renamer.py",
        description="Anti-forensic file renamer via base64 URL-safe encoding.",
        add_help=True,
    )
    parser.add_argument("file", help="Fichier cible")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--view",
        action="store_true",
        help="Décode et affiche le nom d'origine sans renommer le fichier",
    )
    group.add_argument(
        "--no-recover",
        action="store_true",
        help="Renomme avec 6 caractères alphanumériques aléatoires (irréversible)",
    )
    parser.add_argument(
        "--ext",
        action="store_true",
        help="Remplace l'extension par une extension liée au type du fichier (aléatoire)",
    )
    args = parser.parse_args()

    if args.ext and args.view:
        parser.error("--ext ne peut pas être utilisé avec --view")

    path = args.file

    if not os.path.exists(path):
        print(f"Erreur : '{path}' introuvable.", file=sys.stderr)
        sys.exit(1)

    directory = os.path.dirname(os.path.abspath(path))
    basename = os.path.basename(path)
    stem, ext = os.path.splitext(basename)

    if args.view:
        try:
            original_stem = decode_stem(stem)
            print(original_stem + ext)
        except Exception:
            print(f"Erreur : le stem '{stem}' n'est pas un base64 URL-safe valide.", file=sys.stderr)
            sys.exit(1)
        return

    new_ext = random_ext(ext) if args.ext else ext
    new_stem = random_stem() if args.no_recover else encode_stem(stem)
    new_name = new_stem + new_ext
    new_path = os.path.join(directory, new_name)
    os.rename(path, new_path)
    print(f"{basename}  →  {new_name}")


if __name__ == "__main__":
    main()
