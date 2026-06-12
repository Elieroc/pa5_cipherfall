#!/usr/bin/env python3
# =============================================================================
# ShadowScript (obfuscator_py.py) — Obfuscateur Python avancé (technique unique combinée)
# Usage: ./obfuscator_py.py <script.py>
# Techniques :
#   1. Payload   : zlib + base64 + ROT13 (substitution sur l'alphabet base64)
#   2. Chunks    : découpage variable du payload, définition en ordre mélangé
#   3. Noms      : variables aléatoires pour le payload, les commandes, les leurres
#   4. Strings   : toutes les strings critiques encodées en chr() join
#   5. exec      : reconstruit via getattr(__import__('builtins'), chr_seq)
#   6. tr args   : charset ROT13 encodés en chr() join (jamais en clair)
#   7. Leurres   : variables garbage dispersées dans le stub
# =============================================================================

import sys
import os
import zlib
import base64
import random
import string

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <script.py>")
    sys.exit(1)

INPUT = sys.argv[1]
if not os.path.isfile(INPUT):
    print(f"Erreur: fichier '{INPUT}' introuvable.")
    sys.exit(1)

OUTPUT = (INPUT[:-3] if INPUT.endswith('.py') else INPUT) + '_obf.py'


# ── Générateur de nom de variable (préfixe _, 5-12 chars aléatoires) ──────────
def rand_var() -> str:
    length = random.randint(5, 12)
    return '_' + ''.join(random.choice(string.ascii_letters) for _ in range(length))


# ── Encodage chr() : "zlib" → ''.join(chr(c)for c in[122,108,105,98]) ─────────
def to_chr(s: str) -> str:
    codes = ','.join(str(ord(c)) for c in s)
    return f"''.join(chr(c)for c in[{codes}])"


# ── Variables leurres (garbage base64-like pour brouiller l'analyse) ──────────
_FAKE_POOL = [
    'dGhpcyBpcyBub3QgdGhlIHBheWxvYWQ=',
    'aGVsbG8gd29ybGQ=',
    'Zm9vYmFyYmF6',
    'bm90aGluZyBoZXJl',
    'cmFuZG9tIGRhdGE=',
    'c2VjcmV0IGtleQ==',
    'cGxhY2Vob2xkZXI=',
]

def gen_fakes(n: int = 3) -> list[str]:
    lines = []
    for _ in range(n):
        vname = rand_var()
        fake  = random.choice(_FAKE_POOL)
        start = random.randint(0, 4)
        end   = start + random.randint(8, min(16, len(fake) - start))
        lines.append(f"{vname} = '{fake[start:end]}'")
    return lines


# ── Étape 1 : zlib + base64 + ROT13 ──────────────────────────────────────────
with open(INPUT, 'rb') as f:
    source = f.read()

compressed = zlib.compress(source, level=9)
b64 = base64.b64encode(compressed).decode('ascii')

_upper  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
_lower  = 'abcdefghijklmnopqrstuvwxyz'
rot_fwd = _upper + _lower
rot_rev = _upper[13:] + _upper[:13] + _lower[13:] + _lower[:13]
payload = b64.translate(str.maketrans(rot_fwd, rot_rev))


# ── Étape 2 : découpage en chunks (taille 15-40 chars) ────────────────────────
chunk_size = random.randint(15, 40)
chunks  = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
vnames  = [rand_var() for _ in chunks]
nchunks = len(chunks)


# ── Étape 3 : noms aléatoires pour les commandes clés ─────────────────────────
v_pay     = rand_var()
v_rot_fwd = rand_var()
v_rot_rev = rand_var()
v_exec    = rand_var()


# ── Étape 4 : encodage des strings critiques en chr() ─────────────────────────
e_zlib      = to_chr('zlib')
e_base64    = to_chr('base64')
e_builtins  = to_chr('builtins')
e_decomp    = to_chr('decompress')
e_b64dec    = to_chr('b64decode')
e_exec      = to_chr('exec')
e_decode    = to_chr('decode')
e_maketrans = to_chr('maketrans')
e_translate = to_chr('translate')
e_rot_fwd   = to_chr(rot_fwd)
e_rot_rev   = to_chr(rot_rev)


# ── Étape 5 : mélange Fisher-Yates sur les indices des chunks ─────────────────
indices = list(range(nchunks))
random.shuffle(indices)


# ── Étape 6 : construction du stub ───────────────────────────────────────────
lines: list[str] = []
lines.append('#!/usr/bin/env python3')

lines.extend(gen_fakes(random.randint(2, 4)))

# exec function reference — jamais en clair
lines.append(f"{v_exec}=getattr(__import__({e_builtins}),{e_exec})")

lines.extend(gen_fakes(random.randint(1, 3)))

# ROT13 charsets encodés
lines.append(f"{v_rot_fwd}={e_rot_fwd}")
lines.append(f"{v_rot_rev}={e_rot_rev}")

lines.extend(gen_fakes(random.randint(1, 3)))

# Chunks en ordre mélangé
for j in indices:
    lines.append(f"{vnames[j]}='{chunks[j]}'")

lines.extend(gen_fakes(random.randint(1, 3)))

# Reconstruction du payload dans l'ordre original
lines.append(f"{v_pay}={'+'.join(vnames)}")

# Ligne d'exécution (aucune string critique en clair) :
# exec(
#   zlib.decompress(
#     base64.b64decode(
#       payload.translate(str.maketrans(rot_fwd, rot_rev))
#     )
#   ).decode()
# )
exec_line = (
    f"{v_exec}("
    f"getattr(__import__({e_zlib}),{e_decomp})("
    f"getattr(__import__({e_base64}),{e_b64dec})("
    f"getattr({v_pay},{e_translate})(getattr(str,{e_maketrans})({v_rot_fwd},{v_rot_rev}))"
    f")).decode())"
)
lines.append(exec_line)


# ── Écriture du stub ──────────────────────────────────────────────────────────
with open(OUTPUT, 'w') as f:
    f.write('\n'.join(lines) + '\n')

os.chmod(OUTPUT, 0o755)

size_in  = os.path.getsize(INPUT)
size_out = os.path.getsize(OUTPUT)
print(f"\n\033[0;32m✓ Obfuscation terminée\033[0m : {OUTPUT}")
print(f"  Original  : {size_in} octets")
print(f"  Obfusqué  : {size_out} octets")
print(f"  Chunks    : {nchunks}  (taille ~{chunk_size} chars)")
