# netdiscover.sh — Reconnaissance réseau furtive orientée pivoting

Script bash de reconnaissance réseau complet : découverte L2/ICMP, recherche de sous-réseaux, scan de ports sensibles (double méthode), vérification automatique des services, et récapitulatif final par IP.

Conçu pour être couplé dans un autre script — **aucune option requise**, aucune interaction.

> ⚠️ **Doit être lancé en root/sudo.** `nmap` est une dépendance obligatoire.

---

## Fonctionnalités

### 1 — Découverte L2 (ARP) + Ping sweep

- **Scan ARP** pour détecter les hôtes présents à la couche 2 (adresse MAC)
  - Utilise `arp-scan` s'il est disponible (scan ARP raw natif)
  - Sinon : provoque la résolution ARP via tentatives TCP (fonctionne même sur les hôtes qui filtrent l'ICMP)
- **Ping sweep ICMP** en parallèle sur toute la plage
- **Tableau comparatif** : met en évidence les hôtes visibles en L2 mais silencieux au ping → machines firewallées

### 2 — Découverte d'autres sous-réseaux

- Table de routage complète (`ip route`)
- Sous-réseaux directement routés hors du réseau courant
- Voisins ARP appartenant à d'autres réseaux (cache noyau)
- Traceroute vers la passerelle → révèle les routeurs intermédiaires

### 3 — Scan de ports sensibles (double méthode)

#### 3a — Scan nmap de masse (SYN furtif)
Scan simultané de tous les hôtes découverts sur les ports pivoting :
```
nmap -sS -T2 --min-rate 50 --randomize-hosts -p PORTS <hotes>
```

#### 3b — Scan custom IP-by-IP
Scan individuel de chaque hôte sur les mêmes ports.
Peut détecter des ports manqués par le scan de masse (certains IDS/firewalls
ne déclenchent qu'au-dessus d'un seuil de ports simultanés).
Seuls les résultats **supplémentaires** (non détectés par le scan de masse) sont affichés.

**Ports scannés (23 ports pivoting) :**

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 1433 | MSSQL |
| 22 | SSH | 2049 | NFS |
| 23 | Telnet | 3306 | MySQL / MariaDB |
| 53 | DNS | 3389 | RDP |
| 80 | HTTP | 5432 | PostgreSQL |
| 139 | NetBIOS-SMB | 5672 | RabbitMQ |
| 389 | LDAP | 5900 | VNC |
| 443 | HTTPS | 6379 | Redis |
| 445 | SMB | 8080 / 8443 | HTTP alt |
| 9042 | Cassandra | 9092 | Kafka |
| 9200 | Elasticsearch | 11211 | Memcached |
| 27017 | MongoDB | | |

### 4 — Récapitulatif des ports ouverts

Tableau synthétique : une ligne par IP avec tous ses ports ouverts (résultats nmap + custom fusionnés) :
```
  192.168.1.1   : 22/SSH  80/HTTP  445/SMB  3306/MySQL
  192.168.1.50  : 22/SSH  5432/PostgreSQL  27017/MongoDB
```

### 5 — Vérification automatique des services

Pour chaque hôte découvert, lance un scan `nmap -sV -O` + scripts NSE ciblés sur ses ports ouverts uniquement, puis des checks complémentaires en bash/curl.

| Service | Ce qui est vérifié |
|---------|-------------------|
| **OS** | Fingerprinting (`-O --osscan-guess`) |
| **SSH** | Version exacte, SSH host key (fingerprint ECDSA/ED25519) |
| **FTP** | Login anonyme autorisé (`ftp-anon`) |
| **DNS** | Récursion ouverte (`dns-recursion`) |
| **SMB** | Partages anonymes, signing désactivé, **EternalBlue** (`smb-vuln-ms17-010`) |
| **LDAP** | rootDSE accessible sans auth (`ldap-rootdse`) |
| **MSSQL** | Informations serveur, password vide (`ms-sql-empty-password`) |
| **NFS** | Exports listables sans auth (`nfs-showmount`, `nfs-ls`) |
| **MySQL / MariaDB** | Informations serveur, connexion sans mot de passe (`mysql-empty-password`) |
| **PostgreSQL** | Tentative de connexion avec creds par défaut (`postgres/postgres`) |
| **RDP** | Niveau de chiffrement (`rdp-enum-encryption`) |
| **VNC** | Version, authentification requise ou non (`vnc-info`) |
| **Redis** | `PING` sans auth → si positif : `INFO server` (version, OS, port) |
| **Elasticsearch** | GET `/` sans auth → cluster name, version, **liste des index** |
| **MongoDB** | Accès sans auth + liste des bases de données (`mongodb-databases`) |
| **Memcached** | Commande `stats` sans auth → infos serveur |
| **RabbitMQ** | Management UI sur port 15672 avec `guest:guest` |
| **S3 / MinIO** | Endpoint S3-compatible (ports 9000/9001), **liste des buckets** si public |
| **Git natif** | Protocole git sur port 9418 |
| **Git HTTP/S** | `/.git/HEAD` exposé, détection GitLab / Gitea / Gogs / GitHub Enterprise |

---

## Technologies utilisées

| Outil | Obligatoire | Rôle |
|-------|-------------|------|
| `bash` ≥ 4 | ✅ | Shell, `/dev/tcp` pour checks bidirectionnels |
| `nmap` | ✅ | Scan SYN furtif, NSE scripts, OS/version detection |
| `ip` | ✅ | Détection interface, routes, cache ARP |
| `ping` | ✅ | Ping sweep ICMP |
| `awk`, `sort`, `mktemp` | ✅ | Traitement texte, parsing nmap |
| `curl` | ❌ opt | Checks HTTP (Git, S3, Elasticsearch) — fallback `/dev/tcp` sinon |
| `nc` (netcat) | ❌ opt | Checks TCP (Redis, Memcached) — fallback `/dev/tcp` sinon |
| `arp-scan` | ❌ opt | Scan ARP raw natif (meilleur que TCP provoke) |
| `traceroute` | ❌ opt | Découverte de routeurs intermédiaires |

---

## Prérequis & installation

### Obligatoires

```bash
sudo apt install nmap        # Debian / Ubuntu
sudo yum install nmap        # RedHat / CentOS
apk add nmap                 # Alpine
```

### Recommandés (amélioration des checks)

```bash
sudo apt install curl netcat-openbsd arp-scan traceroute
```

### Mise en place du script

```bash
chmod +x netdiscover.sh

# Optionnel : accessible depuis partout
sudo cp netdiscover.sh /usr/local/bin/
```

---

## Usage

### Lancement standard (aucune option)

```bash
sudo ./netdiscover.sh
```

Détecte automatiquement l'interface et le réseau, puis enchaîne les 5 phases sans aucune interaction.

### Options disponibles

```
sudo ./netdiscover.sh [options]

  -i IFACE    Interface réseau (défaut : détection automatique)
  -n CIDR     Réseau cible, ex: 10.0.0.0/24 (défaut : auto)
  -h          Affiche l'aide
```

### Exemples

```bash
# Réseau auto-détecté
sudo ./netdiscover.sh

# Réseau spécifique sur une interface précise
sudo ./netdiscover.sh -n 10.10.10.0/24 -i eth1

# Couplé dans un autre script
output=$(sudo /path/to/netdiscover.sh 2>&1)
echo "$output" | grep "ELASTICSEARCH sans auth"
echo "$output" | grep "REDIS sans auth"
echo "$output" | grep "mongodb-databases"
```

---

## Détails techniques

### ARP Discovery

#### Avec `arp-scan`
Envoie des requêtes ARP broadcast raw à la couche 2.
Détecte **tous** les hôtes présents, même ceux qui filtrent l'ICMP (firewalls).

#### Sans `arp-scan` (fallback)
Tente une connexion TCP sur les ports 80/443/22/445 de chaque IP.
Le noyau Linux doit résoudre le MAC (ARP) **avant** d'envoyer le SYN,
indépendamment de la réponse de l'hôte. Les MACs apparaissent ensuite dans `ip neigh`.

### SSH Host Key

La clé d'hôte SSH est l'identité cryptographique unique d'un serveur.
Nmap la remonte via le script `ssh-hostkey` :

```
22/tcp open  ssh    OpenSSH 9.2p1 Debian
| ssh-hostkey:
|   256 a02adbfa68f60c0c0ca069826e17b033 (ECDSA)
|_  256 56ee4673ccf8655a640de5bb1952444e (ED25519)
```

**Utilité en pentest :**
- **Identifier une machine de manière unique** même si elle change d'IP
- **Détecter des VMs clonées** depuis la même image (même fingerprint = clé non regénérée)
- **Corréler entre réseaux** : même fingerprint trouvée sur deux sous-réseaux différents = même machine accessible depuis deux segments
- **Confirmer la version SSH** pour rechercher des CVE associées

### Scan SYN furtif

```bash
nmap -sS -T2 --min-rate 50 --randomize-hosts -p <ports> <hotes>
```

- `-sS` : SYN scan — envoie un SYN, lit la réponse (SYN-ACK = ouvert, RST = fermé), ne complète jamais la connexion TCP → non loggé par les services applicatifs
- `-T2` : timing "Polite" — lent, réduit le bruit réseau
- `--min-rate 50` : maximum 50 paquets/seconde
- `--randomize-hosts` : ordre aléatoire des cibles

### Scan custom IP-by-IP

Même ports, même flags nmap, mais lancé individuellement par hôte.
Certains IDS/firewalls ne déclenchent que sur les scans de masse (seuil de connexions simultanées).
Un scan IP par IP peut passer sous le radar dans ces cas.
Seuls les ports trouvés **en plus** du scan de masse sont reportés.

### Vérification des services sans creds

Plusieurs services sont souvent déployés sans authentification :

| Service | Vecteur de check |
|---------|-----------------|
| Redis | `PING` TCP → `+PONG` = pas d'auth |
| Elasticsearch | `GET /` HTTP → JSON avec `cluster_name` = pas d'auth |
| MongoDB | NSE `mongodb-databases` → liste DB = pas d'auth |
| Memcached | `stats` TCP → réponse STAT = pas d'auth |
| FTP | NSE `ftp-anon` → login `anonymous:anonymous` |
| MySQL | NSE `mysql-empty-password` → connexion root sans password |
| RabbitMQ | `GET /api/overview` avec `guest:guest` |

---

## Exemples d'output

```
=== Recapitulatif des ports ouverts ===
  192.168.1.1   : 22/SSH  53/DNS  80/HTTP  443/HTTPS
  192.168.1.50  : 22/SSH  3306/MySQL  27017/MongoDB
  192.168.1.100 : 22/SSH  445/SMB  6379/Redis

=== Verification des services ===

┌─[ 192.168.1.100 ]
  22/tcp  open  ssh    OpenSSH 9.2p1 Debian
  445/tcp open  smb    Samba 4.x
  | smb-enum-shares:
  |   SHARE  backup  READ, WRITE  <- partage accessible !
  6379/tcp open  redis  Redis 7.0.5
  [!] REDIS sans auth !
    redis_version:7.0.5
    os:Linux 5.15.0 x86_64
    tcp_port:6379

┌─[ 192.168.1.50 ]
  27017/tcp open  mongodb  MongoDB 6.0
  | mongodb-databases:
  |   databases: admin, config, local, users_prod
  [!] MONGODB sans auth ! Bases accessibles.
```

---

## Troubleshooting

### "Doit etre lance en root/sudo"
```bash
sudo ./netdiscover.sh
```

### "nmap obligatoire"
```bash
sudo apt install nmap
```

### Aucun hôte trouvé
```bash
# Vérifier l'interface et la route
ip addr show
ip route show

# Forcer le réseau manuellement
sudo ./netdiscover.sh -n 192.168.1.0/24 -i eth0
```

### Scan de services très lent
Les checks de services relancent nmap par IP avec `-sV -O` et les scripts NSE.
Sur de grandes plages avec beaucoup d'hôtes, c'est normal que ça prenne du temps.

---

## Notes de sécurité

Ce script est fourni à titre éducatif et pour les tests réseau internes autorisés.

⚠️ **Utilisation responsable** : ne scanner que des réseaux sur lesquels tu as une autorisation explicite. Les scans de ports non-autorisés sont illégaux dans de nombreuses juridictions.
