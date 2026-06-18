# Cipherfall

**Cipherfall** est un projet annuel ESGI simulant la reconstruction de l'arsenal complet d'un groupe APT (*Advanced Persistent Threat*). Chaque module couvre une phase distincte du cycle d'attaque, de la reconnaissance initiale à l'effacement des traces, en passant par la persistance et le contrôle à distance.

L'objectif est académique et défensif : comprendre les techniques offensives réelles pour mieux concevoir les détections et les contre-mesures.

> Tout le code est destiné à la recherche en sécurité autorisée et à des fins éducatives.

---

## Arsenal

| Nom | Catégorie | Fichier | Description | Fonctionnalités principales |
|---|---|---|---|---|
| **Phantom Eye** | Reconnaissance | `phantom_eye.sh` | Collecte passive d'empreinte système sur la cible | Distro/kernel, partages SMB/NFS, buckets S3, bases de données (MariaDB, PostgreSQL, MongoDB), version GitLab — sortie sur une ligne CSV |
| **ShadowScript** | Obfuscation | `shadowscript.sh` / `shadowscript.py` | Obfuscateur multi-couches pour scripts Bash et Python | Compression gzip → base64 → ROT13, découpage en chunks d'ordre aléatoire (Fisher-Yates), encodage hex des commandes, injection de variables leurres |
| **NullRelay** | C2 Cloudflare | `cloudflare-worker/nullrelay.py` | Agent C2 discret via Cloudflare Worker comme dead-drop | Beacon HTTPS vers Cloudflare KV, chiffrement AES-256-GCM, authentification HMAC-SHA256, exécution de commandes shell et exfiltration de fichiers (`UPLOAD:`) |
| **ClockVenom** | C2 NTP | `ntp/clockvenom.py` | Agent C2 dissimulé dans le trafic NTP légitime | Beacon UDP/123 (fallback TCP/443), extension NTS Cookie RFC 8915, chiffrement AES-256-GCM + zlib, résolution DNS redirigée par IronVeil |
| **ShadowDrop** | Dropper | `shadowdrop_bin.py` / `shadowdrop_sh.py` / `shadowdrop_py.py` | Exécution fileless de payloads via `memfd_create` | Téléchargement sans écriture disque, exécution directe depuis un fd mémoire, support binaires ELF / scripts Bash / scripts Python, mode daemon double-fork |
| **PhantomPage** | Phishing | `deviceflowbypass2fa/phantompage.py` | Bypass 2FA Microsoft via OAuth device authorization flow | Proxy du flow device Microsoft, capture de tokens access + refresh, page de phishing Outlook, `offline_access` pour tokens longue durée |
| **IronVeil** | Rootkit LKM | `ironveil.c` | Rootkit noyau Linux injectant et dissimulant le C2 NTP | Injection `/etc/hosts` (redirect NTP → C2), hook `read()` filtrant les entrées C2, masquage fichiers/PIDs, self-hide `lsmod`, interface `/proc/rootkit_ctrl` |
| **EchoErase** | Anti-forensics | `echoerase_ghost.sh` / `echoerase_delayer.sh` / `echoerase_renamer.py` | Suite d'outils d'effacement des traces opérationnelles | Ghost shell (utmp/wtmp, lastlog, auditd, env scrub), injection de délais aléatoires entre commandes, renommage de fichiers (base64 réversible ou CSPRNG irréversible) |

### Modules Privesc

Les modules de privilege escalation n'ont pas de nom de malware — ce sont des exploits de CVE spécifiques :

| Exploit | Fichier | Cible |
|---|---|---|
| CopyFail | `copyfail.py` | AF_ALG + KTLS splice — écrasement /bin/su (Python ≥ 3.10) |
| DirtyFrag | `dirtyfrag/exp` | CVE — fragmentation mémoire |
| ssh-keysign PWN | `ssh-keysign-pwn/sshkeysign_pwn` | Abus du binaire SUID `ssh-keysign` |
| Fragnesia | `fragnesia.sh` | CVE-2026-46300 — wrapper namespace user+network |

---

## Kill Chain

```
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                          CIPHERFALL — Kill Chain                            │
  └─────────────────────────────────────────────────────────────────────────────┘

  ① RECONNAISSANCE          ② OBFUSCATION             ③ DELIVERY
  ┌──────────────┐          ┌───────────────┐          ┌──────────────────┐
  │ Phantom Eye  │          │  ShadowScript │          │  PhantomPage     │
  │              │          │               │          │                  │
  │ Collecte :   │          │ Obfusque :    │          │ Phishing :       │
  │ - distro     │    ┌────►│ - payload     │          │ - device flow    │
  │ - services   │    │     │ - agent C2    │          │ - token capture  │
  │ - databases  │    │     │   (NullRelay/ │          └────────┬─────────┘
  │ - cloud      │    │     │    ClockVenom)│                   │
  └──────┬───────┘    │     └───────────────┘                   │ accès initial
         │            │                                          │
         │ empreinte  │ payload prêt                             ▼
         ▼            │
  ④ EXECUTION / DROP  │         ┌──────────────────────────────────────────┐
  ┌──────────────┐    │         │                 CIBLE                    │
  │  ShadowDrop  │────┘         │                                          │
  │              │              │  ┌────────────┐     ┌──────────────────┐ │
  │ fileless :   │─────────────►│  │  IronVeil  │     │   NullRelay /    │ │
  │ memfd_create │              │  │  (rootkit) │     │   ClockVenom     │ │
  └──────────────┘              │  │            │     │   (agent C2)     │ │
                                │  │ - /hosts   │     │                  │ │
  ⑤ PRIVILEGE ESCALATION        │  │ - self-hide│     │ - beacon         │ │
  ┌──────────────┐              │  │ - hide PID │     │ - shell exec     │ │
  │  DirtyFrag   │              │  └─────┬──────┘     │ - file upload    │ │
  │  ssh-keysign │─────────────►│        │ redirect   └──────────────────┘ │
  │  Fragnesia   │  root        │        │ DNS NTP                │         │
  └──────────────┘              └────────┼────────────────────────┼─────────┘
                                         │                        │
  ⑥ C2 (COMMAND & CONTROL)               │  UDP/123 ou TCP/443    │ HTTPS/443
  ┌───────────────────────────┐          │  (ClockVenom)          │ (NullRelay)
  │  Canal NTP                │◄─────────┘                        │
  │  ntp/server.py            │                                   │
  │  (VPS 87.106.187.97)      │     ┌─────────────────────┐       │
  │                           │     │  Canal Cloudflare   │◄──────┘
  │  Admin API :1338          │     │  server.py + KV     │
  └───────────┬───────────────┘     │                     │
              │                     │  Admin API :1337    │
              │                     └──────────┬──────────┘
              └──────────────┬─────────────────┘
                             │ operator_cli.py / tui.py
                             ▼
                    ┌─────────────────┐
                    │   OPÉRATEUR     │
                    └─────────────────┘

  ⑦ ANTI-FORENSICS
  ┌──────────────────────────────────────────────────────────┐
  │  EchoErase                                               │
  │                                                          │
  │  - ghost shell   : efface utmp/wtmp, lastlog, auditd     │
  │  - delayer       : bruite les timestamps shell           │
  │  - renamer       : obscurcit les noms de fichiers        │
  └──────────────────────────────────────────────────────────┘
```

### Flux complet (séquence opérationnelle)

```
1. Phantom Eye         → cartographie la cible (OS, services, cloud)
2. PhantomPage         → capture un token Microsoft via phishing
3. ShadowScript        → obfusque ClockVenom/NullRelay avant livraison
4. ShadowDrop          → dépose l'agent sur la cible sans toucher le disque
5. IronVeil            → chargé via privesc, redirige DNS NTP, se cache
6. ClockVenom          → beacon NTP vers le VPS C2, reçoit et exécute les tâches
7. DirtyFrag / others  → escalade vers root pour charger IronVeil
8. EchoErase           → efface les traces de l'opération
```

---

## Structure du projet

```
Modules/
├── Recon/
│   └── phantom_eye.sh
├── Obfuscator/
│   ├── shadowscript.sh
│   └── shadowscript.py
├── C2/
│   ├── tui.py                         ← dashboard commun
│   ├── operator_cli.py                ← CLI opérateur commun
│   ├── manual.md
│   ├── cloudflare-worker/
│   │   ├── nullrelay.py               ← agent Cloudflare
│   │   ├── server.py                  ← serveur Cloudflare
│   │   └── worker.js                  ← Cloudflare Worker dead-drop
│   └── ntp/
│       ├── clockvenom.py              ← agent NTP
│       └── server.py                  ← serveur NTP
├── Dropper/
│   ├── shadowdrop_bin.py
│   ├── shadowdrop_sh.py
│   └── shadowdrop_py.py
├── Phishing/
│   └── deviceflowbypass2fa/
│       └── phantompage.py
├── Rootkits/
│   ├── ironveil.c
│   ├── Makefile
│   └── manual.md
├── Privesc/
│   ├── dirtyfrag/
│   ├── ssh-keysign-pwn/
│   └── fragnesia.sh
└── Anti-forensics/
    ├── echoerase_ghost.sh
    ├── echoerase_delayer.sh
    └── echoerase_renamer.py
```

---

## Couverture MITRE ATT&CK

### Matrice de couverture

Les colonnes correspondent aux tactiques ATT&CK Enterprise couvertes par le projet.

| Module | Recon | Initial Access | Execution | Priv. Esc. | Defense Evasion | Credential Access | Discovery | C&C | Exfiltration |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Phantom Eye    | —  | —  | —  | —  | —  | —  | ✓  | —  | —  |
| ShadowScript   | —  | —  | —  | —  | ✓  | —  | —  | —  | —  |
| NullRelay      | —  | —  | —  | —  | ✓  | —  | —  | ✓  | ✓  |
| ClockVenom     | —  | —  | —  | —  | ✓  | —  | —  | ✓  | ✓  |
| ShadowDrop     | —  | —  | ✓  | —  | ✓  | —  | —  | —  | —  |
| PhantomPage    | —  | ✓  | —  | —  | —  | ✓  | —  | —  | —  |
| IronVeil       | —  | —  | —  | —  | ✓  | —  | —  | ✓  | —  |
| EchoErase      | —  | —  | —  | —  | ✓  | —  | —  | —  | —  |
| Privesc        | —  | —  | —  | ✓  | —  | —  | —  | —  | —  |

**Tactiques non couvertes :** Resource Development (TA0042), Persistence (TA0003), Lateral Movement (TA0008), Collection (TA0009), Impact (TA0040).

---

### Techniques par module

#### Phantom Eye — Discovery (TA0007)

| ID | Technique |
|---|---|
| T1082 | System Information Discovery |
| T1016 | System Network Configuration Discovery |
| T1049 | System Network Connections Discovery |
| T1526 | Cloud Service Discovery (buckets S3) |
| T1087.001 | Account Discovery: Local Account (users DB) |

#### ShadowScript — Defense Evasion (TA0005)

| ID | Technique |
|---|---|
| T1027 | Obfuscated Files or Information |
| T1027.010 | Command Obfuscation (encodage hex des commandes) |
| T1140 | Deobfuscate/Decode Files or Information (stub runtime) |

#### NullRelay — Command and Control (TA0011) + Exfiltration (TA0010)

| ID | Technique |
|---|---|
| T1071.001 | Application Layer Protocol: Web Protocols (HTTPS) |
| T1102.003 | Web Service: Bidirectional Communication (Cloudflare KV dead-drop) |
| T1573.001 | Encrypted Channel: Symmetric Cryptography (AES-256-GCM) |
| T1132.001 | Data Encoding: Standard Encoding (base64 wire format) |
| T1041 | Exfiltration Over C2 Channel (commande `UPLOAD:`) |

#### ClockVenom — Command and Control (TA0011) + Exfiltration (TA0010)

| ID | Technique |
|---|---|
| T1095 | Non-Application Layer Protocol (NTP UDP/123) |
| T1572 | Protocol Tunneling (NTP dans TCP/443 en fallback) |
| T1008 | Fallback Channels (UDP/123 → TCP/443) |
| T1573.001 | Encrypted Channel: Symmetric Cryptography (AES-256-GCM) |
| T1041 | Exfiltration Over C2 Channel (commande `UPLOAD:`) |

#### ShadowDrop — Execution (TA0002) + Defense Evasion (TA0005)

| ID | Technique |
|---|---|
| T1620 | Reflective Code Loading (`memfd_create`, jamais écrit sur disque) |
| T1059.004 | Command and Scripting Interpreter: Unix Shell |
| T1059.006 | Command and Scripting Interpreter: Python |

#### PhantomPage — Initial Access (TA0001) + Credential Access (TA0006)

| ID | Technique |
|---|---|
| T1566 | Phishing |
| T1528 | Steal Application Access Token (tokens OAuth Microsoft) |
| T1111 | Multi-Factor Authentication Interception (bypass device flow 2FA) |
| T1078 | Valid Accounts (utilisation des tokens capturés) |

#### IronVeil — Defense Evasion (TA0005) + Command and Control (TA0011)

| ID | Technique |
|---|---|
| T1014 | Rootkit (LKM, kretprobes) |
| T1564.001 | Hide Artifacts: Hidden Files and Directories (fichiers préfixe + runtime) |
| T1601.001 | Modify System Image: Patch System Image (hooks syscall via LKM) |
| T1565.001 | Data Manipulation: Stored Data Manipulation (injection `/etc/hosts`) |
| T1036.005 | Masquerading: Match Legitimate Name or Location (trafic NTP légitime) |
| T1070 | Indicator Removal (filtrage lecture `/etc/hosts` à la volée) |

#### EchoErase — Defense Evasion (TA0005)

| ID | Technique |
|---|---|
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs (utmp/wtmp, lastlog, auditd) |
| T1070.003 | Indicator Removal: Clear Command History |
| T1070.006 | Indicator Removal: Timestomp (délais aléatoires bruitent l'analyse temporelle) |
| T1036.005 | Masquerading: Match Legitimate Name or Location (ghost shell → `[kworker/u:0]`, renamer) |

#### Privesc — Privilege Escalation (TA0004)

| ID | Technique |
|---|---|
| T1068 | Exploitation for Privilege Escalation (DirtyFrag CVE, ssh-keysign) |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid (`ssh-keysign` SUID) |
| T1611 | Escape to Host (Fragnesia — namespace user+network) |

---

### Récapitulatif chiffré

| Métrique | Valeur |
|---|---|
| Tactiques couvertes | 7 / 14 |
| Techniques uniques | 28 |
| Modules offensifs | 9 |

## Ressources
Voici différents articles qui nous ont aidé dans nos recherches pour le projet :
- [Cloudflare Worker C2](https://cgomezsec.com/blog/securing-c2-for-rt-operations-using-cloudflare)
- [NTP C2](https://github.com/d3adzo/mesa)
- [Rootkit](https://github.com/MatheuZSecurity/Singularity)
- [Dropper](https://en.wikipedia.org/wiki/Dropper_(malware))
- [Obfuscation](https://any.run/cybersecurity-blog/6-common-obfuscation-methods-in-malware/)
- [Phishing](https://www.it-connect.fr/microsoft-365-le-kit-de-phishing-kali365-pirate-les-comptes-sans-voler-les-mots-de-passe/)
- [Privesc](https://www.it-connect.fr/dirty-frag-cette-faille-zero-day-donne-les-droits-root-sur-linux/)

## Coûts

### R&D

Les estimations sont approximatives : une partie des techniques était déjà connue avant le projet, d'autres ont nécessité de la recherche spécifique, certaines ont été inventées pour coller aux contraintes (ex. NTP C2 sous 203 octets).

| Poste | Détail | Heures | Taux | Coût |
|---|---|---:|---:|---:|
| Recherche et veille | CVE, protocoles, techniques ATT&CK, outils existants | 20 h | 100 €/h | **2 000 €** |

---

### Développement

Estimé à partir de l'analyse des commits GitHub, du volume de code par module (~6 400 lignes) et du temps de test en conditions réelles (VPS + VM Debian). L'abonnement Claude est inclus car l'IA a contribué au développement.

| Poste | Détail | Heures | Taux | Coût |
|---|---|---:|---:|---:|
| Développement | 9 modules offensifs + TUI + documentation | 175 h | 143 €/h | **25 000 €** |
| Outillage IA | Abonnement Claude (3 mois) | — | — | **33 €** |

Répartition estimée par module :

| Module | Complexité | Heures estimées |
|---|---|---:|
| IronVeil (rootkit LKM) | ★★★★★ | ~35 h |
| NullRelay (C2 Cloudflare) | ★★★★ | ~25 h |
| ClockVenom (C2 NTP) | ★★★★ | ~22 h |
| ShadowScript (obfuscateur) | ★★★ | ~12 h |
| EchoErase (anti-forensics) | ★★★ | ~13 h |
| TUI + operator_cli | ★★★ | ~10 h |
| Privesc (3 exploits) | ★★★ | ~15 h |
| PhantomPage (phishing) | ★★★ | ~7 h |
| ShadowDrop (dropper) | ★★ | ~5 h |
| Phantom Eye (recon) | ★★ | ~5 h |
| Documentation + déploiement | ★ | ~16 h |
| **Total** | | **~175 h** |

---

### Infrastructure

Le projet privilégie l'infrastructure publique et gratuite (Cloudflare, Let's Encrypt) pour minimiser les coûts et l'exposition. Seuls le VPS du C2 et le nom de domaine phishing engendrent des coûts réels.

| Composant | Usage | Fournisseur | Coût annuel |
|---|---|---|---:|
| VPS Linux (IP publique, root) | ClockVenom — serveur NTP C2 + hébergement payloads | Hetzner / OVH | ~60 €/an |
| Cloudflare Workers + KV | NullRelay — dead-drop C2 | Cloudflare | ~60 €/an *(Workers Paid, 5 €/mois)* |
| Nom de domaine | PhantomPage — crédibilité phishing | OVH / Namecheap | ~12 €/an |
| Certificat SSL | PhantomPage — HTTPS | Let's Encrypt | **0 €** |
| **Total infrastructure** | | | **~132 €/an** |

> Le free tier Cloudflare Workers (100 000 requêtes/jour, 100 000 lectures KV/jour) peut suffire pour un usage ponctuel ou en phase de test. L'abonnement Workers Paid à 5 €/mois permet d'être plus à l'aise sur le volume de requêtes lors d'opérations prolongées avec de nombreux agents actifs.

---

### Récapitulatif et prix de vente

| Poste | Coût |
|---|---:|
| R&D | 2 000 € |
| Développement | 25 033 € |
| Infrastructure (1 an) | 132 € |
| **Coût total projet** | **~27 165 €** |

En tenant compte des coûts totaux, des taxes et d'une marge commerciale raisonnable, le prix de vente estimé du produit est de **30 000 €**.

> L'infrastructure représente moins de 0,3 % du coût total — l'essentiel de la valeur est dans l'expertise et le développement.