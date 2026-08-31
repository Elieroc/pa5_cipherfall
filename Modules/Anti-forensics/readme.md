# Présentation des modules Anti-forensic:



### 1. renamer.py 
Objectif : Rendre les outils malveillants invisibles aux yeux des administrateurs.

Encodage et Obfuscation : Transforme les noms de fichiers en chaînes de caractères illisibles.

Falsification : Change l'extension du fichier (un script exécutable se déguise en simple fichier texte ou de configuration).

Furtivité : Transforme les outils en "fichiers cachés" au sein du système.
Risque métier : Permet à un attaquant de cacher ses logiciels de piratage ou les données qu'il s'apprête à voler.
Impact : Ralentit massivement le travail d'investigation de nos équipes en cas de cyberattaque.
Parade : Surveiller les opérations de renommages en masse dans les dossiers sensibles.

### 2. delayer.sh 
Objectif : Ralentir l'attaque pour passer sous les radars de nos systèmes de défense.

Injection : Modifie automatiquement un script d'attaque pour insérer des pauses entre chaque action.

Aléatoire : Fait varier la durée des pauses pour ne pas créer de motif robotique détectable.

Ciblage : Conçu spécifiquement pour étaler les scans réseau dans le temps (Low and Slow).
Risque métier : Empêche le déclenchement de nos alertes de sécurité basées sur le volume (comme la détection de scans ou les pics de trafic).
Impact : Une attaque normalement bruyante devient silencieuse et indétectable par nos sondes standards.
Parade : Configurer nos outils de surveillance pour corréler les comportements suspects sur de très longues périodes.

### 3. ghost-shell.sh 
Objectif : Offrir à l'attaquant un contrôle total de la machine sans laisser aucune trace.

Aveuglement : Désactive ou suspend activement nos agents de sécurité locaux (Auditd, Auditbeat).

Nettoyage chirurgical : Efface les traces de connexion (adresse IP, heure) dans les journaux système de la machine.

Usurpation : Déguise le terminal de l'attaquant pour qu'il ressemble à un processus légitime du système d'exploitation (kworker).
Risque métier : Permet des actions malveillantes en profondeur (vol de données, sabotage) en toute invisibilité.
Impact : Rupture complète de la chaîne de traçabilité locale ; l'attaquant devient un fantôme sur le serveur.
Parade : Exporter obligatoirement tous nos journaux de sécurité en temps réel vers un serveur centralisé (SIEM) hors de portée de l'attaquant.
