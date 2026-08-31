Présentation des modules Recon

1. netdiscover.sh (Cartographie Réseau Interne)
Objectif : Découvrir les autres machines et services vulnérables sur notre réseau depuis un poste déjà compromis.

Reconnaissance : Identifie discrètement les équipements actifs autour de lui (via des requêtes ARP et Ping).

Ciblage : Scanne spécifiquement les ports critiques (bases de données, partages de fichiers, accès à distance).

Audit automatique : Cherche immédiatement si ces services sont mal configurés ou accessibles sans mot de passe.
Risque métier : C'est l'outil classique pour le "mouvement latéral", permettant de rebondir d'un poste non critique vers nos serveurs.
Impact : L'attaquant obtient une carte détaillée de nos angles morts internes en quelques secondes.
Parade : Segmenter strictement nos réseaux internes (Cloisonnement/Zero Trust) et déployer des alertes sur les balayages de ports internes.

2. recon.sh (Inventaire Ciblé des Données)
Objectif : Dresser un inventaire instantané des cibles de grande valeur sur le serveur infiltré.

Profilage : Récupère la version exacte du système pour identifier d'éventuelles failles connues.

Fouille : Localise immédiatement tous les dossiers partagés sur le réseau (SMB, NFS) et les accès Cloud (S3).

Cartographie Data : Liste le nom de toutes les bases de données présentes (MariaDB, PostgreSQL, MongoDB).
Risque métier : Mâche le travail de l'attaquant en lui indiquant directement où se trouvent nos données sensibles à voler ou chiffrer.
Impact : Accélère drastiquement l'attaque ; le pirate trouve nos données critiques en exécutant une seule ligne de code.
Parade : Restreindre les droits d'accès au strict minimum (Moindre Privilège) et utiliser un EDR pour bloquer ces commandes d'énumération suspectes.
