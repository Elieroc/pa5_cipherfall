# Présentation des modules Dropper : 

### net_py_dropper.py 
Objectif : Exécuter un programme malveillant Python récupéré sur Internet sans jamais l'enregistrer sur le disque dur.

Mécanisme : Télécharge le code et l'injecte instantanément dans la mémoire du processus actif (inline) ou dans un fichier virtuel temporaire en RAM (memfd).

Furtivité : Détache le processus du terminal (daemonisation) pour qu'il continue de tourner en arrière-plan même si l'utilisateur se déconnecte.

Risque métier : Rend l'attaque invisible pour 90% des antivirus classiques qui se contentent d'analyser les fichiers écrits sur le disque.

Impact : Permet à l'attaquant de maintenir un accès persistant (backdoor) totalement indétectable par des recherches de fichiers standards.


### net_sh_dropper.py
Objectif : Déployer et exécuter des scripts de commandes système (Bash) de manière fantôme.

Mécanisme : Télécharge un script d'attaque distant, crée un espace isolé en mémoire vive (memfd_create), et force le système à le lire comme s'il s'agissait d'un vrai fichier.

Usurpation : Le script d'attaque masque son nom sous l'étiquette [kworker_system], se faisant passer pour un processus vital du noyau Linux.

Risque métier : Facilite l'automatisation silencieuse du vol de données ou de la modification de notre configuration serveur.

Impact : Les analystes qui inspectent le serveur ne verront qu'un processus système légitime, rendant l'investigation très complexe.


### net_bin_dropper.py
Objectif : Charger et exécuter de gros programmes malveillants compilés (comme un ransomware ou un outil de contrôle à distance) directement en RAM.

Mécanisme : Similaire au précédent, mais conçu pour exécuter de vrais logiciels binaires plutôt que de simples scripts de commandes.

Nettoyage radical : Redirige toutes les sorties d'erreur vers /dev/null (le trou noir du système) pour s'assurer qu'absolument aucun journal d'erreur ne trahisse sa présence.

Risque métier : C'est le vecteur de déploiement final privilégié par les groupes de cybercriminels avancés (APT) pour exécuter leur charge utile principale.

Impact : Compromission totale et profonde du serveur par un logiciel malveillant qui disparaîtra complètement à la minute où le serveur sera redémarré (résidence exclusive en RAM).

