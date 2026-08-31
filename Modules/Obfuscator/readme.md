# Présenation des modules Obfuscator : 

### obfuscator_py.py 
Objectif : Rendre un programme malveillant Python totalement illisible pour contourner les antivirus (bypass) et ralentir l'investigation.

Chiffrement multicouche : Le code est compressé, traduit en Base64, puis ses lettres sont décalées (algorithme ROT13) pour détruire toute signature identifiable.

Puzzle dynamique : Le programme est découpé en dizaines de petits morceaux (chunks) mélangés dans le désordre, reconstitués uniquement à la toute dernière microseconde lors de l'exécution.

Leurres visuels : Injection de faux morceaux de code pour noyer l'analyste sous des informations inutiles.

Risque métier : Permet à un logiciel malveillant connu (et normalement bloqué par les outils/via hash) de franchir nos pare-feux et antivirus en se déguisant.

Impact : Les outils de détection statique deviennent aveugles. Le code s'exécute furtivement en mémoire.


### obfuscator_v2.sh 
Objectif : Masquer des scripts d'attaque système (Linux) sous une bouillie de caractères indéchiffrables.

Standardisation trompeuse : Ajuste mathématiquement le découpage pour que le fichier final fasse toujours entre 70 et 170 lignes. Il est impossible d'estimer la taille ou la dangerosité de l'attaque à l'œil nu.

Mots-clés invisibles : Les commandes d'exécution critiques (comme eval) ne sont jamais écrites en clair, mais encodées mathématiquement (en hexadécimal et octal).

Noyade analytique : Génère jusqu'à 100 fausses lignes de code parfaitement identiques visuellement aux vraies, rendant le déchiffrement manuel cauchemardesque pour un reverser(personne qui réalise du reverse engeenering).

Risque métier : Facilite l'introduction d'outils de sabotage, de persistance ou de vol de données sur les serveurs sans déclencher d'alertes textuelles.

Impact : Rend l'investigation humaine (forensique) extrêmement fastidieuse et rend les règles de détection par mots-clés obsolètes.
