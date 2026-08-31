# Présentation du module de téganographie

### stego_embed.py 

Objectif : Cacher des instructions malveillantes (comme une adresse web) à l'intérieur d'une simple image d'apparence banale.

Stéganographie : Injecte l'adresse du serveur de l'attaquant dans les métadonnées invisibles (chunk tEXt) d'une image PNG normale.

Illusion parfaite : L'image n'est absolument pas altérée visuellement et s'ouvre normalement, trompant la vigilance humaine et les contrôles de base.

Chiffrement : Le lien est chiffré (XOR) et encodé pour échapper aux analyses de sécurité cherchant des adresses web en clair.

Risque métier : Permet à un logiciel malveillant très profond (rootkit) de recevoir ses ordres d'attaque en téléchargeant de simples images depuis des sites de confiance (comme GitHub).

Impact : Contourne totalement les pare-feux et les filtrages web ; nos outils de sécurité ne verront que le téléchargement inoffensif d'un logo ou d'une icône.

Dans l'exemple nous l'avons réalisé avec le favicon de github.
