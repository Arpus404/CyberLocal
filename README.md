# Cyber Local

Cyber Local est une application pédagogique locale écrite en Python avec
FastAPI. Elle réunit l’analyse de fichiers avec ClamAV, la recherche de CVE,
l’historique PostgreSQL et des scans Wi-Fi/BLE réalisés par un ESP32 connecté
en USB.

L’application ne contient pas d’intégration à un modèle d’IA. Les pistes de
correction des CVE sont produites par des règles explicites à partir de la
gravité, des avis éditeurs repérés par la NVD et, lorsqu’elle est présente,
de l’action requise publiée par la CISA.

## Démarrer sous Windows

### Prérequis

- Windows 10 ou 11 ;
- Docker Desktop démarré avec le moteur Linux ;
- Git pour cloner et mettre à jour le dépôt.

### Lancer les services

Depuis PowerShell, dans le dossier du projet, créez `.env` depuis le modèle
et remplacez le mot de passe PostgreSQL par une valeur aléatoire :

```powershell
Copy-Item .env.example .env
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$secret = ([BitConverter]::ToString($bytes) -replace "-", "").ToLower()
Set-Content -Path .env -Value "POSTGRES_PASSWORD=$secret"
docker compose up --build -d
```

Ouvrez <http://localhost:8000>. Le premier démarrage télécharge les images
Docker, les dépendances et les signatures ClamAV. ClamAV peut prendre quelques
minutes avant d’être prêt ; son absence ne produit jamais un résultat « sain ».

Consultez l’état des conteneurs et les journaux :

```powershell
docker compose ps
docker compose logs --tail=100
```

`docker compose down` arrête les services et conserve les données. La commande
`docker compose down -v` supprime aussi les résultats PostgreSQL et les
signatures ClamAV.

Le mot de passe PostgreSQL est fixé lors de la création du volume. Modifier
`.env` ensuite ne change pas le mot de passe déjà enregistré dans PostgreSQL.
Sauvegardez les données avant toute opération de réinitialisation.

## Fonctions

### Analyse de fichier

- Limite d’envoi : 20 Mio.
- Le fichier est transmis au conteneur ClamAV du réseau Docker interne ; il
  n’est pas exécuté ni enregistré volontairement.
- PostgreSQL conserve le nom, la taille, l’empreinte SHA-256, le résultat,
  le détail et la date de l’analyse.
- Les résultats possibles sont **Menace détectée**, **Analyse incomplète** et
  **Échec de l’analyse**. Une absence de détection ne prouve pas qu’un fichier
  est sain.
- Le serveur peut utiliser un fichier temporaire lors de l’envoi. Un arrêt
  brutal peut laisser ce fichier temporaire sur le disque.

### CVE et pistes de correction

- La recherche locale consulte les CVE déjà enregistrées.
- Une recherche NVD est lancée uniquement après un clic explicite ; elle
  enregistre jusqu’à 20 résultats par requête.
- Les fiches affichent le score CVSS, la description et les références. La
  page ajoute des étapes de correction fondées sur la gravité, les références
  marquées comme avis éditeur ou correctif et l’action CISA lorsqu’elle est
  fournie.
- Cyber Local ne connaît pas les logiciels ni les versions installés. Les
  étapes sont des pistes : vérifiez l’applicabilité et le correctif dans l’avis
  officiel de l’éditeur. L’application ne déduit pas une version corrigée et ne
  modifie aucun système.
- Les recherches dépendent de la disponibilité et des limites de requêtes de
  la NVD. Il n’y a pas encore de pagination, de synchronisation automatique
  ni d’inventaire logiciel.

### Wi-Fi et Bluetooth

- Un ESP32 classique est relié à l’ordinateur par USB et communiqué par un
  agent Windows en série.
- Le firmware relève les réseaux Wi-Fi 2,4 GHz et les annonces Bluetooth Low
  Energy (BLE) en écoute passive ; il ne tente pas d’authentification ni
  d’exploitation.
- Un scan peut enregistrer jusqu’à 50 résultats. PostgreSQL conserve chaque
  demande avec son type, son état, son erreur éventuelle, ses résultats et ses
  dates. Les demandes refusées faute d’agent et les expirations sont aussi
  enregistrées quand la base est disponible.
- Les scans ne sont pas une preuve de vulnérabilité. Des appareils silencieux
  peuvent être absents et les adresses BLE peuvent changer.
- Les résultats radio sont supprimables depuis la page Wi-Fi et Bluetooth.

### Historique et conservation

Les analyses, les résultats de scans radio et les CVE reçues sont conservés
dans PostgreSQL jusqu’à suppression administrative ou suppression du volume. La page
d’historique affiche les 100 dernières analyses de fichier ; la page radio
affiche les 20 derniers enregistrements. Ces limites d’affichage ne suppriment
pas les lignes plus anciennes de la base.

## Installer l’ESP32

Le firmware vise une carte **ESP32 Dev Module**, le paquet Arduino ESP32
**2.0.17** et ArduinoJson **6.21.5**.

1. Installez ces versions depuis les gestionnaires de cartes et de bibliothèques
   de l’Arduino IDE.
2. Ouvrez `firmware/CyberLocal/CyberLocal.ino`, sélectionnez ESP32 Dev Module
   et le port COM, puis téléversez le firmware.
3. Dans PowerShell, installez pyserial et créez un secret agent distinct de
   celui de PostgreSQL :

```powershell
py -m pip install -r agent/requirements.txt
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$token = ([BitConverter]::ToString($bytes) -replace "-", "").ToLower()
Add-Content -Path .env -Value "ESP32_AGENT_TOKEN=$token"
docker compose up -d
```

4. Remplacez `COM3` par le port indiqué par Windows ou l’Arduino IDE, puis
   démarrez l’agent sans afficher le secret :

```powershell
$env:CYBERLOCAL_AGENT_TOKEN = (
    (Get-Content .env | Where-Object { $_ -match '^ESP32_AGENT_TOKEN=' } |
        Select-Object -Last 1) -replace '^ESP32_AGENT_TOKEN=', ''
)
py agent/agent.py --port COM3
```

Gardez cette fenêtre ouverte pendant les scans. Fermez le moniteur série de
l’Arduino IDE si le port COM est occupé. Un seul scan peut s’exécuter à la fois.
L’agent conserve le résultat en mémoire et réessaie de l’enregistrer si
l’application locale répond temporairement avec une erreur serveur.

## Vérification avant remise

La suite unitaire existante peut être lancée depuis le dossier du projet :

```powershell
python -m unittest discover -s tests
```

Elle utilise des réponses réseau et série simulées. Elle ne remplace pas les
vérifications suivantes en environnement réel :

1. Vérifier que Docker Desktop démarre les trois services et que l’interface
   indique PostgreSQL connecté et ClamAV prêt.
2. Analyser un fichier texte et vérifier que le résultat et l’empreinte sont
   enregistrés.
3. Utiliser uniquement le fichier de test officiel EICAR pour vérifier le cas
   « Menace détectée ». Ne pas utiliser de vrai logiciel malveillant.
4. Interrompre ClamAV, analyser un fichier de test et vérifier que le résultat
   indique un échec ; redémarrer ensuite ClamAV.
5. Rechercher une CVE sur la NVD, vérifier les références et pistes proposées,
   puis relancer une recherche locale hors ligne.
6. Avec une carte ESP32 connectée, vérifier la détection du port, le message
   de connexion, un scan Wi-Fi, un scan BLE et l’enregistrement des résultats
   et des échecs dans PostgreSQL.

La carte ESP32 et les services réels doivent être validés sur le matériel et
l’ordinateur de remise. Aucun résultat de test matériel ne doit être déclaré
avant cette vérification.

## Architecture

```text
Navigateur local
      │
      ▼
FastAPI ───── PostgreSQL (analyses, CVE, scans radio)
   │  │
   │  └────── ClamAV (analyse locale de fichiers)
   │
   └──────── NVD (recherche déclenchée par l’utilisateur)

ESP32 ◄──── USB série ──── Agent Windows ──── FastAPI local
```

Docker Compose lie l’interface à `127.0.0.1:8000`. Les services PostgreSQL
et ClamAV ne publient pas de port sur l’ordinateur. Il n’y a pas de compte
utilisateur : toute personne ayant accès à la session locale peut utiliser
l’application. **Ne publiez pas le serveur sur Internet.**

## Git et secrets

- `.env` est exclu par `.gitignore` ; ne publiez jamais les secrets qu’il
  contient.
- `.env.example` ne contient que des valeurs de remplacement.
- La liste des prompts IA utilisés pour cadrer et modifier ce projet est
  conservée dans [`docs/PROMPTS_IA.md`](docs/PROMPTS_IA.md).
- Le code source est formaté pour rester lisible dans GitHub et dans un éditeur.
