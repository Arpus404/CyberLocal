# Cyber Local — première version

Un premier tableau de bord local piloté par Python (FastAPI). Le serveur affiche le site et fournit `/api/status`. L'antivirus, la base de données, les CVE et l'ESP32 ne sont pas encore implémentés : les mentions « à venir » ne représentent aucun scan.

## Démarrer sous Windows avec Docker Desktop

1. Décompresse le ZIP, puis ouvre le dossier `cyber-local`.
2. Ouvre PowerShell dans ce dossier : clique dans la barre d'adresse de l'explorateur, saisis `powershell` puis Entrée.
3. Vérifie que Docker Desktop est démarré. Lance :

```powershell
docker compose up --build -d
```

4. Ouvre http://localhost:8000 dans ton navigateur. Le premier démarrage nécessite Internet pour télécharger l'image et les dépendances.

Pour voir les journaux : `docker compose logs -f` (Ctrl+C pour quitter les journaux). Pour arrêter et retirer le conteneur : `docker compose down`. Cette première version ne crée pas de base de données ni de volume.

Si le port 8000 est déjà utilisé, modifie dans `compose.yaml` le côté gauche du mappage, par exemple `127.0.0.1:8001:8000`, puis ouvre http://localhost:8001. Si Docker ne répond pas, vérifie que Docker Desktop a fini de démarrer.

## Structure

- `main.py` : serveur Python et API d'état.
- `static/` : page HTML, style CSS et JavaScript.
- `Dockerfile`, `compose.yaml` : construction et lancement local du serveur.
- `requirements.txt` : versions des bibliothèques Python.

Le serveur est exposé uniquement sur l'interface locale de Windows. Cette version ne contient pas encore d'authentification : ne l'expose pas sur Internet. La suite pourra ajouter PostgreSQL, ClamAV et l'agent ESP32 par étapes.
