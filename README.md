# Cyber Local

Plateforme pédagogique locale pilotée par Python (FastAPI). Cette version apporte la consultation CVE NVD, l’analyse de fichier avec ClamAV et l’historique dans PostgreSQL. Le Wi-Fi et le Bluetooth ESP32 ne sont pas encore disponibles : le modèle de carte doit être identifié et l’agent Windows ainsi que le firmware restent à développer.

## Mise en route sur Windows

1. Installer et démarrer Docker Desktop. Télécharger le projet et ouvrir un PowerShell dans son dossier.
2. Créer un fichier `.env` à partir du modèle et générer un secret hexadécimal (il ne faut pas publier ce fichier) :

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

3. Ouvrir http://localhost:8000. Le premier démarrage nécessite Internet pour télécharger les images, les dépendances et les signatures antivirus. ClamAV peut mettre plusieurs minutes à démarrer : pendant ce temps l’analyse indique un échec, jamais un fichier sûr.
4. Consulter les services avec `docker compose ps` et les journaux avec `docker compose logs --tail=100`. `docker compose down` arrête et supprime les conteneurs et le réseau, mais conserve les volumes. Ne pas utiliser `docker compose down -v` sauf si vous voulez effacer les résultats PostgreSQL et les signatures stockées.

Le mot de passe PostgreSQL est défini lors de l’initialisation du volume. Le modifier uniquement dans `.env` ne change pas le mot de passe dans une base déjà créée. Il faut utiliser une procédure de changement de mot de passe PostgreSQL ; ne supprimez pas le volume pour résoudre ce problème sans sauvegarder vos données.

## Utilisation et limites

- **Analyse** : fichier de 20 Mio maximum, traité en mémoire et jamais exécuté ni conservé par l’application. SHA-256 et résultat enregistrés. ClamAV envoie ses résultats à l’application ; aucune transmission du fichier à un service externe. Les réponses sans détection sont volontairement classées **analyse incomplète** : les limites d’analyse d’archives, fichiers chiffrés et signatures ne sont pas encore vérifiées. Un résultat négatif ne prouve pas l’absence de malware.
- **CVE** : la recherche locale fonctionne sur les résultats déjà enregistrés. Le bouton NVD envoie le terme de recherche sur Internet et enregistre au maximum 20 résultats. Pas de pagination NVD, synchronisation incrémentale, filtre produit/version structuré ou recommandations automatiques dans cette version. Consultez les avis officiels liés avant d’appliquer un correctif. La disponibilité de la NVD dépend de ses limites de requêtes.
- **Historique** : dernières 100 analyses. Le bouton de suppression efface tous les résultats d’analyse, sans supprimer les CVE. Pas de durée de conservation automatique ni de pagination pour l’instant.
- **ESP32** : pas de connexion, firmware ou scans dans cette version ; aucune donnée simulée n’est présentée comme réelle.
- **Sécurité** : le port web est lié à 127.0.0.1, les autres services ne publient pas de port. Ne pas exposer l’application sur Internet. Aucun compte utilisateur n’est prévu ; toute personne ayant accès à la session locale du navigateur peut utiliser l’application. La base et le cache CVE peuvent contenir des informations sensibles.

## Recette simple

1. Ouvrir le tableau de bord et vérifier que la base est connectée.
2. Analyser un petit fichier texte : son empreinte et un résultat doivent s’afficher et être enregistrés dans l’historique. Sans détection, le statut est « Analyse incomplète ».
3. Tester avec le fichier officiel de test EICAR téléchargé depuis eicar.org : le résultat attendu est « Menace détectée ». Ne pas envoyer de véritable logiciel malveillant.
4. Arrêter uniquement ClamAV avec `docker compose stop clamav`, analyser à nouveau un fichier et vérifier « Échec de l’analyse », puis redémarrer avec `docker compose start clamav`.
5. Chercher une CVE connue avec le bouton NVD, puis rechercher son identifiant en local. Tester à nouveau la recherche locale sans accès Internet.
6. Vérifier l’historique et sa suppression uniquement si vous souhaitez effacer toutes les analyses enregistrées.

Tests unitaires des fonctions sans accès réseau : `python -m unittest discover -s tests`. Ils utilisent un faux moteur et une fausse réponse NVD ; ils ne remplacent pas les essais Docker réels et EICAR.

## Architecture

Navigateur → FastAPI/Python → PostgreSQL pour les métadonnées, ClamAV pour l’analyse locale, NVD pour les recherches explicitement demandées. Les fichiers ne sont pas enregistrés en base. Les services communiquent sur un réseau Docker interne. ClamAV télécharge ses signatures ; la NVD est contactée uniquement sur demande.
