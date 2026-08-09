# Audit complet du projet — v10.4

Date : 9 août 2026

## Verdict opérationnel

Le paquet de lancement contient tous les fichiers nécessaires pour démarrer
Suricata, FastAPI, Streamlit, Docker Compose et Caddy avec un seul double-clic
sur `interface_detection_cyberattaques/LANCER_TOUT.bat`.

L'adresse publiée est uniquement `https://localhost/SCA/`. Les ports internes
FastAPI `8000` et Streamlit `8501` ne sont pas exposés sur Windows.

## Fichiers obligatoires vérifiés

- lanceurs Windows : `LANCER_TOUT.bat`, `ARRETER_TOUT.bat`,
  `demarrer_tout.ps1`, `arreter_tout.ps1`, `suricata_runtime.ps1` ;
- Docker/HTTPS : `compose.yaml`, `Dockerfile`, `Caddyfile`, `.dockerignore` ;
- application : `api.py`, `app.py`, `auth_security.py`, `data_migration.py` ;
- dépendances : `requirements.txt`, `requirements-dev.txt` ;
- modèle : `meilleur_modele.pkl`, `meilleur_modele.json`,
  `label_encoder_mapping.json`.

Le modèle versionné se charge correctement avec scikit-learn 1.8.0. Il contient
70 variables et 15 classes, cohérentes avec les métadonnées et le mapping.

## Correctifs réalisés

- correction Schannel `CRYPT_E_NO_REVOCATION_CHECK` avec validation TLS au
  mieux, sans `--insecure` ;
- installation de l'autorité Caddy dans les magasins Windows utilisateur et
  ordinateur ;
- gestion correcte de la progression `docker compose cp` ;
- création automatique du `threshold.config` attendu par Suricata ;
- suppression des chemins propres à un utilisateur Windows ;
- verrouillage de scikit-learn 1.8.0, version du modèle sérialisé ;
- ajout de `httpx2` aux dépendances de test ;
- correction du nom du mapping de classes lu par l'API ;
- vérification explicite des fichiers avant la construction Docker ;
- retrait du suivi Git des comptes, sessions, profil e-mail et certificats
  générés localement.

## Fichier ML absent

`outputs/preprocessing/processed/minmax_scaler.joblib` n'était pas enregistré
par l'ancien script de prétraitement. Le script est corrigé pour le produire à
la prochaine exécution.

En attendant, l'API refuse d'envoyer des valeurs brutes au modèle entraîné sur
des valeurs MinMax et utilise son mode de secours. Cela évite des prédictions
fausses ; le Dashboard, Suricata, les alertes, l'authentification et HTTPS
restent disponibles.

## Fichiers volontairement absents de Git

- `.env` et secrets Gmail ;
- `security/`, `history/`, `profile.json` ;
- `certificates/`, `.runtime/`, clés privées Caddy ;
- `alerts/eve.json` ;
- CSV CIC-IDS2017 bruts et matrices Train/Test volumineuses.

Ces éléments sont créés, conservés ou montés localement. Ils ne doivent pas
être ajoutés au dépôt public.

## Validations exécutées

- compilation de tous les fichiers Python ;
- analyse syntaxique des trois scripts PowerShell ;
- cohérence du modèle, des 70 variables et des 15 classes ;
- structure Docker Compose et exposition réseau ;
- routage HTTPS `/SCA/` et absence de `--insecure` ;
- authentification, inscription, CORS et limites d'import ;
- isolation des utilisateurs et des historiques ;
- migration/sauvegarde SQLite ;
- remise à zéro isolée du compteur de flux ;
- synchronisation du jeton du Dashboard ;
- contrôle des dépendances Python.

La validation dynamique finale de Suricata, Docker Desktop, du magasin de
certificats Windows et de Chrome doit être effectuée sur le poste Windows cible,
car ces composants ne sont pas disponibles dans l'environnement d'audit Linux.
