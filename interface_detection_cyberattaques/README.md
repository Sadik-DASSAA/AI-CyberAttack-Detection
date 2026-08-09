# Supervision des cyberattaques

Application locale v10.4 composée de Suricata, d'une API FastAPI, d'un
Dashboard Streamlit et d'une passerelle HTTPS Caddy exécutée avec Docker
Compose.

## Fichiers principaux

- `app.py` : interface Streamlit.
- `api.py` : API de détection et gestion des incidents.
- `compose.yaml` : services Docker.
- `Dockerfile` : image Python.
- `LANCER_TOUT.bat` : démarrage complet en un clic.
- `ARRETER_TOUT.bat` : arrêt et sauvegarde locale.
- `requirements.txt` : dépendances Python.

## Données d'exécution

- `alerts/eve.json` : événements Suricata.
- `history` : historique persistant des analyses et alertes, exclu de Git.
- `security` : comptes et sessions, exclu de Git.
- `certificates` et `.runtime` : état TLS local, exclu de Git.

## Modèle IA

Le modèle est conservé hors de l'application :

`..\outputs\modelisation_evaluation\models\meilleur_modele.pkl`

Dans Docker, ce dossier est monté sous :

`/workspace/outputs`

## Démarrage en un clic

1. Installer une seule fois Docker Desktop, Npcap et Suricata 8 sous Windows.
2. Conserver le fichier local `.env` si Gmail est déjà configuré. Pour une
   première installation, copier `.env.example` vers `.env` et renseigner le
   compte Gmail ainsi que son mot de passe d'application.
3. Double-cliquer uniquement sur `LANCER_TOUT.bat` et accepter la demande
   administrateur.

Le navigateur s'ouvre automatiquement sur :

`https://localhost/SCA/`

Les ports internes `8000` et `8501` ne sont pas exposés sur Windows. Le
certificat Caddy est approuvé automatiquement dans les magasins Windows de
l'utilisateur et de l'ordinateur.
