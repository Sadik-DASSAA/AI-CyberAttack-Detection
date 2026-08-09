# Supervision des cyberattaques

Application de supervision composée d'une API FastAPI et d'un Dashboard
Streamlit exécutés avec Docker Compose.

## Fichiers principaux

- `app.py` : interface Streamlit.
- `api.py` : API de détection et gestion des incidents.
- `compose.yaml` : services Docker.
- `Dockerfile` : image Python.
- `demarrer.bat` : démarrage et contrôles.
- `arreter.bat` : arrêt des services.
- `requirements.txt` : dépendances Python.

## Données d'exécution

- `alerts/eve.json` : événements Suricata.
- `history` : historique persistant des analyses et alertes.
- `profile.json` : profil de notification.
- `.streamlit/config.toml` : configuration Streamlit.

## Modèle IA

Le modèle est conservé hors de l'application :

`..\outputs\modelisation_evaluation\models\meilleur_modele.pkl`

Dans Docker, ce dossier est monté sous :

`/workspace/outputs`

## Démarrage

Double-cliquer sur `demarrer.bat`, puis ouvrir :

- Dashboard : http://localhost:8501
- API : http://localhost:8000/docs
