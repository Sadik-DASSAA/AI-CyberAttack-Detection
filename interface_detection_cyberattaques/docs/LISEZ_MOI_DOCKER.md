# Démarrage Docker — Supervision des cyberattaques

Cette configuration lance ensemble :

- l'API FastAPI sur `http://localhost:8000` ;
- la documentation FastAPI sur `http://localhost:8000/docs` ;
- le Dashboard Streamlit sur `http://localhost:8501`.

Suricata sera ajouté plus tard comme troisième service, après validation de son extracteur de flux et de la liaison avec le modèle. Cette première version regroupe uniquement les deux services déjà opérationnels.

L'API et le Dashboard utilisent la même image Python. Cette image est construite
une seule fois par le service `api`, puis réutilisée par `dashboard`. Cela évite
le conflit Docker `image ... already exists` provoqué lorsque deux constructions
parallèles exportent le même tag.

## Fichiers qui doivent être dans le même dossier

```text
interface_detection_cyberattaques/
├── api.py
├── app.py
├── requirements.txt
├── Dockerfile
├── compose.yaml
├── .dockerignore
├── demarrer.bat
└── arreter.bat
```

Les dossiers de modèles, de données, de sorties et d'historique restent à leur place habituelle. Le projet complet est monté dans les deux conteneurs sous `/app`.

Le fichier `app.py` fourni dans ce kit correspond à la dernière interface corrigée. Il accepte maintenant l'adresse de l'API via la variable `API_URL`, indispensable pour la communication entre conteneurs.

## Première utilisation

1. Installer Docker Desktop pour Windows et activer son moteur WSL 2.
2. Démarrer Docker Desktop et attendre l'état **Engine running**.
3. Vérifier que `requirements.txt` contient toutes les dépendances de `api.py` et `app.py`.
4. Double-cliquer sur `demarrer.bat`.

La première construction télécharge Python et installe les dépendances. Elle est donc plus longue. Les lancements suivants utilisent le cache Docker.

## Utilisation quotidienne

- Démarrer les deux services : double-clic sur `demarrer.bat`.
- Arrêter les deux services : double-clic sur `arreter.bat`.

Commandes équivalentes dans CMD ou PowerShell :

```powershell
docker compose build api
docker compose up -d --no-build
docker compose logs --follow
docker compose down
```

La commande compacte suivante reste également valide :

```powershell
docker compose up --build -d
```

## Fonctionnement du réseau

Dans Windows, le Dashboard reste accessible sur `localhost:8501`. À l'intérieur de Docker, le Dashboard contacte l'API avec `http://api:8000`. La variable `API_URL` est réglée automatiquement dans `compose.yaml`.

`app.py` garde aussi une valeur par défaut, `http://127.0.0.1:8000`, afin de pouvoir encore lancer l'application sans Docker si nécessaire.

## Vérifications rapides

```powershell
docker compose ps
docker compose logs api
docker compose logs dashboard
```

Les deux services doivent avoir l'état `Up` ou `healthy`.

## En cas d'échec pendant l'installation des dépendances

Le fichier `requirements.txt` doit contenir des paquets compatibles avec Linux/Python 3.11. Retirer les paquets exclusivement Windows, par exemple `pywin32`, d'une copie appelée `requirements.docker.txt`, puis remplacer dans le `Dockerfile` :

```dockerfile
COPY requirements.txt /tmp/requirements.txt
```

par :

```dockerfile
COPY requirements.docker.txt /tmp/requirements.txt
```

## Pourquoi cette solution évite le blocage actuel

Pandas, NumPy et scikit-learn sont installés dans un conteneur Linux géré par Docker. Le projet n'utilise donc plus les fichiers `.pyd` Windows refusés par Smart App Control.
