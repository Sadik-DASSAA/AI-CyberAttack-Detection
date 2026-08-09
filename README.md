# Détection intelligente des cyberattaques

Projet de stage consacré à la détection automatisée des cyberattaques
à partir du jeu de données CIC-IDS2017.

## Pipeline scientifique

1. `01_EDA.py` : analyse exploratoire initiale.
2. `01_EDA_CICIDS2017.py` : analyse détaillée de CIC-IDS2017.
3. `02_Global_EDA.py` : analyse globale des huit fichiers.
4. `03_Preprocessing_CICIDS2017.py` : prétraitement des données.
5. `04_Modelisation_Evaluation.py` : modélisation et évaluation.

## Organisation

- `data/raw` : huit fichiers CSV originaux.
- `data/interim` : données intermédiaires.
- `data/processed` : données finales réutilisables.
- `docs` : documentation du projet.
- `outputs/eda` : résultats de l'analyse exploratoire.
- `outputs/preprocessing` : résultats du prétraitement.
- `outputs/modelisation_evaluation` : modèles, métriques et figures.
- `interface_detection_cyberattaques` : Dashboard et API Docker.

## Modèle final

`outputs/modelisation_evaluation/models/meilleur_modele.pkl`

## Démarrage du Dashboard

Sous Windows, ouvrir `interface_detection_cyberattaques`, puis double-cliquer
uniquement sur `LANCER_TOUT.bat`. Le lanceur démarre Docker Desktop, Suricata,
l'API, le Dashboard et la passerelle HTTPS, approuve le certificat local et
ouvre automatiquement :

`https://localhost/SCA/`

Le fichier `.env` reste local et n'est jamais versionné. Copier
`.env.example` vers `.env` une seule fois pour configurer Gmail. Les comptes,
historiques, certificats et journaux d'exécution sont également exclus de Git.

Le résultat des contrôles de complétude, sécurité et dépendances est détaillé
dans `AUDIT_PROJET_V10_4.md`.
