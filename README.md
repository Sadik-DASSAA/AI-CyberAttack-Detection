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

Ouvrir `interface_detection_cyberattaques`, puis exécuter
`demarrer.bat`.
