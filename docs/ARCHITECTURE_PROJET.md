# Architecture du projet

## Code scientifique

Les scripts numérotés restent à la racine afin de préserver leur ordre
d'exécution et leurs chemins relatifs.

## Données

- `data/raw` contient uniquement les données originales.
- `data/interim` reçoit les données intermédiaires.
- `data/processed` reçoit les jeux de données réutilisables.
- Les matrices Train/Test actuellement consommées par la modélisation
  restent dans `outputs/preprocessing/processed`.

## Résultats

Chaque étape possède son propre dossier dans `outputs` :

- `eda` ;
- `preprocessing` ;
- `modelisation_evaluation`.

Les figures, tableaux, preuves, journaux et modèles ne doivent pas être
mélangés avec les données brutes.

## Application

L'application conserve uniquement :

- son code ;
- sa configuration Docker ;
- les alertes Suricata ;
- son historique d'exécution ;
- sa documentation.

Le modèle scientifique demeure dans le dossier `outputs` de la racine.
