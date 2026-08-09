# README - Pretraitement CIC-IDS2017

Ce dossier contient les sorties du script `03_Preprocessing_CICIDS2017.py`.

## Objectif

Preparer les huit fichiers CIC-IDS2017 pour l'apprentissage automatique, apres l'analyse exploratoire.

## Etapes executees

1. Creation du workflow du pretraitement.
2. Detection et chargement des huit fichiers CSV.
3. Verification des colonnes et correction des labels.
4. Fusion des fichiers.
5. Remplacement des valeurs infinies par des valeurs manquantes.
6. Suppression des doublons.
7. Analyse descriptive des valeurs aberrantes par IQR / Tukey, sans suppression.
8. Separation stratifiee 70 % Train / 30 % Test.
9. Cross-validation stratifiee sur Train.
10. Comparaison des methodes statistiques, ML et DL.
11. Imputation finale des valeurs manquantes.
12. Suppression des variables constantes.
13. Normalisation des caracteristiques.
14. Analyse du desequilibre des classes sur Train.
15. Reequilibrage par poids de classes calcules uniquement sur Train.

## Resultat final

- Train : 1,801,984 observations
- Test : 772,280 observations
- Caracteristiques finales : 70
- Classes : 15
- Valeurs manquantes finales : 0
- Valeurs infinies finales : 0

## Dossiers produits

- `figures/` : graphiques du pretraitement.
- `tables/` : tableaux CSV servant de preuves.
- `proofs/` : preuves JSON des etapes importantes.
- `processed/` : fichiers finaux pour la modelisation (`X_train_final.csv`, `X_test_final.csv`, `y_train.csv`, `y_test.csv`, `label_encoder_mapping.json`, `class_weights.json`, `minmax_scaler.joblib`).
- `preuve_execution_pretraitement.log` : journal complet d'execution.

## Remarque importante

Les transformations sont ajustees uniquement sur Train, puis appliquees au Test. La validation est realisee uniquement a l'interieur du Train avec la cross-validation, ce qui evite la fuite d'information vers l'ensemble de test.

Le desequilibre des classes est traite par ponderation calculee uniquement sur Train. Le Test n'est jamais reechantillonne ni modifie, afin de rester representatif des donnees reelles.
