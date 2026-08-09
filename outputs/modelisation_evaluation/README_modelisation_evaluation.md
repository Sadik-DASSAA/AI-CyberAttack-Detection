# README - Modelisation et evaluation

## Objectif

Cette partie entraine plusieurs modeles de classification sur les donnees
pretraitees du dataset CIC-IDS2017, puis compare leurs performances.

## Mode d'entrainement

- Mode utilise : toutes les lignes du Train
- Lignes Train utilisees : 1801984
- Lignes Test utilisees : 772280
- Regression logistique entrainee : False
- Nombre d'arbres pour Random Forest et Extra Trees : 20

## Donnees utilisees

Les donnees sont lues depuis :

`outputs/preprocessing/processed/`

Fichiers utilises :

- `X_train_final.csv`
- `X_test_final.csv`
- `y_train.csv`
- `y_test.csv`
- `label_encoder_mapping.json`
- `class_weights.json`

## Modeles entraines

1. Decision Tree
2. Random Forest
3. Extra Trees
4. Naive Bayes

## Metriques utilisees

- Accuracy
- Precision macro
- Recall macro
- F1-score macro
- Precision weighted
- Recall weighted
- F1-score weighted
- Matrice de confusion

## Critere principal

Le critere principal est le F1-score macro, car le dataset CIC-IDS2017 est
desequilibre. Cette metrique donne le meme poids a toutes les classes, y compris
les classes rares.

## Optimisation des graphes

Les graphes de distribution, d'erreurs et certaines importances utilisent une
echelle symlog. Cette echelle permet de garder les grandes valeurs visibles tout
en rendant les petites valeurs et les classes rares plus lisibles.

## Meilleur modele

- Modele retenu : Decision Tree
- F1-score macro : 0.8702

## Sorties generees

- `tables/01_resume_donnees_chargees.csv`
- `tables/02_distribution_classes_train_test.csv`
- `tables/03_mode_entrainement.csv`
- `tables/04_modeles_utilises.csv`
- `tables/05_comparaison_modeles.csv`
- `tables/06_meilleur_modele.csv`
- `tables/07_importance_variables_meilleur_modele.csv`
- `tables/08_erreurs_par_classe_meilleur_modele.csv`
- `figures/`
- `models/meilleur_modele.pkl`
- `model_info/meilleur_modele.json`
