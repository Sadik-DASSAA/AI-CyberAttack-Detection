# Analyse exploratoire unifiée de CIC-IDS2017

## 1. Présentation

Ce projet réalise une analyse exploratoire des données, appelée **EDA** (*Exploratory Data Analysis*), sur les **huit fichiers CSV** du dataset CIC-IDS2017.

Le script principal est :

```text
01_EDA_CICIDS2017.py
```

Son objectif est d’étudier la structure, la qualité et la distribution des données avant de commencer le prétraitement et l’entraînement des modèles de détection d’intrusions.

Le programme réalise deux niveaux d’analyse dans un seul workflow :

1. une analyse individuelle et comparative des huit fichiers ;
2. une analyse globale représentant l’ensemble du dataset.

> **Important :** ce script observe les problèmes, mais ne modifie pas les données. Il ne réalise ni imputation, ni suppression des doublons, ni remplacement des valeurs infinies, ni normalisation, ni rééquilibrage.

---

## 2. Organisation attendue du projet

```text
projet/
├── 01_EDA_CICIDS2017.py
├── data/
│   └── raw/
│       └── CIC-IDS2017/
│           └── MachineLearningCVE/
│               ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
│               ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│               ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│               ├── Monday-WorkingHours.pcap_ISCX.csv
│               ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│               ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│               ├── Tuesday-WorkingHours.pcap_ISCX.csv
│               └── Wednesday-workingHours.pcap_ISCX.csv
└── outputs/
    └── eda/
        ├── figures/
        ├── tables/
        ├── preuve_execution.log
        └── manifest_outputs.csv
```

Le dossier `outputs/eda/` est créé automatiquement au lancement du programme.

---

## 3. Installation et exécution

### Bibliothèques nécessaires

```bash
pip install pandas numpy matplotlib seaborn
```

### Lancement

Depuis la racine du projet :

```bash
python 01_EDA_CICIDS2017.py
```

Pendant l’exécution, chaque étape est annoncée dans le terminal. Les mêmes messages sont enregistrés dans :

```text
outputs/eda/preuve_execution.log
```

La fin normale du programme affiche :

```text
ANALYSE EXPLORATOIRE TERMINÉE AVEC SUCCÈS
```

---

## 4. Explication détaillée du code et interprétation des sorties

### Étape 0 — Configuration générale

#### Objectif

Cette partie définit :

* le chemin vers les huit fichiers CSV ;
* les dossiers de résultats ;
* le nombre attendu de fichiers ;
* la taille de l’échantillon prélevé dans chaque fichier ;
* la graine aléatoire utilisée pour rendre l’échantillonnage reproductible.

#### Paramètres importants


| Paramètre             | Valeur | Signification                                                   |
| ---------------------- | -----: | --------------------------------------------------------------- |
| `EXPECTED_FILE_COUNT`  |      8 | Le programme exige exactement huit CSV.                         |
| `SAMPLE_SIZE_PER_FILE` | 25 000 | Nombre maximal de lignes prélevées dans chaque fichier.       |
| `RANDOM_STATE`         |     42 | Permet de retrouver le même échantillon à chaque exécution. |

#### Sortie

Les dossiers `tables` et `figures` sont automatiquement créés.

#### Interprétation professionnelle

La graine fixe assure la **reproductibilité** de l’étude. Deux exécutions réalisées sur les mêmes données produisent donc le même échantillon global et des résultats comparables.

---

### Journal d’exécution

#### Objectif

Le module `logging` affiche les informations dans le terminal et les conserve dans un fichier texte.

#### Sortie

```text
outputs/eda/preuve_execution.log
```

#### Interprétation professionnelle

Ce journal constitue une **trace d’exécution**. Il permet de vérifier les fichiers analysés, les dimensions détectées, le nombre d’anomalies observées et le bon déroulement de toutes les étapes.

---

### Étape 1 — Workflow général de l’EDA

#### Objectif

Créer un diagramme qui résume l’enchaînement de l’analyse :

1. détection des fichiers ;
2. vérification des colonnes ;
3. analyse individuelle ;
4. comparaison ;
5. agrégation ;
6. distribution des classes ;
7. statistiques ;
8. corrélations et valeurs aberrantes.

#### Sortie graphique

```text
figures/01_workflow_eda.png
```

#### Interprétation professionnelle

Le workflow montre que l’EDA commence par le contrôle des sources, puis passe de l’analyse détaillée de chaque fichier vers une vision globale des huit fichiers. Cette organisation garantit une démarche structurée et traçable.

---

### Étape 2 — Détection des huit fichiers CSV

#### Objectif

Le programme recherche automatiquement tous les fichiers portant l’extension `.csv` dans le dossier `MachineLearningCVE`.

Pour chaque fichier, il récupère :

* son numéro ;
* son nom complet ;
* un nom court plus lisible ;
* sa taille en mégaoctets.

Le programme s’arrête si le nombre détecté est différent de huit.

#### Sortie tabulaire

```text
tables/01_inventaire_fichiers.csv
```

#### Preuve affichée

Le terminal présente le chemin des données, le nombre de CSV détectés et la liste des huit fichiers.

#### Interprétation professionnelle

Cette vérification prouve que l’analyse couvre bien l’intégralité des huit scénarios de CIC-IDS2017. Elle évite d’exécuter involontairement l’EDA sur un seul fichier ou sur un ensemble incomplet.

---

### Étape 3 — Vérification de la compatibilité des colonnes

#### Objectif

Le script lit uniquement l’en-tête de chaque fichier, supprime les espaces inutiles dans les noms des colonnes et compare chaque schéma au premier CSV.

Il contrôle :

* le nombre de colonnes ;
* leur nom ;
* leur ordre ;
* les colonnes manquantes ;
* les colonnes supplémentaires.

#### Sortie tabulaire

```text
tables/02_verification_schema.csv
```

#### Résultat attendu

Les huit fichiers doivent être indiqués comme compatibles et posséder les mêmes **79 colonnes**.

#### Interprétation professionnelle

La compatibilité du schéma est indispensable avant toute agrégation. Si les colonnes diffèrent, une fusion directe peut introduire des valeurs manquantes artificielles ou associer incorrectement les variables.

---

### Étape 4 — Analyse individuelle des huit fichiers

#### Objectif

Chaque fichier est chargé et analysé automatiquement dans une boucle. Le programme calcule :

* le nombre de lignes et de colonnes ;
* le nombre de variables numériques ;
* le nombre de classes ;
* les valeurs manquantes ;
* les valeurs positives ou négatives infinies ;
* les lignes dupliquées ;
* les observations `BENIGN` ;
* les observations correspondant à des attaques ;
* le taux d’attaques ;
* les zéros, médianes et valeurs uniques de chaque variable.

Un échantillon reproductible de 25 000 lignes au maximum est ensuite conservé pour l’analyse globale approfondie.

#### Preuve affichée

Pour chaque CSV, le terminal présente notamment :

```text
Dimensions
Classes présentes
Valeurs manquantes
Valeurs infinies
Doublons
Trafic BENIGN
Attaques
Taille de l’échantillon
```

#### Interprétation professionnelle

Cette étape met en évidence les différences de volume, de qualité et de composition entre les journées. Les fichiers ne représentent pas les mêmes attaques et ne possèdent pas le même niveau de déséquilibre.

Les valeurs manquantes et infinies signalent des mesures non exploitables directement par la majorité des algorithmes d’apprentissage automatique. Les doublons peuvent surreprésenter certains comportements. Ils devront être traités pendant le prétraitement, pas pendant l’EDA.

> Une valeur égale à zéro n’est pas automatiquement une erreur. Selon la variable réseau, elle peut représenter une absence réelle d’activité. Son sens doit être vérifié avant toute modification.

---

### Étape 5 — Création des tableaux comparatifs

#### Objectif

Transformer les résultats collectés dans la boucle en trois tableaux structurés.

#### Sorties


| Fichier                                   | Contenu                                                                                  |
| ----------------------------------------- | ---------------------------------------------------------------------------------------- |
| `03_resume_qualite_par_fichier.csv`       | Résumé des dimensions, classes et problèmes de qualité pour chaque CSV.              |
| `04_distribution_classes_par_fichier.csv` | Effectif et pourcentage de chaque classe dans chaque fichier.                            |
| `05_profil_variables_par_fichier.csv`     | Type, valeurs manquantes, infinies, nulles, médiane et cardinalité de chaque variable. |

#### Preuve affichée

Un résumé comparatif des huit fichiers apparaît directement dans le terminal.

#### Interprétation professionnelle

Ces tableaux constituent les principales preuves chiffrées de l’analyse comparative. Ils permettent d’identifier précisément le fichier qui contient le plus de doublons, de valeurs invalides ou de classes d’attaque.

---

### Étape 6 — Graphiques comparatifs

#### 6.1 Nombre d’observations par fichier

**Sortie :**

```text
figures/02_nombre_lignes_par_fichier.png
```

**Interprétation :** les fichiers ont des volumes différents. Les journées les plus volumineuses auront naturellement plus d’influence sur une fusion complète si aucune stratégie de pondération n’est appliquée.

#### 6.2 Problèmes de qualité

**Sortie :**

```text
figures/03_qualite_par_fichier.png
```

**Interprétation :** le graphique compare les taux de valeurs manquantes, de valeurs infinies et de doublons. Les doublons peuvent être visuellement dominants, car leur taux est généralement beaucoup plus élevé que celui des cellules manquantes ou infinies.

> Les trois taux n’utilisent pas exactement le même dénominateur : les doublons sont rapportés aux lignes, tandis que les valeurs manquantes et infinies sont rapportées aux cellules. Le graphique sert donc à comparer les fichiers pour chaque problème, pas à affirmer qu’un doublon est directement équivalent à une cellule manquante.

#### 6.3 Trafic normal et attaques

**Sortie :**

```text
figures/04_benign_attaques_par_fichier.png
```

**Interprétation :** ce graphique empilé montre la proportion de trafic `BENIGN` et d’attaques dans chaque fichier. Une forte dominance de `BENIGN` révèle un déséquilibre binaire susceptible d’orienter un modèle vers la classe normale.

#### 6.4 Présence des classes

**Sortie :**

```text
figures/05_presence_classes_par_fichier.png
```

**Interprétation :** la carte thermique indique les fichiers dans lesquels chaque classe apparaît. L’échelle logarithmique `log10(effectif + 1)` rend simultanément visibles les classes fréquentes et rares.

> Les couleurs représentent des effectifs transformés en logarithme. Elles ne correspondent pas directement aux effectifs bruts.

---

### Étape 7 — Agrégation des résultats des huit fichiers

#### Objectif

Additionner les résultats individuels afin d’obtenir une synthèse globale sans charger simultanément les 2,8 millions de lignes en mémoire.

#### Sorties

```text
tables/06_resume_global.csv
tables/07_distribution_globale_classes.csv
```

#### Résultats de référence

L’ensemble CIC-IDS2017 analysé contient :

* **8 fichiers CSV** ;
* **2 830 743 observations** ;
* **79 colonnes** ;
* **15 classes**, en comptant la classe `BENIGN`.

#### Interprétation professionnelle

La classe `BENIGN` est largement majoritaire, avec environ **80,30 %** des observations. Les attaques rares, comme `SQL Injection` et `Infiltration`, ne contiennent que très peu d’exemples. Cette distribution confirme un déséquilibre important des classes.

#### Limite à connaître

La valeur `doublons_internes_aux_fichiers` correspond à la somme des doublons trouvés séparément dans chaque CSV. Elle ne détecte pas d’éventuels doublons entre deux fichiers différents. Une recherche de doublons sur les données fusionnées devra être réalisée pendant le prétraitement.

---

### Étape 8 — Distribution globale des classes

#### Objectif

Présenter l’effectif total de chaque classe dans les huit fichiers et calculer le rapport entre la classe la plus fréquente et la classe la plus rare.

#### Sorties

```text
figures/06_distribution_globale_classes.png
tables/08_preuve_desequilibre_classes.csv
```

#### Interprétation professionnelle

L’axe horizontal utilise une échelle logarithmique, car l’écart entre les classes est très élevé. Sans cette échelle, les classes minoritaires seraient presque invisibles.

La domination de `BENIGN` et le faible nombre d’exemples de certaines attaques montrent qu’une simple exactitude globale ne suffira pas pour évaluer le futur modèle. Il faudra également utiliser la précision, le rappel, le score F1 et une matrice de confusion par classe.

> Cette étape diagnostique le déséquilibre. Le rééquilibrage sera effectué uniquement après la séparation des données d’entraînement, de validation et de test afin d’éviter une fuite de données.

---

### Étape 9 — Échantillon global représentatif des huit fichiers

#### Objectif

Fusionner les échantillons prélevés dans les huit CSV. Avec 25 000 lignes par fichier, l’échantillon global contient normalement :

```text
8 × 25 000 = 200 000 observations
```

#### Sortie

```text
tables/09_composition_echantillon_global.csv
```

#### Interprétation professionnelle

L’échantillonnage réduit la consommation de mémoire et le temps de calcul tout en garantissant la présence de chacun des huit fichiers.

Il s’agit d’un **échantillonnage équilibré par fichier**, et non proportionnel à la taille originale des fichiers. Un petit fichier et un grand fichier peuvent donc contribuer avec le même nombre de lignes. Cette méthode favorise la représentation de chaque journée, mais ne reproduit pas exactement la distribution naturelle du dataset complet.

---

### Étape 10 — Statistiques descriptives globales

#### Objectif

Calculer sur l’échantillon global, pour chaque variable numérique :

* le nombre de valeurs disponibles ;
* la moyenne ;
* l’écart-type ;
* le minimum et le maximum ;
* les quartiles ;
* la médiane ;
* le nombre et le taux de zéros ;
* les valeurs manquantes après remplacement temporaire des infinis par `NaN`.

#### Sortie

```text
tables/10_statistiques_descriptives_globales.csv
```

#### Interprétation professionnelle

Les différences importantes entre les moyennes, les médianes et les maxima peuvent révéler des distributions asymétriques ou la présence de valeurs extrêmes. Les écarts d’échelle entre variables justifient également l’étude d’une méthode de normalisation pendant le prétraitement.

Le remplacement temporaire des infinis par `NaN` sert uniquement à permettre les calculs statistiques. Il ne modifie pas les fichiers CSV d’origine.

---

### Étape 11 — Corrélation globale

#### Objectif

Transformer la cible en problème binaire :

* `0` : trafic `BENIGN` ;
* `1` : présence d’une attaque.

Le programme calcule ensuite :

1. la corrélation de chaque variable numérique avec cette cible ;
2. les vingt variables ayant la plus forte corrélation absolue ;
3. une matrice de corrélation entre ces variables et la cible.

#### Sorties

```text
tables/11_correlation_variables_attaque.csv
tables/12_matrice_correlation_globale.csv
figures/07_matrice_correlation_globale.png
figures/08_correlation_avec_attaque.png
```

#### Interprétation de la matrice

Le coefficient de Pearson varie entre `-1` et `+1` :


|        Valeur | Interprétation                     |
| ------------: | ----------------------------------- |
| Proche de`+1` | Relation linéaire positive forte.  |
| Proche de`-1` | Relation linéaire négative forte. |
|  Proche de`0` | Faible relation linéaire.          |

Une corrélation positive avec `Type_Attaque` signifie que la variable tend à augmenter en présence d’une attaque. Une corrélation négative signifie qu’elle tend à diminuer.

#### Interprétation professionnelle

La matrice permet :

* de repérer les variables liées à la présence d’une attaque ;
* d’identifier des variables fortement redondantes ;
* d’orienter la future sélection de caractéristiques.

Cependant, une corrélation ne prouve pas une relation de causalité. De plus, Pearson mesure surtout les relations linéaires et peut manquer des relations non linéaires utiles aux modèles.

> La corrélation est calculée sur l’échantillon global de **200 000 observations issues des huit fichiers**, et non sur les 2 830 743 observations complètes.

> La cible est binaire. Cette analyse étudie donc la relation avec la présence générale d’une attaque, pas avec chaque type d’attaque séparément.

---

### Étape 12 — Détection des valeurs aberrantes avec l’IQR

#### Objectif

Appliquer la méthode de l’écart interquartile aux quinze variables les plus corrélées avec la cible.

Pour chaque variable :

```text
IQR = Q3 - Q1
Limite inférieure = Q1 - 1,5 × IQR
Limite supérieure = Q3 + 1,5 × IQR
```

Une observation située à l’extérieur de ces limites est signalée comme valeur aberrante.

#### Sorties

```text
tables/13_valeurs_aberrantes_iqr.csv
figures/09_valeurs_aberrantes_iqr.png
```

#### Interprétation professionnelle

Un taux élevé indique une distribution contenant de nombreuses valeurs éloignées de la zone centrale. Dans les données réseau, ces valeurs peuvent correspondre :

* à une erreur de mesure ;
* à une forte asymétrie statistique ;
* à un comportement réseau inhabituel ;
* à une attaque réelle.

Elles ne doivent donc pas être supprimées automatiquement. Une valeur extrême peut porter une information essentielle pour la détection d’intrusions.

> Les résultats concernent uniquement l’échantillon global et les quinze variables sélectionnées. Une variable signalée comme aberrante par l’IQR n’est pas nécessairement incorrecte.

---

### Étape 13 — Manifeste final

#### Objectif

Recenser automatiquement toutes les sorties générées, avec leur chemin relatif et leur taille.

#### Sortie

```text
outputs/eda/manifest_outputs.csv
```

#### Interprétation professionnelle

Le manifeste permet de vérifier qu’aucun tableau ou graphique attendu ne manque. Il facilite aussi l’identification des éléments à intégrer dans le rapport.

---

## 5. Récapitulatif de toutes les sorties

### Tableaux


| N° | Fichier                                     | Utilité                                    |
| --: | ------------------------------------------- | ------------------------------------------- |
|   1 | `01_inventaire_fichiers.csv`                | Prouver la présence des huit CSV.          |
|   2 | `02_verification_schema.csv`                | Vérifier la compatibilité des colonnes.   |
|   3 | `03_resume_qualite_par_fichier.csv`         | Comparer la qualité des huit fichiers.     |
|   4 | `04_distribution_classes_par_fichier.csv`   | Étudier les classes fichier par fichier.   |
|   5 | `05_profil_variables_par_fichier.csv`       | Examiner chaque variable en détail.        |
|   6 | `06_resume_global.csv`                      | Présenter la synthèse globale.            |
|   7 | `07_distribution_globale_classes.csv`       | Donner les effectifs globaux des classes.   |
|   8 | `08_preuve_desequilibre_classes.csv`        | Quantifier le déséquilibre.               |
|   9 | `09_composition_echantillon_global.csv`     | Prouver l’origine des 200 000 lignes.      |
|  10 | `10_statistiques_descriptives_globales.csv` | Résumer les variables numériques.         |
|  11 | `11_correlation_variables_attaque.csv`      | Classer les variables liées à la cible.   |
|  12 | `12_matrice_correlation_globale.csv`        | Conserver les coefficients de corrélation. |
|  13 | `13_valeurs_aberrantes_iqr.csv`             | Quantifier les valeurs extrêmes.           |

### Figures


| N° | Fichier                               | Utilité                                     |
| --: | ------------------------------------- | -------------------------------------------- |
|   1 | `01_workflow_eda.png`                 | Présenter la méthodologie générale.      |
|   2 | `02_nombre_lignes_par_fichier.png`    | Comparer les volumes.                        |
|   3 | `03_qualite_par_fichier.png`          | Comparer les problèmes de qualité.         |
|   4 | `04_benign_attaques_par_fichier.png`  | Comparer trafic normal et attaques.          |
|   5 | `05_presence_classes_par_fichier.png` | Localiser les classes dans les CSV.          |
|   6 | `06_distribution_globale_classes.png` | Montrer le déséquilibre global.            |
|   7 | `07_matrice_correlation_globale.png`  | Examiner les dépendances linéaires.        |
|   8 | `08_correlation_avec_attaque.png`     | Identifier les variables liées à la cible. |
|   9 | `09_valeurs_aberrantes_iqr.png`       | Comparer les taux de valeurs extrêmes.      |

---

## 6. Résultats à utiliser dans le rapport

Les résultats exacts calculés sur les huit fichiers complets sont :

* leurs dimensions ;
* les valeurs manquantes et infinies ;
* les doublons internes à chaque fichier ;
* la distribution des classes ;
* la synthèse globale des 2 830 743 lignes.

Les résultats calculés sur l’échantillon global de 200 000 lignes sont :

* les statistiques descriptives globales ;
* les corrélations ;
* la sélection des variables les plus corrélées ;
* la détection des valeurs aberrantes par IQR.

Cette distinction doit être indiquée dans le rapport afin de présenter une méthodologie exacte et transparente.

---

## 7. Conclusion générale de l’EDA

L’analyse exploratoire unifiée montre que CIC-IDS2017 est un dataset volumineux, hétérogène et fortement déséquilibré. Les huit fichiers possèdent un schéma compatible, mais leur taille, leurs attaques et leurs problèmes de qualité diffèrent.

Les principales difficultés identifiées sont :

* la forte domination du trafic `BENIGN` ;
* la rareté de certaines attaques ;
* la présence de valeurs manquantes et infinies ;
* l’existence de nombreuses lignes dupliquées dans certains fichiers ;
* les fortes différences d’échelle entre les variables ;
* la présence de valeurs extrêmes qui peuvent être légitimes dans un contexte de cybersécurité.

Ces constats justifient la phase suivante : fusion contrôlée, correction des valeurs invalides, traitement des doublons, séparation des données, normalisation, sélection de caractéristiques et rééquilibrage réservé aux données d’entraînement.

---

## 8. Formulation professionnelle courte

> L’analyse exploratoire a été appliquée de manière unifiée aux huit fichiers du dataset CIC-IDS2017. Une analyse comparative a d’abord permis d’évaluer la structure, la qualité et la distribution des classes de chaque fichier. Les résultats ont ensuite été agrégés afin d’obtenir une vision globale du dataset. Pour les calculs plus coûteux, notamment les statistiques descriptives, les corrélations et la détection des valeurs aberrantes, un échantillon reproductible de 200 000 observations a été constitué à raison de 25 000 observations par fichier. Cette démarche garantit la représentation de tous les scénarios tout en maîtrisant la consommation des ressources informatiques.
>
