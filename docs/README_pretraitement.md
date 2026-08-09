# Partie Pretraitement - CIC-IDS2017

## Objectif

Cette partie presente les etapes de pretraitement appliquees au jeu de donnees CIC-IDS2017 dans le cadre du projet de detection intelligente et automatisee des cyberattaques basee sur l'intelligence artificielle.

L'objectif du pretraitement est de transformer les donnees brutes en donnees propres, coherentes et exploitables par les modeles d'apprentissage automatique.

Le pretraitement est une etape essentielle, car les donnees brutes contiennent plusieurs problemes : valeurs infinies, valeurs manquantes, doublons, classes desequilibrees et variables avec des ordres de grandeur tres differents.

## Jeu de donnees utilise

Le dataset utilise est CIC-IDS2017. Il contient du trafic reseau normal et plusieurs types d'attaques modernes.

Les donnees sont composees de huit fichiers CSV :

| Fichier | Role |
| --- | --- |
| Monday | Trafic normal principalement BENIGN |
| Tuesday | Attaques FTP-Patator et SSH-Patator |
| Wednesday | Attaques DoS |
| Thursday-Morning-WebAttacks | Attaques Web |
| Thursday-Afternoon-Infiltration | Attaque Infiltration |
| Friday-Morning | Botnet |
| Friday-Afternoon-PortScan | PortScan |
| Friday-Afternoon-DDoS | DDoS |

Apres la fusion, le dataset global contient 2 830 743 observations et 79 colonnes.

## Pipeline general du pretraitement

Le pretraitement suit les etapes suivantes :

1. Chargement des huit fichiers CSV
2. Fusion des fichiers dans un seul dataset global
3. Correction et uniformisation des labels
4. Analyse du desequilibre des classes
5. Traitement des valeurs infinies
6. Detection des valeurs manquantes
7. Suppression des doublons
8. Suppression des variables inutiles ou constantes
9. Separation stratifiee Train/Test
10. Imputation des valeurs manquantes
11. Normalisation Min-Max
12. Prise en compte du desequilibre des classes
13. Sauvegarde des donnees finales

## 1. Chargement et fusion des fichiers

Les huit fichiers CSV du dataset CIC-IDS2017 sont charges puis fusionnes dans un seul dataset global.

Cette etape permet de regrouper toutes les observations dans une structure unique afin de faciliter l'analyse, le nettoyage et la preparation des donnees.

Avant la fusion, les colonnes sont verifiees pour s'assurer que les fichiers possedent la meme structure.

### Pourquoi cette methode ?

La fusion des huit fichiers est necessaire, car CIC-IDS2017 est distribue par jour et par type de trafic. Pour entrainer un modele capable de reconnaitre plusieurs attaques, il faut travailler sur une base globale qui contient toutes les classes.

### Pourquoi pas traiter chaque fichier separement ?

Traiter chaque fichier seul limiterait la vision du modele. Par exemple, un modele entraine seulement sur le fichier DDoS ne pourrait pas bien apprendre les autres attaques comme PortScan, Web Attack ou Botnet. La fusion permet donc une preparation plus complete et plus coherente.

## 2. Correction et uniformisation des labels

Les labels representent les classes du dataset, par exemple BENIGN, DoS Hulk, PortScan, DDoS, Bot, Web Attack et Infiltration.

Certains labels peuvent contenir des espaces, des differences d'ecriture ou des caracteres inutiles. Ils sont donc corriges et uniformises pour eviter la creation de fausses classes.

### Pourquoi cette methode ?

Cette methode garantit que chaque attaque possede un nom unique et stable. Par exemple, deux labels qui designent la meme attaque ne doivent pas etre consideres comme deux classes differentes a cause d'un espace ou d'une difference d'ecriture.

### Pourquoi pas garder les labels bruts ?

Garder les labels bruts peut creer des erreurs dans la distribution des classes et dans l'entrainement du modele. Le modele risque alors d'apprendre des classes incorrectes ou dupliquees.

## 3. Analyse du desequilibre des classes

L'analyse de la distribution des classes montre que le dataset CIC-IDS2017 est fortement desequilibre.

La classe BENIGN est majoritaire avec environ 80,30 % des observations. En revanche, certaines attaques sont tres rares, comme SQL Injection, Infiltration et Heartbleed.

Ce desequilibre peut influencer les modeles d'apprentissage automatique, car un modele peut favoriser les classes majoritaires et mal detecter les attaques rares.

### Pourquoi cette analyse ?

Elle permet de comprendre la repartition reelle des classes avant la modelisation. Dans un projet de detection d'intrusion, il ne suffit pas d'obtenir une bonne accuracy globale. Il faut aussi verifier si les attaques rares sont bien prises en compte.

### Pourquoi pas ignorer le desequilibre ?

Si le desequilibre est ignore, un modele peut obtenir une bonne accuracy simplement en favorisant la classe BENIGN, tout en detectant mal les attaques minoritaires. Cela serait dangereux dans un contexte de cybersurveillance.

## 4. Nettoyage initial des donnees

Le nettoyage initial permet de corriger les principaux problemes presents dans les donnees brutes.

Les problemes traites sont :

| Probleme | Traitement applique |
| --- | --- |
| Valeurs infinies | Remplacement par des valeurs manquantes NaN |
| Valeurs manquantes | Detection avant imputation |
| Doublons | Suppression des observations dupliquees |
| Variables inutiles ou constantes | Suppression lorsqu'elles n'apportent pas d'information |

Les valeurs infinies apparaissent souvent dans les variables liees au debit reseau, comme Flow Bytes/s et Flow Packets/s. Elles peuvent etre causees par une division par zero ou par une duree de flux egale a zero.

Les valeurs infinies sont converties en valeurs manquantes. Leur remplacement final est effectue apres la separation Train/Test afin d'eviter la fuite d'information.

### Pourquoi remplacer les valeurs infinies par NaN ?

Les valeurs infinies ne sont pas exploitables directement par la plupart des algorithmes de machine learning. Les convertir en NaN permet de les traiter avec la meme strategie que les valeurs manquantes.

### Pourquoi pas remplacer directement par zero ?

Remplacer directement par zero peut introduire une fausse information. Zero peut avoir une signification reelle pour certaines variables reseau. Il est donc plus prudent de convertir d'abord en NaN, puis d'utiliser une methode d'imputation adaptee.

### Pourquoi supprimer les doublons ?

Les doublons peuvent donner trop d'importance a certaines observations et biaiser l'apprentissage du modele. Leur suppression reduit la redondance et rend le dataset plus fiable.

### Pourquoi supprimer les variables constantes ?

Une variable constante ne permet pas de distinguer les classes, car elle garde la meme valeur pour toutes les observations. Elle n'apporte donc pas d'information utile au modele.

## 5. Separation stratifiee Train/Test

Apres le nettoyage initial, les donnees sont separees en deux ensembles :

| Ensemble | Role |
| --- | --- |
| Train | Utilise pour apprendre les transformations et entrainer les modeles |
| Test | Utilise uniquement pour l'evaluation finale |

La separation est realisee de maniere stratifiee. Cela signifie que la proportion des classes est conservee dans Train et Test.

Dans ce travail, la separation retenue est Train/Test, avec 70 % pour Train et 30 % pour Test.

Les transformations comme l'imputation et la normalisation sont apprises uniquement sur l'ensemble Train, puis appliquees sur Test. Cela evite la fuite d'information.

### Pourquoi une separation stratifiee ?

La stratification est importante, car CIC-IDS2017 contient des classes tres desequilibrees. Elle permet de conserver la proportion des classes dans Train et Test, y compris pour les attaques rares.

### Pourquoi pas une separation aleatoire simple ?

Une separation aleatoire simple peut mal repartir les classes rares. Certaines attaques peu representees peuvent se retrouver presque absentes de Train ou de Test. Cela rendrait l'entrainement ou l'evaluation moins fiable.

### Pourquoi Train/Test et pas Train/Validation/Test ?

Dans cette version du travail, l'objectif principal est la preparation des donnees pour la modelisation. Le choix retenu est donc une separation simple Train/Test. La validation peut etre realisee plus tard pendant la phase de modelisation, par exemple avec une cross-validation sur Train.

## 6. Imputation des valeurs manquantes

L'imputation consiste a remplacer les valeurs manquantes par des valeurs estimees.

Dans ce travail, plusieurs methodes d'imputation ont ete comparees :

| Methode | Principe |
| --- | --- |
| Moyenne | Remplace les valeurs manquantes par la moyenne de la variable |
| Mediane | Remplace les valeurs manquantes par la valeur centrale |
| Valeur frequente | Remplace les valeurs manquantes par la valeur la plus frequente |
| Zero | Remplace les valeurs manquantes par 0 |
| KNN | Estime les valeurs a partir des observations les plus proches |
| Random Forest | Estime les valeurs a l'aide de plusieurs arbres de decision |
| VAE | Estime les valeurs a partir d'un modele generatif |

Les methodes ont ete comparees par cross-validation avec deux metriques :

| Metrique | Signification |
| --- | --- |
| NRMSE | Mesure l'erreur quadratique normalisee |
| NMAE | Mesure l'erreur absolue moyenne normalisee |

La methode retenue est Random Forest, car elle donne les erreurs les plus faibles :

| Methode retenue | NRMSE | NMAE |
| --- | --- | --- |
| Random Forest | 25.200 | 0.693 |

### Pourquoi Random Forest ?

Random Forest est retenue car elle prend en compte les relations entre les variables numeriques. Elle peut estimer une valeur manquante a partir de plusieurs caracteristiques du flux reseau, ce qui donne une estimation plus pertinente que les methodes simples.

### Pourquoi pas la moyenne ?

La moyenne est rapide, mais elle est sensible aux valeurs extremes. Dans CIC-IDS2017, certaines variables reseau peuvent avoir de grands ecarts de valeurs. La moyenne peut donc produire une estimation moins representative.

### Pourquoi pas la mediane ?

La mediane est plus robuste que la moyenne face aux valeurs extremes, mais elle reste une methode simple. Elle ne prend pas en compte les relations entre les variables.

### Pourquoi pas la valeur frequente ?

La valeur frequente est surtout utile pour des variables categorielles. Dans ce projet, les donnees sont principalement numeriques, donc cette methode est moins adaptee.

### Pourquoi pas zero ?

Zero est simple, mais il peut changer le sens des donnees. Pour certaines caracteristiques reseau, zero peut etre une vraie valeur et non une valeur estimee. Cela peut introduire un biais.

### Pourquoi pas KNN ?

KNN peut donner de bons resultats, mais il devient couteux sur un dataset tres volumineux comme CIC-IDS2017. Il doit chercher les observations les plus proches, ce qui demande beaucoup de temps et de memoire.

### Pourquoi pas VAE ?

Le VAE est une methode avancee basee sur les reseaux de neurones. Cependant, elle est plus complexe a configurer et demande plus de ressources. Dans ce travail, Random Forest donne de meilleurs resultats tout en restant plus interpretable.

## 7. Normalisation Min-Max

Apres l'imputation, les variables numeriques sont normalisees avec la methode Min-Max.

La normalisation Min-Max permet de ramener les valeurs numeriques dans l'intervalle [0, 1].

La formule utilisee est :

```text
X_normalise = (X - X_min) / (X_max - X_min)
```

Cette etape est importante, car les variables du dataset n'ont pas les memes unites ni les memes ordres de grandeur.

Les parametres de normalisation sont appris uniquement sur l'ensemble Train. Ensuite, les memes parametres sont appliques sur l'ensemble Test.

### Pourquoi Min-Max ?

Min-Max garde les valeurs dans un intervalle clair et fixe : [0, 1]. Cela facilite l'apprentissage des modeles sensibles a l'echelle des variables et rend les caracteristiques comparables.

### Pourquoi pas la standardisation ?

La standardisation transforme les donnees autour d'une moyenne de 0 et d'un ecart-type de 1. Elle est utile dans certains cas, mais elle ne garantit pas un intervalle fixe. Dans ce travail, Min-Max est retenue pour obtenir des donnees normalisees dans une plage simple et controlee.

### Pourquoi pas garder les valeurs brutes ?

Garder les valeurs brutes peut poser probleme, car certaines variables ont des valeurs tres grandes et d'autres tres petites. Les variables avec de grandes valeurs peuvent alors dominer l'apprentissage.

## 8. Prise en compte du desequilibre des classes

Le desequilibre des classes est pris en compte avec la methode :

```text
class_weight="balanced"
```

Cette methode ne modifie pas directement le nombre d'observations dans le dataset. Elle attribue plutot des poids differents aux classes pendant l'apprentissage.

Les classes minoritaires recoivent des poids plus eleves, tandis que les classes majoritaires recoivent des poids plus faibles.

Cette strategie permet au modele de mieux prendre en compte les attaques rares, sans modifier la distribution reelle de l'ensemble Test.

Le reequilibrage par ponderation est applique uniquement sur l'ensemble Train.

### Pourquoi class_weight="balanced" ?

Cette methode est adaptee car elle corrige l'influence des classes pendant l'apprentissage sans modifier les donnees. Les attaques rares gardent leur place dans le dataset, mais le modele leur donne plus d'importance.

### Pourquoi pas SMOTE ?

SMOTE cree de nouvelles observations synthetiques pour les classes minoritaires. Cette methode peut etre utile, mais elle peut aussi generer des flux reseau artificiels qui ne representent pas toujours la realite. Dans ce travail, on prefere garder un Test realiste et utiliser une ponderation sur Train.

### Pourquoi pas le sous-echantillonnage ?

Le sous-echantillonnage supprime une partie des classes majoritaires. Dans CIC-IDS2017, cela peut faire perdre beaucoup d'informations, surtout pour la classe BENIGN qui represente le trafic normal.

### Pourquoi pas appliquer le reequilibrage sur Test ?

Le Test doit rester realiste pour evaluer le modele dans des conditions proches de la realite. Modifier le Test donnerait une evaluation moins fiable.

## 9. Sauvegarde des donnees finales

A la fin du pretraitement, les donnees propres sont sauvegardees afin d'etre utilisees dans la phase de modelisation.

Les fichiers generes sont :

| Fichier | Role |
| --- | --- |
| X_train_final.csv | Caracteristiques de l'ensemble Train apres pretraitement |
| X_test_final.csv | Caracteristiques de l'ensemble Test apres pretraitement |
| y_train.csv | Labels de l'ensemble Train |
| y_test.csv | Labels de l'ensemble Test |

Cette organisation separe les caracteristiques et les labels, ce qui facilite l'entrainement et l'evaluation des modeles.

### Pourquoi sauvegarder les donnees finales ?

La sauvegarde permet de reutiliser directement les donnees preparees dans la phase de modelisation. Elle evite aussi de refaire toutes les etapes de pretraitement a chaque execution.

### Pourquoi separer X et y ?

Les fichiers X contiennent les caracteristiques utilisees par les modeles. Les fichiers y contiennent les classes a predire. Cette separation correspond a la structure classique utilisee en apprentissage automatique.

## Resume des choix methodologiques

| Partie | Methode retenue | Pourquoi ce choix ? | Pourquoi pas une autre ? |
| --- | --- | --- | --- |
| Fusion des fichiers | Fusion des 8 CSV | Obtenir un dataset global avec toutes les classes | Traiter chaque fichier seul limiterait l'apprentissage |
| Labels | Correction et uniformisation | Eviter les fausses classes | Garder les labels bruts peut creer des doublons de classes |
| Valeurs infinies | Conversion en NaN | Les traiter proprement avec l'imputation | Zero peut introduire une fausse information |
| Doublons | Suppression | Reduire la redondance | Les garder peut biaiser l'apprentissage |
| Variables constantes | Suppression | Elles n'apportent aucune information | Les garder augmente la taille sans gain |
| Separation | Train/Test stratifie | Conserver la proportion des classes | Une separation simple peut mal repartir les attaques rares |
| Imputation | Random Forest | Meilleurs resultats NRMSE/NMAE et relations entre variables | Moyenne, mediane, zero sont trop simples; KNN/VAE sont plus lourds |
| Normalisation | Min-Max | Ramener les valeurs dans [0, 1] | La standardisation ne donne pas une plage fixe |
| Desequilibre | class_weight="balanced" | Donner plus d'importance aux classes rares sans modifier Test | SMOTE cree des donnees synthetiques; sous-echantillonnage supprime des donnees |
| Sauvegarde | X_train, X_test, y_train, y_test | Faciliter la modelisation | Un seul fichier serait moins pratique |

## Points importants a retenir

- Le pretraitement est applique pour rendre les donnees propres et exploitables.
- Les valeurs infinies sont converties en valeurs manquantes.
- L'imputation est realisee apres la separation Train/Test pour eviter la fuite d'information.
- Random Forest est retenue pour l'imputation des valeurs manquantes.
- La normalisation utilisee est Min-Max.
- Le desequilibre des classes est traite avec class_weight="balanced".
- Le reequilibrage ne modifie pas directement le nombre de lignes.
- Le Test est garde realiste et n'est pas modifie par SMOTE ou sous-echantillonnage.

## Conclusion

La partie pretraitement a permis de transformer les donnees brutes du dataset CIC-IDS2017 en donnees propres, structurees et pretes pour la modelisation.

Les principales operations realisees sont la fusion des fichiers, la correction des labels, le nettoyage des valeurs infinies et des doublons, la separation stratifiee Train/Test, l'imputation par Random Forest, la normalisation Min-Max et la prise en compte du desequilibre des classes avec class_weight="balanced".

Les choix effectues sont justifies par la nature du dataset CIC-IDS2017 : volume important, classes desequilibrees, variables numeriques heterogenes et presence de valeurs problematiques. Ces donnees finales peuvent maintenant etre utilisees pour entrainer et evaluer les modeles de detection des cyberattaques.
