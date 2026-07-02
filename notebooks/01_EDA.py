import pandas as pd
from pathlib import Path

# Chemin du projet
project_root = Path(__file__).resolve().parents[1]

# Chemin vers le dataset
file_path = project_root / "CIC-IDS2017" / "MachineLearningCVE" / "Wednesday-workingHours.pcap_ISCX.csv"

print("=" * 60)
print("CHARGEMENT DU DATASET")
print("=" * 60)
print("Fichier utilisé :", file_path)

# Chargement du fichier CSV
df = pd.read_csv(file_path)

print("\nDataset chargé avec succès !")

print("\n" + "=" * 60)
print("DIMENSIONS DU DATASET")
print("=" * 60)
print("Nombre de lignes   :", df.shape[0])
print("Nombre de colonnes :", df.shape[1])

print("\n" + "=" * 60)
print("LISTE DES COLONNES")
print("=" * 60)

for i, col in enumerate(df.columns, start=1):
    print(f"{i}. {col}")

print("\n" + "=" * 60)
print("TYPES DES COLONNES")
print("=" * 60)

print(df.dtypes)

print("\n" + "=" * 60)
print("VALEURS MANQUANTES")
print("=" * 60)

# Nombre total de valeurs manquantes dans tout le dataset
total_missing = df.isnull().sum().sum()
print("Nombre total de valeurs manquantes :", total_missing)

# Valeurs manquantes par colonne
missing_by_column = df.isnull().sum()

# Afficher seulement les colonnes qui contiennent des valeurs manquantes
missing_columns = missing_by_column[missing_by_column > 0]

print("\nColonnes contenant des valeurs manquantes :")
print(missing_columns)

if missing_columns.empty:
    print("Aucune valeur manquante détectée.")


print("\n" + "=" * 60)
print("VALEURS DUPLIQUÉES")
print("=" * 60)

# Nombre total de lignes dupliquées
duplicates_count = df.duplicated().sum()

print("Nombre de lignes dupliquées :", duplicates_count)

# Pourcentage de doublons
duplicates_percentage = (duplicates_count / df.shape[0]) * 100

print(f"Pourcentage de doublons : {duplicates_percentage:.2f}%")

print("\n" + "=" * 60)
print("ANALYSE DE LA VARIABLE CIBLE")
print("=" * 60)

# Détection automatique de la colonne Label
label_col = [col for col in df.columns if col.strip() == "Label"][0]

print("Nom exact de la colonne cible :", label_col)

# Nombre de classes différentes
nombre_classes = df[label_col].nunique()
print("Nombre de classes :", nombre_classes)

# Liste des classes
print("\nClasses présentes dans le dataset :")
print(df[label_col].unique())

# Répartition des classes
print("\nRépartition des classes :")
print(df[label_col].value_counts())

print("\n" + "=" * 60)
print("DÉSÉQUILIBRE DES CLASSES")
print("=" * 60)

# Nombre d'exemples par classe
class_counts = df[label_col].value_counts()

# Pourcentage par classe
class_percentages = (class_counts / len(df)) * 100

# Créer un tableau récapitulatif
class_distribution = pd.DataFrame({
    "Nombre": class_counts,
    "Pourcentage (%)": class_percentages.round(4)
})

print(class_distribution)


import matplotlib.pyplot as plt

print("\n" + "=" * 60)
print("VISUALISATION DU DÉSÉQUILIBRE DES CLASSES")
print("=" * 60)

# Création du graphique
plt.figure(figsize=(10, 6))
class_counts.plot(kind="bar")

plt.title("Répartition des classes - Wednesday CIC-IDS2017")
plt.xlabel("Classes")
plt.ylabel("Nombre d'observations")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()

# Sauvegarde du graphique
output_path = project_root / "class_distribution_wednesday.png"
plt.savefig(output_path)

print("Graphique sauvegardé ici :", output_path)


import numpy as np

print("\n" + "=" * 60)
print("VALEURS INFINIES")
print("=" * 60)

# Sélection des colonnes numériques
numeric_df = df.select_dtypes(include=["int64", "float64"])

# Nombre total de valeurs infinies
total_inf = np.isinf(numeric_df).sum().sum()
print("Nombre total de valeurs infinies :", total_inf)

# Valeurs infinies par colonne
inf_by_column = np.isinf(numeric_df).sum()
inf_columns = inf_by_column[inf_by_column > 0]

print("\nColonnes contenant des valeurs infinies :")
print(inf_columns)

if inf_columns.empty:
    print("Aucune valeur infinie détectée.")


print("\n" + "=" * 60)
print("ANALYSE DES CORRÉLATIONS")
print("=" * 60)

# Préparer les données numériques pour la corrélation
numeric_corr_df = df.select_dtypes(include=["int64", "float64"]).copy()

# Remplacer les valeurs infinies par NaN uniquement pour l'analyse
numeric_corr_df = numeric_corr_df.replace([np.inf, -np.inf], np.nan)

# Calcul de la matrice de corrélation
corr_matrix = numeric_corr_df.corr()

print("Matrice de corrélation calculée avec succès.")
print("Taille de la matrice :", corr_matrix.shape)

# Sauvegarde de la matrice de corrélation en CSV
corr_csv_path = project_root / "correlation_matrix_wednesday.csv"
corr_matrix.to_csv(corr_csv_path)

print("Matrice de corrélation sauvegardée ici :", corr_csv_path)

# Recherche des corrélations fortes
strong_corr = []

columns = corr_matrix.columns

for i in range(len(columns)):
    for j in range(i + 1, len(columns)):
        corr_value = corr_matrix.iloc[i, j]
        if abs(corr_value) >= 0.90:
            strong_corr.append((columns[i], columns[j], corr_value))

strong_corr_df = pd.DataFrame(
    strong_corr,
    columns=["Feature 1", "Feature 2", "Correlation"]
)

print("\nNombre de corrélations fortes détectées :", len(strong_corr_df))

print("\nTop 20 des corrélations fortes :")
print(strong_corr_df.sort_values(by="Correlation", ascending=False).head(20))

# Sauvegarde des corrélations fortes
strong_corr_path = project_root / "strong_correlations_wednesday.csv"
strong_corr_df.to_csv(strong_corr_path, index=False)

print("\nCorrélations fortes sauvegardées ici :", strong_corr_path)

# Génération d'une heatmap avec Matplotlib
plt.figure(figsize=(18, 14))
plt.imshow(corr_matrix, aspect="auto")
plt.colorbar(label="Coefficient de corrélation")

plt.title("Matrice de corrélation - Wednesday CIC-IDS2017")
plt.xticks(range(len(corr_matrix.columns)), corr_matrix.columns, rotation=90, fontsize=6)
plt.yticks(range(len(corr_matrix.columns)), corr_matrix.columns, fontsize=6)
plt.tight_layout()

heatmap_path = project_root / "correlation_heatmap_wednesday.png"
plt.savefig(heatmap_path, dpi=300)

print("Heatmap de corrélation sauvegardée ici :", heatmap_path)