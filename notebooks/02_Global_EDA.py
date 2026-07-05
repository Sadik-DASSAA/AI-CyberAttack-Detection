import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

# Chemin du projet
project_root = Path(__file__).resolve().parents[1]

# Dossier de sortie pour les résultats EDA
output_dir = project_root / "outputs" / "eda"
output_dir.mkdir(parents=True, exist_ok=True)

# Dossier contenant les fichiers CSV
data_dir = project_root / "data" / "raw" / "CIC-IDS2017" / "MachineLearningCVE"

# Récupération de tous les fichiers CSV
csv_files = list(data_dir.glob("*.csv"))

print("=" * 80)
print("ANALYSE GLOBALE DU DATASET CIC-IDS2017")
print("=" * 80)
print(f"Nombre de fichiers CSV trouvés : {len(csv_files)}")

summary = []
global_class_counts = pd.Series(dtype="int64")

for file_path in csv_files:
    print("\n" + "=" * 80)
    print(f"Analyse du fichier : {file_path.name}")
    print("=" * 80)

    df = pd.read_csv(file_path, low_memory=False)

    # Dimensions
    rows, cols = df.shape

    # Valeurs manquantes
    missing_total = df.isnull().sum().sum()

    # Doublons
    duplicates_count = df.duplicated().sum()
    duplicates_percentage = (duplicates_count / rows) * 100

    # Valeurs infinies
    numeric_df = df.select_dtypes(include=["int64", "float64"])
    inf_total = np.isinf(numeric_df).sum().sum()

    # Détection de la colonne Label
    label_col = [col for col in df.columns if col.strip() == "Label"][0]

    # Analyse des classes
    class_counts = df[label_col].value_counts()
    global_class_counts = global_class_counts.add(class_counts, fill_value=0)

    nb_classes = df[label_col].nunique()
    classes = ", ".join(df[label_col].unique())

    print(f"Lignes : {rows}")
    print(f"Colonnes : {cols}")
    print(f"Valeurs manquantes : {missing_total}")
    print(f"Valeurs infinies : {inf_total}")
    print(f"Doublons : {duplicates_count} ({duplicates_percentage:.2f}%)")
    print(f"Nombre de classes : {nb_classes}")
    print("Classes :", classes)

    summary.append({
        "Fichier": file_path.name,
        "Lignes": rows,
        "Colonnes": cols,
        "Valeurs manquantes": missing_total,
        "Valeurs infinies": inf_total,
        "Doublons": duplicates_count,
        "Pourcentage doublons (%)": round(duplicates_percentage, 2),
        "Nombre de classes": nb_classes,
        "Classes": classes
    })

# Création du tableau global
summary_df = pd.DataFrame(summary)

print("\n" + "=" * 80)
print("TABLEAU RÉCAPITULATIF GLOBAL")
print("=" * 80)
print(summary_df)

# Sauvegarde du tableau global
summary_path = output_dir / "global_eda_summary.csv"
summary_df.to_csv(summary_path, index=False)

print("\nTableau global sauvegardé ici :", summary_path)

# Distribution globale des classes
global_class_counts = global_class_counts.astype(int).sort_values(ascending=False)

global_distribution_df = pd.DataFrame({
    "Nombre": global_class_counts,
    "Pourcentage (%)": ((global_class_counts / global_class_counts.sum()) * 100).round(4)
})

print("\n" + "=" * 80)
print("DISTRIBUTION GLOBALE DES CLASSES")
print("=" * 80)
print(global_distribution_df)

# Sauvegarde distribution globale
global_distribution_path = output_dir / "global_class_distribution.csv"
global_distribution_df.to_csv(global_distribution_path)

print("\nDistribution globale sauvegardée ici :", global_distribution_path)

# Graphique global
plt.figure(figsize=(12, 7))
global_class_counts.plot(kind="bar")

plt.title("Distribution globale des classes - CIC-IDS2017")
plt.xlabel("Classes")
plt.ylabel("Nombre d'observations")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()

plot_path = output_dir / "global_class_distribution.png"
plt.savefig(plot_path, dpi=300)

print("Graphique global sauvegardé ici :", plot_path)

print("\nAnalyse globale terminée avec succès.")