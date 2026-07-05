import pandas as pd
from pathlib import Path

print("=" * 80)
print("ÉTAPE 1 : FUSION DES FICHIERS CSV")
print("=" * 80)

# Chemin du projet
project_root = Path(__file__).resolve().parents[1]

# Dossier contenant les fichiers CSV originaux
data_dir = project_root / "data" / "raw" / "CIC-IDS2017" / "MachineLearningCVE"

print("Dossier recherché :", data_dir)
print("Le dossier existe :", data_dir.exists())

# Récupérer tous les fichiers CSV
csv_files = list(data_dir.glob("*.csv"))

if len(csv_files) == 0:
    raise FileNotFoundError("Aucun fichier CSV trouvé. Vérifiez le chemin du dataset.")
print(f"Nombre de fichiers trouvés : {len(csv_files)}")

dataframes = []

for file in csv_files:
    print(f"Chargement : {file.name}")
    df_temp = pd.read_csv(file, low_memory=False)

    # Nettoyage des noms de colonnes
    df_temp.columns = df_temp.columns.str.strip()

    dataframes.append(df_temp)

# Fusionner tous les fichiers
df = pd.concat(dataframes, ignore_index=True)

print("\nFusion terminée avec succès.")
print("Nombre total de lignes :", df.shape[0])
print("Nombre total de colonnes :", df.shape[1])

print("\nColonnes du dataset :")
print(df.columns.tolist())

# Sauvegarde du dataset fusionné
interim_dir = project_root / "data" / "interim"
interim_dir.mkdir(parents=True, exist_ok=True)

output_path = interim_dir / "merged_cicids2017.csv"
df.to_csv(output_path, index=False)

print("\nDataset fusionné sauvegardé ici :")
print(output_path)

print("\n" + "=" * 80)
print("ÉTAPE 2 : CORRECTION DES LABELS")
print("=" * 80)

# Vérifier que la colonne Label existe
label_col = "Label"

print("Labels avant correction :")
print(df[label_col].unique())

# Nettoyage des labels
df[label_col] = df[label_col].astype(str).str.strip()

# Correction du caractère mal encodé
df[label_col] = df[label_col].str.replace("�", "-", regex=False)

# Correction des espaces autour du tiret
df[label_col] = df[label_col].str.replace(" - ", " - ", regex=False)

print("\nLabels après correction :")
print(df[label_col].unique())

print("\nCorrection des labels terminée avec succès.")


import numpy as np

print("\n" + "=" * 80)
print("ÉTAPE 3 : TRAITEMENT DES VALEURS INFINIES")
print("=" * 80)

# Sélection des colonnes numériques
numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns

# Compter les valeurs infinies avant traitement
total_inf_before = np.isinf(df[numeric_cols]).sum().sum()
print("Nombre total de valeurs infinies avant traitement :", total_inf_before)

# Remplacer les valeurs infinies par NaN
df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

# Vérifier après traitement
total_inf_after = np.isinf(df[numeric_cols]).sum().sum()
print("Nombre total de valeurs infinies après traitement :", total_inf_after)

print("Traitement des valeurs infinies terminé avec succès.")


print("\n" + "=" * 80)
print("ÉTAPE 4 : REMPLISSAGE DES VALEURS MANQUANTES")
print("=" * 80)

# Compter les valeurs manquantes avant remplissage
missing_before = df.isnull().sum().sum()
print("Nombre total de valeurs manquantes avant remplissage :", missing_before)

# Afficher les colonnes contenant des valeurs manquantes
missing_by_column = df.isnull().sum()
missing_columns = missing_by_column[missing_by_column > 0]

print("\nColonnes avec valeurs manquantes avant remplissage :")
print(missing_columns)

# Remplissage des valeurs manquantes numériques par la médiane
numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns

for col in numeric_cols:
    if df[col].isnull().sum() > 0:
        median_value = df[col].median()
        df[col] = df[col].fillna(median_value)

# Vérification après remplissage
missing_after = df.isnull().sum().sum()
print("\nNombre total de valeurs manquantes après remplissage :", missing_after)

print("Remplissage des valeurs manquantes terminé avec succès.")


print("\n" + "=" * 80)
print("ÉTAPE 5 : SUPPRESSION DES DOUBLONS ET RÉDUCTION DU BRUIT")
print("=" * 80)

# Nombre de lignes avant suppression
rows_before = df.shape[0]
print("Nombre de lignes avant suppression des doublons :", rows_before)

# Nombre de doublons
duplicates_count = df.duplicated().sum()
duplicates_percentage = (duplicates_count / rows_before) * 100

print("Nombre de lignes dupliquées :", duplicates_count)
print(f"Pourcentage de doublons : {duplicates_percentage:.2f}%")

# Suppression des doublons
df = df.drop_duplicates()

# Nombre de lignes après suppression
rows_after = df.shape[0]
print("Nombre de lignes après suppression des doublons :", rows_after)

# Nombre de lignes supprimées
removed_rows = rows_before - rows_after
print("Nombre de lignes supprimées :", removed_rows)

print("Suppression des doublons et réduction du bruit terminées avec succès.")


from sklearn.preprocessing import LabelEncoder

print("\n" + "=" * 80)
print("ÉTAPE 6 : LABELLISATION DE LA VARIABLE CIBLE")
print("=" * 80)

# Vérification de la colonne cible
label_col = "Label"

print("Classes avant labellisation :")
print(df[label_col].value_counts())

# Création du LabelEncoder
label_encoder = LabelEncoder()

# Transformation des labels texte en nombres
df["Label_Encoded"] = label_encoder.fit_transform(df[label_col])

print("\nCorrespondance entre labels et valeurs numériques :")
for label, encoded_value in zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)):
    print(f"{label} -> {encoded_value}")

print("\nAperçu après labellisation :")
print(df[[label_col, "Label_Encoded"]].head())

print("\nLabellisation terminée avec succès.")


print("\n" + "=" * 80)
print("ÉTAPE 7 : FEATURE ENGINEERING ET SÉLECTION DES CARACTÉRISTIQUES")
print("=" * 80)

# Séparation initiale des variables
X = df.drop(columns=["Label", "Label_Encoded"])
y = df["Label_Encoded"]

print("Nombre de caractéristiques avant sélection :", X.shape[1])

# Détection des colonnes constantes
constant_columns = [col for col in X.columns if X[col].nunique() <= 1]

print("Nombre de colonnes constantes détectées :", len(constant_columns))

if len(constant_columns) > 0:
    print("Colonnes constantes supprimées :")
    print(constant_columns)

# Suppression des colonnes constantes
X = X.drop(columns=constant_columns)

print("Nombre de caractéristiques après suppression des colonnes constantes :", X.shape[1])

print("\nDimensions finales après feature engineering :")
print("X :", X.shape)
print("y :", y.shape)

print("Feature engineering terminé avec succès.")


from sklearn.model_selection import train_test_split

print("\n" + "=" * 80)
print("ÉTAPE 8 : SÉPARATION TRAIN / TEST")
print("=" * 80)

# Séparation des données en entraînement et test
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Dimensions des données d'entraînement :")
print("X_train :", X_train.shape)
print("y_train :", y_train.shape)

print("\nDimensions des données de test :")
print("X_test :", X_test.shape)
print("y_test :", y_test.shape)

print("\nRépartition des classes dans y_train :")
print(y_train.value_counts().sort_index())

print("\nRépartition des classes dans y_test :")
print(y_test.value_counts().sort_index())

print("\nSéparation Train/Test terminée avec succès.")


from sklearn.preprocessing import StandardScaler

print("\n" + "=" * 80)
print("ÉTAPE 9 : NORMALISATION DES DONNÉES")
print("=" * 80)

# Création du scaler
scaler = StandardScaler()

# Apprentissage de la normalisation uniquement sur X_train
X_train_scaled = scaler.fit_transform(X_train)

# Application de la même transformation sur X_test
X_test_scaled = scaler.transform(X_test)

print("Normalisation terminée avec succès.")

print("\nDimensions après normalisation :")
print("X_train_scaled :", X_train_scaled.shape)
print("X_test_scaled  :", X_test_scaled.shape)

print("\nExemple des 5 premières lignes normalisées :")
print(X_train_scaled[:5])


from sklearn.utils.class_weight import compute_class_weight

print("\n" + "=" * 80)
print("ÉTAPE 10 : GESTION DU DÉSÉQUILIBRE DES CLASSES")
print("=" * 80)

# Classes présentes dans y_train
classes = np.unique(y_train)

# Calcul automatique des poids des classes
class_weights_values = compute_class_weight(
    class_weight="balanced",
    classes=classes,
    y=y_train
)

# Création du dictionnaire des poids
class_weights = dict(zip(classes, class_weights_values))

print("Poids des classes calculés :")
for class_id, weight in class_weights.items():
    print(f"Classe {class_id} -> poids : {weight:.4f}")

# Tableau de correspondance Label / Label_Encoded / Poids
label_mapping = pd.DataFrame({
    "Label": label_encoder.classes_,
    "Label_Encoded": label_encoder.transform(label_encoder.classes_)
})

weights_df = pd.DataFrame({
    "Label_Encoded": list(class_weights.keys()),
    "Class_Weight": list(class_weights.values())
})

class_weights_table = label_mapping.merge(weights_df, on="Label_Encoded")

print("\nTableau des poids des classes :")
print(class_weights_table)

# Sauvegarde des poids des classes
preprocessing_output_dir = project_root / "outputs" / "preprocessing"
preprocessing_output_dir.mkdir(parents=True, exist_ok=True)

class_weights_path = preprocessing_output_dir / "class_weights.csv"
class_weights_table.to_csv(class_weights_path, index=False)

print("\nPoids des classes sauvegardés ici :")
print(class_weights_path)

print("\nGestion du déséquilibre des classes terminée avec succès.")


import joblib

print("\n" + "=" * 80)
print("ÉTAPE 11 : SAUVEGARDE FINALE DES DONNÉES PRÉTRAITÉES")
print("=" * 80)

# Création du dossier de sortie
processed_dir = project_root / "data" / "processed"
processed_dir.mkdir(exist_ok=True)

# Conversion en float32 pour réduire la taille des fichiers
X_train_scaled = X_train_scaled.astype("float32")
X_test_scaled = X_test_scaled.astype("float32")

# Sauvegarde des données train/test normalisées
np.savez_compressed(
    processed_dir / "train_test_data.npz",
    X_train=X_train_scaled,
    X_test=X_test_scaled,
    y_train=y_train.to_numpy(),
    y_test=y_test.to_numpy()
)

# Sauvegarde du scaler
joblib.dump(scaler, processed_dir / "scaler.joblib")

# Sauvegarde de l'encodeur des labels
joblib.dump(label_encoder, processed_dir / "label_encoder.joblib")

# Sauvegarde des noms des caractéristiques sélectionnées
features_path = processed_dir / "selected_features.csv"
pd.DataFrame({"Feature": X.columns}).to_csv(features_path, index=False)

# Sauvegarde des poids des classes
class_weights_table.to_csv(processed_dir / "class_weights.csv", index=False)

print("Données prétraitées sauvegardées dans :")
print(processed_dir)

print("\nFichiers générés :")
print("- train_test_data.npz")
print("- scaler.joblib")
print("- label_encoder.joblib")
print("- selected_features.csv")
print("- class_weights.csv")

print("\nPrétraitement terminé avec succès.")