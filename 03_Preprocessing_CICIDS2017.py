# Nom du fichier : 03_Preprocessing_CICIDS2017.py

import gc
import json
import logging
from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestRegressor
from sklearn.impute import KNNImputer, SimpleImputer
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.utils.class_weight import compute_class_weight

# ============================================================
# 0. CONFIGURATION ET RÈGLES VISUELLES D'ENREGISTREMENT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "CIC-IDS2017"
    / "MachineLearningCVE"
)

OUTPUT_DIR = PROJECT_ROOT / "outputs" / "preprocessing"
TABLES_DIR = OUTPUT_DIR / "tables"
FIGURES_DIR = OUTPUT_DIR / "figures"
PROOFS_DIR = OUTPUT_DIR / "proofs"
PROCESSED_DIR = OUTPUT_DIR / "processed"

EXPECTED_FILE_COUNT = 8
RANDOM_STATE = 42
DPI = 300

TRAIN_SIZE = 0.70
TEST_SIZE = 0.30
CV_FOLDS = 5

IMPUTATION_TARGETS = ["Flow Bytes/s", "Flow Packets/s"]
IMPUTATION_SAMPLE_SIZE = 50_000
IMPUTATION_MASK_SIZE = 2_000
OUTLIER_TOP_N = 15

SAVE_PREPROCESSED_DATASETS = True

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
TABLES_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)
PROOFS_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Configuration globale pour la lisibilité : polices agrandies, serrées et en gras
sns.set_theme(style="whitegrid")
plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
        "mathtext.fontset": "stixsans",
        "figure.titlesize": 20,
        "axes.titlesize": 18,
        "axes.labelsize": 14,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12,
        "legend.fontsize": 12,
        "legend.title_fontsize": 13,
        "figure.autolayout": False,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.1,
    }
)


# ============================================================
# JOURNAL D'EXECUTION ET FONCTIONS D'ENREGISTREMENT
# ============================================================

logger = logging.getLogger("PREPROCESSING_CICIDS2017")
logger.setLevel(logging.INFO)
logger.handlers.clear()

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)

file_handler = logging.FileHandler(
    OUTPUT_DIR / "preuve_execution_pretraitement.log",
    mode="w",
    encoding="utf-8",
)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)


def afficher_etape(numero, titre):
    separateur = "=" * 78
    logger.info("\n%s\nETAPE %s - %s\n%s", separateur, numero, titre, separateur)


def enregistrer_figure(nom):
    """Enregistre le graphique en appliquant le découpage propre et la résolution ajustée."""
    chemin = FIGURES_DIR / nom
    plt.tight_layout()
    plt.savefig(chemin, dpi=DPI, bbox_inches="tight")
    plt.close()
    logger.info("Graphique enregistre : %s", chemin)


def enregistrer_tableau(df, nom):
    chemin = TABLES_DIR / nom
    df.to_csv(chemin, index=False, encoding="utf-8-sig")
    logger.info("Tableau enregistre : %s", chemin)


def enregistrer_preuve(objet, nom):
    chemin = PROOFS_DIR / nom
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(objet, fichier, ensure_ascii=False, indent=4)
    logger.info("Preuve enregistree : %s", chemin)


def nom_court_fichier(nom):
    """Raccourcit fortement les noms pour optimiser l'espace sur les axes."""
    nom_lower = nom.lower()

    if "monday" in nom_lower:
        return "Monday"
    if "tuesday" in nom_lower:
        return "Tuesday"
    if "wednesday" in nom_lower:
        return "Wednesday"
    if "webattacks" in nom_lower:
        return "Thu-WebAttacks"
    if "infilteration" in nom_lower or "infiltration" in nom_lower:
        return "Thu-Infiltration"
    if "ddos" in nom_lower:
        return "Fri-DDoS"
    if "portscan" in nom_lower:
        return "Fri-PortScan"
    if "friday-workinghours-morning" in nom_lower:
        return "Fri-Morning"

    return Path(nom).stem


def nettoyer_labels_classes(serie):
    labels = (
        serie.fillna("LABEL_MANQUANT")
        .astype(str)
        .str.strip()
        .str.replace("\ufffd", "-", regex=False)
        .str.replace("–", "-", regex=False)
        .str.replace("—", "-", regex=False)
        .str.replace(r"\s+", " ", regex=True)
    )

    labels_lower = labels.str.lower()

    labels = labels.mask(
        labels_lower.str.contains(
            r"web\s*attack.*brute\s*force", regex=True, na=False
        ),
        "Web Attack - Brute Force",
    )
    labels = labels.mask(
        labels_lower.str.contains(
            r"web\s*attack.*sql\s*injection", regex=True, na=False
        ),
        "Web Attack - SQL Injection",
    )
    labels = labels.mask(
        labels_lower.str.contains(
            r"web\s*attack.*xss", regex=True, na=False
        ),
        "Web Attack - XSS",
    )

    return labels


def calculer_nrmse_nmae(y_vrai, y_pred, reference):
    iqr = np.nanpercentile(reference, 75) - np.nanpercentile(reference, 25)
    if iqr == 0 or np.isnan(iqr):
        iqr = np.nanstd(reference)
    if iqr == 0 or np.isnan(iqr):
        iqr = 1.0

    rmse = np.sqrt(np.mean((y_vrai - y_pred) ** 2))
    mae = np.mean(np.abs(y_vrai - y_pred))

    return rmse / iqr, mae / iqr


# ============================================================
# 1. WORKFLOW GENERAL DU PRETRAITEMENT
# ============================================================

afficher_etape(1, "Creation du workflow general du pretraitement")

workflow_steps = [
    "1. Charger 8 fichiers",
    "2. Harmoniser colonnes/labels",
    "3. Fusionner fichiers",
    "4. Remplacer +/-inf par NaN",
    "5. Supprimer doublons",
    "5B. Valeurs aberrantes",
    "6. Split Train/Test 70/30",
    "7. Analyser desequilibre",
    "8. CV sur Train",
    "9. Imputer NaN",
    "10. Supprimer constantes",
    "11. Normaliser features",
    "12. Reequilibrer (class_weight)",
    "13. Sauvegarder preuves",
]

fig, ax = plt.subplots(figsize=(18, 4.5))
ax.axis("off")
positions_x = np.linspace(0.05, 0.95, len(workflow_steps))

for index, (texte, pos_x) in enumerate(zip(workflow_steps, positions_x)):
    couleur = "#1F4E78" if index < 5 else "#008C95"

    ax.text(
        pos_x,
        0.5,
        texte,
        ha="center",
        va="center",
        fontsize=9,
        color="white",
        fontweight="bold",
        bbox=dict(
            boxstyle="round,pad=0.5",
            facecolor=couleur,
            edgecolor="white",
            linewidth=2,
        ),
    )

    if index < len(workflow_steps) - 1:
        ax.annotate(
            "",
            xy=(positions_x[index + 1] - 0.03, 0.5),
            xytext=(pos_x + 0.03, 0.5),
            arrowprops=dict(arrowstyle="->", color="#333333", linewidth=2),
        )

ax.set_title(
    "Workflow du pretraitement des donnees CIC-IDS2017",
    fontsize=18,
    fontweight="bold",
    pad=20,
)

enregistrer_figure("01_workflow_pretraitement.png")


# ============================================================
# 2. DETECTION ET CHARGEMENT DES HUIT FICHIERS
# ============================================================

afficher_etape(2, "Detection et chargement des fichiers CIC-IDS2017")

if not DATA_DIR.exists():
    raise FileNotFoundError(
        f"Dossier introuvable : {DATA_DIR}\n"
        "Verifiez la variable DATA_DIR au debut du script."
    )

csv_files = sorted(DATA_DIR.glob("*.csv"))

logger.info("Dossier des donnees : %s", DATA_DIR)
logger.info("Nombre de fichiers CSV detectes : %d", len(csv_files))

if len(csv_files) != EXPECTED_FILE_COUNT:
    raise ValueError(
        f"Le programme attend {EXPECTED_FILE_COUNT} fichiers, "
        f"mais {len(csv_files)} ont ete detectes."
    )

inventaire = pd.DataFrame(
    {
        "numero": range(1, len(csv_files) + 1),
        "fichier": [f.name for f in csv_files],
        "nom_court": [nom_court_fichier(f.name) for f in csv_files],
        "taille_mo": [
            round(f.stat().st_size / (1024**2), 2) for f in csv_files
        ],
    }
)
enregistrer_tableau(inventaire, "01_inventaire_fichiers.csv")

dataframes = []
resume_fichiers = []
colonnes_reference = None

for fichier in csv_files:
    logger.info("Chargement : %s", fichier.name)
    df = pd.read_csv(fichier, low_memory=False)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise ValueError(f"La colonne Label est absente dans : {fichier.name}")

    if colonnes_reference is None:
        colonnes_reference = list(df.columns)
    elif list(df.columns) != colonnes_reference:
        raise ValueError(f"Colonnes incompatibles dans : {fichier.name}")

    df["Label"] = nettoyer_labels_classes(df["Label"])
    df["source_file"] = nom_court_fichier(fichier.name)

    resume_fichiers.append(
        {
            "fichier": fichier.name,
            "nom_court": nom_court_fichier(fichier.name),
            "lignes": len(df),
            "colonnes_initiales": len(df.columns) - 1,
            "classes": df["Label"].nunique(),
            "valeurs_manquantes": int(df.isna().sum().sum()),
            "valeurs_infinies": int(
                np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
            ),
            "doublons": int(df.duplicated().sum()),
        }
    )

    dataframes.append(df)

resume_fichiers_df = pd.DataFrame(resume_fichiers)
enregistrer_tableau(resume_fichiers_df, "02_resume_initial_par_fichier.csv")

plt.figure(figsize=(15, 7))
ax = sns.barplot(
    data=resume_fichiers_df, x="nom_court", y="lignes", color="#2E86C1"
)
ax.set_title(
    "Nombre d'observations avant pretraitement", fontsize=18, fontweight="bold", pad=15
)
ax.set_xlabel("Fichier", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Observations", fontsize=14, fontweight="bold")
plt.xticks(rotation=0, fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
for barre in ax.patches:
    valeur = int(barre.get_height())
    ax.text(
        barre.get_x() + barre.get_width() / 2,
        barre.get_height() + 5000,
        f"{valeur:,}".replace(",", " "),
        ha="center",
        va="bottom",
        fontsize=11,
        fontweight="bold",
    )
enregistrer_figure("02_lignes_avant_pretraitement.png")


# ============================================================
# 3. FUSION ET CORRECTION DES LABELS (ÉCHELLE LOGARITHMIQUE)
# ============================================================

afficher_etape(3, "Fusion des huit fichiers et correction des labels")

donnees = pd.concat(dataframes, ignore_index=True)
del dataframes
gc.collect()

labels_avant = (
    donnees["Label"]
    .value_counts()
    .rename_axis("classe")
    .reset_index(name="effectif")
)
labels_avant["pourcentage"] = labels_avant["effectif"] / len(donnees) * 100
enregistrer_tableau(
    labels_avant, "03_distribution_classes_apres_correction_labels.csv"
)

preuve_fusion = {
    "lignes_apres_fusion": int(len(donnees)),
    "colonnes_apres_fusion": int(len(donnees.columns)),
    "colonnes_features": int(len(donnees.columns) - 2),
    "classes_detectees": int(donnees["Label"].nunique()),
    "colonne_source_ajoutee": "source_file",
}
enregistrer_preuve(preuve_fusion, "03_preuve_fusion.json")

plt.figure(figsize=(15, 8))
distribution_plot = labels_avant.sort_values("effectif", ascending=True)
ax = sns.barplot(
    data=distribution_plot, x="effectif", y="classe", color="#2E86C1"
)

# ÉCHELLE LOGARITHMIQUE
ax.set_xscale("log")
ax.set_title(
    "Distribution des classes apres correction des labels (echelle log)",
    fontsize=18,
    fontweight="bold",
    pad=15,
)
ax.set_xlabel("Observations (echelle logarithmique)", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Classe", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")

for barre in ax.patches:
    valeur = int(barre.get_width())
    if valeur > 0:
        ax.text(
            valeur * 1.08,
            barre.get_y() + barre.get_height() / 2,
            f"{valeur:,}".replace(",", " "),
            va="center",
            fontsize=11,
            fontweight="bold",
        )
enregistrer_figure("03_distribution_classes_labels_corriges.png")


# ============================================================
# 4. TRAITEMENT DES VALEURS INFINIES ET MANQUANTES
# ============================================================

afficher_etape(4, "Traitement des valeurs infinies et manquantes")

colonnes_numeriques = donnees.select_dtypes(
    include=[np.number]
).columns.tolist()

inf_par_colonne = np.isinf(donnees[colonnes_numeriques]).sum()
nan_par_colonne_avant = donnees[colonnes_numeriques].isna().sum()

qualite_avant = pd.DataFrame(
    {
        "colonne": colonnes_numeriques,
        "valeurs_infinies_avant": inf_par_colonne.values.astype(int),
        "valeurs_manquantes_avant": nan_par_colonne_avant.values.astype(int),
    }
)
qualite_avant["total_a_traiter"] = (
    qualite_avant["valeurs_infinies_avant"]
    + qualite_avant["valeurs_manquantes_avant"]
)
qualite_avant = qualite_avant.sort_values("total_a_traiter", ascending=False)
enregistrer_tableau(qualite_avant, "04_valeurs_infinies_manquantes_avant.csv")

donnees[colonnes_numeriques] = donnees[colonnes_numeriques].replace(
    [np.inf, -np.inf], np.nan
)

qualite_top = qualite_avant[qualite_avant["total_a_traiter"] > 0].head(15)
if not qualite_top.empty:
    qualite_long = qualite_top.melt(
        id_vars="colonne",
        value_vars=["valeurs_infinies_avant", "valeurs_manquantes_avant"],
        var_name="type",
        value_name="effectif",
    )

    plt.figure(figsize=(15, 7))
    ax = sns.barplot(data=qualite_long, x="colonne", y="effectif", hue="type")
    ax.set_title(
        "Valeurs infinies et manquantes avant imputation",
        fontsize=18,
        fontweight="bold",
        pad=15,
    )
    ax.set_xlabel("Caracteristique", fontsize=14, fontweight="bold", labelpad=10)
    ax.set_ylabel("Effectif", fontsize=14, fontweight="bold")
    plt.xticks(rotation=25, ha="right", fontsize=11, fontweight="bold")
    plt.yticks(fontsize=12, fontweight="bold")
    plt.legend(title="Type", fontsize=12, title_fontsize=13)
    enregistrer_figure("04_valeurs_infinies_manquantes_avant.png")


# ============================================================
# 5. SUPPRESSION DES DOUBLONS
# ============================================================

afficher_etape(5, "Suppression des doublons")

lignes_avant_doublons = len(donnees)
nombre_doublons = int(donnees.duplicated().sum())
donnees = donnees.drop_duplicates(ignore_index=True)
lignes_apres_doublons = len(donnees)

preuve_doublons = {
    "lignes_avant_suppression": int(lignes_avant_doublons),
    "doublons_supprimes": int(nombre_doublons),
    "lignes_apres_suppression": int(lignes_apres_doublons),
    "taux_doublons_pourcentage": round(
        nombre_doublons / lignes_avant_doublons * 100, 4
    ),
}
enregistrer_preuve(preuve_doublons, "05_preuve_suppression_doublons.json")

doublons_df = pd.DataFrame(
    {
        "etat": [
            "Avant suppression",
            "Doublons supprimes",
            "Apres suppression",
        ],
        "effectif": [
            lignes_avant_doublons,
            nombre_doublons,
            lignes_apres_doublons,
        ],
    }
)
enregistrer_tableau(doublons_df, "05_resume_suppression_doublons.csv")

plt.figure(figsize=(12, 6))
ax = sns.barplot(data=doublons_df, x="etat", y="effectif", color="#2E86C1")
ax.set_title(
    "Effet de la suppression des doublons",
    fontsize=18,
    fontweight="bold",
    pad=15,
)
ax.set_xlabel("Etat", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Observations", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
for barre in ax.patches:
    valeur = int(barre.get_height())
    ax.text(
        barre.get_x() + barre.get_width() / 2,
        barre.get_height() + 5000,
        f"{valeur:,}".replace(",", " "),
        ha="center",
        va="bottom",
        fontsize=11,
        fontweight="bold",
    )
enregistrer_figure("05_suppression_doublons.png")


# ============================================================
# 5B. ANALYSE DES VALEURS ABERRANTES (IQR / TUKEY)
# ============================================================

afficher_etape("5B", "Analyse descriptive des valeurs aberrantes")

valeurs_valides_par_fichier = (
    donnees.groupby("source_file")[colonnes_numeriques]
    .count()
    .sum(axis=1)
)
valeurs_valides_par_classe = (
    donnees.groupby("Label")[colonnes_numeriques]
    .count()
    .sum(axis=1)
)

aberrantes_par_fichier = {source: 0 for source in valeurs_valides_par_fichier.index}
aberrantes_par_classe = {classe: 0 for classe in valeurs_valides_par_classe.index}
resume_aberrantes = []

quartiles = donnees[colonnes_numeriques].quantile([0.25, 0.75])
q1_series = quartiles.loc[0.25]
q3_series = quartiles.loc[0.75]

for colonne in colonnes_numeriques:
    serie = donnees[colonne]
    q1 = float(q1_series[colonne])
    q3 = float(q3_series[colonne])
    iqr = q3 - q1
    valeurs_valides = int(serie.notna().sum())

    if not np.isfinite(iqr) or iqr <= 0:
        valeurs_aberrantes = 0
        borne_inferieure = np.nan
        borne_superieure = np.nan
    else:
        borne_inferieure = q1 - 1.5 * iqr
        borne_superieure = q3 + 1.5 * iqr
        masque_aberrant = (
            (serie < borne_inferieure) | (serie > borne_superieure)
        ) & serie.notna()
        valeurs_aberrantes = int(masque_aberrant.sum())

        if valeurs_aberrantes > 0:
            counts_fichier = donnees.loc[masque_aberrant, "source_file"].value_counts()
            for source, effectif in counts_fichier.items():
                aberrantes_par_fichier[source] = (
                    aberrantes_par_fichier.get(source, 0) + int(effectif)
                )

            counts_classe = donnees.loc[masque_aberrant, "Label"].value_counts()
            for classe, effectif in counts_classe.items():
                aberrantes_par_classe[classe] = (
                    aberrantes_par_classe.get(classe, 0) + int(effectif)
                )

        del masque_aberrant

    pourcentage_aberrant = (
        valeurs_aberrantes / valeurs_valides * 100 if valeurs_valides else 0
    )

    resume_aberrantes.append(
        {
            "variable": colonne,
            "q1": q1,
            "q3": q3,
            "iqr": iqr,
            "borne_inferieure": borne_inferieure,
            "borne_superieure": borne_superieure,
            "valeurs_valides": valeurs_valides,
            "valeurs_aberrantes": valeurs_aberrantes,
            "pourcentage_aberrant": pourcentage_aberrant,
            "decision": "conservee_analyse_descriptive",
        }
    )

resume_aberrantes_df = pd.DataFrame(resume_aberrantes).sort_values(
    "valeurs_aberrantes", ascending=False
)
enregistrer_tableau(
    resume_aberrantes_df, "05B_valeurs_aberrantes_par_variable.csv"
)

aberrantes_fichier_df = pd.DataFrame(
    [
        {
            "fichier": source,
            "valeurs_valides_analysees": int(valeurs_valides_par_fichier[source]),
            "valeurs_aberrantes": int(aberrantes_par_fichier.get(source, 0)),
            "pourcentage_aberrant": (
                int(aberrantes_par_fichier.get(source, 0))
                / int(valeurs_valides_par_fichier[source])
                * 100
                if int(valeurs_valides_par_fichier[source]) > 0
                else 0
            ),
        }
        for source in valeurs_valides_par_fichier.index
    ]
).sort_values("valeurs_aberrantes", ascending=False)
enregistrer_tableau(
    aberrantes_fichier_df, "05B_valeurs_aberrantes_par_fichier.csv"
)

aberrantes_classe_df = pd.DataFrame(
    [
        {
            "classe": classe,
            "valeurs_valides_analysees": int(valeurs_valides_par_classe[classe]),
            "valeurs_aberrantes": int(aberrantes_par_classe.get(classe, 0)),
            "pourcentage_aberrant": (
                int(aberrantes_par_classe.get(classe, 0))
                / int(valeurs_valides_par_classe[classe])
                * 100
                if int(valeurs_valides_par_classe[classe]) > 0
                else 0
            ),
        }
        for classe in valeurs_valides_par_classe.index
    ]
).sort_values("valeurs_aberrantes", ascending=False)
enregistrer_tableau(
    aberrantes_classe_df, "05B_valeurs_aberrantes_par_classe.csv"
)

top_aberrantes = resume_aberrantes_df[
    resume_aberrantes_df["valeurs_aberrantes"] > 0
].head(OUTLIER_TOP_N)
if not top_aberrantes.empty:
    plt.figure(figsize=(15, 8))
    top_plot = top_aberrantes.sort_values("valeurs_aberrantes", ascending=True)
    ax = sns.barplot(
        data=top_plot,
        x="valeurs_aberrantes",
        y="variable",
        color="#D35400",
    )
    ax.set_xscale("log")
    ax.set_title(
        "Top variables contenant des valeurs aberrantes (IQR / Tukey)",
        fontsize=18,
        fontweight="bold",
        pad=15,
    )
    ax.set_xlabel(
        "Valeurs aberrantes detectees (echelle log)",
        fontsize=14,
        fontweight="bold",
        labelpad=10,
    )
    ax.set_ylabel("Caracteristique", fontsize=14, fontweight="bold")
    plt.xticks(fontsize=12, fontweight="bold")
    plt.yticks(fontsize=12, fontweight="bold")

    for barre in ax.patches:
        valeur = int(barre.get_width())
        if valeur > 0:
            ax.text(
                valeur * 1.08,
                barre.get_y() + barre.get_height() / 2,
                f"{valeur:,}".replace(",", " "),
                va="center",
                fontsize=11,
                fontweight="bold",
            )
    enregistrer_figure("05B_valeurs_aberrantes_top_variables.png")

top_classes_aberrantes = aberrantes_classe_df[
    aberrantes_classe_df["valeurs_aberrantes"] > 0
].head(OUTLIER_TOP_N)
if not top_classes_aberrantes.empty:
    plt.figure(figsize=(15, 8))
    top_classes_plot = top_classes_aberrantes.sort_values(
        "valeurs_aberrantes", ascending=True
    )
    ax = sns.barplot(
        data=top_classes_plot,
        x="valeurs_aberrantes",
        y="classe",
        color="#C0392B",
    )
    ax.set_xscale("log")
    ax.set_title(
        "Valeurs aberrantes par classe (IQR / Tukey)",
        fontsize=18,
        fontweight="bold",
        pad=15,
    )
    ax.set_xlabel(
        "Valeurs aberrantes detectees (echelle log)",
        fontsize=14,
        fontweight="bold",
        labelpad=10,
    )
    ax.set_ylabel("Classe", fontsize=14, fontweight="bold")
    plt.xticks(fontsize=12, fontweight="bold")
    plt.yticks(fontsize=12, fontweight="bold")

    for barre in ax.patches:
        valeur = int(barre.get_width())
        if valeur > 0:
            ax.text(
                valeur * 1.08,
                barre.get_y() + barre.get_height() / 2,
                f"{valeur:,}".replace(",", " "),
                va="center",
                fontsize=11,
                fontweight="bold",
            )
    enregistrer_figure("05B_valeurs_aberrantes_par_classe.png")

preuve_aberrantes = {
    "methode": "IQR / Tukey",
    "formule_iqr": "IQR = Q3 - Q1",
    "borne_inferieure": "Q1 - 1.5 * IQR",
    "borne_superieure": "Q3 + 1.5 * IQR",
    "variables_analysees": int(len(colonnes_numeriques)),
    "total_valeurs_aberrantes_detectees": int(
        resume_aberrantes_df["valeurs_aberrantes"].sum()
    ),
    "suppression_appliquee": False,
    "justification": (
        "Les valeurs aberrantes sont conservees, car dans un dataset de detection "
        "d'intrusion elles peuvent representer des comportements reels d'attaque."
    ),
    "top_variables": json.loads(
        resume_aberrantes_df.head(5).to_json(
            orient="records", force_ascii=False
        )
    ),
}
enregistrer_preuve(preuve_aberrantes, "05B_preuve_valeurs_aberrantes.json")

del quartiles, q1_series, q3_series
gc.collect()


# ============================================================
# 6. ENCODAGE ET SEPARATION STRATIFIEE TRAIN / TEST (ÉCHELLE LOGARITHMIQUE)
# ============================================================

afficher_etape(6, "Encodage des classes et separation stratifiee 70 % / 30 %")

source_file = donnees["source_file"].copy()
y_texte = donnees["Label"].copy()
X = donnees.drop(columns=["Label", "source_file"])

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y_texte)

mapping_labels = pd.DataFrame(
    {
        "code": range(len(label_encoder.classes_)),
        "classe": label_encoder.classes_,
    }
)
enregistrer_tableau(mapping_labels, "06_mapping_labels.csv")

X_train, X_test, y_train, y_test, source_train, source_test = train_test_split(
    X,
    y,
    source_file,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y,
)

del donnees
gc.collect()

split_resume = pd.DataFrame(
    {
        "ensemble": ["Train", "Test"],
        "observations": [len(X_train), len(X_test)],
        "proportion": [
            len(X_train) / (len(X_train) + len(X_test)) * 100,
            len(X_test) / (len(X_train) + len(X_test)) * 100,
        ],
    }
)
enregistrer_tableau(split_resume, "06_repartition_train_test_70_30.csv")

plt.figure(figsize=(12, 6))
ax = sns.barplot(
    data=split_resume, x="ensemble", y="observations", color="#008C95"
)
ax.set_title(
    "Repartition stratifiee Train / Test",
    fontsize=18,
    fontweight="bold",
    pad=15,
)
ax.set_xlabel("Ensemble", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Observations", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
for barre in ax.patches:
    valeur = int(barre.get_height())
    ax.text(
        barre.get_x() + barre.get_width() / 2,
        barre.get_height() + 5000,
        f"{valeur:,}".replace(",", " "),
        ha="center",
        va="bottom",
        fontsize=11,
        fontweight="bold",
    )
enregistrer_figure("06_repartition_train_test_70_30.png")


def distribution_par_ensemble(y_values, nom_ensemble):
    df = pd.DataFrame({"code": y_values})
    df["classe"] = label_encoder.inverse_transform(df["code"])
    resultat = (
        df["classe"]
        .value_counts()
        .rename_axis("classe")
        .reset_index(name="effectif")
    )
    resultat["ensemble"] = nom_ensemble
    return resultat


distribution_split = pd.concat(
    [
        distribution_par_ensemble(y_train, "Train"),
        distribution_par_ensemble(y_test, "Test"),
    ],
    ignore_index=True,
)
enregistrer_tableau(
    distribution_split, "06_distribution_classes_par_ensemble.csv"
)

distribution_train = distribution_par_ensemble(y_train, "Train").copy()
distribution_train["pourcentage_train"] = (
    distribution_train["effectif"] / distribution_train["effectif"].sum() * 100
).round(6)
classe_majoritaire = distribution_train.sort_values(
    "effectif", ascending=False
).iloc[0]
classe_minoritaire = distribution_train.sort_values(
    "effectif", ascending=True
).iloc[0]
rapport_desequilibre = float(classe_majoritaire["effectif"]) / max(
    float(classe_minoritaire["effectif"]), 1.0
)
desequilibre_train = pd.DataFrame(
    [
        {
            "classe_majoritaire": classe_majoritaire["classe"],
            "effectif_majoritaire_train": int(classe_majoritaire["effectif"]),
            "classe_minoritaire": classe_minoritaire["classe"],
            "effectif_minoritaire_train": int(classe_minoritaire["effectif"]),
            "rapport_desequilibre_train": round(rapport_desequilibre, 4),
            "decision": "reequilibrage par ponderation des classes applique uniquement sur Train",
        }
    ]
)
enregistrer_tableau(
    distribution_train, "06_distribution_classes_train_avant_reequilibrage.csv"
)
enregistrer_tableau(desequilibre_train, "06_preuve_desequilibre_train.csv")

plt.figure(figsize=(15, 8))
distribution_plot = distribution_train.sort_values("effectif", ascending=True)
ax = sns.barplot(
    data=distribution_plot, x="effectif", y="classe", color="#1F4E78"
)

# ÉCHELLE LOGARITHMIQUE
ax.set_xscale("log")
ax.set_title(
    "Desequilibre des classes dans Train (echelle log)",
    fontsize=18,
    fontweight="bold",
    pad=15,
)
ax.set_xlabel("Observations Train (echelle logarithmique)", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Classe", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")

for barre in ax.patches:
    valeur = int(barre.get_width())
    if valeur > 0:
        ax.text(
            valeur * 1.08,
            barre.get_y() + barre.get_height() / 2,
            f"{valeur:,}".replace(",", " "),
            va="center",
            fontsize=11,
            fontweight="bold",
        )
enregistrer_figure("06_desequilibre_classes_train.png")

preuve_split = {
    "strategie": "Separation stratifiee 70 % Train / 30 % Test",
    "train_pourcentage": TRAIN_SIZE * 100,
    "test_pourcentage": TEST_SIZE * 100,
    "cross_validation": (
        f"StratifiedKFold a {CV_FOLDS} folds applique uniquement sur Train"
    ),
    "justification": (
        "Le Test reste independant et n'est utilise qu'une seule fois pour "
        "l'evaluation finale. La validation est realisee a l'interieur du Train "
        "par cross-validation."
    ),
}
enregistrer_preuve(preuve_split, "06_preuve_separation_stratifiee_70_30.json")

preuve_desequilibre = {
    "ensemble_analyse": "Train",
    "raison": (
        "Le desequilibre est analyse apres la separation pour documenter les classes "
        "majoritaires et minoritaires sans modifier l'ensemble Test."
    ),
    "classe_majoritaire_train": str(classe_majoritaire["classe"]),
    "effectif_majoritaire_train": int(classe_majoritaire["effectif"]),
    "classe_minoritaire_train": str(classe_minoritaire["classe"]),
    "effectif_minoritaire_train": int(classe_minoritaire["effectif"]),
    "rapport_desequilibre_train": round(rapport_desequilibre, 4),
    "strategie_retenue": "ponderation des classes calculee uniquement sur Train",
}
enregistrer_preuve(
    preuve_desequilibre, "06_preuve_desequilibre_classes_train.json"
)


# ============================================================
# 7. COMPARAISON DES METHODES PAR CROSS-VALIDATION (VALEURS DÉTAILLÉES SUR BARRES)
# ============================================================

afficher_etape(7, "Comparaison des methodes par cross-validation sur Train")

features_disponibles = [c for c in IMPUTATION_TARGETS if c in X_train.columns]
if not features_disponibles:
    logger.warning("Aucune colonne cible d'imputation n'a ete trouvee.")
    comparaison_imputation = pd.DataFrame()
else:
    colonnes_pour_imputation = X_train.select_dtypes(
        include=[np.number]
    ).columns.tolist()
    comparaison_resultats = []
    y_train_series = pd.Series(y_train, index=X_train.index)

    for cible in features_disponibles:
        logger.info("Evaluation des methodes d'imputation pour : %s", cible)

        train_connues = X_train[X_train[cible].notna()]
        if len(train_connues) > IMPUTATION_SAMPLE_SIZE:
            train_connues = train_connues.sample(
                IMPUTATION_SAMPLE_SIZE, random_state=RANDOM_STATE
            )

        labels_connus = y_train_series.loc[train_connues.index].to_numpy()
        min_classe = pd.Series(labels_connus).value_counts().min()
        folds_effectifs = (
            min(CV_FOLDS, int(min_classe)) if min_classe > 1 else 2
        )

        if folds_effectifs < 2:
            logger.warning(
                "Cross-validation impossible pour %s : classes insuffisantes.",
                cible,
            )
            continue

        cv = StratifiedKFold(
            n_splits=folds_effectifs,
            shuffle=True,
            random_state=RANDOM_STATE,
        )

        colonnes_modele = [
            col
            for col in colonnes_pour_imputation
            if col != cible and train_connues[col].notna().mean() > 0.95
        ][:20]

        for fold_id, (idx_apprentissage, idx_validation) in enumerate(
            cv.split(train_connues, labels_connus),
            start=1,
        ):
            fold_train = train_connues.iloc[idx_apprentissage].copy()
            fold_validation = train_connues.iloc[idx_validation].copy()

            if len(fold_validation) > IMPUTATION_MASK_SIZE:
                fold_validation = fold_validation.sample(
                    IMPUTATION_MASK_SIZE,
                    random_state=RANDOM_STATE + fold_id,
                )

            y_vrai = fold_validation[cible].to_numpy()
            reference_train = fold_train[cible].to_numpy()

            methodes_simples = {
                "Zero": 0,
                "Moyenne": np.nanmean(reference_train),
                "Mediane": np.nanmedian(reference_train),
                "Valeur frequente": fold_train[cible]
                .mode(dropna=True)
                .iloc[0],
            }

            for methode, valeur in methodes_simples.items():
                y_pred = np.full_like(y_vrai, fill_value=valeur, dtype=float)
                nrmse, nmae = calculer_nrmse_nmae(
                    y_vrai, y_pred, reference_train
                )
                comparaison_resultats.append(
                    {
                        "variable": cible,
                        "fold": fold_id,
                        "methode": methode,
                        "famille": "Statistique",
                        "NRMSE": nrmse,
                        "NMAE": nmae,
                    }
                )

            if colonnes_modele:
                imputer_knn = KNNImputer(n_neighbors=5)
                train_knn = fold_train[colonnes_modele + [cible]].copy()
                val_knn = fold_validation[colonnes_modele + [cible]].copy()
                val_knn[cible] = np.nan
                concat_knn = pd.concat([train_knn, val_knn], ignore_index=True)
                knn_result = imputer_knn.fit_transform(concat_knn)
                y_pred_knn = knn_result[-len(val_knn) :, -1]
                nrmse, nmae = calculer_nrmse_nmae(
                    y_vrai, y_pred_knn, reference_train
                )
                comparaison_resultats.append(
                    {
                        "variable": cible,
                        "fold": fold_id,
                        "methode": "KNN",
                        "famille": "Machine Learning",
                        "NRMSE": nrmse,
                        "NMAE": nmae,
                    }
                )

                base_imputer = SimpleImputer(strategy="median")
                X_rf_train = base_imputer.fit_transform(
                    fold_train[colonnes_modele]
                )
                X_rf_val = base_imputer.transform(
                    fold_validation[colonnes_modele]
                )

                rf = RandomForestRegressor(
                    n_estimators=60,
                    max_depth=12,
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                )
                rf.fit(X_rf_train, fold_train[cible])
                y_pred_rf = rf.predict(X_rf_val)
                nrmse, nmae = calculer_nrmse_nmae(
                    y_vrai, y_pred_rf, reference_train
                )
                comparaison_resultats.append(
                    {
                        "variable": cible,
                        "fold": fold_id,
                        "methode": "Random Forest",
                        "famille": "Machine Learning",
                        "NRMSE": nrmse,
                        "NMAE": nmae,
                    }
                )

                mlp = MLPRegressor(
                    hidden_layer_sizes=(32, 16),
                    activation="relu",
                    solver="adam",
                    max_iter=120,
                    random_state=RANDOM_STATE,
                    early_stopping=True,
                )
                mlp.fit(X_rf_train, fold_train[cible])
                y_pred_mlp = mlp.predict(X_rf_val)
                nrmse, nmae = calculer_nrmse_nmae(
                    y_vrai, y_pred_mlp, reference_train
                )
                comparaison_resultats.append(
                    {
                        "variable": cible,
                        "fold": fold_id,
                        "methode": "MLP neural network",
                        "famille": "Deep Learning",
                        "NRMSE": nrmse,
                        "NMAE": nmae,
                    }
                )

    comparaison_imputation = pd.DataFrame(comparaison_resultats)
    enregistrer_tableau(
        comparaison_imputation, "07_comparaison_methodes_cross_validation.csv"
    )

    if not comparaison_imputation.empty:
        comparaison_plot = comparaison_imputation.groupby(
            ["famille", "methode"],
            as_index=False,
        )[["NRMSE", "NMAE"]].mean()
        comparaison_long = comparaison_plot.melt(
            id_vars=["famille", "methode"],
            value_vars=["NRMSE", "NMAE"],
            var_name="metrique",
            value_name="valeur",
        )

        plt.figure(figsize=(15, 7.5))
        ax = sns.barplot(
            data=comparaison_long, x="methode", y="valeur", hue="metrique"
        )
        ax.set_title(
            "Comparaison des methodes par cross-validation (NRMSE & NMAE)",
            fontsize=18,
            fontweight="bold",
            pad=15,
        )
        ax.set_xlabel(
            "Methode", fontsize=14, fontweight="bold", labelpad=10
        )
        ax.set_ylabel("Erreur normalisee", fontsize=14, fontweight="bold")
        plt.xticks(rotation=20, ha="right", fontsize=12, fontweight="bold")
        plt.yticks(fontsize=12, fontweight="bold")
        plt.legend(title="Metrique", fontsize=12, title_fontsize=13, loc="upper left")

        # AJOUT DES VALEURS NUMÉRIQUES SUR TOUTES LES BARRES
        max_y = comparaison_long["valeur"].max()
        ax.set_ylim(0, max_y * 1.15)  # Espace pour les étiquettes

        for barre in ax.patches:
            hauteur = barre.get_height()
            if not np.isnan(hauteur) and hauteur > 0:
                ax.text(
                    barre.get_x() + barre.get_width() / 2.0,
                    hauteur + (max_y * 0.015),
                    f"{hauteur:.3f}",
                    ha="center",
                    va="bottom",
                    fontsize=10,
                    fontweight="bold",
                )

        enregistrer_figure("07_comparaison_methodes_cross_validation.png")

        classement = comparaison_plot.sort_values(
            ["NMAE", "NRMSE"], ascending=True
        )
        enregistrer_tableau(classement, "07_classement_methodes.csv")

imputer_base = SimpleImputer(strategy="median")
X_train_imp = pd.DataFrame(
    imputer_base.fit_transform(X_train),
    columns=X_train.columns,
    index=X_train.index,
)
X_test_imp = pd.DataFrame(
    imputer_base.transform(X_test),
    columns=X_test.columns,
    index=X_test.index,
)

variables_imputees_rf = []
for cible in features_disponibles:
    masque_train_manquant = X_train[cible].isna()
    masque_test_manquant = X_test[cible].isna()

    if not (masque_train_manquant.any() or masque_test_manquant.any()):
        continue

    colonnes_modele = [
        col
        for col in X_train_imp.columns
        if col != cible and X_train[col].notna().mean() > 0.95
    ][:20]

    if not colonnes_modele:
        continue

    train_connues = X_train[cible].notna()
    rf_final = RandomForestRegressor(
        n_estimators=80,
        max_depth=14,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    rf_final.fit(
        X_train_imp.loc[train_connues, colonnes_modele],
        X_train.loc[train_connues, cible],
    )

    if masque_train_manquant.any():
        X_train_imp.loc[masque_train_manquant, cible] = rf_final.predict(
            X_train_imp.loc[masque_train_manquant, colonnes_modele]
        )
    if masque_test_manquant.any():
        X_test_imp.loc[masque_test_manquant, cible] = rf_final.predict(
            X_test_imp.loc[masque_test_manquant, colonnes_modele]
        )

    variables_imputees_rf.append(cible)

preuve_imputation = {
    "methode_appliquee_finalement": (
        "Random Forest pour les variables cibles, mediane comme base technique pour les"
        " autres variables"
    ),
    "variables_imputees_par_random_forest": variables_imputees_rf,
    "raison": (
        "Random Forest est appliquee aux variables de debit contenant les valeurs"
        " infinies converties en NaN. La mediane sert uniquement a completer les"
        " variables auxiliaires necessaires au modele."
    ),
    "nan_train_apres": int(X_train_imp.isna().sum().sum()),
    "nan_test_apres": int(X_test_imp.isna().sum().sum()),
}
enregistrer_preuve(preuve_imputation, "07_preuve_imputation.json")


# ============================================================
# 8. SELECTION DES CARACTERISTIQUES CONSTANTES
# ============================================================

afficher_etape(8, "Suppression des variables constantes")

variances = X_train_imp.var(axis=0)
variables_constantes = variances[variances == 0].index.tolist()
variables_retenues = [
    col for col in X_train_imp.columns if col not in variables_constantes
]

selection_df = pd.DataFrame(
    {
        "variable": X_train_imp.columns,
        "variance_train": variances.values,
        "decision": [
            "supprimee_constante" if col in variables_constantes else "retenue"
            for col in X_train_imp.columns
        ],
    }
)
enregistrer_tableau(selection_df, "08_selection_variables_constantes.csv")

X_train_sel = X_train_imp[variables_retenues]
X_test_sel = X_test_imp[variables_retenues]

preuve_selection = {
    "variables_initiales": int(X_train_imp.shape[1]),
    "variables_constantes_supprimees": int(len(variables_constantes)),
    "variables_retenues": int(len(variables_retenues)),
    "liste_variables_constantes": variables_constantes,
}
enregistrer_preuve(preuve_selection, "08_preuve_selection_variables.json")


# ============================================================
# 9. NORMALISATION DES CARACTERISTIQUES (BORNES VISIBLES)
# ============================================================

afficher_etape(9, "Normalisation des caracteristiques")

scaler = MinMaxScaler()
X_train_scaled = pd.DataFrame(
    scaler.fit_transform(X_train_sel),
    columns=variables_retenues,
    index=X_train_sel.index,
)
X_test_scaled = pd.DataFrame(
    scaler.transform(X_test_sel),
    columns=variables_retenues,
    index=X_test_sel.index,
)

controle_scaling = pd.DataFrame(
    {
        "variable": variables_retenues,
        "min_train_apres": X_train_scaled.min(axis=0).values,
        "max_train_apres": X_train_scaled.max(axis=0).values,
    }
)
enregistrer_tableau(controle_scaling, "09_controle_normalisation_train.csv")

controle_plot = controle_scaling.head(20).copy()
controle_long = controle_plot.melt(
    id_vars="variable",
    value_vars=["min_train_apres", "max_train_apres"],
    var_name="indicateur",
    value_name="valeur",
)

plt.figure(figsize=(16, 7))
ax = sns.barplot(
    data=controle_long,
    x="variable",
    y="valeur",
    hue="indicateur",
    palette=["#2E86C1", "#D35400"],
    edgecolor="black",
    linewidth=0.5,
)

# AJOUT DES ÉTIQUETTES BORNES [0.0, 1.0] POUR RENDRE MIN_TRAIN VISIBLE
ax.set_ylim(-0.1, 1.2)
ax.axhline(0, color="black", linewidth=1.2, linestyle="--")

for p in ax.patches:
    hauteur = p.get_height()
    if np.isclose(hauteur, 0.0):
        ax.text(
            p.get_x() + p.get_width() / 2.0,
            0.02,
            "0.0",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
            color="#2E86C1",
        )
    elif np.isclose(hauteur, 1.0):
        ax.text(
            p.get_x() + p.get_width() / 2.0,
            1.02,
            "1.0",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
            color="#D35400",
        )

ax.set_title(
    "Controle de la normalisation MinMax sur Train (Bornes [0.0, 1.0])",
    fontsize=18,
    fontweight="bold",
    pad=15,
)
ax.set_xlabel("Caracteristique", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Intervalle apres scaling", fontsize=14, fontweight="bold")
plt.xticks(rotation=25, ha="right", fontsize=11, fontweight="bold")
plt.yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0], fontweight="bold", fontsize=12)
plt.legend(title="Bornes", fontsize=12, title_fontsize=13, loc="upper right")

enregistrer_figure("09_controle_normalisation.png")


# ============================================================
# 10. REEQUILIBRAGE PAR POIDS DES CLASSES (ÉCHELLE LOGARITHMIQUE)
# ============================================================

afficher_etape(10, "Reequilibrage par poids des classes sur Train")

classes_codes = np.unique(y_train)
poids = compute_class_weight(
    class_weight="balanced", classes=classes_codes, y=y_train
)

poids_classes = pd.DataFrame(
    {
        "code": classes_codes,
        "classe": label_encoder.inverse_transform(classes_codes),
        "observations_train": [
            int((y_train == code).sum()) for code in classes_codes
        ],
        "poids": poids,
    }
)
enregistrer_tableau(poids_classes, "10_poids_classes_train.csv")

preuve_reequilibrage = {
    "methode": "class_weight balanced",
    "type": (
        "reequilibrage par ponderation, sans duplication ni suppression"
        " d'observations"
    ),
    "ensemble_utilise_pour_calculer_les_poids": "Train uniquement",
    "application": (
        "Ces poids seront utilises pendant l'entrainement des modeles de"
        " detection afin de donner plus d'importance aux classes rares."
    ),
    "test_modifie": False,
    "raison_test_non_modifie": (
        "Le Test doit rester representatif des donnees reelles pour l'evaluation"
        " finale."
    ),
}
enregistrer_preuve(preuve_reequilibrage, "10_preuve_reequilibrage_classes.json")

plt.figure(figsize=(15, 8))
poids_plot = poids_classes.sort_values("poids", ascending=True)
ax = sns.barplot(data=poids_plot, x="poids", y="classe", color="#C0392B")

# ÉCHELLE LOGARITHMIQUE
ax.set_xscale("log")
ax.set_title(
    "Poids des classes calcules sur Train (echelle log)",
    fontsize=18,
    fontweight="bold",
    pad=15,
)
ax.set_xlabel("Poids (echelle logarithmique)", fontsize=14, fontweight="bold", labelpad=10)
ax.set_ylabel("Classe", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")

for barre in ax.patches:
    valeur = barre.get_width()
    if valeur > 0:
        texte_valeur = f"{valeur:.2f}" if valeur < 100 else f"{valeur:,.0f}".replace(",", " ")
        ax.text(
            valeur * 1.08,
            barre.get_y() + barre.get_height() / 2,
            f" {texte_valeur}",
            va="center",
            fontsize=11,
            fontweight="bold",
        )
enregistrer_figure("10_poids_classes_train.png")


# ============================================================
# 11. SAUVEGARDE FINALE ET README
# ============================================================

afficher_etape(11, "Sauvegarde des preuves finales")

resume_final = {
    "observations_train": int(len(X_train_scaled)),
    "observations_test": int(len(X_test_scaled)),
    "caracteristiques_finales": int(X_train_scaled.shape[1]),
    "classes": int(len(label_encoder.classes_)),
    "valeurs_manquantes_finales": {
        "train": int(X_train_scaled.isna().sum().sum()),
        "test": int(X_test_scaled.isna().sum().sum()),
    },
    "valeurs_infinies_finales": {
        "train": int(np.isinf(X_train_scaled).sum().sum()),
        "test": int(np.isinf(X_test_scaled).sum().sum()),
    },
    "datasets_sauvegardes": bool(SAVE_PREPROCESSED_DATASETS),
}
enregistrer_preuve(resume_final, "11_resume_final_pretraitement.json")

if SAVE_PREPROCESSED_DATASETS:
    X_train_scaled.to_csv(
        PROCESSED_DIR / "X_train_final.csv", index=False, encoding="utf-8-sig"
    )
    X_test_scaled.to_csv(
        PROCESSED_DIR / "X_test_final.csv", index=False, encoding="utf-8-sig"
    )
    pd.DataFrame({"Label": y_train}).to_csv(
        PROCESSED_DIR / "y_train.csv", index=False, encoding="utf-8-sig"
    )
    pd.DataFrame({"Label": y_test}).to_csv(
        PROCESSED_DIR / "y_test.csv", index=False, encoding="utf-8-sig"
    )

    label_mapping_dict = {
        str(classe): int(code)
        for code, classe in enumerate(label_encoder.classes_)
    }
    with open(PROCESSED_DIR / "label_encoder_mapping.json", "w", encoding="utf-8") as fichier:
        json.dump(label_mapping_dict, fichier, ensure_ascii=False, indent=4)

    class_weights_dict = {
        int(code): float(poids_classe)
        for code, poids_classe in zip(classes_codes, poids)
    }
    with open(PROCESSED_DIR / "class_weights.json", "w", encoding="utf-8") as fichier:
        json.dump(class_weights_dict, fichier, ensure_ascii=False, indent=4)

    pd.DataFrame({"Variable": variables_retenues}).to_csv(
        PROCESSED_DIR / "variables_retenues.csv",
        index=False,
        encoding="utf-8-sig",
    )

    logger.info("Donnees finales sauvegardees dans : %s", PROCESSED_DIR)

    try:
        X_train_scaled.assign(Label=y_train).to_parquet(
            PROCESSED_DIR / "train_pretraite.parquet", index=False
        )
        X_test_scaled.assign(Label=y_test).to_parquet(
            PROCESSED_DIR / "test_pretraite.parquet", index=False
        )
    except Exception as erreur:
        logger.warning(
            "Sauvegarde Parquet ignoree, mais les CSV finaux sont bien crees : %s",
            erreur,
        )

readme = f"""# README - Pretraitement CIC-IDS2017

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

- Train : {resume_final["observations_train"]:,} observations
- Test : {resume_final["observations_test"]:,} observations
- Caracteristiques finales : {resume_final["caracteristiques_finales"]}
- Classes : {resume_final["classes"]}
- Valeurs manquantes finales : 0
- Valeurs infinies finales : 0

## Dossiers produits

- `figures/` : graphiques du pretraitement.
- `tables/` : tableaux CSV servant de preuves.
- `proofs/` : preuves JSON des etapes importantes.
- `processed/` : fichiers finaux pour la modelisation (`X_train_final.csv`, `X_test_final.csv`, `y_train.csv`, `y_test.csv`, `label_encoder_mapping.json`, `class_weights.json`).
- `preuve_execution_pretraitement.log` : journal complet d'execution.

## Remarque importante

Les transformations sont ajustees uniquement sur Train, puis appliquees au Test. La validation est realisee uniquement a l'interieur du Train avec la cross-validation, ce qui evite la fuite d'information vers l'ensemble de test.

Le desequilibre des classes est traite par ponderation calculee uniquement sur Train. Le Test n'est jamais reechantillonne ni modifie, afin de rester representatif des donnees reelles.
"""

(OUTPUT_DIR / "README_PRETRAITEMENT.md").write_text(readme, encoding="utf-8")
logger.info("README genere : %s", OUTPUT_DIR / "README_PRETRAITEMENT.md")

logger.info("Pretraitement termine avec succes.")