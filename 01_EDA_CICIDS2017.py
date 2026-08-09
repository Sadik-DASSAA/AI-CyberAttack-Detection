# Nom du fichier : 01_EDA_CICIDS2017.py

from pathlib import Path
import gc
import logging
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns


# ============================================================
# 0. CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "CIC-IDS2017"
    / "MachineLearningCVE"
)

OUTPUT_DIR = PROJECT_ROOT / "outputs" / "eda"
TABLES_DIR = OUTPUT_DIR / "tables"
FIGURES_DIR = OUTPUT_DIR / "figures"

EXPECTED_FILE_COUNT = 8
SAMPLE_SIZE_PER_FILE = 25_000
RANDOM_STATE = 42

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
TABLES_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

sns.set_theme(style="whitegrid")


# ============================================================
# JOURNAL D’EXÉCUTION
# ============================================================

logger = logging.getLogger("EDA_CICIDS2017")
logger.setLevel(logging.INFO)
logger.handlers.clear()

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)

file_handler = logging.FileHandler(
    OUTPUT_DIR / "preuve_execution.log",
    mode="w",
    encoding="utf-8",
)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)


def afficher_etape(numero, titre):
    separateur = "=" * 75
    logger.info("\n%s\nÉTAPE %s — %s\n%s", separateur, numero, titre, separateur)


def enregistrer_figure(nom):
    chemin = FIGURES_DIR / nom
    plt.tight_layout()
    plt.savefig(chemin, dpi=300, bbox_inches="tight")
    plt.close()
    logger.info("Graphique enregistré : %s", chemin)


def nom_court_fichier(nom):
    nom_lower = nom.lower()

    if "monday" in nom_lower:
        return "Monday"
    if "tuesday" in nom_lower:
        return "Tuesday"
    if "wednesday" in nom_lower:
        return "Wednesday"
    if "webattacks" in nom_lower:
        return "Thursday-WebAttacks"
    if "infilteration" in nom_lower or "infiltration" in nom_lower:
        return "Thursday-Infiltration"
    if "ddos" in nom_lower:
        return "Friday-DDoS"
    if "portscan" in nom_lower:
        return "Friday-PortScan"
    if "friday-workinghours-morning" in nom_lower:
        return "Friday-Morning"

    return Path(nom).stem


def nettoyer_labels_classes(serie):
    """
    Uniformise les noms des classes sans modifier les données sources.

    Certains fichiers CIC-IDS2017 contiennent un caractère mal décodé
    dans les trois classes « Web Attack ». Cette fonction corrige
    uniquement l'affichage et les tableaux produits par l'EDA.
    """
    labels = (
        serie
        .fillna("LABEL_MANQUANT")
        .astype(str)
        .str.strip()
        .str.replace("\ufffd", "-", regex=False)
        .str.replace("–", "-", regex=False)
        .str.replace("—", "-", regex=False)
        .str.replace(r"\s+", " ", regex=True)
    )

    labels_normalises = labels.str.lower()

    labels = labels.mask(
        labels_normalises.str.contains(
            r"web\s*attack.*brute\s*force",
            regex=True,
            na=False,
        ),
        "Web Attack - Brute Force",
    )
    labels = labels.mask(
        labels_normalises.str.contains(
            r"web\s*attack.*sql\s*injection",
            regex=True,
            na=False,
        ),
        "Web Attack - SQL Injection",
    )
    labels = labels.mask(
        labels_normalises.str.contains(
            r"web\s*attack.*xss",
            regex=True,
            na=False,
        ),
        "Web Attack - XSS",
    )

    return labels


# ============================================================
# 1. DIAGRAMME DU WORKFLOW EDA
# ============================================================

afficher_etape(1, "Création du workflow général de l’EDA")

workflow_steps = [
    "1. Détection des 8 fichiers CSV",
    "2. Vérification des colonnes",
    "3. Analyse de chaque fichier",
    "4. Tableau comparatif",
    "5. Agrégation des résultats",
    "6. Distribution globale des classes",
    "7. Statistiques sur échantillon global",
    "8. Corrélations et valeurs aberrantes",
]

fig, ax = plt.subplots(figsize=(12, 12))
ax.axis("off")

positions = np.linspace(0.92, 0.08, len(workflow_steps))

for index, (texte, position_y) in enumerate(zip(workflow_steps, positions)):
    couleur = "#1F4E78" if index < 4 else "#008C95"

    ax.text(
        0.5,
        position_y,
        texte,
        ha="center",
        va="center",
        fontsize=13,
        color="white",
        fontweight="bold",
        bbox=dict(
            boxstyle="round,pad=0.8",
            facecolor=couleur,
            edgecolor="white",
            linewidth=2,
        ),
    )

    if index < len(workflow_steps) - 1:
        ax.annotate(
            "",
            xy=(0.5, positions[index + 1] + 0.045),
            xytext=(0.5, position_y - 0.045),
            arrowprops=dict(
                arrowstyle="->",
                color="#333333",
                linewidth=2,
            ),
        )

ax.set_title(
    "Workflow unifié de l’analyse exploratoire des huit fichiers CIC-IDS2017",
    fontsize=16,
    fontweight="bold",
    pad=20,
)

enregistrer_figure("01_workflow_eda.png")


# ============================================================
# 2. DÉTECTION DES HUIT FICHIERS
# ============================================================

afficher_etape(2, "Détection des fichiers CIC-IDS2017")

if not DATA_DIR.exists():
    raise FileNotFoundError(
        f"\nDossier introuvable : {DATA_DIR}\n"
        "Vérifiez la variable DATA_DIR au début du script."
    )

csv_files = sorted(DATA_DIR.glob("*.csv"))

logger.info("Dossier des données : %s", DATA_DIR)
logger.info("Nombre de fichiers CSV détectés : %d", len(csv_files))

for numero, fichier in enumerate(csv_files, start=1):
    logger.info("%d. %s", numero, fichier.name)

if len(csv_files) != EXPECTED_FILE_COUNT:
    raise ValueError(
        f"Le programme attend exactement {EXPECTED_FILE_COUNT} fichiers, "
        f"mais {len(csv_files)} ont été détectés."
    )

inventaire = pd.DataFrame(
    {
        "numero": range(1, len(csv_files) + 1),
        "fichier": [fichier.name for fichier in csv_files],
        "nom_court": [nom_court_fichier(fichier.name) for fichier in csv_files],
        "taille_mo": [
            round(fichier.stat().st_size / (1024 ** 2), 2)
            for fichier in csv_files
        ],
    }
)

inventaire.to_csv(
    TABLES_DIR / "01_inventaire_fichiers.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info("Preuve enregistrée : 01_inventaire_fichiers.csv")


# ============================================================
# 3. VÉRIFICATION DE LA COMPATIBILITÉ DES COLONNES
# ============================================================

afficher_etape(3, "Vérification de la compatibilité des colonnes")

schemas = {}
schema_reference = None
nom_reference = None
verification_schema = []

for fichier in csv_files:
    colonnes = [
        colonne.strip()
        for colonne in pd.read_csv(fichier, nrows=0).columns
    ]

    schemas[fichier.name] = colonnes

    if schema_reference is None:
        schema_reference = colonnes
        nom_reference = fichier.name

    colonnes_manquantes = sorted(set(schema_reference) - set(colonnes))
    colonnes_supplementaires = sorted(set(colonnes) - set(schema_reference))

    compatible = (
        colonnes == schema_reference
        and len(colonnes_manquantes) == 0
        and len(colonnes_supplementaires) == 0
    )

    verification_schema.append(
        {
            "fichier": fichier.name,
            "nombre_colonnes": len(colonnes),
            "compatible": compatible,
            "colonnes_manquantes": ", ".join(colonnes_manquantes),
            "colonnes_supplementaires": ", ".join(
                colonnes_supplementaires
            ),
        }
    )

schema_df = pd.DataFrame(verification_schema)

schema_df.to_csv(
    TABLES_DIR / "02_verification_schema.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info("Fichier de référence : %s", nom_reference)
logger.info("Nombre de colonnes attendu : %d", len(schema_reference))
logger.info(
    "Fichiers compatibles : %d/%d",
    int(schema_df["compatible"].sum()),
    len(schema_df),
)

if not schema_df["compatible"].all():
    raise ValueError(
        "Les colonnes des huit fichiers ne sont pas compatibles. "
        "Consultez 02_verification_schema.csv."
    )

logger.info("Preuve : les huit fichiers possèdent les mêmes colonnes.")


# ============================================================
# 4. ANALYSE INDIVIDUELLE DES HUIT FICHIERS
# ============================================================

afficher_etape(4, "Analyse automatique de chaque fichier")

resumes_fichiers = []
distributions_classes = []
profils_variables = []
echantillons = []

for index, fichier in enumerate(csv_files, start=1):
    logger.info(
        "\nAnalyse du fichier %d/%d : %s",
        index,
        len(csv_files),
        fichier.name,
    )

    df = pd.read_csv(fichier, low_memory=False)
    df.columns = df.columns.str.strip()

    label_candidates = [
        colonne
        for colonne in df.columns
        if colonne.lower() == "label"
    ]

    if not label_candidates:
        raise KeyError(
            f"La colonne Label est absente du fichier {fichier.name}."
        )

    label_column = label_candidates[0]
    nom_court = nom_court_fichier(fichier.name)

    labels = nettoyer_labels_classes(df[label_column])

    numeric_df = df.select_dtypes(include=[np.number])
    numeric_without_inf = numeric_df.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    nombre_lignes = len(df)
    nombre_colonnes = len(df.columns)
    nombre_variables_numeriques = len(numeric_df.columns)

    valeurs_manquantes = int(df.isna().sum().sum())
    valeurs_infinies = int(
        np.isinf(numeric_df.to_numpy(copy=False)).sum()
    )
    doublons = int(df.duplicated().sum())
    nombre_classes = int(labels.nunique())

    lignes_benignes = int(
        labels.str.upper().eq("BENIGN").sum()
    )
    lignes_attaques = nombre_lignes - lignes_benignes

    cellules_totales = nombre_lignes * nombre_colonnes
    cellules_numeriques = (
        nombre_lignes * max(nombre_variables_numeriques, 1)
    )

    resumes_fichiers.append(
        {
            "fichier": fichier.name,
            "nom_court": nom_court,
            "lignes": nombre_lignes,
            "colonnes": nombre_colonnes,
            "variables_numeriques": nombre_variables_numeriques,
            "classes": nombre_classes,
            "valeurs_manquantes": valeurs_manquantes,
            "taux_manquantes_pct": round(
                100 * valeurs_manquantes / cellules_totales,
                6,
            ),
            "valeurs_infinies": valeurs_infinies,
            "taux_infinies_pct": round(
                100 * valeurs_infinies / cellules_numeriques,
                6,
            ),
            "doublons": doublons,
            "taux_doublons_pct": round(
                100 * doublons / nombre_lignes,
                4,
            ),
            "benign": lignes_benignes,
            "attaques": lignes_attaques,
            "taux_attaques_pct": round(
                100 * lignes_attaques / nombre_lignes,
                4,
            ),
        }
    )

    class_counts = labels.value_counts(dropna=False)

    for classe, effectif in class_counts.items():
        distributions_classes.append(
            {
                "fichier": fichier.name,
                "nom_court": nom_court,
                "classe": classe,
                "effectif": int(effectif),
                "pourcentage_fichier": round(
                    100 * effectif / nombre_lignes,
                    6,
                ),
            }
        )

    missing_by_column = df.isna().sum()
    infinite_by_column = pd.Series(
        0,
        index=df.columns,
        dtype="int64",
    )
    infinite_by_column.loc[numeric_df.columns] = np.isinf(
        numeric_df.to_numpy(copy=False)
    ).sum(axis=0)

    zero_by_column = pd.Series(
        0,
        index=df.columns,
        dtype="int64",
    )
    zero_by_column.loc[numeric_df.columns] = (
        numeric_df.eq(0).sum()
    )

    medians = numeric_without_inf.median()

    for colonne in df.columns:
        profils_variables.append(
            {
                "fichier": fichier.name,
                "nom_court": nom_court,
                "variable": colonne,
                "type": str(df[colonne].dtype),
                "valeurs_manquantes": int(
                    missing_by_column[colonne]
                ),
                "valeurs_infinies": int(
                    infinite_by_column[colonne]
                ),
                "valeurs_zero": int(
                    zero_by_column[colonne]
                ),
                "mediane": (
                    float(medians[colonne])
                    if colonne in medians.index
                    and pd.notna(medians[colonne])
                    else np.nan
                ),
                "valeurs_uniques": int(
                    df[colonne].nunique(dropna=True)
                ),
            }
        )

    taille_echantillon = min(
        SAMPLE_SIZE_PER_FILE,
        nombre_lignes,
    )

    echantillon = df.sample(
        n=taille_echantillon,
        random_state=RANDOM_STATE,
    ).copy()

    echantillon["Source_File"] = nom_court
    echantillons.append(echantillon)

    logger.info("Dimensions : %s", df.shape)
    logger.info("Classes présentes : %d", nombre_classes)
    logger.info("Valeurs manquantes : %d", valeurs_manquantes)
    logger.info("Valeurs infinies : %d", valeurs_infinies)
    logger.info(
        "Doublons : %d (%.2f%%)",
        doublons,
        100 * doublons / nombre_lignes,
    )
    logger.info(
        "Trafic BENIGN : %d | Attaques : %d",
        lignes_benignes,
        lignes_attaques,
    )
    logger.info(
        "Échantillon conservé : %d observations",
        taille_echantillon,
    )

    del df
    del numeric_df
    del numeric_without_inf
    gc.collect()


# ============================================================
# 5. ENREGISTREMENT DES PREUVES PAR FICHIER
# ============================================================

afficher_etape(5, "Création des tableaux comparatifs")

resume_df = pd.DataFrame(resumes_fichiers)
classes_df = pd.DataFrame(distributions_classes)
profils_df = pd.DataFrame(profils_variables)

resume_df.to_csv(
    TABLES_DIR / "03_resume_qualite_par_fichier.csv",
    index=False,
    encoding="utf-8-sig",
)

classes_df.to_csv(
    TABLES_DIR / "04_distribution_classes_par_fichier.csv",
    index=False,
    encoding="utf-8-sig",
)

profils_df.to_csv(
    TABLES_DIR / "05_profil_variables_par_fichier.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info(
    "Tableau principal : 03_resume_qualite_par_fichier.csv"
)
logger.info(
    "Distribution des classes : "
    "04_distribution_classes_par_fichier.csv"
)
logger.info(
    "Profil détaillé : 05_profil_variables_par_fichier.csv"
)

print("\nRésumé comparatif des huit fichiers :")
print(
    resume_df[
        [
            "nom_court",
            "lignes",
            "colonnes",
            "classes",
            "valeurs_manquantes",
            "valeurs_infinies",
            "doublons",
        ]
    ].to_string(index=False)
)


# ============================================================
# 6. GRAPHIQUES COMPARATIFS DES HUIT FICHIERS
# ============================================================

afficher_etape(6, "Création des graphiques comparatifs")

# 6.1 Nombre de lignes par fichier

plot_df = resume_df.sort_values("lignes")

plt.figure(figsize=(13, 7))
bars = plt.barh(
    plot_df["nom_court"],
    plot_df["lignes"],
    color="#1F77B4",
)

plt.title(
    "Nombre d’observations dans chacun des huit fichiers",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Nombre d’observations")
plt.ylabel("Fichier")

for barre in bars:
    valeur = int(barre.get_width())
    plt.text(
        valeur,
        barre.get_y() + barre.get_height() / 2,
        f" {valeur:,}".replace(",", " "),
        va="center",
        fontsize=9,
    )

enregistrer_figure("02_nombre_lignes_par_fichier.png")


# 6.2 Valeurs manquantes et infinies
#
# Elles sont représentées en effectifs dans deux panneaux séparés.
# Une échelle logarithmique symétrique rend visibles les petites valeurs
# sans masquer les valeurs nulles.

qualite_rare = resume_df.set_index("nom_court")[
    ["valeurs_manquantes", "valeurs_infinies"]
]

fig, axes = plt.subplots(2, 1, figsize=(15, 11), sharex=True)

configurations = [
    ("valeurs_manquantes", "Valeurs manquantes", "#F4B942"),
    ("valeurs_infinies", "Valeurs infinies", "#D95F59"),
]

for ax, (colonne, titre, couleur) in zip(axes, configurations):
    valeurs = qualite_rare[colonne]
    bars = ax.bar(
        qualite_rare.index,
        valeurs,
        color=couleur,
        edgecolor="white",
    )
    ax.set_yscale("symlog", linthresh=1)
    ax.set_title(titre, fontsize=13, fontweight="bold")
    ax.set_ylabel("Nombre de valeurs")
    ax.bar_label(
        bars,
        labels=[f"{int(valeur):,}".replace(",", " ") for valeur in valeurs],
        padding=3,
        fontsize=9,
    )

axes[-1].set_xlabel("Fichier")
axes[-1].tick_params(axis="x", rotation=35)
for etiquette in axes[-1].get_xticklabels():
    etiquette.set_ha("right")

fig.suptitle(
    "Valeurs manquantes et infinies dans les huit fichiers",
    fontsize=15,
    fontweight="bold",
)

enregistrer_figure("03_qualite_par_fichier.png")


# 6.3 Doublons

doublons_plot = resume_df.set_index("nom_court")[
    "taux_doublons_pct"
]

plt.figure(figsize=(15, 8))
bars = plt.bar(
    doublons_plot.index,
    doublons_plot,
    color="#6A4C93",
    edgecolor="white",
)

plt.title(
    "Taux de doublons dans chacun des huit fichiers",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Fichier")
plt.ylabel("Doublons (%)")
plt.xticks(rotation=35, ha="right")
plt.bar_label(
    bars,
    labels=[f"{valeur:.2f} %" for valeur in doublons_plot],
    padding=3,
    fontsize=9,
)

enregistrer_figure("03b_taux_doublons.png")


# 6.4 Trafic BENIGN et attaques

trafic_plot = resume_df.set_index("nom_court")[
    ["benign", "attaques"]
].copy()

trafic_percent = trafic_plot.div(
    trafic_plot.sum(axis=1),
    axis=0,
) * 100

trafic_percent.plot(
    kind="bar",
    stacked=True,
    figsize=(15, 8),
    color=["#2CA02C", "#D62728"],
)

plt.title(
    "Proportion du trafic BENIGN et des attaques par fichier",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Fichier")
plt.ylabel("Pourcentage des observations")
plt.xticks(rotation=35, ha="right")
plt.legend(["BENIGN", "Attaques"], title="Type de trafic")

enregistrer_figure("04_benign_attaques_par_fichier.png")


# 6.5 Taux d'attaques seul
#
# L'échelle symlog conserve la valeur zéro et agrandit les faibles taux.

taux_attaques_plot = (
    resume_df
    .set_index("nom_court")["taux_attaques_pct"]
    .sort_values()
)

plt.figure(figsize=(13, 8))
bars = plt.barh(
    taux_attaques_plot.index,
    taux_attaques_plot,
    color="#D62728",
    edgecolor="white",
)

plt.xscale("symlog", linthresh=0.01)
plt.title(
    "Taux d’attaques détecté dans chacun des huit fichiers",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Attaques (%) — échelle symlog")
plt.ylabel("Fichier")
plt.bar_label(
    bars,
    labels=[
        f"{valeur:.4f} %" if valeur < 0.1 else f"{valeur:.2f} %"
        for valeur in taux_attaques_plot
    ],
    padding=4,
    fontsize=9,
)

enregistrer_figure("04b_taux_attaques_par_fichier.png")


# 6.6 Carte de présence des classes dans les fichiers

presence_classes = classes_df.pivot_table(
    index="classe",
    columns="nom_court",
    values="effectif",
    aggfunc="sum",
    fill_value=0,
)

plt.figure(
    figsize=(19, max(9, 0.65 * len(presence_classes)))
)

annotations_classes = presence_classes.applymap(
    lambda valeur: (
        f"{int(valeur):,}".replace(",", " ")
        if valeur > 0
        else ""
    )
)

sns.heatmap(
    np.log10(presence_classes + 1),
    cmap="Blues",
    linewidths=0.5,
    cbar_kws={"label": "log10(effectif + 1)"},
    annot=annotations_classes,
    fmt="",
    annot_kws={"fontsize": 7},
)

plt.title(
    "Présence des classes dans les huit fichiers CIC-IDS2017",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Fichier")
plt.ylabel("Classe")

enregistrer_figure("05_presence_classes_par_fichier.png")


# ============================================================
# 7. RÉSULTATS GLOBAUX DES HUIT FICHIERS
# ============================================================

afficher_etape(7, "Agrégation des résultats des huit fichiers")

total_lignes = int(resume_df["lignes"].sum())
total_manquantes = int(
    resume_df["valeurs_manquantes"].sum()
)
total_infinies = int(
    resume_df["valeurs_infinies"].sum()
)
total_doublons_internes = int(
    resume_df["doublons"].sum()
)
total_benign = int(resume_df["benign"].sum())
total_attaques = int(resume_df["attaques"].sum())

distribution_globale = (
    classes_df.groupby("classe", as_index=False)["effectif"]
    .sum()
    .sort_values("effectif", ascending=False)
)

distribution_globale["pourcentage_global"] = (
    100 * distribution_globale["effectif"] / total_lignes
).round(6)

resume_global = pd.DataFrame(
    [
        {
            "nombre_fichiers": len(csv_files),
            "nombre_lignes": total_lignes,
            "nombre_colonnes": len(schema_reference),
            "nombre_classes": distribution_globale["classe"].nunique(),
            "valeurs_manquantes": total_manquantes,
            "valeurs_infinies": total_infinies,
            "doublons_internes_aux_fichiers": total_doublons_internes,
            "lignes_benign": total_benign,
            "lignes_attaques": total_attaques,
            "taux_benign_pct": round(
                100 * total_benign / total_lignes,
                4,
            ),
            "taux_attaques_pct": round(
                100 * total_attaques / total_lignes,
                4,
            ),
        }
    ]
)

resume_global.to_csv(
    TABLES_DIR / "06_resume_global.csv",
    index=False,
    encoding="utf-8-sig",
)

distribution_globale.to_csv(
    TABLES_DIR / "07_distribution_globale_classes.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info("Nombre total de fichiers : %d", len(csv_files))
logger.info("Nombre total de lignes : %s", f"{total_lignes:,}")
logger.info("Nombre de colonnes : %d", len(schema_reference))
logger.info(
    "Nombre global de classes : %d",
    distribution_globale["classe"].nunique(),
)
logger.info(
    "Valeurs manquantes globales : %s",
    f"{total_manquantes:,}",
)
logger.info(
    "Valeurs infinies globales : %s",
    f"{total_infinies:,}",
)
logger.info(
    "Somme des doublons internes : %s",
    f"{total_doublons_internes:,}",
)

print("\nRésumé global :")
print(resume_global.to_string(index=False))


# ============================================================
# 8. DISTRIBUTION GLOBALE DES CLASSES
# ============================================================

afficher_etape(8, "Analyse globale des classes")

plot_classes = distribution_globale.sort_values("effectif")

plt.figure(
    figsize=(14, max(8, 0.55 * len(plot_classes)))
)

bars = plt.barh(
    plot_classes["classe"],
    plot_classes["effectif"],
    color=[
        "#2CA02C" if str(classe).upper() == "BENIGN"
        else "#D62728"
        for classe in plot_classes["classe"]
    ],
)

plt.xscale("log")
plt.title(
    "Distribution globale des classes des huit fichiers CIC-IDS2017",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Nombre d’observations — échelle logarithmique")
plt.ylabel("Classe")

for barre, valeur in zip(bars, plot_classes["effectif"]):
    plt.text(
        barre.get_width(),
        barre.get_y() + barre.get_height() / 2,
        f" {int(valeur):,}".replace(",", " "),
        va="center",
        fontsize=8,
    )

enregistrer_figure("06_distribution_globale_classes.png")

classe_majoritaire = distribution_globale.iloc[0]
classe_minoritaire = distribution_globale.iloc[-1]

rapport_desequilibre = (
    classe_majoritaire["effectif"]
    / max(classe_minoritaire["effectif"], 1)
)

desequilibre_df = pd.DataFrame(
    [
        {
            "classe_majoritaire": classe_majoritaire["classe"],
            "effectif_majoritaire": int(
                classe_majoritaire["effectif"]
            ),
            "classe_minoritaire": classe_minoritaire["classe"],
            "effectif_minoritaire": int(
                classe_minoritaire["effectif"]
            ),
            "rapport_desequilibre": round(
                rapport_desequilibre,
                2,
            ),
        }
    ]
)

desequilibre_df.to_csv(
    TABLES_DIR / "08_preuve_desequilibre_classes.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info(
    "Classe majoritaire : %s (%d observations)",
    classe_majoritaire["classe"],
    classe_majoritaire["effectif"],
)
logger.info(
    "Classe minoritaire : %s (%d observations)",
    classe_minoritaire["classe"],
    classe_minoritaire["effectif"],
)
logger.info(
    "Rapport de déséquilibre : %.2f",
    rapport_desequilibre,
)


# ============================================================
# 9. CRÉATION DE L’ÉCHANTILLON GLOBAL REPRÉSENTATIF
# ============================================================

afficher_etape(
    9,
    "Création d’un échantillon provenant des huit fichiers",
)

echantillon_global = pd.concat(
    echantillons,
    ignore_index=True,
)

logger.info(
    "Taille de l’échantillon global : %s",
    echantillon_global.shape,
)
logger.info(
    "Nombre de fichiers représentés : %d",
    echantillon_global["Source_File"].nunique(),
)

preuve_echantillon = (
    echantillon_global["Source_File"]
    .value_counts()
    .rename_axis("fichier")
    .reset_index(name="observations")
)

preuve_echantillon.to_csv(
    TABLES_DIR / "09_composition_echantillon_global.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info(
    "Preuve enregistrée : 09_composition_echantillon_global.csv"
)


# ============================================================
# 10. STATISTIQUES DESCRIPTIVES GLOBALES
# ============================================================

afficher_etape(10, "Statistiques descriptives globales")

sample_numeric = echantillon_global.select_dtypes(
    include=[np.number]
).replace(
    [np.inf, -np.inf],
    np.nan,
)

statistiques = sample_numeric.describe(
    percentiles=[0.25, 0.50, 0.75]
).T

statistiques["mediane"] = sample_numeric.median()
statistiques["valeurs_zero"] = sample_numeric.eq(0).sum()
statistiques["taux_zero_pct"] = (
    100
    * statistiques["valeurs_zero"]
    / len(sample_numeric)
).round(4)

statistiques["valeurs_manquantes"] = (
    sample_numeric.isna().sum()
)

statistiques.to_csv(
    TABLES_DIR / "10_statistiques_descriptives_globales.csv",
    encoding="utf-8-sig",
)

logger.info(
    "Statistiques calculées sur %d observations issues des huit fichiers.",
    len(echantillon_global),
)
logger.info(
    "Preuve enregistrée : "
    "10_statistiques_descriptives_globales.csv"
)


# ============================================================
# 11. CORRÉLATION GLOBALE
# ============================================================

afficher_etape(11, "Calcul de la corrélation globale")

label_column = next(
    colonne
    for colonne in echantillon_global.columns
    if colonne.lower() == "label"
)

target_attack = (
    nettoyer_labels_classes(echantillon_global[label_column])
    .str.upper()
    .ne("BENIGN")
    .astype(int)
)

variables_valides = sample_numeric.columns[
    sample_numeric.nunique(dropna=True) > 1
]

correlation_target = (
    sample_numeric[variables_valides]
    .corrwith(target_attack)
    .dropna()
    .sort_values(key=np.abs, ascending=False)
)

correlation_target_df = correlation_target.rename(
    "correlation_avec_attaque"
).reset_index()

correlation_target_df.columns = [
    "variable",
    "correlation_avec_attaque",
]

correlation_target_df[
    "correlation_absolue"
] = correlation_target_df[
    "correlation_avec_attaque"
].abs()

correlation_target_df.to_csv(
    TABLES_DIR / "11_correlation_variables_attaque.csv",
    index=False,
    encoding="utf-8-sig",
)

top_features = correlation_target_df.head(20)[
    "variable"
].tolist()

correlation_data = sample_numeric[top_features].copy()
correlation_data["Type_Attaque"] = target_attack

correlation_matrix = correlation_data.corr(method="pearson")

correlation_matrix.to_csv(
    TABLES_DIR / "12_matrice_correlation_globale.csv",
    encoding="utf-8-sig",
)

plt.figure(figsize=(18, 15))

sns.heatmap(
    correlation_matrix,
    cmap="coolwarm",
    center=0,
    vmin=-1,
    vmax=1,
    square=False,
    linewidths=0.3,
    cbar_kws={"label": "Coefficient de corrélation de Pearson"},
)

plt.title(
    "Matrice de corrélation globale — échantillon des huit fichiers",
    fontsize=15,
    fontweight="bold",
)
plt.xticks(rotation=65, ha="right")
plt.yticks(rotation=0)

enregistrer_figure("07_matrice_correlation_globale.png")

top_corr_plot = correlation_target_df.head(15).sort_values(
    "correlation_avec_attaque"
)

plt.figure(figsize=(13, 8))

couleurs = [
    "#D62728" if valeur > 0 else "#1F77B4"
    for valeur in top_corr_plot["correlation_avec_attaque"]
]

plt.barh(
    top_corr_plot["variable"],
    top_corr_plot["correlation_avec_attaque"],
    color=couleurs,
)

plt.axvline(0, color="black", linewidth=1)
plt.title(
    "Variables les plus corrélées avec la présence d’une attaque",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Coefficient de corrélation")
plt.ylabel("Variable")

enregistrer_figure("08_correlation_avec_attaque.png")

logger.info(
    "Corrélation calculée sur un échantillon de %d observations.",
    len(echantillon_global),
)
logger.info(
    "Chaque fichier contribue avec un maximum de %d observations.",
    SAMPLE_SIZE_PER_FILE,
)


# ============================================================
# 12. DÉTECTION DES VALEURS ABERRANTES
# ============================================================

afficher_etape(
    12,
    "Détection des valeurs aberrantes par la méthode IQR",
)

resultats_outliers = []

for variable in top_features[:15]:
    serie = sample_numeric[variable].dropna()

    if serie.empty:
        continue

    q1 = serie.quantile(0.25)
    q3 = serie.quantile(0.75)
    iqr = q3 - q1

    limite_inferieure = q1 - 1.5 * iqr
    limite_superieure = q3 + 1.5 * iqr

    outliers = (
        (serie < limite_inferieure)
        | (serie > limite_superieure)
    )

    nombre_outliers = int(outliers.sum())

    resultats_outliers.append(
        {
            "variable": variable,
            "q1": q1,
            "q3": q3,
            "iqr": iqr,
            "limite_inferieure": limite_inferieure,
            "limite_superieure": limite_superieure,
            "nombre_valeurs_aberrantes": nombre_outliers,
            "taux_valeurs_aberrantes_pct": round(
                100 * nombre_outliers / len(serie),
                4,
            ),
        }
    )

outliers_df = pd.DataFrame(resultats_outliers).sort_values(
    "taux_valeurs_aberrantes_pct",
    ascending=False,
)

outliers_df.to_csv(
    TABLES_DIR / "13_valeurs_aberrantes_iqr.csv",
    index=False,
    encoding="utf-8-sig",
)

plt.figure(figsize=(13, 8))

plt.barh(
    outliers_df["variable"],
    outliers_df["taux_valeurs_aberrantes_pct"],
    color="#E67E22",
)

plt.gca().invert_yaxis()
plt.title(
    "Taux de valeurs aberrantes détectées par la méthode IQR",
    fontsize=15,
    fontweight="bold",
)
plt.xlabel("Valeurs aberrantes (%)")
plt.ylabel("Variable")

enregistrer_figure("09_valeurs_aberrantes_iqr.png")

logger.info(
    "Preuve enregistrée : 13_valeurs_aberrantes_iqr.csv"
)


# ============================================================
# 13. MANIFESTE FINAL DES RÉSULTATS
# ============================================================

afficher_etape(13, "Vérification finale des sorties produites")

fichiers_produits = sorted(
    [
        fichier
        for fichier in OUTPUT_DIR.rglob("*")
        if fichier.is_file()
    ]
)

manifeste = pd.DataFrame(
    {
        "numero": range(1, len(fichiers_produits) + 1),
        "fichier": [
            str(fichier.relative_to(OUTPUT_DIR))
            for fichier in fichiers_produits
        ],
        "taille_ko": [
            round(fichier.stat().st_size / 1024, 2)
            for fichier in fichiers_produits
        ],
    }
)

manifeste.to_csv(
    OUTPUT_DIR / "manifest_outputs.csv",
    index=False,
    encoding="utf-8-sig",
)

logger.info("EDA terminée avec succès.")
logger.info("Résultats enregistrés dans : %s", OUTPUT_DIR)
logger.info(
    "Nombre de tableaux produits : %d",
    len(list(TABLES_DIR.glob("*.csv"))),
)
logger.info(
    "Nombre de graphiques produits : %d",
    len(list(FIGURES_DIR.glob("*.png"))),
)
logger.info(
    "Aucune suppression, imputation, normalisation ou correction "
    "des données n’a été réalisée pendant l’EDA."
)

print("\n" + "=" * 75)
print("ANALYSE EXPLORATOIRE TERMINÉE AVEC SUCCÈS")
print(f"Résultats : {OUTPUT_DIR}")
print("=" * 75)