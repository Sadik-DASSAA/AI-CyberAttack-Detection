# Nom du fichier : 04_Modelisation_Evaluation_COMPLET_ECHELLE.py

import json
import time
import warnings
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from matplotlib.colors import LogNorm
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")


# ============================================================
# 1. Configuration generale et styles graphiques
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

PREPROCESSED_DIR = PROJECT_ROOT / "outputs" / "preprocessing" / "processed"

OUTPUT_DIR = PROJECT_ROOT / "outputs" / "modelisation_evaluation"
TABLES_DIR = OUTPUT_DIR / "tables"
FIGURES_DIR = OUTPUT_DIR / "figures"
MODELS_DIR = OUTPUT_DIR / "models"
MODEL_INFO_DIR = OUTPUT_DIR / "model_info"

for folder in [OUTPUT_DIR, TABLES_DIR, FIGURES_DIR, MODELS_DIR, MODEL_INFO_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
DPI = 300

# None signifie : utiliser tout l'ensemble Train.
# Attention : cette execution peut etre longue avec CIC-IDS2017 complet.
TRAIN_SAMPLE_SIZE = None

# La regression logistique est tres lente sur CIC-IDS2017 complet.
# Elle reste desactivee par defaut pour eviter un blocage tres long.
RUN_LOGISTIC_REGRESSION = False

# Nombre d'arbres raisonnable pour entrainer sur toutes les donnees.
N_ESTIMATORS_TREE_ENSEMBLES = 20

# Configuration typographique globale pour une lisibilité accrue
sns.set_theme(style="whitegrid")
plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
        "mathtext.fontset": "stixsans",  # Compacter visuellement la typographie
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
# 2. Fonctions utilitaires
# ============================================================

def enregistrer_tableau(df, nom):
    chemin = TABLES_DIR / nom
    df.to_csv(chemin, index=False, encoding="utf-8-sig")
    print(f"Tableau enregistre : {chemin}")


def enregistrer_figure(nom):
    chemin = FIGURES_DIR / nom
    plt.tight_layout()
    plt.savefig(chemin, dpi=DPI, bbox_inches="tight")
    plt.close()
    print(f"Graphique enregistre : {chemin}")


def formater_valeur_graphique(valeur, decimales=None, suffixe=""):
    if pd.isna(valeur) or not np.isfinite(float(valeur)):
        return ""

    valeur = float(valeur)

    if decimales is not None:
        texte = f"{valeur:.{decimales}f}"
    elif abs(valeur) >= 1000:
        texte = f"{valeur:,.0f}".replace(",", " ")
    elif abs(valeur) >= 100:
        texte = f"{valeur:.0f}"
    elif abs(valeur) >= 10:
        texte = f"{valeur:.2f}".rstrip("0").rstrip(".")
    else:
        texte = f"{valeur:.4f}".rstrip("0").rstrip(".")

    return f"{texte}{suffixe}"


def annoter_barres(ax, orientation="vertical", decimales=None, suffixe="", taille=11):
    for conteneur in ax.containers:
        etiquettes = []

        for barre in conteneur:
            valeur = barre.get_width() if orientation == "horizontal" else barre.get_height()
            etiquettes.append(
                formater_valeur_graphique(valeur, decimales=decimales, suffixe=suffixe)
            )

        try:
            ax.bar_label(
                conteneur,
                labels=etiquettes,
                padding=4,
                fontsize=taille,
                fontweight="bold",
            )
        except AttributeError:
            for barre, etiquette in zip(conteneur, etiquettes):
                if not etiquette:
                    continue

                if orientation == "horizontal":
                    x = barre.get_width()
                    y = barre.get_y() + barre.get_height() / 2
                    ax.annotate(
                        etiquette,
                        (x, y),
                        xytext=(4, 0),
                        textcoords="offset points",
                        ha="left",
                        va="center",
                        fontsize=taille,
                        fontweight="bold",
                    )
                else:
                    x = barre.get_x() + barre.get_width() / 2
                    y = barre.get_height()
                    ax.annotate(
                        etiquette,
                        (x, y),
                        xytext=(0, 4),
                        textcoords="offset points",
                        ha="center",
                        va="bottom",
                        fontsize=taille,
                        fontweight="bold",
                    )


def appliquer_echelle_symlog(ax, axe="x", seuil=1, maximum=None):
    seuil = max(float(seuil), 1e-9)

    if axe == "x":
        ax.set_xscale("symlog", linthresh=seuil)
        if maximum is not None and pd.notna(maximum):
            ax.set_xlim(0, max(float(maximum) * 1.7, seuil * 2))
    else:
        ax.set_yscale("symlog", linthresh=seuil)
        if maximum is not None and pd.notna(maximum):
            ax.set_ylim(0, max(float(maximum) * 1.7, seuil * 2))


def ajuster_zoom_scores(ax, valeurs):
    valeurs = pd.Series(valeurs).dropna()
    if valeurs.empty:
        ax.set_ylim(0, 1.08)
        return

    score_min = float(valeurs.min())
    score_max = float(valeurs.max())

    if score_min >= 0.70 and (score_max - score_min) <= 0.25:
        bas = max(0, score_min - 0.03)
        haut = min(1.05, score_max + 0.03)
        ax.set_ylim(bas, haut)
        ax.set_ylabel("Score (zoom)", fontsize=14, fontweight="bold")
    else:
        ax.set_ylim(0, 1.08)
        ax.set_ylabel("Score", fontsize=14, fontweight="bold")


def charger_json(chemin):
    with open(chemin, "r", encoding="utf-8") as fichier:
        return json.load(fichier)


def obtenir_classes_ordonnees(mapping_labels):
    return [
        classe
        for classe, _ in sorted(mapping_labels.items(), key=lambda element: element[1])
    ]


def nom_fichier_modele(nom_modele):
    return (
        nom_modele.lower()
        .replace(" ", "_")
        .replace("-", "_")
        .replace("/", "_")
    )


def lire_labels(chemin):
    labels = pd.read_csv(chemin)
    if "Label" in labels.columns:
        return labels["Label"].astype(int)
    return labels.iloc[:, 0].astype(int)


def verifier_fichiers_requis(fichiers):
    fichiers_manquants = [str(chemin) for chemin in fichiers if not chemin.exists()]
    if fichiers_manquants:
        message = "\n".join(fichiers_manquants)
        raise FileNotFoundError(
            "Fichiers introuvables. Verifiez d'abord le dossier processed :\n"
            f"{message}"
        )


def echantillonner_train(X_train, y_train, taille):
    if taille is None or len(X_train) <= taille:
        return X_train, y_train

    train = X_train.copy()
    train["Label"] = y_train.values

    parties = []
    for _, groupe in train.groupby("Label"):
        n = max(1, int(taille * len(groupe) / len(train)))
        n = min(n, len(groupe))
        parties.append(groupe.sample(n=n, random_state=RANDOM_STATE))

    train_sample = pd.concat(parties, ignore_index=True)
    train_sample = train_sample.sample(frac=1, random_state=RANDOM_STATE)

    y_sample = train_sample["Label"].astype(int)
    X_sample = train_sample.drop(columns=["Label"])

    return X_sample, y_sample


def tracer_matrice_confusion(y_true, y_pred, classes, nom_modele):
    labels = list(range(len(classes)))
    matrice = confusion_matrix(y_true, y_pred, labels=labels)

    matrice_normale = matrice.astype(float) / matrice.sum(axis=1, keepdims=True)
    matrice_normale = np.nan_to_num(matrice_normale)

    matrice_df = pd.DataFrame(matrice, index=classes, columns=classes)
    enregistrer_tableau(
        matrice_df.reset_index().rename(columns={"index": "Classe reelle"}),
        f"matrice_confusion_{nom_fichier_modele(nom_modele)}.csv",
    )

    plt.figure(figsize=(15, 10))
    sns.heatmap(
        matrice_normale,
        cmap="Blues",
        xticklabels=classes,
        yticklabels=classes,
        annot=True,
        fmt=".3f",
        annot_kws={"size": 10, "weight": "bold"},
    )
    plt.title(
        f"Matrice de confusion normalisee - {nom_modele}",
        fontsize=18,
        fontweight="bold",
        pad=15,
    )
    plt.xlabel("Classe predite", fontsize=14, fontweight="bold", labelpad=10)
    plt.ylabel("Classe reelle", fontsize=14, fontweight="bold")
    plt.xticks(rotation=45, ha="right", fontsize=11, fontweight="bold")
    plt.yticks(rotation=0, fontsize=11, fontweight="bold")
    enregistrer_figure(f"matrice_confusion_{nom_fichier_modele(nom_modele)}.png")

    matrice_positive = np.where(matrice > 0, matrice, np.nan)
    vmax = max(int(matrice.max()), 1)

    plt.figure(figsize=(15, 10))
    sns.heatmap(
        matrice_positive,
        cmap="YlGnBu",
        norm=LogNorm(vmin=1, vmax=vmax),
        xticklabels=classes,
        yticklabels=classes,
        annot=matrice,
        fmt="d",
        annot_kws={"size": 9, "weight": "bold"},
        cbar_kws={"label": "Nombre d'observations"},
    )
    plt.title(
        f"Matrice de confusion en nombres - {nom_modele}",
        fontsize=18,
        fontweight="bold",
        pad=15,
    )
    plt.xlabel("Classe predite", fontsize=14, fontweight="bold", labelpad=10)
    plt.ylabel("Classe reelle", fontsize=14, fontweight="bold")
    plt.xticks(rotation=45, ha="right", fontsize=11, fontweight="bold")
    plt.yticks(rotation=0, fontsize=11, fontweight="bold")
    enregistrer_figure(
        f"matrice_confusion_{nom_fichier_modele(nom_modele)}_nombres_log.png"
    )


def evaluer_modele(nom_modele, modele, X_train, y_train, X_test, y_test, classes):
    debut = time.time()
    print(f"\nEntrainement du modele : {nom_modele}", flush=True)
    print(f"Lignes Train utilisees : {len(X_train)}", flush=True)

    modele.fit(X_train, y_train)

    duree_fit = (time.time() - debut) / 60
    print(f"Entrainement termine pour {nom_modele} en {duree_fit:.2f} minutes.", flush=True)
    print(f"Evaluation du modele : {nom_modele}", flush=True)

    y_pred = modele.predict(X_test)

    labels = list(range(len(classes)))

    rapport = classification_report(
        y_test,
        y_pred,
        labels=labels,
        target_names=classes,
        output_dict=True,
        zero_division=0,
    )

    rapport_df = pd.DataFrame(rapport).transpose().reset_index()
    rapport_df.rename(columns={"index": "Classe"}, inplace=True)
    enregistrer_tableau(
        rapport_df,
        f"rapport_classification_{nom_fichier_modele(nom_modele)}.csv",
    )

    tracer_matrice_confusion(y_test, y_pred, classes, nom_modele)

    duree_totale = (time.time() - debut) / 60
    print(f"Modele {nom_modele} termine en {duree_totale:.2f} minutes.", flush=True)

    return {
        "Modele": nom_modele,
        "Accuracy": round(accuracy_score(y_test, y_pred), 4),
        "Precision macro": round(
            precision_score(y_test, y_pred, average="macro", zero_division=0), 4
        ),
        "Recall macro": round(
            recall_score(y_test, y_pred, average="macro", zero_division=0), 4
        ),
        "F1-score macro": round(
            f1_score(y_test, y_pred, average="macro", zero_division=0), 4
        ),
        "Precision weighted": round(
            precision_score(y_test, y_pred, average="weighted", zero_division=0), 4
        ),
        "Recall weighted": round(
            recall_score(y_test, y_pred, average="weighted", zero_division=0), 4
        ),
        "F1-score weighted": round(
            f1_score(y_test, y_pred, average="weighted", zero_division=0), 4
        ),
        "Objet modele": modele,
        "Predictions": y_pred,
    }


# ============================================================
# 3. Chargement des donnees pretraitees
# ============================================================

X_train_path = PREPROCESSED_DIR / "X_train_final.csv"
X_test_path = PREPROCESSED_DIR / "X_test_final.csv"
y_train_path = PREPROCESSED_DIR / "y_train.csv"
y_test_path = PREPROCESSED_DIR / "y_test.csv"
mapping_path = PREPROCESSED_DIR / "label_encoder_mapping.json"
class_weights_path = PREPROCESSED_DIR / "class_weights.json"

fichiers_requis = [
    X_train_path,
    X_test_path,
    y_train_path,
    y_test_path,
    mapping_path,
    class_weights_path,
]
verifier_fichiers_requis(fichiers_requis)

print("Chargement des donnees pretraitees...")
X_train = pd.read_csv(X_train_path, dtype=np.float32)
X_test = pd.read_csv(X_test_path, dtype=np.float32)
y_train = lire_labels(y_train_path)
y_test = lire_labels(y_test_path)

mapping_labels = charger_json(mapping_path)
classes = obtenir_classes_ordonnees(mapping_labels)

poids_classes_brut = charger_json(class_weights_path)
poids_classes = {int(code): float(poids) for code, poids in poids_classes_brut.items()}

if X_train.shape[1] != X_test.shape[1]:
    raise ValueError("X_train et X_test n'ont pas le meme nombre de colonnes.")

if list(X_train.columns) != list(X_test.columns):
    raise ValueError("X_train et X_test n'ont pas les memes variables.")

if len(X_train) != len(y_train):
    raise ValueError("X_train et y_train n'ont pas le meme nombre de lignes.")

if len(X_test) != len(y_test):
    raise ValueError("X_test et y_test n'ont pas le meme nombre de lignes.")

resume_chargement = pd.DataFrame(
    [
        {"Element": "X_train", "Lignes": X_train.shape[0], "Colonnes": X_train.shape[1]},
        {"Element": "X_test", "Lignes": X_test.shape[0], "Colonnes": X_test.shape[1]},
        {"Element": "y_train", "Lignes": len(y_train), "Colonnes": 1},
        {"Element": "y_test", "Lignes": len(y_test), "Colonnes": 1},
    ]
)
enregistrer_tableau(resume_chargement, "01_resume_donnees_chargees.csv")

plt.figure(figsize=(10, 6))
ax = sns.barplot(data=resume_chargement.iloc[:2], x="Element", y="Lignes", color="#2E86C1")
annoter_barres(ax, orientation="vertical", taille=11)
ax.margins(y=0.15)
plt.title("Nombre d'observations chargees", fontsize=18, fontweight="bold", pad=15)
plt.xlabel("Ensemble", fontsize=14, fontweight="bold", labelpad=10)
plt.ylabel("Nombre d'observations", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
enregistrer_figure("01_resume_donnees_chargees.png")


# ============================================================
# 4. Verification de la distribution Train/Test
# ============================================================

codes_classes = list(range(len(classes)))

distribution = pd.DataFrame(
    {
        "Code classe": codes_classes,
        "Classe": classes,
        "Train": y_train.value_counts().reindex(codes_classes, fill_value=0).sort_index().values,
        "Test": y_test.value_counts().reindex(codes_classes, fill_value=0).sort_index().values,
    }
)
distribution["Total"] = distribution["Train"] + distribution["Test"]
distribution["Pourcentage total"] = (
    distribution["Total"] / distribution["Total"].sum() * 100
).round(6)

enregistrer_tableau(distribution, "02_distribution_classes_train_test.csv")

distribution_long = distribution.melt(
    id_vars="Classe",
    value_vars=["Train", "Test"],
    var_name="Ensemble",
    value_name="Observations",
)

plt.figure(figsize=(15, 8))
ax = sns.barplot(data=distribution_long, y="Classe", x="Observations", hue="Ensemble")
annoter_barres(ax, orientation="horizontal", taille=10)
max_observations = max(distribution_long["Observations"].max(), 1)
appliquer_echelle_symlog(ax, axe="x", seuil=10, maximum=max_observations)
plt.title("Distribution des classes dans Train et Test", fontsize=18, fontweight="bold", pad=15)
plt.xlabel("Observations", fontsize=14, fontweight="bold", labelpad=10)
plt.ylabel("Classe", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
plt.legend(title="Ensemble", fontsize=12, title_fontsize=13)
enregistrer_figure("02_distribution_classes_train_test.png")


# ============================================================
# 5. Preparation de l'entrainement
# ============================================================

X_train_modele, y_train_modele = echantillonner_train(
    X_train, y_train, TRAIN_SAMPLE_SIZE
)

mode_entrainement = pd.DataFrame(
    [
        {
            "Parametre": "Mode donnees",
            "Valeur": (
                "Toutes les lignes du Train"
                if TRAIN_SAMPLE_SIZE is None
                else "Echantillon stratifie"
            ),
        },
        {
            "Parametre": "TRAIN_SAMPLE_SIZE",
            "Valeur": (
                "None - dataset complet"
                if TRAIN_SAMPLE_SIZE is None
                else TRAIN_SAMPLE_SIZE
            ),
        },
        {"Parametre": "RUN_LOGISTIC_REGRESSION", "Valeur": RUN_LOGISTIC_REGRESSION},
        {"Parametre": "N_ESTIMATORS_TREE_ENSEMBLES", "Valeur": N_ESTIMATORS_TREE_ENSEMBLES},
        {"Parametre": "Lignes Train utilisees", "Valeur": len(X_train_modele)},
        {"Parametre": "Lignes Test utilisees", "Valeur": len(X_test)},
        {"Parametre": "Variables", "Valeur": X_train_modele.shape[1]},
        {"Parametre": "Classes", "Valeur": len(classes)},
    ]
)
enregistrer_tableau(mode_entrainement, "03_mode_entrainement.csv")


# ============================================================
# 6. Definition des modeles
# ============================================================

modeles = {
    "Decision Tree": DecisionTreeClassifier(
        random_state=RANDOM_STATE,
        class_weight=poids_classes,
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=N_ESTIMATORS_TREE_ENSEMBLES,
        random_state=RANDOM_STATE,
        class_weight=poids_classes,
        n_jobs=-1,
        verbose=1,
    ),
    "Extra Trees": ExtraTreesClassifier(
        n_estimators=N_ESTIMATORS_TREE_ENSEMBLES,
        random_state=RANDOM_STATE,
        class_weight=poids_classes,
        n_jobs=-1,
        verbose=1,
    ),
    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        solver="saga",
        class_weight=poids_classes,
        n_jobs=-1,
        random_state=RANDOM_STATE,
    ),
    "Naive Bayes": GaussianNB(),
}

if not RUN_LOGISTIC_REGRESSION:
    modeles.pop("Logistic Regression")

resume_modeles = pd.DataFrame(
    [
        {
            "Modele": "Decision Tree",
            "Role": "Modele simple et interpretable",
            "Gestion desequilibre": "class_weight",
        },
        {
            "Modele": "Random Forest",
            "Role": "Ensemble de plusieurs arbres",
            "Gestion desequilibre": "class_weight",
        },
        {
            "Modele": "Extra Trees",
            "Role": "Variante plus aleatoire des forets d'arbres",
            "Gestion desequilibre": "class_weight",
        },
        {
            "Modele": "Logistic Regression",
            "Role": "Modele lineaire de reference",
            "Gestion desequilibre": "class_weight",
        },
        {
            "Modele": "Naive Bayes",
            "Role": "Baseline probabiliste simple",
            "Gestion desequilibre": "Non applique",
        },
    ]
)
resume_modeles = resume_modeles[resume_modeles["Modele"].isin(modeles.keys())]
enregistrer_tableau(resume_modeles, "04_modeles_utilises.csv")


# ============================================================
# 7. Entrainement et evaluation
# ============================================================

resultats = []

for nom_modele, modele in modeles.items():
    resultat = evaluer_modele(
        nom_modele=nom_modele,
        modele=modele,
        X_train=X_train_modele,
        y_train=y_train_modele,
        X_test=X_test,
        y_test=y_test,
        classes=classes,
    )
    resultats.append(resultat)

comparaison = pd.DataFrame(resultats).drop(columns=["Objet modele", "Predictions"])
comparaison = comparaison.sort_values("F1-score macro", ascending=False)
enregistrer_tableau(comparaison, "05_comparaison_modeles.csv")

comparaison_long = comparaison.melt(
    id_vars="Modele",
    value_vars=["Accuracy", "Precision macro", "Recall macro", "F1-score macro"],
    var_name="Metrique",
    value_name="Score",
)

plt.figure(figsize=(15, 7.5))
ax = sns.barplot(data=comparaison_long, x="Modele", y="Score", hue="Metrique")
annoter_barres(ax, orientation="vertical", decimales=3, taille=10)
ajuster_zoom_scores(ax, comparaison_long["Score"])
plt.title("Comparaison globale des modeles", fontsize=18, fontweight="bold", pad=15)
plt.xlabel("Modele", fontsize=14, fontweight="bold", labelpad=10)
plt.xticks(rotation=15, ha="right", fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
plt.legend(title="Metrique", fontsize=12, title_fontsize=13, loc="lower right")
enregistrer_figure("05_comparaison_modeles.png")


# ============================================================
# 8. Choix du meilleur modele
# ============================================================

meilleur_nom = comparaison.iloc[0]["Modele"]
meilleur_score = comparaison.iloc[0]["F1-score macro"]

meilleur_resultat = next(
    resultat for resultat in resultats if resultat["Modele"] == meilleur_nom
)
meilleur_modele = meilleur_resultat["Objet modele"]
y_pred_meilleur = meilleur_resultat["Predictions"]

resume_meilleur = pd.DataFrame(
    [
        {
            "Meilleur modele": meilleur_nom,
            "Critere principal": "F1-score macro",
            "Score": meilleur_score,
            "Justification": (
                "Le F1-score macro est retenu car il donne le meme poids a toutes "
                "les classes, ce qui est adapte au desequilibre de CIC-IDS2017."
            ),
        }
    ]
)
enregistrer_tableau(resume_meilleur, "06_meilleur_modele.csv")

joblib.dump(meilleur_modele, MODELS_DIR / "meilleur_modele.pkl")

with open(MODEL_INFO_DIR / "meilleur_modele.json", "w", encoding="utf-8") as fichier:
    json.dump(
        {
            "meilleur_modele": meilleur_nom,
            "critere": "F1-score macro",
            "score": float(meilleur_score),
            "mode_donnees": (
                "Toutes les lignes du Train"
                if TRAIN_SAMPLE_SIZE is None
                else "Echantillon stratifie"
            ),
            "train_sample_size": TRAIN_SAMPLE_SIZE,
            "lignes_train_utilisees": int(len(X_train_modele)),
            "lignes_test_utilisees": int(len(X_test)),
            "run_logistic_regression": RUN_LOGISTIC_REGRESSION,
            "n_estimators_tree_ensembles": N_ESTIMATORS_TREE_ENSEMBLES,
            "variables": list(X_train.columns),
            "classes": classes,
        },
        fichier,
        ensure_ascii=False,
        indent=4,
    )


# ============================================================
# 9. Importance des variables
# ============================================================

if hasattr(meilleur_modele, "feature_importances_"):
    importance = pd.DataFrame(
        {
            "Variable": X_train.columns,
            "Importance": meilleur_modele.feature_importances_,
        }
    ).sort_values("Importance", ascending=False)
elif hasattr(meilleur_modele, "coef_"):
    importance = pd.DataFrame(
        {
            "Variable": X_train.columns,
            "Importance": np.mean(np.abs(meilleur_modele.coef_), axis=0),
        }
    ).sort_values("Importance", ascending=False)
else:
    importance = pd.DataFrame(
        [{"Variable": "Non disponible", "Importance": np.nan}]
    )

enregistrer_tableau(importance, "07_importance_variables_meilleur_modele.csv")

if "Non disponible" not in importance["Variable"].values:
    plt.figure(figsize=(15, 8))
    importance_top20 = importance.head(20)
    ax = sns.barplot(data=importance_top20, y="Variable", x="Importance", color="#2E86C1")
    annoter_barres(ax, orientation="horizontal", decimales=4, taille=10)
    max_importance = importance_top20["Importance"].max()
    if pd.notna(max_importance) and max_importance > 0:
        valeurs_importance = importance_top20["Importance"]
        valeurs_positives = valeurs_importance[valeurs_importance > 0]

        if not valeurs_positives.empty and max_importance / valeurs_positives.min() >= 50:
            appliquer_echelle_symlog(
                ax,
                axe="x",
                seuil=max(max_importance / 100, 1e-6),
                maximum=max_importance,
            )
            plt.xlabel("Importance", fontsize=14, fontweight="bold", labelpad=10)
        else:
            ax.set_xlim(0, max_importance * 1.25)
            plt.xlabel("Importance", fontsize=14, fontweight="bold", labelpad=10)
    plt.title(f"Top 20 des variables importantes - {meilleur_nom}", fontsize=18, fontweight="bold", pad=15)
    plt.ylabel("Variable", fontsize=14, fontweight="bold")
    plt.xticks(fontsize=12, fontweight="bold")
    plt.yticks(fontsize=12, fontweight="bold")
    enregistrer_figure("07_importance_variables_meilleur_modele.png")


# ============================================================
# 10. Analyse des erreurs du meilleur modele
# ============================================================

erreurs = pd.DataFrame(
    {
        "Classe reelle": y_test.astype(int),
        "Classe predite": y_pred_meilleur.astype(int),
    }
)
erreurs["Erreur"] = erreurs["Classe reelle"] != erreurs["Classe predite"]

erreurs_classe = (
    erreurs.groupby("Classe reelle")
    .agg(Nombre_total=("Erreur", "count"), Nombre_erreurs=("Erreur", "sum"))
    .reset_index()
)
erreurs_classe["Classe"] = erreurs_classe["Classe reelle"].apply(
    lambda code: classes[int(code)]
)
erreurs_classe["Taux erreur (%)"] = (
    erreurs_classe["Nombre_erreurs"] / erreurs_classe["Nombre_total"] * 100
).round(4)
erreurs_classe = erreurs_classe[
    ["Classe reelle", "Classe", "Nombre_total", "Nombre_erreurs", "Taux erreur (%)"]
]

enregistrer_tableau(erreurs_classe, "08_erreurs_par_classe_meilleur_modele.csv")

plt.figure(figsize=(15, 8))
ax = sns.barplot(data=erreurs_classe, y="Classe", x="Taux erreur (%)", color="#C0392B")
annoter_barres(ax, orientation="horizontal", decimales=2, suffixe="%", taille=10)
max_erreur = erreurs_classe["Taux erreur (%)"].max()
if pd.notna(max_erreur):
    if max_erreur > 0:
        appliquer_echelle_symlog(
            ax,
            axe="x",
            seuil=0.1,
            maximum=max(max_erreur, 0.1),
        )
        plt.xlabel("Taux d'erreur (%)", fontsize=14, fontweight="bold", labelpad=10)
    else:
        ax.set_xlim(0, 1)
        plt.xlabel("Taux d'erreur (%)", fontsize=14, fontweight="bold", labelpad=10)
plt.title(f"Taux d'erreur par classe - {meilleur_nom}", fontsize=18, fontweight="bold", pad=15)
plt.ylabel("Classe", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
enregistrer_figure("08_erreurs_par_classe_meilleur_modele.png")

plt.figure(figsize=(15, 8))
ax = sns.barplot(data=erreurs_classe, y="Classe", x="Nombre_erreurs", color="#884EA0")
annoter_barres(ax, orientation="horizontal", taille=10)
max_nombre_erreurs = erreurs_classe["Nombre_erreurs"].max()
if pd.notna(max_nombre_erreurs):
    if max_nombre_erreurs > 0:
        appliquer_echelle_symlog(
            ax,
            axe="x",
            seuil=1,
            maximum=max_nombre_erreurs,
        )
    else:
        ax.set_xlim(0, 1)
plt.title(f"Nombre d'erreurs par classe - {meilleur_nom}", fontsize=18, fontweight="bold", pad=15)
plt.xlabel("Nombre d'erreurs ", fontsize=14, fontweight="bold", labelpad=10)
plt.ylabel("Classe", fontsize=14, fontweight="bold")
plt.xticks(fontsize=12, fontweight="bold")
plt.yticks(fontsize=12, fontweight="bold")
enregistrer_figure("08b_nombre_erreurs_par_classe_log.png")


# ============================================================
# 11. README final
# ============================================================

liste_modeles_readme = "\n".join(
    f"{index}. {nom_modele}" for index, nom_modele in enumerate(modeles.keys(), start=1)
)

readme = f"""# README - Modelisation et evaluation

## Objectif

Cette partie entraine plusieurs modeles de classification sur les donnees
pretraitees du dataset CIC-IDS2017, puis compare leurs performances.

## Mode d'entrainement

- Mode utilise : {"toutes les lignes du Train" if TRAIN_SAMPLE_SIZE is None else "echantillon stratifie"}
- Lignes Train utilisees : {len(X_train_modele)}
- Lignes Test utilisees : {len(X_test)}
- Regression logistique entrainee : {RUN_LOGISTIC_REGRESSION}
- Nombre d'arbres pour Random Forest et Extra Trees : {N_ESTIMATORS_TREE_ENSEMBLES}

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

{liste_modeles_readme}

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

- Modele retenu : {meilleur_nom}
- F1-score macro : {meilleur_score}

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
"""

(OUTPUT_DIR / "README_modelisation_evaluation.md").write_text(readme, encoding="utf-8")


# ============================================================
# 12. Fin du script
# ============================================================

print("\nModelisation et evaluation terminees.")
print(f"Meilleur modele : {meilleur_nom}")
print(f"F1-score macro : {meilleur_score}")
print(f"Tableaux generes dans : {TABLES_DIR}")
print(f"Figures generees dans : {FIGURES_DIR}")
print(f"Modele sauvegarde dans : {MODELS_DIR / 'meilleur_modele.pkl'}")
print(f"README genere dans : {OUTPUT_DIR / 'README_modelisation_evaluation.md'}")