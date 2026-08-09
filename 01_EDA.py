"""
Analyse exploratoire individuelle des huit fichiers CIC-IDS2017.

Ce script calcule, pour chaque fichier CSV :
- les dimensions ;
- la distribution des classes ;
- les valeurs manquantes ;
- les valeurs infinies ;
- les lignes dupliquées ;
- le pourcentage de doublons.

Résultats :
    outputs/eda_individuelle/

Dépendances :
    pip install numpy pandas matplotlib
"""

from __future__ import annotations

import argparse
import gc
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


EXPECTED_FILES = {
    "Monday-WorkingHours.pcap_ISCX.csv": "Lundi",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "Mardi",
    "Wednesday-workingHours.pcap_ISCX.csv": "Mercredi",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":
        "Jeudi matin - Attaques Web",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv":
        "Jeudi après-midi - Infiltration",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": "Vendredi matin - Bot",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv":
        "Vendredi après-midi - PortScan",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv":
        "Vendredi après-midi - DDoS",
}

LABEL_COLUMN = "Label"


def format_integer(value: int) -> str:
    return f"{int(value):,}".replace(",", " ")


def find_project_root() -> Path:
    """Trouve la racine contenant les données CIC-IDS2017."""
    relative_data_path = Path(
        "data/raw/CIC-IDS2017/MachineLearningCVE"
    )
    script_path = Path(__file__).resolve()

    for candidate in (script_path.parent, *script_path.parents):
        if (candidate / relative_data_path).is_dir():
            return candidate

    raise FileNotFoundError(
        "Le dossier data/raw/CIC-IDS2017/MachineLearningCVE "
        "est introuvable. Placez ce script dans votre projet."
    )


def normalize_labels(labels: pd.Series) -> pd.Series:
    """Uniformise les espaces, les tirets et SQL Injection."""
    return (
        labels.astype("string")
        .str.strip()
        .str.replace("\ufffd", "-", regex=False)
        .str.replace("–", "-", regex=False)
        .str.replace("—", "-", regex=False)
        .str.replace(r"\s*-\s*", " - ", regex=True)
        .replace({
            "Web Attack - Sql Injection":
                "Web Attack - SQL Injection",
        })
    )


def safe_name(filename: str) -> str:
    return (
        filename.replace(".pcap_ISCX.csv", "")
        .replace(".csv", "")
        .replace("-", "_")
        .replace(" ", "_")
        .lower()
    )


def save_class_chart(
    distribution: pd.Series,
    title: str,
    output_path: Path,
) -> None:
    """Crée un graphique lisible de la distribution des classes."""
    ordered = distribution.sort_values(ascending=True)
    total = int(ordered.sum())
    height = max(4.5, 0.65 * len(ordered) + 2.5)

    fig, ax = plt.subplots(figsize=(13, height))
    colors = [
        "#59A14F" if label == "BENIGN" else "#2C7FB8"
        for label in ordered.index
    ]
    bars = ax.barh(
        ordered.index,
        ordered.values,
        color=colors,
        edgecolor="white",
    )

    if (
        len(ordered) > 1
        and int(ordered.min()) > 0
        and int(ordered.max()) / int(ordered.min()) >= 20
    ):
        ax.set_xscale("log")
        ax.set_xlabel(
            "Nombre d'observations - échelle logarithmique"
        )
    else:
        ax.set_xlabel("Nombre d'observations")

    ax.set_title(f"Distribution des classes - {title}", fontweight="bold")
    ax.set_ylabel("Classe")
    ax.grid(axis="x", linestyle="--", alpha=0.35)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, count in zip(bars, ordered.values):
        percentage = count / total * 100
        label = (
            f"{format_integer(count)} "
            f"({percentage:.4f} %)"
        )
        ax.text(
            bar.get_width() * 1.05,
            bar.get_y() + bar.get_height() / 2,
            label,
            va="center",
            fontsize=9,
        )

    fig.tight_layout()
    fig.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight",
        facecolor="white",
    )
    plt.close(fig)


def analyze_file(
    csv_path: Path,
    display_title: str,
    output_dir: Path,
) -> dict[str, object]:
    """Analyse complètement un fichier et sauvegarde ses résultats."""
    print("\n" + "=" * 88)
    print(f"ANALYSE : {display_title}")
    print(f"FICHIER : {csv_path.name}")
    print("=" * 88)

    dataframe = pd.read_csv(csv_path, low_memory=False)
    dataframe.columns = dataframe.columns.astype(str).str.strip()

    if dataframe.columns.duplicated().any():
        duplicated_columns = (
            dataframe.columns[dataframe.columns.duplicated()].tolist()
        )
        raise ValueError(
            f"Colonnes dupliquées dans {csv_path.name} : "
            f"{duplicated_columns}"
        )
    if LABEL_COLUMN not in dataframe.columns:
        raise KeyError(
            f"La colonne {LABEL_COLUMN!r} est absente de {csv_path.name}."
        )

    dataframe[LABEL_COLUMN] = normalize_labels(
        dataframe[LABEL_COLUMN]
    )
    numeric_data = dataframe.select_dtypes(include=[np.number])

    missing_by_column = (
        dataframe.isna().sum().loc[lambda values: values > 0]
        .sort_values(ascending=False)
    )
    infinite_by_column = (
        np.isinf(numeric_data).sum().loc[lambda values: values > 0]
        .sort_values(ascending=False)
    )
    duplicate_count = int(dataframe.duplicated().sum())
    duplicate_percentage = duplicate_count / len(dataframe) * 100

    distribution = (
        dataframe[LABEL_COLUMN]
        .value_counts(dropna=False)
        .sort_values(ascending=False)
    )
    distribution_table = (
        distribution.rename_axis("Classe")
        .reset_index(name="Effectif")
    )
    distribution_table["Pourcentage"] = (
        distribution_table["Effectif"] / len(dataframe) * 100
    )

    stem = safe_name(csv_path.name)
    distribution_table.to_csv(
        output_dir / f"{stem}_distribution_classes.csv",
        index=False,
        encoding="utf-8-sig",
    )
    missing_by_column.rename(
        "Valeurs_manquantes"
    ).to_csv(
        output_dir / f"{stem}_valeurs_manquantes.csv",
        encoding="utf-8-sig",
    )
    infinite_by_column.rename(
        "Valeurs_infinies"
    ).to_csv(
        output_dir / f"{stem}_valeurs_infinies.csv",
        encoding="utf-8-sig",
    )
    save_class_chart(
        distribution,
        display_title,
        output_dir / f"{stem}_distribution_classes.png",
    )

    summary = {
        "Fichier": csv_path.name,
        "Période": display_title,
        "Lignes": int(len(dataframe)),
        "Colonnes": int(dataframe.shape[1]),
        "Colonnes_numériques": int(numeric_data.shape[1]),
        "Nombre_classes": int(distribution.shape[0]),
        "Valeurs_manquantes": int(missing_by_column.sum()),
        "Valeurs_infinies": int(infinite_by_column.sum()),
        "Lignes_dupliquées": duplicate_count,
        "Pourcentage_doublons": duplicate_percentage,
    }

    print(f"Lignes               : {format_integer(summary['Lignes'])}")
    print(f"Colonnes             : {summary['Colonnes']}")
    print(f"Classes              : {summary['Nombre_classes']}")
    print(
        "Valeurs manquantes  : "
        f"{format_integer(summary['Valeurs_manquantes'])}"
    )
    print(
        "Valeurs infinies    : "
        f"{format_integer(summary['Valeurs_infinies'])}"
    )
    print(
        "Lignes dupliquées   : "
        f"{format_integer(duplicate_count)} "
        f"({duplicate_percentage:.2f} %)"
    )
    print("\nDistribution des classes :")
    print(
        distribution_table.to_string(
            index=False,
            formatters={
                "Pourcentage": lambda value: f"{value:.4f} %"
            },
        )
    )

    del dataframe, numeric_data
    gc.collect()
    return summary


def save_quality_chart(
    summaries: pd.DataFrame,
    output_path: Path,
) -> None:
    """Compare les trois principaux problèmes entre les fichiers."""
    chart_data = summaries.set_index("Période")[
        [
            "Valeurs_manquantes",
            "Valeurs_infinies",
            "Lignes_dupliquées",
        ]
    ]
    ax = chart_data.plot(
        kind="bar",
        figsize=(15, 7),
        color=["#F28E2B", "#E15759", "#4E79A7"],
    )
    ax.set_yscale("symlog", linthresh=1)
    ax.set_xlabel("")
    ax.set_ylabel("Nombre détecté - échelle symlog")
    ax.set_title(
        "Problèmes de qualité détectés dans les huit fichiers",
        fontweight="bold",
    )
    ax.tick_params(axis="x", rotation=30)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.legend(title="Problème")
    ax.figure.tight_layout()
    ax.figure.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight",
        facecolor="white",
    )
    plt.close(ax.figure)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyse un fichier CIC-IDS2017 ou les huit fichiers."
        )
    )
    parser.add_argument(
        "--fichier",
        choices=list(EXPECTED_FILES),
        help=(
            "Nom du fichier à présenter. "
            "Sans cette option, les huit fichiers sont analysés."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    project_root = find_project_root()
    data_dir = (
        project_root
        / "data"
        / "raw"
        / "CIC-IDS2017"
        / "MachineLearningCVE"
    )
    output_dir = project_root / "outputs" / "eda_individuelle"
    output_dir.mkdir(parents=True, exist_ok=True)

    selected_files = (
        {args.fichier: EXPECTED_FILES[args.fichier]}
        if args.fichier
        else EXPECTED_FILES
    )

    missing_files = [
        filename
        for filename in selected_files
        if not (data_dir / filename).is_file()
    ]
    if missing_files:
        raise FileNotFoundError(
            "Fichiers introuvables :\n- " + "\n- ".join(missing_files)
        )

    summaries = [
        analyze_file(
            data_dir / filename,
            display_title,
            output_dir,
        )
        for filename, display_title in selected_files.items()
    ]

    summary_table = pd.DataFrame(summaries)
    summary_path = output_dir / "resume_qualite_par_fichier.csv"
    summary_table.to_csv(
        summary_path,
        index=False,
        encoding="utf-8-sig",
    )

    if len(summary_table) > 1:
        save_quality_chart(
            summary_table,
            output_dir / "comparaison_qualite_huit_fichiers.png",
        )

    print("\n" + "=" * 88)
    print("ANALYSE INDIVIDUELLE TERMINÉE")
    print("=" * 88)
    print(summary_table.to_string(index=False))
    print(f"\nRésumé enregistré : {summary_path}")


if __name__ == "__main__":
    main()