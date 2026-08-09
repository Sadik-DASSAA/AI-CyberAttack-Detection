"""
Analyse exploratoire globale des huit fichiers CIC-IDS2017.

Le script agrège les résultats des huit CSV sans conserver simultanément
les 2,8 millions de lignes en mémoire. Il produit :
- les dimensions globales ;
- la distribution globale des classes ;
- les totaux de valeurs manquantes et infinies ;
- la somme des doublons détectés à l'intérieur de chaque fichier ;
- une analyse des corrélations numériques sur un échantillon reproductible ;
- les tableaux et graphiques utiles pour la présentation.

Résultats :
    outputs/eda_globale/

Dépendances :
    pip install numpy pandas matplotlib
"""

from __future__ import annotations

import gc
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


EXPECTED_FILES = (
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)

LABEL_COLUMN = "Label"
CORRELATION_SAMPLE_PER_FILE = 25_000
RANDOM_STATE = 42


def format_integer(value: int) -> str:
    return f"{int(value):,}".replace(",", " ")


def find_project_root() -> Path:
    relative_data_path = Path(
        "data/raw/CIC-IDS2017/MachineLearningCVE"
    )
    script_path = Path(__file__).resolve()

    for candidate in (script_path.parent, *script_path.parents):
        if (candidate / relative_data_path).is_dir():
            return candidate

    raise FileNotFoundError(
        "Le dossier data/raw/CIC-IDS2017/MachineLearningCVE "
        "est introuvable."
    )


def normalize_labels(labels: pd.Series) -> pd.Series:
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


def check_files(data_dir: Path) -> list[Path]:
    file_paths = [data_dir / filename for filename in EXPECTED_FILES]
    missing = [path.name for path in file_paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "Fichiers introuvables :\n- " + "\n- ".join(missing)
        )
    return file_paths


def analyze_global(
    file_paths: list[Path],
) -> tuple[
    pd.DataFrame,
    pd.DataFrame,
    dict[str, int],
    pd.DataFrame,
]:
    """Agrège les informations des huit fichiers."""
    class_counter: Counter[str] = Counter()
    file_rows: list[dict[str, object]] = []
    reference_columns: list[str] | None = None

    total_rows = 0
    total_missing = 0
    total_infinite = 0
    total_duplicates = 0
    correlation_samples: list[pd.DataFrame] = []

    for index, file_path in enumerate(file_paths, start=1):
        print("\n" + "-" * 88)
        print(f"[{index}/8] Lecture de {file_path.name}")

        dataframe = pd.read_csv(file_path, low_memory=False)
        dataframe.columns = dataframe.columns.astype(str).str.strip()

        if dataframe.columns.duplicated().any():
            raise ValueError(
                f"Colonnes dupliquées dans {file_path.name}."
            )
        if LABEL_COLUMN not in dataframe.columns:
            raise KeyError(
                f"La colonne {LABEL_COLUMN!r} est absente "
                f"de {file_path.name}."
            )

        current_columns = dataframe.columns.tolist()
        if reference_columns is None:
            reference_columns = current_columns
        elif current_columns != reference_columns:
            missing_columns = sorted(
                set(reference_columns) - set(current_columns)
            )
            extra_columns = sorted(
                set(current_columns) - set(reference_columns)
            )
            raise ValueError(
                f"Structure différente dans {file_path.name}. "
                f"Colonnes absentes : {missing_columns}. "
                f"Colonnes supplémentaires : {extra_columns}."
            )

        dataframe[LABEL_COLUMN] = normalize_labels(
            dataframe[LABEL_COLUMN]
        )
        numeric_data = dataframe.select_dtypes(include=[np.number])

        sample_size = min(
            CORRELATION_SAMPLE_PER_FILE,
            len(dataframe),
        )
        correlation_samples.append(
            numeric_data.sample(
                n=sample_size,
                random_state=RANDOM_STATE + index,
            ).copy()
        )

        rows = int(len(dataframe))
        missing = int(dataframe.isna().sum().sum())
        infinite = int(np.isinf(numeric_data).sum().sum())
        duplicates = int(dataframe.duplicated().sum())
        duplicate_percentage = duplicates / rows * 100

        class_counter.update(
            dataframe[LABEL_COLUMN].dropna().tolist()
        )
        total_rows += rows
        total_missing += missing
        total_infinite += infinite
        total_duplicates += duplicates

        file_rows.append({
            "Fichier": file_path.name,
            "Lignes": rows,
            "Colonnes": int(dataframe.shape[1]),
            "Valeurs_manquantes": missing,
            "Valeurs_infinies": infinite,
            "Lignes_dupliquées": duplicates,
            "Pourcentage_doublons": duplicate_percentage,
        })

        print(f"Lignes             : {format_integer(rows)}")
        print(f"Valeurs manquantes : {format_integer(missing)}")
        print(f"Valeurs infinies   : {format_integer(infinite)}")
        print(
            f"Doublons           : {format_integer(duplicates)} "
            f"({duplicate_percentage:.2f} %)"
        )

        del dataframe, numeric_data
        gc.collect()

    distribution = (
        pd.Series(class_counter, dtype="int64", name="Effectif")
        .sort_values(ascending=False)
        .rename_axis("Classe")
        .reset_index()
    )
    distribution["Pourcentage"] = (
        distribution["Effectif"] / total_rows * 100
    )

    totals = {
        "Nombre_fichiers": len(file_paths),
        "Nombre_lignes": total_rows,
        "Nombre_colonnes": len(reference_columns or []),
        "Nombre_classes": len(class_counter),
        "Valeurs_manquantes": total_missing,
        "Valeurs_infinies": total_infinite,
        "Doublons_intra_fichiers": total_duplicates,
    }
    correlation_sample = pd.concat(
        correlation_samples,
        ignore_index=True,
    )
    return (
        pd.DataFrame(file_rows),
        distribution,
        totals,
        correlation_sample,
    )


def analyze_correlations(
    numeric_sample: pd.DataFrame,
    output_dir: Path,
) -> None:
    """Calcule et enregistre les corrélations numériques."""
    correlation_dir = output_dir / "correlations"
    correlation_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 88)
    print("ANALYSE DES CORRÉLATIONS")
    print("=" * 88)
    print(
        "Échantillon utilisé : "
        f"{format_integer(len(numeric_sample))} lignes"
    )

    clean_sample = numeric_sample.replace(
        [np.inf, -np.inf],
        np.nan,
    )
    variable_columns = [
        column
        for column in clean_sample.columns
        if clean_sample[column].nunique(dropna=True) > 1
    ]
    clean_sample = clean_sample[variable_columns]

    correlation_matrix = clean_sample.corr(method="pearson")
    correlation_matrix.to_csv(
        correlation_dir / "matrice_correlation_complete.csv",
        encoding="utf-8-sig",
    )

    upper_triangle = np.triu(
        np.ones(correlation_matrix.shape, dtype=bool),
        k=1,
    )
    correlation_pairs = (
        correlation_matrix.where(upper_triangle)
        .stack()
        .rename("Correlation")
        .reset_index()
        .rename(columns={
            "level_0": "Variable_1",
            "level_1": "Variable_2",
        })
    )
    correlation_pairs["Correlation_absolue"] = (
        correlation_pairs["Correlation"].abs()
    )
    correlation_pairs = correlation_pairs.sort_values(
        "Correlation_absolue",
        ascending=False,
    )
    top_100 = correlation_pairs.head(100)
    top_100.to_csv(
        correlation_dir / "top_100_paires_correlees.csv",
        index=False,
        encoding="utf-8-sig",
    )

    top_variables: list[str] = []
    for row in top_100.itertuples(index=False):
        for variable in (row.Variable_1, row.Variable_2):
            if variable not in top_variables:
                top_variables.append(variable)
            if len(top_variables) == 20:
                break
        if len(top_variables) == 20:
            break

    if top_variables:
        top_matrix = correlation_matrix.loc[
            top_variables,
            top_variables,
        ]
        fig, ax = plt.subplots(figsize=(16, 13))
        image = ax.imshow(
            top_matrix,
            cmap="coolwarm",
            vmin=-1,
            vmax=1,
        )
        ax.set_xticks(range(len(top_variables)))
        ax.set_yticks(range(len(top_variables)))
        ax.set_xticklabels(
            top_variables,
            rotation=70,
            ha="right",
            fontsize=8,
        )
        ax.set_yticklabels(top_variables, fontsize=8)
        ax.set_title(
            "Matrice des 20 variables les plus corrélées",
            fontweight="bold",
            pad=18,
        )
        colorbar = fig.colorbar(image, ax=ax, shrink=0.82)
        colorbar.set_label("Coefficient de corrélation de Pearson")
        fig.tight_layout()
        fig.savefig(
            correlation_dir / "matrice_correlation_top20.png",
            dpi=300,
            bbox_inches="tight",
            facecolor="white",
        )
        plt.close(fig)

    strongest_lines = (
        top_100.head(20).to_string(
            index=False,
            formatters={
                "Correlation": lambda value: f"{value:.6f}",
                "Correlation_absolue": lambda value: f"{value:.6f}",
            },
        )
        if not top_100.empty
        else "Aucune paire de variables exploitable."
    )
    summary_lines = [
        "ANALYSE DES CORRÉLATIONS - CIC-IDS2017",
        "=" * 58,
        (
            "Méthode : corrélation de Pearson sur un échantillon "
            "reproductible."
        ),
        (
            "Nombre de lignes échantillonnées : "
            f"{format_integer(len(clean_sample))}"
        ),
        f"Nombre de variables numériques : {len(variable_columns)}",
        "",
        "20 PAIRES AVEC LA PLUS FORTE CORRÉLATION ABSOLUE",
        "-" * 58,
        strongest_lines,
        "",
        (
            "Une corrélation élevée signale une relation linéaire forte, "
            "mais ne prouve pas une relation de cause à effet."
        ),
    ]
    (
        correlation_dir / "resume_correlations.txt"
    ).write_text("\n".join(summary_lines), encoding="utf-8")

    print(
        "Variables numériques analysées : "
        f"{len(variable_columns)}"
    )
    print(
        "Fichiers de corrélation enregistrés dans : "
        f"{correlation_dir}"
    )


def save_distribution_chart(
    distribution: pd.DataFrame,
    output_path: Path,
) -> None:
    ordered = distribution.sort_values("Effectif", ascending=True)
    fig, ax = plt.subplots(
        figsize=(14, max(7, 0.55 * len(ordered) + 3))
    )
    colors = [
        "#59A14F" if label == "BENIGN" else "#2C7FB8"
        for label in ordered["Classe"]
    ]
    bars = ax.barh(
        ordered["Classe"],
        ordered["Effectif"],
        color=colors,
        edgecolor="white",
    )
    ax.set_xscale("log")
    ax.set_xlabel(
        "Nombre d'observations - échelle logarithmique"
    )
    ax.set_ylabel("Classe")
    ax.set_title(
        "Distribution globale des classes de CIC-IDS2017",
        fontweight="bold",
    )
    ax.grid(axis="x", which="both", linestyle="--", alpha=0.35)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, count, percentage in zip(
        bars,
        ordered["Effectif"],
        ordered["Pourcentage"],
    ):
        ax.text(
            count * 1.08,
            bar.get_y() + bar.get_height() / 2,
            f"{format_integer(count)} ({percentage:.4f} %)",
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


def save_problem_chart(
    totals: dict[str, int],
    output_path: Path,
) -> None:
    labels = [
        "Valeurs\nmanquantes",
        "Valeurs\ninfinies",
        "Doublons\nintra-fichiers",
    ]
    values = [
        totals["Valeurs_manquantes"],
        totals["Valeurs_infinies"],
        totals["Doublons_intra_fichiers"],
    ]

    fig, ax = plt.subplots(figsize=(9, 6))
    bars = ax.bar(
        labels,
        values,
        color=["#F28E2B", "#E15759", "#4E79A7"],
        width=0.65,
    )
    ax.set_ylabel("Nombre détecté")
    ax.set_title(
        "Résumé global des problèmes de qualité",
        fontweight="bold",
    )
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.set_axisbelow(True)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value,
            format_integer(value),
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    fig.tight_layout()
    fig.savefig(
        output_path,
        dpi=300,
        bbox_inches="tight",
        facecolor="white",
    )
    plt.close(fig)


def save_text_summary(
    totals: dict[str, int],
    distribution: pd.DataFrame,
    output_path: Path,
) -> None:
    duplicate_percentage = (
        totals["Doublons_intra_fichiers"]
        / totals["Nombre_lignes"]
        * 100
    )

    lines = [
        "ANALYSE EXPLORATOIRE GLOBALE - CIC-IDS2017",
        "=" * 58,
        f"Fichiers CSV : {totals['Nombre_fichiers']}",
        f"Lignes : {format_integer(totals['Nombre_lignes'])}",
        f"Colonnes : {totals['Nombre_colonnes']}",
        f"Classes : {totals['Nombre_classes']}",
        (
            "Valeurs manquantes : "
            f"{format_integer(totals['Valeurs_manquantes'])}"
        ),
        (
            "Valeurs infinies : "
            f"{format_integer(totals['Valeurs_infinies'])}"
        ),
        (
            "Doublons détectés dans les fichiers : "
            f"{format_integer(totals['Doublons_intra_fichiers'])} "
            f"({duplicate_percentage:.2f} %)"
        ),
        "",
        "DISTRIBUTION GLOBALE DES CLASSES",
        "-" * 58,
        distribution.to_string(
            index=False,
            formatters={
                "Effectif": format_integer,
                "Pourcentage": lambda value: f"{value:.4f} %",
            },
        ),
        "",
        "Remarque : le nombre de doublons correspond à la somme des",
        "doublons détectés à l'intérieur de chacun des huit fichiers.",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    project_root = find_project_root()
    data_dir = (
        project_root
        / "data"
        / "raw"
        / "CIC-IDS2017"
        / "MachineLearningCVE"
    )
    output_dir = project_root / "outputs" / "eda_globale"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 88)
    print("ANALYSE EXPLORATOIRE GLOBALE DE CIC-IDS2017")
    print("=" * 88)
    print(f"Données : {data_dir}")

    file_paths = check_files(data_dir)
    (
        file_summary,
        distribution,
        totals,
        correlation_sample,
    ) = analyze_global(file_paths)

    file_summary.to_csv(
        output_dir / "resume_par_fichier.csv",
        index=False,
        encoding="utf-8-sig",
    )
    distribution.to_csv(
        output_dir / "distribution_globale_classes.csv",
        index=False,
        encoding="utf-8-sig",
    )
    pd.DataFrame(
        [{"Indicateur": key, "Valeur": value}
         for key, value in totals.items()]
    ).to_csv(
        output_dir / "indicateurs_globaux.csv",
        index=False,
        encoding="utf-8-sig",
    )

    save_distribution_chart(
        distribution,
        output_dir / "distribution_globale_classes.png",
    )
    save_problem_chart(
        totals,
        output_dir / "problemes_qualite_globaux.png",
    )
    save_text_summary(
        totals,
        distribution,
        output_dir / "resume_presentation.txt",
    )
    analyze_correlations(
        correlation_sample,
        output_dir,
    )
    del correlation_sample
    gc.collect()

    duplicate_percentage = (
        totals["Doublons_intra_fichiers"]
        / totals["Nombre_lignes"]
        * 100
    )

    print("\n" + "=" * 88)
    print("RÉSULTATS GLOBAUX")
    print("=" * 88)
    print(f"Fichiers CSV        : {totals['Nombre_fichiers']}")
    print(
        "Lignes fusionnées   : "
        f"{format_integer(totals['Nombre_lignes'])}"
    )
    print(f"Colonnes            : {totals['Nombre_colonnes']}")
    print(f"Classes             : {totals['Nombre_classes']}")
    print(
        "Valeurs manquantes : "
        f"{format_integer(totals['Valeurs_manquantes'])}"
    )
    print(
        "Valeurs infinies   : "
        f"{format_integer(totals['Valeurs_infinies'])}"
    )
    print(
        "Doublons détectés  : "
        f"{format_integer(totals['Doublons_intra_fichiers'])} "
        f"({duplicate_percentage:.2f} %)"
    )
    print("\nDistribution globale :")
    print(
        distribution.to_string(
            index=False,
            formatters={
                "Effectif": format_integer,
                "Pourcentage": lambda value: f"{value:.4f} %",
            },
        )
    )
    print(f"\nRésultats enregistrés : {output_dir}")


if __name__ == "__main__":
    main()