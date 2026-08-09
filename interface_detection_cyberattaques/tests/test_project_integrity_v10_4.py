from __future__ import annotations

import json
import subprocess
from pathlib import Path

import joblib


APP_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = APP_DIR.parent


def test_fichiers_obligatoires_du_lancement_presents() -> None:
    required = [
        "LANCER_TOUT.bat",
        "ARRETER_TOUT.bat",
        "demarrer_tout.ps1",
        "arreter_tout.ps1",
        "suricata_runtime.ps1",
        "compose.yaml",
        "Caddyfile",
        "Dockerfile",
        "requirements.txt",
        "requirements-dev.txt",
        "api.py",
        "app.py",
        "auth_security.py",
        "data_migration.py",
        ".env.example",
    ]
    missing = [name for name in required if not (APP_DIR / name).is_file()]
    assert not missing, f"Fichiers obligatoires absents : {missing}"


def test_paquet_modele_coherent() -> None:
    model_path = (
        PROJECT_ROOT
        / "outputs"
        / "modelisation_evaluation"
        / "models"
        / "meilleur_modele.pkl"
    )
    info_path = (
        PROJECT_ROOT
        / "outputs"
        / "modelisation_evaluation"
        / "model_info"
        / "meilleur_modele.json"
    )
    mapping_path = (
        PROJECT_ROOT
        / "outputs"
        / "preprocessing"
        / "processed"
        / "label_encoder_mapping.json"
    )

    model = joblib.load(model_path)
    info = json.loads(info_path.read_text(encoding="utf-8"))
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))

    model_features = list(getattr(model, "feature_names_in_", []))
    model_classes = [int(value) for value in getattr(model, "classes_", [])]
    assert model_features == info["variables"]
    assert model_classes == sorted(int(value) for value in mapping.values())
    assert info["classes"] == list(mapping.keys())


def test_pipeline_produit_le_scaler_requis_par_api() -> None:
    preprocessing = (PROJECT_ROOT / "03_Preprocessing_CICIDS2017.py").read_text(
        encoding="utf-8"
    )
    api = (APP_DIR / "api.py").read_text(encoding="utf-8")

    assert 'joblib.dump(scaler, PROCESSED_DIR / "minmax_scaler.joblib")' in preprocessing
    assert 'Path("preprocessing") / "processed" / "minmax_scaler.joblib"' in api
    assert "scaler.transform(model_input)" in api
    assert "les flux bruts utilisent le mode de secours" in api


def test_versions_runtime_reproductibles() -> None:
    requirements = (APP_DIR / "requirements.txt").read_text(encoding="utf-8")
    requirements_dev = (APP_DIR / "requirements-dev.txt").read_text(encoding="utf-8")
    dockerfile = (APP_DIR / "Dockerfile").read_text(encoding="utf-8")
    compose = (APP_DIR / "compose.yaml").read_text(encoding="utf-8")
    api = (APP_DIR / "api.py").read_text(encoding="utf-8")

    assert "scikit-learn==1.8.0" in requirements
    assert '"scikit-learn==1.8.0"' in dockerfile
    assert "httpx2==2.10.0" in requirements_dev
    assert "soc-v10-4-one-click" in compose
    assert 'API_VERSION = "dashboard-soc-v10-4-one-click"' in api


def test_donnees_runtime_exclues_du_depot() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8-sig")
    for ignored in [
        "interface_detection_cyberattaques/security/",
        "interface_detection_cyberattaques/certificates/",
        "interface_detection_cyberattaques/.runtime/",
        "interface_detection_cyberattaques/profile.json",
        "*.db",
        "*.db-shm",
        "*.db-wal",
    ]:
        assert ignored in gitignore

    if (PROJECT_ROOT / ".git").exists():
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        forbidden = [
            path
            for path in tracked
            if path.startswith("interface_detection_cyberattaques/security/")
            or path.startswith("interface_detection_cyberattaques/.runtime/")
            or path.startswith("interface_detection_cyberattaques/certificates/")
        ]
        assert not forbidden, f"Données runtime encore versionnées : {forbidden}"


if __name__ == "__main__":
    test_fichiers_obligatoires_du_lancement_presents()
    test_paquet_modele_coherent()
    test_pipeline_produit_le_scaler_requis_par_api()
    test_versions_runtime_reproductibles()
    test_donnees_runtime_exclues_du_depot()
    print("PROJECT INTEGRITY TESTS PASSED")
