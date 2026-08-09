from __future__ import annotations

import io
import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel

from auth_security import (
    authentication_middleware,
    get_primary_alert_user,
    get_user_recipient,
    initialize_auth_database,
    mask_email,
    record_security_event,
    request_user,
    router as auth_router,
    send_smtp_message,
    smtp_configuration,
)

try:
    from dotenv import load_dotenv
except ImportError:  # L'API reste utilisable si python-dotenv n'est pas encore installe.
    load_dotenv = None


APP_DIR = Path(__file__).resolve().parent

if load_dotenv is not None:
    load_dotenv(APP_DIR / ".env", override=False)


def env_list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


app = FastAPI(
    title="SOC API",
    docs_url="/docs" if os.getenv("API_DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
)
API_VERSION = "dashboard-soc-v10-3-3-https-health-fix"

app.add_middleware(
    CORSMiddleware,
    allow_origins=env_list(
        "API_ALLOWED_ORIGINS",
        "https://localhost",
    ),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=env_list("API_ALLOWED_HOSTS", "api,localhost,127.0.0.1,testserver"),
)
app.middleware("http")(authentication_middleware)
app.include_router(auth_router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path.startswith("/auth") or request.url.path.startswith("/profile"):
        response.headers["Cache-Control"] = "no-store"
    return response


def chemin_configure(nom_variable: str, chemin_defaut: Path) -> Path:
    """Résout un chemin absolu configurable depuis l'environnement."""
    valeur = os.getenv(nom_variable, "").strip()
    if not valeur:
        return chemin_defaut.resolve()

    chemin = Path(valeur).expanduser()
    if not chemin.is_absolute():
        chemin = APP_DIR / chemin
    return chemin.resolve()


def trouver_racine_projet() -> Path:
    """Trouve la racine du projet sous Windows comme dans Docker."""
    racine_configuree = os.getenv("PROJECT_ROOT", "").strip()
    if racine_configuree:
        return chemin_configure("PROJECT_ROOT", APP_DIR.parent)

    for candidate in (APP_DIR, APP_DIR.parent):
        if (candidate / "outputs").is_dir():
            return candidate.resolve()

    return APP_DIR.parent.resolve()


PROJECT_ROOT = trouver_racine_projet()

HISTORY_DIR = Path("history")
HISTORY_FILE = HISTORY_DIR / "alert_history.csv"
SURICATA_HISTORY_FILE = HISTORY_DIR / "suricata_history.csv"
SURICATA_CURSOR_FILE = HISTORY_DIR / "suricata_cursor.json"
ANALYSIS_METRICS_FILE = HISTORY_DIR / "analysis_metrics.json"
SURICATA_EVE_FILE = chemin_configure(
    "SURICATA_EVE_FILE",
    APP_DIR / "alerts" / "eve.json",
)


def upload_limit_bytes(name: str, default_mb: int, maximum_mb: int) -> int:
    try:
        configured_mb = int(os.getenv(name, str(default_mb)))
    except ValueError:
        configured_mb = default_mb
    return max(1, min(configured_mb, maximum_mb)) * 1024 * 1024


MAX_CSV_UPLOAD_BYTES = upload_limit_bytes("MAX_CSV_UPLOAD_MB", 200, 512)
MAX_EVE_UPLOAD_BYTES = upload_limit_bytes("MAX_EVE_UPLOAD_MB", 64, 256)
UPLOAD_CHUNK_BYTES = 1024 * 1024

HISTORY_LOCK = threading.RLock()
SURICATA_STATUS_LOCK = threading.Lock()
SURICATA_STOP_EVENT = threading.Event()
SURICATA_MONITOR_THREAD: threading.Thread | None = None
SURICATA_MONITOR_STATUS: dict[str, Any] = {
    "started_at": "",
    "last_scan_at": "",
    "last_event_at": "",
    "last_error": "",
    "alerts_imported_total": 0,
    "new_alerts_last_cycle": 0,
    "duplicates_ignored_total": 0,
}

MODEL_RELATIVE_PATH = (
    Path("modelisation_evaluation") / "models" / "meilleur_modele.pkl"
)
MODEL_INFO_RELATIVE_PATH = (
    Path("modelisation_evaluation") / "model_info" / "meilleur_modele.json"
)


def chemins_sorties_candidats() -> list[Path]:
    """Retourne les emplacements d'outputs possibles sous Windows et Docker."""
    candidats = [
        PROJECT_ROOT / "outputs",
        APP_DIR / "outputs",
        APP_DIR.parent / "outputs",
        Path("/workspace/outputs"),
    ]

    resultat: list[Path] = []
    deja_vus: set[str] = set()
    for candidat in candidats:
        chemin = candidat.resolve()
        cle = str(chemin)
        if cle not in deja_vus:
            resultat.append(chemin)
            deja_vus.add(cle)
    return resultat


def chemins_modeles_candidats() -> list[Path]:
    """Construit la liste exacte des modèles à tester, par ordre de priorité."""
    valeur_configuree = os.getenv("MODEL_PATH", "").strip()
    candidats: list[Path] = []
    if valeur_configuree:
        candidats.append(chemin_configure("MODEL_PATH", APP_DIR / MODEL_RELATIVE_PATH))
    candidats.extend(racine / MODEL_RELATIVE_PATH for racine in chemins_sorties_candidats())

    resultat: list[Path] = []
    deja_vus: set[str] = set()
    for candidat in candidats:
        chemin = candidat.resolve()
        cle = str(chemin)
        if cle not in deja_vus:
            resultat.append(chemin)
            deja_vus.add(cle)
    return resultat


def trouver_chemin_modele() -> Path:
    """Trouve le modèle même si outputs est local au projet ou monté par Docker."""
    candidats = chemins_modeles_candidats()
    for candidat in candidats:
        if candidat.is_file():
            return candidat

    # Tolère une sous-arborescence supplémentaire créée par un ancien script.
    for racine in chemins_sorties_candidats():
        if not racine.is_dir():
            continue
        correspondances = sorted(racine.rglob("meilleur_modele.pkl"))
        if correspondances:
            return correspondances[0].resolve()

    return candidats[0]


def trouver_chemin_info_modele(chemin_modele: Path) -> Path:
    valeur_configuree = os.getenv("MODEL_INFO_PATH", "").strip()
    if valeur_configuree:
        return chemin_configure(
            "MODEL_INFO_PATH",
            APP_DIR / MODEL_INFO_RELATIVE_PATH,
        )

    # .../modelisation_evaluation/models/meilleur_modele.pkl
    # -> .../modelisation_evaluation/model_info/meilleur_modele.json
    if chemin_modele.parent.name == "models":
        voisin = chemin_modele.parent.parent / "model_info" / "meilleur_modele.json"
        if voisin.is_file():
            return voisin.resolve()

    for racine in chemins_sorties_candidats():
        candidat = racine / MODEL_INFO_RELATIVE_PATH
        if candidat.is_file():
            return candidat.resolve()
    return (chemin_modele.parent.parent / "model_info" / "meilleur_modele.json").resolve()
LABEL_MAPPING_CANDIDATES = [
    PROJECT_ROOT / "outputs" / "preprocessing" / "processed" / "label_mapping.json",
    PROJECT_ROOT / "outputs" / "preprocessing" / "proofs" / "label_mapping.json",
    PROJECT_ROOT / "outputs" / "preprocessing" / "tables" / "label_mapping.json",
]

_MODEL_CACHE: Any = None
_MODEL_CACHE_PATH: Path | None = None
_MODEL_LOAD_ERROR = ""


class StatutUpdate(BaseModel):
    historique_id: str
    statut: str


CLASS_GRAVITY = {
    "BENIGN": "Faible",
    "Bot": "Elevee",
    "DDoS": "Critique",
    "DoS GoldenEye": "Critique",
    "DoS Hulk": "Critique",
    "DoS Slowhttptest": "Elevee",
    "DoS slowloris": "Elevee",
    "FTP-Patator": "Elevee",
    "Heartbleed": "Critique",
    "Infiltration": "Critique",
    "PortScan": "Elevee",
    "SSH-Patator": "Elevee",
    "Web Attack - Brute Force": "Elevee",
    "Web Attack - SQL Injection": "Critique",
    "Web Attack - XSS": "Elevee",
}

CLASS_ACTIONS = {
    "BENIGN": "Aucune action requise",
    "Bot": "Isoler la machine et analyser le processus suspect",
    "DDoS": "Activer la mitigation DDoS et analyser le trafic",
    "DoS GoldenEye": "Limiter le trafic et surveiller le service cible",
    "DoS Hulk": "Bloquer la source et renforcer les regles IDS",
    "DoS Slowhttptest": "Limiter les connexions lentes vers le serveur",
    "DoS slowloris": "Limiter les sessions longues et surveiller le serveur",
    "FTP-Patator": "Bloquer la source et verifier les tentatives FTP",
    "Heartbleed": "Isoler le service et verifier la version OpenSSL",
    "Infiltration": "Isoler l'hote et lancer une investigation",
    "PortScan": "Surveiller puis bloquer l'adresse source",
    "SSH-Patator": "Bloquer la source et renforcer l'authentification SSH",
    "Web Attack - Brute Force": "Bloquer la source et verifier les journaux web",
    "Web Attack - SQL Injection": "Bloquer la requete et verifier l'application web",
    "Web Attack - XSS": "Bloquer la requete et filtrer les entrees utilisateur",
}

PRIORITES_GRAVITE = {
    "Critique": 1,
    "Elevee": 2,
    "Moyenne": 3,
    "Faible": 4,
}

BASE_HISTORY_COLUMNS = [
    "user_id",
    "date",
    "source",
    "fichier",
    "classe",
    "nombre",
    "gravite",
    "action_recommandee",
    "ip_source",
    "ip_destination",
    "protocole",
    "statut",
    "notification_email",
    "erreur_notification_email",
    "details",
    "mode_analyse",
    "event_id",
]

DEFAULT_ANALYSIS_METRICS = {
    "analyses_csv": 0,
    "analyses_suricata": 0,
    "flux_reseau_analyses": 0,
    "evenements_ids_analyses": 0,
    "derniere_analyse": "",
    "derniere_source": "",
}


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def lire_metriques_analyse(user_id: str) -> dict[str, Any]:
    raw_document = read_json_file(ANALYSIS_METRICS_FILE)
    users_metrics = raw_document.get("users", {}) if isinstance(raw_document, dict) else {}
    raw_metrics = users_metrics.get(user_id, {}) if isinstance(users_metrics, dict) else {}
    metrics = DEFAULT_ANALYSIS_METRICS.copy()

    for key in metrics:
        if key in raw_metrics:
            metrics[key] = raw_metrics[key]

    for key in [
        "analyses_csv",
        "analyses_suricata",
        "flux_reseau_analyses",
        "evenements_ids_analyses",
    ]:
        try:
            metrics[key] = max(0, int(metrics[key]))
        except (TypeError, ValueError):
            metrics[key] = 0

    return metrics


def enregistrer_metriques_analyse(
    *,
    user_id: str,
    source: str,
    flux_reseau: int = 0,
    evenements_ids: int = 0,
) -> dict[str, Any]:
    with HISTORY_LOCK:
        return _enregistrer_metriques_analyse(
            user_id=user_id,
            source=source,
            flux_reseau=flux_reseau,
            evenements_ids=evenements_ids,
        )


def _enregistrer_metriques_analyse(
    *,
    user_id: str,
    source: str,
    flux_reseau: int = 0,
    evenements_ids: int = 0,
) -> dict[str, Any]:
    metrics = lire_metriques_analyse(user_id)
    metrics["flux_reseau_analyses"] += max(0, int(flux_reseau))
    metrics["evenements_ids_analyses"] += max(0, int(evenements_ids))
    metrics["derniere_analyse"] = now_text()
    metrics["derniere_source"] = source

    if source == "CSV":
        metrics["analyses_csv"] += 1
    elif source == "Suricata":
        metrics["analyses_suricata"] += 1

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    document = read_json_file(ANALYSIS_METRICS_FILE)
    if not isinstance(document, dict) or not isinstance(document.get("users"), dict):
        document = {"schema_version": 2, "users": {}}
    document["schema_version"] = 2
    document["users"][user_id] = metrics
    temporary_path = ANALYSIS_METRICS_FILE.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(ANALYSIS_METRICS_FILE)
    return metrics


def reinitialiser_volume_flux(user_id: str) -> dict[str, int]:
    """Remet uniquement le compteur de flux de l'utilisateur à zéro."""
    with HISTORY_LOCK:
        metrics = lire_metriques_analyse(user_id)
        ancien_volume = max(0, int(metrics.get("flux_reseau_analyses", 0) or 0))
        metrics["flux_reseau_analyses"] = 0

        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        document = read_json_file(ANALYSIS_METRICS_FILE)
        if not isinstance(document, dict) or not isinstance(document.get("users"), dict):
            document = {"schema_version": 2, "users": {}}
        document["schema_version"] = 2
        document["users"][user_id] = metrics

        temporary_path = ANALYSIS_METRICS_FILE.with_suffix(".tmp")
        temporary_path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temporary_path.replace(ANALYSIS_METRICS_FILE)

    return {"ancien_volume": ancien_volume, "nouveau_volume": 0}


def migrer_metriques_legacy(owner_id: str) -> None:
    if not owner_id or not ANALYSIS_METRICS_FILE.exists():
        return
    document = read_json_file(ANALYSIS_METRICS_FILE)
    if not document or "users" in document:
        return
    legacy = DEFAULT_ANALYSIS_METRICS.copy()
    for key in legacy:
        if key in document:
            legacy[key] = document[key]
    migrated = {"schema_version": 2, "users": {owner_id: legacy}}
    temporary_path = ANALYSIS_METRICS_FILE.with_suffix(".migration.tmp")
    temporary_path.write_text(
        json.dumps(migrated, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(ANALYSIS_METRICS_FILE)


def model_status() -> dict[str, Any]:
    chemin_modele = trouver_chemin_modele()
    chemin_info = trouver_chemin_info_modele(chemin_modele)
    info = read_json_file(chemin_info)
    modele = load_model()
    fichier_modele_trouve = chemin_modele.is_file()
    modele_charge = modele is not None
    mode_secours = not modele_charge

    if modele_charge:
        nom_modele = info.get("meilleur_modele") or type(modele).__name__
        score = info.get("score")
    else:
        nom_modele = "Mode de secours (regles/labels)"
        score = None

    return {
        # Champ historique conservé pour les anciennes versions de l'interface.
        "model_found": fichier_modele_trouve,
        "model_loaded": modele_charge,
        "engine_available": True,
        "fallback_active": mode_secours,
        "api_version": API_VERSION,
        "model_path": str(chemin_modele),
        "model_info_path": str(chemin_info),
        "model_candidates": [str(path) for path in chemins_modeles_candidats()],
        "model_name": nom_modele,
        "score": score,
        "load_error": _MODEL_LOAD_ERROR,
    }


def load_label_mapping() -> dict[int, str]:
    for path in LABEL_MAPPING_CANDIDATES:
        raw = read_json_file(path)
        if not raw:
            continue

        mapping: dict[int, str] = {}
        for key, value in raw.items():
            try:
                if isinstance(value, int):
                    mapping[int(value)] = nettoyer_label(key)
                else:
                    mapping[int(key)] = nettoyer_label(value)
            except (TypeError, ValueError):
                continue

        if mapping:
            return mapping

    default_order = [
        "BENIGN",
        "Bot",
        "DDoS",
        "DoS GoldenEye",
        "DoS Hulk",
        "DoS Slowhttptest",
        "DoS slowloris",
        "FTP-Patator",
        "Heartbleed",
        "Infiltration",
        "PortScan",
        "SSH-Patator",
        "Web Attack - Brute Force",
        "Web Attack - SQL Injection",
        "Web Attack - XSS",
    ]
    return {index: label for index, label in enumerate(default_order)}


def load_model() -> Any:
    global _MODEL_CACHE, _MODEL_CACHE_PATH, _MODEL_LOAD_ERROR

    chemin_modele = trouver_chemin_modele()

    if _MODEL_CACHE is not None and _MODEL_CACHE_PATH == chemin_modele:
        return _MODEL_CACHE

    if not chemin_modele.is_file():
        candidats = " ; ".join(str(path) for path in chemins_modeles_candidats())
        _MODEL_LOAD_ERROR = (
            "Fichier du modele introuvable. Chemins verifies : " + candidats
        )
        return None

    try:
        import joblib

        _MODEL_CACHE = joblib.load(chemin_modele)
        _MODEL_CACHE_PATH = chemin_modele
        _MODEL_LOAD_ERROR = ""
        return _MODEL_CACHE
    except Exception as exc:  # noqa: BLE001
        _MODEL_CACHE = None
        _MODEL_CACHE_PATH = None
        _MODEL_LOAD_ERROR = f"{exc.__class__.__name__}: {exc}"
        return None


def nettoyer_label(label: Any) -> str:
    if label is None:
        return ""

    value = str(label).strip()
    if not value:
        return ""

    value = (
        value.replace("\ufffd", "-")
        .replace("–", "-")
        .replace("—", "-")
        .replace("_", " ")
    )
    value = " ".join(value.split())
    lower = value.lower()

    aliases = {
        "benign": "BENIGN",
        "bot": "Bot",
        "ddos": "DDoS",
        "dos goldeneye": "DoS GoldenEye",
        "dos hulk": "DoS Hulk",
        "dos slowhttptest": "DoS Slowhttptest",
        "dos slowloris": "DoS slowloris",
        "ftp-patator": "FTP-Patator",
        "heartbleed": "Heartbleed",
        "infiltration": "Infiltration",
        "portscan": "PortScan",
        "ssh-patator": "SSH-Patator",
        "web attack - brute force": "Web Attack - Brute Force",
        "web attack - sql injection": "Web Attack - SQL Injection",
        "web attack - xss": "Web Attack - XSS",
    }

    if lower in aliases:
        return aliases[lower]

    if "sql" in lower:
        return "Web Attack - SQL Injection"
    if "xss" in lower:
        return "Web Attack - XSS"
    if "brute" in lower and "web" in lower:
        return "Web Attack - Brute Force"
    if "port" in lower and "scan" in lower:
        return "PortScan"
    if "goldeneye" in lower:
        return "DoS GoldenEye"
    if "hulk" in lower:
        return "DoS Hulk"
    if "slowhttptest" in lower:
        return "DoS Slowhttptest"
    if "slowloris" in lower:
        return "DoS slowloris"
    if "ddos" in lower:
        return "DDoS"
    if "ssh" in lower:
        return "SSH-Patator"
    if "ftp" in lower:
        return "FTP-Patator"

    return value


def normaliser_gravite(gravite: Any) -> str:
    value = str(gravite or "").strip()
    mapping = {
        "Eleve": "Elevee",
        "Elevee": "Elevee",
        "Moyen": "Moyenne",
        "Moyenne": "Moyenne",
        "Critique": "Critique",
        "Faible": "Faible",
    }
    return mapping.get(value, value or "Moyenne")


def determiner_gravite(classe: Any) -> str:
    label = nettoyer_label(classe)
    if label in CLASS_GRAVITY:
        return CLASS_GRAVITY[label]
    return "Moyenne" if label and label != "BENIGN" else "Faible"


def action_recommandee(classe: Any) -> str:
    label = nettoyer_label(classe)
    return CLASS_ACTIONS.get(label, "Analyser l'evenement et verifier les journaux")


def to_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default

    try:
        cleaned = str(value).strip().replace(",", ".")
        if cleaned in {"", "nan", "NaN", "inf", "Infinity", "-inf"}:
            return default
        return float(cleaned)
    except (TypeError, ValueError):
        return default


def first_value(row: dict[str, Any], names: list[str], default: str = "") -> str:
    normalized = {str(key).strip().lower(): value for key, value in row.items()}
    for name in names:
        value = normalized.get(name.strip().lower())
        if value not in (None, ""):
            return str(value)
    return default


def class_from_prediction(prediction: Any) -> str:
    mapping = load_label_mapping()
    try:
        return mapping.get(int(prediction), nettoyer_label(prediction))
    except (TypeError, ValueError):
        return nettoyer_label(prediction)


def predict_with_model(row: dict[str, Any]) -> str | None:
    model = load_model()
    if model is None:
        return None

    try:
        feature_names = list(getattr(model, "feature_names_in_", []))
        if not feature_names:
            return None

        normalized_row = {str(key).strip(): value for key, value in row.items()}
        if any(name not in normalized_row for name in feature_names):
            return None

        values = {name: to_float(normalized_row.get(name)) for name in feature_names}
        prediction = model.predict(pd.DataFrame([values], columns=feature_names))[0]
        return class_from_prediction(prediction)
    except Exception:  # noqa: BLE001
        return None


def infer_class_from_row(row: dict[str, Any]) -> str:
    for label_key in ["Label", "label", "Classe", "classe", "attack_class", "Attack"]:
        if label_key in row:
            label = nettoyer_label(row.get(label_key))
            if label:
                return label

    model_prediction = predict_with_model(row)
    if model_prediction:
        return model_prediction

    dst_port = first_value(row, ["Destination Port", "dest_port", "destination_port", "dp"])
    flow_bytes = to_float(first_value(row, ["Flow Bytes/s", "flow_bytes_s", "flow.bytes/s"]))
    flow_packets = to_float(first_value(row, ["Flow Packets/s", "flow_packets_s", "flow.packets/s"]))
    fwd_packets = to_float(first_value(row, ["Total Fwd Packets", "tot_fwd_pkts"]))
    duration = to_float(first_value(row, ["Flow Duration", "duration"]))

    if flow_packets > 150_000 or flow_bytes > 80_000_000:
        return "DDoS"
    if str(dst_port) in {"22", "2222"} and fwd_packets > 15:
        return "SSH-Patator"
    if str(dst_port) in {"21", "20"} and fwd_packets > 15:
        return "FTP-Patator"
    if duration < 2_000 and 0 < fwd_packets <= 4:
        return "PortScan"
    if str(dst_port) in {"80", "443", "8080"} and flow_packets > 20_000:
        return "DoS Hulk"

    return "BENIGN"


def infer_class_from_suricata(event: dict[str, Any]) -> str:
    alert = event.get("alert") or {}
    signature = nettoyer_label(alert.get("signature") or event.get("signature") or "")
    category = nettoyer_label(alert.get("category") or "")
    combined = f"{signature} {category}".lower()

    if "sql" in combined:
        return "Web Attack - SQL Injection"
    if "xss" in combined:
        return "Web Attack - XSS"
    if "brute" in combined and "web" in combined:
        return "Web Attack - Brute Force"
    if "scan" in combined:
        return "PortScan"
    if "ddos" in combined:
        return "DDoS"
    if "dos" in combined or "denial" in combined:
        return "DoS Hulk"
    if "ssh" in combined:
        return "SSH-Patator"
    if "ftp" in combined:
        return "FTP-Patator"
    if "trojan" in combined or "malware" in combined or "bot" in combined:
        return "Bot"

    return signature or "Alerte Suricata"


def gravite_suricata(severity: Any) -> str:
    try:
        value = int(severity)
    except (TypeError, ValueError):
        value = 4

    if value == 1:
        return "Critique"
    if value == 2:
        return "Elevee"
    if value == 3:
        return "Moyenne"
    return "Faible"


def identifiant_evenement_suricata(event: dict[str, Any]) -> str:
    """Construit un identifiant stable pour éviter les imports en double."""
    alert = event.get("alert") or {}
    valeurs = {
        "timestamp": event.get("timestamp", ""),
        "flow_id": event.get("flow_id", ""),
        "src_ip": event.get("src_ip", ""),
        "src_port": event.get("src_port", ""),
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", ""),
        "proto": event.get("proto", ""),
        "signature_id": alert.get("signature_id", ""),
        "rev": alert.get("rev", ""),
        "signature": alert.get("signature", ""),
    }
    contenu = json.dumps(
        valeurs,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(contenu.encode("utf-8")).hexdigest()


def construire_alerte_suricata(
    event: dict[str, Any],
) -> dict[str, Any] | None:
    """Normalise un événement EVE de type alert pour le registre SOC."""
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert") or {}
    classe = infer_class_from_suricata(event)
    gravite = gravite_suricata(alert.get("severity", "N/A"))

    return {
        "event_id": identifiant_evenement_suricata(event),
        "date": event.get("timestamp", now_text()),
        "ip_source": event.get("src_ip", ""),
        "ip_destination": event.get("dest_ip", ""),
        "protocole": event.get("proto", ""),
        "signature": alert.get("signature", ""),
        "categorie": alert.get("category", ""),
        "classe": classe,
        "gravite": gravite,
        "action_recommandee": action_recommandee(classe),
    }


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "oui", "on"}


def masquer_destinataire(value: str) -> str:
    value = value.strip()
    if not value:
        return ""

    if "@" in value:
        local, domain = value.split("@", 1)
        visible = local[:2] if len(local) > 1 else local[:1]
        return f"{visible}***@{domain}"

    if len(value) <= 4:
        return "****"
    return f"***{value[-4:]}"


EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def normaliser_email(value: str) -> str:
    return value.strip().lower()


def email_valide(value: str) -> bool:
    return len(value) <= 254 and bool(EMAIL_PATTERN.fullmatch(value))


def configuration_notifications(user_id: str) -> dict[str, Any]:
    smtp = smtp_configuration()
    recipient = get_user_recipient(user_id)

    return {
        "gmail": {
            "enabled": smtp["enabled"],
            "smtp_configured": smtp["configured"],
            "configured": bool(smtp["configured"] and recipient),
            "recipient": recipient,
            "recipient_count": 1 if recipient else 0,
            "recipient_masked": mask_email(recipient),
        },
    }


def message_notification(ligne: dict[str, Any]) -> tuple[str, str]:
    classe = nettoyer_label(ligne.get("classe", "")) or "Alerte inconnue"
    gravite = normaliser_gravite(ligne.get("gravite", ""))
    source = str(ligne.get("source", "SOC"))
    date = str(ligne.get("date", now_text()))
    nombre = str(ligne.get("nombre", "1"))
    action = str(ligne.get("action_recommandee", "Analyser l'evenement"))
    ip_source = str(ligne.get("ip_source", ""))
    ip_destination = str(ligne.get("ip_destination", ""))
    protocole = str(ligne.get("protocole", ""))

    subject = f"[SOC][{gravite}] {classe}"
    parts = [
        "Alerte de cybersecurite detectee",
        f"Type d'attaque : {classe}",
        f"Gravite : {gravite}",
        f"Source de detection : {source}",
        f"Date/heure : {date}",
        f"Nombre : {nombre}",
    ]
    if ip_source:
        parts.append(f"IP source : {ip_source}")
    if ip_destination:
        parts.append(f"IP destination : {ip_destination}")
    if protocole:
        parts.append(f"Protocole : {protocole}")
    parts.append(f"Action recommandee : {action}")
    return subject, "\n".join(parts)


def envoyer_gmail(subject: str, body: str, user_id: str) -> tuple[str, str]:
    config = configuration_notifications(user_id)["gmail"]
    if not config["enabled"]:
        return "Desactivee", ""
    if not config["smtp_configured"]:
        return "Non configuree", "Parametres Gmail incomplets dans .env"
    if not config["recipient"]:
        return "Non configuree", "Aucun destinataire verifie"

    recipient = str(config["recipient"])
    sent, error = send_smtp_message(recipient, subject, body)
    if sent:
        return "Envoyee", ""
    return "Echec", f"{mask_email(recipient)}: {error}"


def envoyer_notifications(
    lignes: list[dict[str, Any]],
    user_id: str,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "demandes": 0,
        "envoyees": 0,
        "echecs": 0,
        "gmail_envoyes": 0,
        "details": [],
    }

    for ligne in lignes:
        classe = nettoyer_label(ligne.get("classe", ""))
        ligne["notification_email"] = "Non demandee"
        ligne["erreur_notification_email"] = ""

        if not classe or classe.upper() == "BENIGN":
            continue

        subject, body = message_notification(ligne)
        summary["demandes"] += 1
        status, error = envoyer_gmail(subject, body, user_id)
        ligne["notification_email"] = status
        ligne["erreur_notification_email"] = error
        if status == "Envoyee":
            summary["envoyees"] += 1
            summary["gmail_envoyes"] += 1
        else:
            summary["echecs"] += 1
        summary["details"].append(
            {"canal": "Gmail", "classe": classe, "statut": status, "erreur": error}
        )

    return summary


def nom_upload_securise(file: UploadFile, extensions: set[str]) -> str:
    filename = str(file.filename or "").replace("\\", "/").split("/")[-1].strip()
    if not filename or len(filename) > 180:
        raise HTTPException(status_code=422, detail="Nom de fichier invalide.")
    if Path(filename).suffix.lower() not in extensions:
        formats = ", ".join(sorted(extensions))
        raise HTTPException(
            status_code=415,
            detail=f"Format de fichier refuse. Formats autorises : {formats}.",
        )
    return filename


async def lire_upload_limite(
    file: UploadFile,
    *,
    max_bytes: int,
    extensions: set[str],
) -> tuple[bytes, str]:
    filename = nom_upload_securise(file, extensions)
    contenu = bytearray()
    try:
        while True:
            chunk = await file.read(UPLOAD_CHUNK_BYTES)
            if not chunk:
                break
            contenu.extend(chunk)
            if len(contenu) > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"Fichier trop volumineux. Limite : {max_bytes // (1024 * 1024)} Mo.",
                )
    finally:
        await file.close()
    if not contenu:
        raise HTTPException(status_code=422, detail="Le fichier transmis est vide.")
    return bytes(contenu), filename


def lire_csv_depuis_upload(contents: bytes) -> pd.DataFrame:
    try:
        return pd.read_csv(io.BytesIO(contents), low_memory=False)
    except UnicodeDecodeError:
        try:
            return pd.read_csv(io.BytesIO(contents), encoding="latin1", low_memory=False)
        except (pd.errors.ParserError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Fichier CSV invalide.") from exc
    except (pd.errors.ParserError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Fichier CSV invalide.") from exc


def append_history(path: Path, lignes: list[dict[str, Any]]) -> None:
    if not lignes:
        return

    with HISTORY_LOCK:
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        df_new = pd.DataFrame(lignes).fillna("")

        if path.exists():
            df_old = pd.read_csv(path, dtype=str).fillna("")
            columns = list(dict.fromkeys(list(df_old.columns) + list(df_new.columns)))
            df_old = df_old.reindex(columns=columns, fill_value="")
            df_new = df_new.reindex(columns=columns, fill_value="")
            df_final = pd.concat([df_old, df_new], ignore_index=True)
        else:
            columns = list(dict.fromkeys(BASE_HISTORY_COLUMNS + list(df_new.columns)))
            df_final = df_new.reindex(columns=columns, fill_value="")

        temporary_path = path.with_suffix(path.suffix + ".tmp")
        df_final.to_csv(temporary_path, index=False, encoding="utf-8-sig")
        temporary_path.replace(path)


def enregistrer_historique_csv(
    filename: str,
    details_classes: list[dict[str, Any]],
    mode_analyse: str,
    user_id: str,
) -> dict[str, Any]:
    date_analyse = now_text()
    lignes = []

    for item in details_classes:
        gravite = normaliser_gravite(item.get("gravite", ""))
        lignes.append(
            {
                "date": date_analyse,
                "source": "CSV",
                "fichier": filename,
                "classe": item.get("classe", ""),
                "nombre": item.get("nombre", 0),
                "gravite": gravite,
                "action_recommandee": item.get("action_recommandee", ""),
                "ip_source": "",
                "ip_destination": "",
                "protocole": "",
                "statut": "Non traitee",
                "details": "Analyse des flux CIC-IDS2017",
                "mode_analyse": mode_analyse,
                "user_id": user_id,
            }
        )

    notification_summary = envoyer_notifications(lignes, user_id)
    append_history(HISTORY_FILE, lignes)
    return notification_summary


def enregistrer_historique_suricata(
    filename: str,
    alertes: list[dict[str, Any]],
    user_id: str,
) -> dict[str, Any]:
    lignes = []

    for item in alertes:
        gravite = normaliser_gravite(item.get("gravite", ""))
        lignes.append(
            {
                "date": item.get("date", now_text()),
                "source": "Suricata",
                "fichier": filename,
                "classe": item.get("classe") or item.get("signature", ""),
                "nombre": 1,
                "gravite": gravite,
                "action_recommandee": action_recommandee(item.get("classe", "")),
                "ip_source": item.get("ip_source", ""),
                "ip_destination": item.get("ip_destination", ""),
                "protocole": item.get("protocole", ""),
                "statut": "Non traitee",
                "details": item.get("signature", ""),
                "mode_analyse": "Suricata eve.json",
                "event_id": item.get("event_id", ""),
                "user_id": user_id,
            }
        )

    with HISTORY_LOCK:
        identifiants_existants: set[str] = set()
        if SURICATA_HISTORY_FILE.exists():
            historique = pd.read_csv(
                SURICATA_HISTORY_FILE,
                dtype=str,
                usecols=lambda colonne: colonne in {"event_id", "user_id"},
            ).fillna("")
            if "user_id" in historique.columns:
                historique = historique[historique["user_id"] == user_id]
            if "event_id" in historique.columns:
                identifiants_existants = {
                    valeur
                    for valeur in historique["event_id"].astype(str)
                    if valeur
                }

        identifiants_du_lot: set[str] = set()
        nouvelles_lignes = []
        for ligne in lignes:
            event_id = str(ligne.get("event_id", ""))
            if event_id and (
                event_id in identifiants_existants
                or event_id in identifiants_du_lot
            ):
                continue
            nouvelles_lignes.append(ligne)
            if event_id:
                identifiants_du_lot.add(event_id)

        notification_summary = envoyer_notifications(nouvelles_lignes, user_id)
        append_history(SURICATA_HISTORY_FILE, nouvelles_lignes)

    notification_summary["nouveaux_evenements"] = len(nouvelles_lignes)
    notification_summary["doublons_ignores"] = len(lignes) - len(nouvelles_lignes)
    return notification_summary


def intervalle_surveillance_suricata() -> float:
    try:
        valeur = float(os.getenv("SURICATA_POLL_INTERVAL", "2"))
    except ValueError:
        valeur = 2.0
    return min(60.0, max(0.5, valeur))


def taille_lecture_suricata() -> int:
    try:
        valeur = int(os.getenv("SURICATA_MAX_READ_BYTES", str(4 * 1024 * 1024)))
    except ValueError:
        valeur = 4 * 1024 * 1024
    return min(64 * 1024 * 1024, max(64 * 1024, valeur))


def identite_fichier_suricata(stat_result: os.stat_result) -> str:
    return f"{stat_result.st_dev}:{stat_result.st_ino}"


def charger_curseur_suricata() -> dict[str, Any]:
    etat = read_json_file(SURICATA_CURSOR_FILE)
    try:
        offset = max(0, int(etat.get("offset", 0)))
    except (TypeError, ValueError):
        offset = 0
    return {
        "file_identity": str(etat.get("file_identity", "")),
        "offset": offset,
    }


def sauvegarder_curseur_suricata(etat: dict[str, Any]) -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    temporary_path = SURICATA_CURSOR_FILE.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps(etat, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(SURICATA_CURSOR_FILE)


def mettre_a_jour_statut_suricata(**valeurs: Any) -> None:
    with SURICATA_STATUS_LOCK:
        SURICATA_MONITOR_STATUS.update(valeurs)


def cycle_surveillance_suricata() -> dict[str, int]:
    """Lit uniquement les nouvelles lignes complètes de eve.json."""
    chemin = SURICATA_EVE_FILE
    if not chemin.is_file():
        mettre_a_jour_statut_suricata(
            last_scan_at=now_text(),
            last_error=f"Fichier introuvable : {chemin}",
            new_alerts_last_cycle=0,
        )
        return {"nouveaux": 0, "doublons": 0}

    stat_result = chemin.stat()
    identite = identite_fichier_suricata(stat_result)

    # Au premier démarrage, on se place à la fin du fichier. Les événements
    # historiques ont déjà été importés manuellement et ne doivent pas être
    # enregistrés une seconde fois.
    if not SURICATA_CURSOR_FILE.exists():
        sauvegarder_curseur_suricata(
            {
                "file_identity": identite,
                "offset": stat_result.st_size,
            }
        )
        mettre_a_jour_statut_suricata(
            last_scan_at=now_text(),
            last_error="",
            new_alerts_last_cycle=0,
        )
        return {"nouveaux": 0, "doublons": 0}

    curseur = charger_curseur_suricata()
    offset = int(curseur["offset"])
    if curseur["file_identity"] != identite or stat_result.st_size < offset:
        offset = 0

    with chemin.open("rb") as fichier:
        fichier.seek(offset)
        donnees = fichier.read(taille_lecture_suricata())

    if not donnees:
        mettre_a_jour_statut_suricata(
            last_scan_at=now_text(),
            last_error="",
            new_alerts_last_cycle=0,
        )
        return {"nouveaux": 0, "doublons": 0}

    derniere_fin_ligne = donnees.rfind(b"\n")
    if derniere_fin_ligne < 0:
        mettre_a_jour_statut_suricata(
            last_scan_at=now_text(),
            last_error="",
            new_alerts_last_cycle=0,
        )
        return {"nouveaux": 0, "doublons": 0}

    bloc_complet = donnees[: derniere_fin_ligne + 1]
    nouvel_offset = offset + len(bloc_complet)
    alertes: list[dict[str, Any]] = []

    for ligne_binaire in bloc_complet.splitlines():
        if not ligne_binaire.strip():
            continue
        try:
            evenement = json.loads(ligne_binaire.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        alerte = construire_alerte_suricata(evenement)
        if alerte is not None:
            alertes.append(alerte)

    owner = get_primary_alert_user()
    if owner is None:
        mettre_a_jour_statut_suricata(
            last_scan_at=now_text(),
            last_error="Aucun compte administrateur verifie pour attribuer les alertes.",
            new_alerts_last_cycle=0,
        )
        return {"nouveaux": 0, "doublons": 0}

    resume = enregistrer_historique_suricata(
        "eve.json (automatique)",
        alertes,
        owner["id"],
    )
    nouveaux = int(resume.get("nouveaux_evenements", 0))
    doublons = int(resume.get("doublons_ignores", 0))

    sauvegarder_curseur_suricata(
        {
            "file_identity": identite,
            "offset": nouvel_offset,
        }
    )

    if nouveaux:
        enregistrer_metriques_analyse(
            user_id=owner["id"],
            source="Suricata",
            evenements_ids=nouveaux,
        )

    with SURICATA_STATUS_LOCK:
        total_importe = int(
            SURICATA_MONITOR_STATUS.get("alerts_imported_total", 0)
        ) + nouveaux
        total_doublons = int(
            SURICATA_MONITOR_STATUS.get("duplicates_ignored_total", 0)
        ) + doublons

    valeurs_statut: dict[str, Any] = {
        "last_scan_at": now_text(),
        "last_error": "",
        "alerts_imported_total": total_importe,
        "new_alerts_last_cycle": nouveaux,
        "duplicates_ignored_total": total_doublons,
    }
    if alertes:
        valeurs_statut["last_event_at"] = alertes[-1]["date"]
    mettre_a_jour_statut_suricata(
        **valeurs_statut,
    )
    return {"nouveaux": nouveaux, "doublons": doublons}


def boucle_surveillance_suricata() -> None:
    mettre_a_jour_statut_suricata(started_at=now_text(), last_error="")
    while not SURICATA_STOP_EVENT.is_set():
        try:
            cycle_surveillance_suricata()
        except Exception as exc:  # noqa: BLE001
            mettre_a_jour_statut_suricata(
                last_scan_at=now_text(),
                last_error=f"{exc.__class__.__name__}: {exc}",
                new_alerts_last_cycle=0,
            )
        SURICATA_STOP_EVENT.wait(intervalle_surveillance_suricata())


def demarrer_surveillance_suricata() -> None:
    global SURICATA_MONITOR_THREAD

    if not env_bool("SURICATA_MONITOR_ENABLED", True):
        return
    if SURICATA_MONITOR_THREAD is not None and SURICATA_MONITOR_THREAD.is_alive():
        return

    SURICATA_STOP_EVENT.clear()
    SURICATA_MONITOR_THREAD = threading.Thread(
        target=boucle_surveillance_suricata,
        name="suricata-eve-monitor",
        daemon=True,
    )
    SURICATA_MONITOR_THREAD.start()


def arreter_surveillance_suricata() -> None:
    SURICATA_STOP_EVENT.set()
    if SURICATA_MONITOR_THREAD is not None:
        SURICATA_MONITOR_THREAD.join(timeout=5)


def alertes_suricata_recentes(
    user_id: str,
    limite: int = 5,
) -> list[dict[str, Any]]:
    if not SURICATA_HISTORY_FILE.exists():
        return []
    with HISTORY_LOCK:
        historique = pd.read_csv(SURICATA_HISTORY_FILE, dtype=str).fillna("")
    if "user_id" not in historique.columns:
        return []
    historique = historique[historique["user_id"] == user_id]
    colonnes = [
        "date",
        "classe",
        "gravite",
        "ip_source",
        "ip_destination",
        "protocole",
        "statut",
    ]
    for colonne in colonnes:
        if colonne not in historique.columns:
            historique[colonne] = ""
    return historique.tail(max(1, min(20, limite)))[colonnes].to_dict(
        orient="records"
    )


def statut_surveillance_suricata(user_id: str = "") -> dict[str, Any]:
    with SURICATA_STATUS_LOCK:
        statut = dict(SURICATA_MONITOR_STATUS)
    thread_actif = bool(
        SURICATA_MONITOR_THREAD is not None
        and SURICATA_MONITOR_THREAD.is_alive()
    )
    taille_fichier = 0
    if SURICATA_EVE_FILE.is_file():
        try:
            taille_fichier = SURICATA_EVE_FILE.stat().st_size
        except OSError:
            taille_fichier = 0
    curseur = charger_curseur_suricata() if SURICATA_CURSOR_FILE.exists() else {
        "offset": 0,
        "file_identity": "",
    }
    statut.update(
        {
            "enabled": env_bool("SURICATA_MONITOR_ENABLED", True),
            "thread_alive": thread_actif,
            "file_exists": SURICATA_EVE_FILE.is_file(),
            "file_name": SURICATA_EVE_FILE.name,
            "configured_path": str(SURICATA_EVE_FILE),
            "file_size_bytes": taille_fichier,
            "cursor_offset": int(curseur.get("offset", 0)),
            "poll_interval_seconds": intervalle_surveillance_suricata(),
            "recent_alerts": alertes_suricata_recentes(user_id, 5) if user_id else [],
        }
    )
    return statut


def normaliser_historique(df: pd.DataFrame, source_defaut: str) -> pd.DataFrame:
    df = df.copy().fillna("")

    if "date" not in df.columns and "timestamp" in df.columns:
        df["date"] = df["timestamp"]
    if "classe" not in df.columns and "attack_class" in df.columns:
        df["classe"] = df["attack_class"]
    if "gravite" not in df.columns and "severity" in df.columns:
        df["gravite"] = df["severity"]
    if "statut" not in df.columns and "status" in df.columns:
        df["statut"] = df["status"].replace({"Nouvelle": "Non traitee", "Normal": "Traitee"})
    if "action_recommandee" not in df.columns and "action" in df.columns:
        df["action_recommandee"] = df["action"]
    if "ip_source" not in df.columns and "source_ip" in df.columns:
        df["ip_source"] = df["source_ip"]
    if "ip_destination" not in df.columns and "destination_ip" in df.columns:
        df["ip_destination"] = df["destination_ip"]

    for column in BASE_HISTORY_COLUMNS:
        if column not in df.columns:
            df[column] = ""

    df["source"] = df["source"].replace("", source_defaut)
    df["gravite"] = df["gravite"].apply(normaliser_gravite)
    df["statut"] = df["statut"].replace({"Nouvelle": "Non traitee", "Normal": "Traitee", "": "Non traitee"})

    return df


def migrer_historiques_legacy(owner_id: str) -> None:
    """Attribue les lignes v9 sans propriétaire au compte principal, une fois."""
    if not owner_id:
        return
    with HISTORY_LOCK:
        for path in (HISTORY_FILE, SURICATA_HISTORY_FILE):
            if not path.exists():
                continue
            dataframe = pd.read_csv(path, dtype=str).fillna("")
            changed = False
            if "user_id" not in dataframe.columns:
                dataframe["user_id"] = owner_id
                changed = True
            else:
                missing_owner = dataframe["user_id"].astype(str).str.strip() == ""
                if missing_owner.any():
                    dataframe.loc[missing_owner, "user_id"] = owner_id
                    changed = True
            if changed:
                temporary_path = path.with_suffix(path.suffix + ".migration.tmp")
                dataframe.to_csv(temporary_path, index=False, encoding="utf-8-sig")
                temporary_path.replace(path)


def lire_historiques(user_id: str) -> pd.DataFrame:
    historiques = []

    if HISTORY_FILE.exists():
        df_csv = pd.read_csv(HISTORY_FILE, dtype=str).fillna("")
        df_csv = normaliser_historique(df_csv, "CSV")
        df_csv["historique_type"] = "csv"
        df_csv["historique_index"] = df_csv.index
        df_csv["historique_id"] = ["csv-" + str(index) for index in df_csv.index]
        historiques.append(df_csv)

    if SURICATA_HISTORY_FILE.exists():
        df_suricata = pd.read_csv(SURICATA_HISTORY_FILE, dtype=str).fillna("")
        df_suricata = normaliser_historique(df_suricata, "Suricata")
        df_suricata["historique_type"] = "suricata"
        df_suricata["historique_index"] = df_suricata.index
        df_suricata["historique_id"] = ["suricata-" + str(index) for index in df_suricata.index]
        historiques.append(df_suricata)

    if not historiques:
        return pd.DataFrame()

    resultat = pd.concat(historiques, ignore_index=True).fillna("")
    if "user_id" not in resultat.columns:
        return pd.DataFrame()
    return resultat[resultat["user_id"] == user_id].reset_index(drop=True)


def compter_par_colonne(df: pd.DataFrame, colonne: str) -> dict[str, int]:
    if colonne not in df.columns or df.empty:
        return {}

    categories = df[colonne].replace("", "Non defini")
    if "nombre" in df.columns:
        occurrences = pd.to_numeric(df["nombre"], errors="coerce").fillna(1).clip(lower=0)
        valeurs = occurrences.groupby(categories).sum().sort_values(ascending=False)
    else:
        valeurs = categories.value_counts()
    return {str(cle): int(valeur) for cle, valeur in valeurs.items()}


def occurrences_par_gravite(df: pd.DataFrame) -> dict[str, int]:
    resultat = {
        "Critique": 0,
        "Elevee": 0,
        "Moyenne": 0,
        "Faible": 0,
    }
    if df.empty:
        return resultat

    occurrences = pd.to_numeric(df["nombre"], errors="coerce").fillna(1).clip(lower=0)
    for gravite in resultat:
        resultat[gravite] = int(occurrences[df["gravite"] == gravite].sum())
    return resultat


def evaluer_risque_global(df_history: pd.DataFrame) -> dict[str, Any]:
    if df_history.empty:
        return {
            "niveau": "Maitrise",
            "score": 0,
            "incidents_actifs": 0,
            "par_gravite_active": occurrences_par_gravite(df_history),
        }

    df_actifs = df_history[df_history["statut"] != "Traitee"].copy()
    repartition = occurrences_par_gravite(df_actifs)
    incidents_actifs = int(sum(repartition.values()))

    if repartition["Critique"] > 0:
        niveau, score = "Critique", 100
    elif repartition["Elevee"] > 0:
        niveau, score = "Eleve", 75
    elif repartition["Moyenne"] > 0:
        niveau, score = "Modere", 50
    elif repartition["Faible"] > 0:
        niveau, score = "Faible", 25
    else:
        niveau, score = "Maitrise", 0

    return {
        "niveau": niveau,
        "score": score,
        "incidents_actifs": incidents_actifs,
        "par_gravite_active": repartition,
    }


def fichier_historique_par_type(historique_type: str) -> Path | None:
    if historique_type == "csv":
        return HISTORY_FILE
    if historique_type == "suricata":
        return SURICATA_HISTORY_FILE
    return None


def preparer_notifications(df_history: pd.DataFrame) -> list[dict[str, Any]]:
    if df_history.empty:
        return []

    df_notifications = df_history[
        (df_history["statut"] == "Non traitee")
        & (df_history["gravite"].isin(["Critique", "Elevee"]))
    ].copy()

    if df_notifications.empty:
        return []

    df_notifications["priorite"] = df_notifications["gravite"].map(PRIORITES_GRAVITE).fillna(99)
    df_notifications = df_notifications.sort_values(
        by=["priorite", "date"],
        ascending=[True, False],
    )

    notifications = []
    for _, ligne in df_notifications.iterrows():
        source = str(ligne.get("source", ""))
        gravite = str(ligne.get("gravite", ""))
        classe = str(ligne.get("classe", ""))
        action = str(ligne.get("action_recommandee", ""))
        ip_source = str(ligne.get("ip_source", ""))
        ip_destination = str(ligne.get("ip_destination", ""))

        message = (
            f"Alerte {gravite} detectee depuis {source}: {classe}. "
            f"Action recommandee: {action}."
        )
        if ip_source or ip_destination:
            message += f" IP source: {ip_source}. IP destination: {ip_destination}."

        notifications.append(
            {
                "historique_id": str(ligne.get("historique_id", "")),
                "date": str(ligne.get("date", "")),
                "source": source,
                "classe": classe,
                "gravite": gravite,
                "action_recommandee": action,
                "ip_source": ip_source,
                "ip_destination": ip_destination,
                "protocole": str(ligne.get("protocole", "")),
                "statut": str(ligne.get("statut", "")),
                "notification_email": str(ligne.get("notification_email", "")),
                "message_notification": message,
            }
        )

    return notifications


def labels_from_dataframe(df: pd.DataFrame) -> tuple[pd.Series, str]:
    label_columns = [column for column in df.columns if str(column).strip().lower() == "label"]

    if label_columns:
        labels = df[label_columns[0]].apply(nettoyer_label)
        return labels, "Labels CIC-IDS2017"

    labels = pd.Series(
        [infer_class_from_row(row) for row in df.to_dict(orient="records")],
        index=df.index,
    )

    if load_model() is not None:
        return labels, "Modele IA"

    return labels, "Regles de detection"


def construire_details_classes(labels: pd.Series, total_flux: int) -> list[dict[str, Any]]:
    df_attaques = labels[labels.astype(str).str.upper() != "BENIGN"]
    repartition_attaques = df_attaques.value_counts()

    details_classes = []
    for classe, nombre in repartition_attaques.items():
        gravite = determiner_gravite(classe)
        details_classes.append(
            {
                "classe": str(classe),
                "nombre": int(nombre),
                "pourcentage": round((int(nombre) / total_flux) * 100, 4) if total_flux else 0,
                "gravite": gravite,
                "action_recommandee": action_recommandee(classe),
            }
        )

    return details_classes


@app.on_event("startup")
def api_startup() -> None:
    initialize_auth_database()
    owner = get_primary_alert_user()
    if owner:
        migrer_historiques_legacy(owner["id"])
        migrer_metriques_legacy(owner["id"])
    demarrer_surveillance_suricata()


@app.on_event("shutdown")
def api_shutdown() -> None:
    arreter_surveillance_suricata()


@app.get("/")
def home() -> dict[str, str]:
    return {
        "message": "API SOC fonctionne correctement",
        "version": API_VERSION,
    }


@app.get("/health/ready")
def readiness() -> dict[str, Any]:
    """Expose uniquement les indicateurs requis par le lanceur local."""
    model = model_status()
    monitor = statut_surveillance_suricata()
    return {
        "version": API_VERSION,
        "model_loaded": bool(model.get("model_loaded")),
        "model_error": str(model.get("load_error", "")),
        "monitor_enabled": bool(monitor.get("enabled")),
        "monitor_thread_alive": bool(monitor.get("thread_alive")),
        "monitor_file_exists": bool(monitor.get("file_exists")),
        "monitor_error": str(monitor.get("last_error", "")),
    }


@app.get("/model-status")
def get_model_status() -> dict[str, Any]:
    return model_status()


@app.get("/suricata-monitor/status")
def get_suricata_monitor_status(request: Request) -> dict[str, Any]:
    user = request_user(request)
    return statut_surveillance_suricata(user["id"])


@app.get("/system-status")
def get_system_status(request: Request) -> dict[str, Any]:
    user = request_user(request)
    model = model_status()
    notification_config = configuration_notifications(user["id"])["gmail"]
    metrics = lire_metriques_analyse(user["id"])

    model_operational = bool(model["model_loaded"])
    gmail_operational = bool(
        notification_config["enabled"] and notification_config["configured"]
    )

    if model_operational and gmail_operational:
        global_status = "Operationnel"
    else:
        global_status = "Degrade"

    return {
        "statut_global": global_status,
        "api": "Operationnelle",
        "moteur_detection": (
            "Operationnel" if model_operational else "Mode de secours"
        ),
        "gmail": "Operationnelle" if gmail_operational else "Configuration requise",
        "derniere_analyse": metrics["derniere_analyse"],
        "derniere_source": metrics["derniere_source"],
        "horodatage": now_text(),
    }


@app.get("/notification-config")
def get_notification_config(request: Request) -> dict[str, Any]:
    user = request_user(request)
    config = configuration_notifications(user["id"])
    user_email = user.get("email", "") if user.get("email_verified") else ""
    return {
        "gmail": {
            "enabled": config["gmail"]["enabled"],
            "smtp_configured": config["gmail"]["smtp_configured"],
            "configured": bool(config["gmail"]["smtp_configured"] and user_email),
            "recipient": mask_email(user_email),
            "email_verified": bool(user_email),
            "verified_recipients": config["gmail"]["recipient_count"],
        },
    }


@app.post("/test-notification")
def test_notification(request: Request) -> dict[str, Any]:
    user = request_user(request)
    ligne_test = {
        "date": now_text(),
        "source": "Test interface SOC",
        "classe": "Test de notification",
        "nombre": 1,
        "gravite": "Moyenne",
        "action_recommandee": "Aucune action : il s'agit d'un test de configuration",
        "ip_source": "",
        "ip_destination": "",
        "protocole": "",
    }
    summary = envoyer_notifications([ligne_test], user["id"])
    return {
        "message": "Test de notification termine",
        "notification_summary": summary,
    }


@app.post("/analyze")
async def analyze_csv(
    request: Request,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    user = request_user(request)
    contents, safe_filename = await lire_upload_limite(
        file,
        max_bytes=MAX_CSV_UPLOAD_BYTES,
        extensions={".csv"},
    )
    df = lire_csv_depuis_upload(contents)
    df.columns = df.columns.astype(str).str.strip()

    total_flux = len(df)
    total_colonnes = len(df.columns)
    labels, mode_analyse = labels_from_dataframe(df)
    distribution_classes = {str(key): int(value) for key, value in labels.value_counts().items()}
    details_classes = construire_details_classes(labels, total_flux)
    attaques_detectees = int(sum(item["nombre"] for item in details_classes))

    notification_summary = enregistrer_historique_csv(
        filename=safe_filename,
        details_classes=details_classes,
        mode_analyse=mode_analyse,
        user_id=user["id"],
    )
    enregistrer_metriques_analyse(
        user_id=user["id"],
        source="CSV",
        flux_reseau=total_flux,
    )

    return {
        "filename": safe_filename,
        "total_flux": total_flux,
        "total_colonnes": total_colonnes,
        "attaques_detectees": attaques_detectees,
        "distribution_classes": distribution_classes,
        "details_classes": details_classes,
        "colonnes": list(df.columns[:10]),
        "mode_analyse": mode_analyse,
        "model": model_status(),
        "notifications_preparees": notification_summary["demandes"],
        "notifications_envoyees": notification_summary["envoyees"],
        "notifications_echecs": notification_summary["echecs"],
        "notification_summary": notification_summary,
        "message": "Fichier CSV analyse avec succes",
    }


@app.post("/analyze-suricata")
async def analyze_suricata(
    request: Request,
    file: UploadFile = File(...),
) -> dict[str, Any]:
    user = request_user(request)
    contents, safe_filename = await lire_upload_limite(
        file,
        max_bytes=MAX_EVE_UPLOAD_BYTES,
        extensions={".json", ".jsonl", ".ndjson"},
    )
    text = contents.decode("utf-8", errors="replace")

    alertes = []
    for line in text.splitlines():
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        alerte = construire_alerte_suricata(event)
        if alerte is not None:
            alertes.append(alerte)

    notification_summary = enregistrer_historique_suricata(
        safe_filename,
        alertes,
        user["id"],
    )
    nouveaux_evenements = int(
        notification_summary.get("nouveaux_evenements", 0)
    )
    if nouveaux_evenements:
        enregistrer_metriques_analyse(
            user_id=user["id"],
            source="Suricata",
            evenements_ids=nouveaux_evenements,
        )

    return {
        "filename": safe_filename,
        "total_alertes": len(alertes),
        "nouvelles_alertes": nouveaux_evenements,
        "doublons_ignores": int(
            notification_summary.get("doublons_ignores", 0)
        ),
        "alertes": alertes,
        "notifications_preparees": notification_summary["demandes"],
        "notifications_envoyees": notification_summary["envoyees"],
        "notifications_echecs": notification_summary["echecs"],
        "notification_summary": notification_summary,
        "message": "Fichier Suricata analyse avec succes",
    }


@app.get("/history")
def get_history(request: Request) -> dict[str, list[dict[str, Any]]]:
    user = request_user(request)
    if user.get("role") == "admin":
        migrer_historiques_legacy(user["id"])
    df_history = lire_historiques(user["id"])

    if df_history.empty:
        return {"history": []}

    public_history = df_history.drop(columns=["user_id"], errors="ignore")
    return {"history": public_history.to_dict(orient="records")}


@app.get("/stats")
def get_stats(request: Request) -> dict[str, Any]:
    user = request_user(request)
    if user.get("role") == "admin":
        migrer_historiques_legacy(user["id"])
        migrer_metriques_legacy(user["id"])
    df_history = lire_historiques(user["id"])
    metrics = lire_metriques_analyse(user["id"])

    if df_history.empty:
        return {
            "total_alertes": 0,
            "attaques_detectees": 0,
            "alertes_csv": 0,
            "alertes_suricata": 0,
            "alertes_critiques": 0,
            "alertes_non_traitees": 0,
            "par_source": {},
            "par_gravite": {},
            "risque_global": evaluer_risque_global(df_history),
            **metrics,
            "horodatage": now_text(),
        }

    repartition_occurrences = occurrences_par_gravite(df_history)

    return {
        "total_alertes": int(len(df_history)),
        "attaques_detectees": int(sum(repartition_occurrences.values())),
        "alertes_csv": int((df_history["source"] == "CSV").sum()),
        "alertes_suricata": int((df_history["source"] == "Suricata").sum()),
        "alertes_critiques": int((df_history["gravite"] == "Critique").sum()),
        "alertes_non_traitees": int((df_history["statut"] == "Non traitee").sum()),
        "par_source": compter_par_colonne(df_history, "source"),
        "par_gravite": repartition_occurrences,
        "risque_global": evaluer_risque_global(df_history),
        **metrics,
        "horodatage": now_text(),
    }


@app.post("/metrics/traffic/reset")
def reset_traffic_volume(request: Request) -> dict[str, Any]:
    user = request_user(request)
    resultat = reinitialiser_volume_flux(user["id"])
    record_security_event(
        "traffic_volume_reset",
        "success",
        user_id=user["id"],
        request=request,
    )
    return {
        **resultat,
        "message": "Le volume de trafic analyse a ete remis a zero.",
    }


@app.get("/notifications")
def get_notifications(request: Request) -> dict[str, Any]:
    user = request_user(request)
    df_history = lire_historiques(user["id"])
    notifications = preparer_notifications(df_history)

    return {
        "total_notifications": len(notifications),
        "critiques": sum(1 for item in notifications if item["gravite"] == "Critique"),
        "elevees": sum(1 for item in notifications if item["gravite"] == "Elevee"),
        "notifications": notifications,
    }


@app.post("/update-status")
def update_status(update: StatutUpdate, request: Request) -> dict[str, str]:
    user = request_user(request)
    statuts_valides = ["Non traitee", "Traitee"]

    if update.statut not in statuts_valides:
        raise HTTPException(status_code=400, detail="Statut invalide")

    if "-" not in update.historique_id:
        raise HTTPException(status_code=400, detail="Identifiant historique invalide")

    historique_type, historique_index = update.historique_id.split("-", 1)
    fichier_historique = fichier_historique_par_type(historique_type)

    if fichier_historique is None:
        raise HTTPException(status_code=400, detail="Type d'historique invalide")

    if not fichier_historique.exists():
        raise HTTPException(status_code=404, detail="Fichier historique introuvable")

    try:
        index_ligne = int(historique_index)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Index historique invalide") from exc

    with HISTORY_LOCK:
        df_history = pd.read_csv(fichier_historique, dtype=str).fillna("")

        if index_ligne < 0 or index_ligne >= len(df_history):
            raise HTTPException(status_code=404, detail="Alerte introuvable")
        if "user_id" not in df_history.columns or str(
            df_history.loc[index_ligne, "user_id"]
        ) != user["id"]:
            raise HTTPException(status_code=404, detail="Alerte introuvable")

        if "statut" not in df_history.columns:
            df_history["statut"] = "Non traitee"

        df_history.loc[index_ligne, "statut"] = update.statut
        temporary_path = fichier_historique.with_suffix(
            fichier_historique.suffix + ".status.tmp"
        )
        df_history.to_csv(temporary_path, index=False, encoding="utf-8-sig")
        temporary_path.replace(fichier_historique)

    return {
        "message": "Statut mis a jour avec succes",
        "historique_id": update.historique_id,
        "statut": update.statut,
    }
