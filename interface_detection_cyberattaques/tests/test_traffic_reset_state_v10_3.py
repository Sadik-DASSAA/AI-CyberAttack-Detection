from __future__ import annotations

import ast
import json
import tempfile
import threading
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
API_PATH = PROJECT_DIR / "api.py"


def load_metric_functions(test_root: Path) -> dict[str, Any]:
    source = API_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted_functions = {
        "read_json_file",
        "lire_metriques_analyse",
        "reinitialiser_volume_flux",
    }
    selected_nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            }
            if "DEFAULT_ANALYSIS_METRICS" in names:
                selected_nodes.append(node)
        if isinstance(node, ast.FunctionDef) and node.name in wanted_functions:
            selected_nodes.append(node)

    namespace: dict[str, Any] = {
        "Any": Any,
        "Path": Path,
        "json": json,
        "HISTORY_LOCK": threading.Lock(),
        "HISTORY_DIR": test_root,
        "ANALYSIS_METRICS_FILE": test_root / "analysis_metrics.json",
    }
    module = ast.Module(body=selected_nodes, type_ignores=[])
    exec(compile(module, API_PATH, "exec"), namespace)
    return namespace


def test_reset_preserve_les_autres_compteurs_et_utilisateurs() -> None:
    test_root = Path(tempfile.mkdtemp(prefix="soc-v10-3-reset-"))
    namespace = load_metric_functions(test_root)
    metrics_file = test_root / "analysis_metrics.json"
    original = {
        "schema_version": 2,
        "users": {
            "user-one": {
                "analyses_csv": 3,
                "analyses_suricata": 7,
                "flux_reseau_analyses": 6_662_856,
                "evenements_ids_analyses": 59,
                "derniere_analyse": "2026-08-09 14:03:37",
                "derniere_source": "Suricata",
            },
            "user-two": {
                "analyses_csv": 1,
                "analyses_suricata": 0,
                "flux_reseau_analyses": 42,
                "evenements_ids_analyses": 0,
                "derniere_analyse": "",
                "derniere_source": "CSV",
            },
        },
    }
    metrics_file.write_text(json.dumps(original), encoding="utf-8")

    result = namespace["reinitialiser_volume_flux"]("user-one")
    persisted = json.loads(metrics_file.read_text(encoding="utf-8"))

    assert result == {"ancien_volume": 6_662_856, "nouveau_volume": 0}
    assert persisted["users"]["user-one"]["flux_reseau_analyses"] == 0
    assert persisted["users"]["user-one"]["analyses_csv"] == 3
    assert persisted["users"]["user-one"]["analyses_suricata"] == 7
    assert persisted["users"]["user-one"]["evenements_ids_analyses"] == 59
    assert persisted["users"]["user-two"] == original["users"]["user-two"]


if __name__ == "__main__":
    test_reset_preserve_les_autres_compteurs_et_utilisateurs()
    print("TRAFFIC RESET TEST PASSED")
