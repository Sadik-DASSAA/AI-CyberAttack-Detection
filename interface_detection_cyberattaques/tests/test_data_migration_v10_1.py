from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(tempfile.mkdtemp(prefix="soc-v10-1-migration-"))

active_security = TEST_ROOT / "active" / "security"
active_history = TEST_ROOT / "active" / "history"
legacy_security = TEST_ROOT / "legacy" / "security"
legacy_history = TEST_ROOT / "legacy" / "history"

os.environ.update(
    {
        "ACTIVE_SECURITY_DIR": str(active_security),
        "ACTIVE_HISTORY_DIR": str(active_history),
        "LEGACY_SECURITY_DIR": str(legacy_security),
        "LEGACY_HISTORY_DIR": str(legacy_history),
    }
)

import sys

sys.path.insert(0, str(PROJECT_DIR))
import data_migration  # noqa: E402


def run() -> None:
    legacy_security.mkdir(parents=True)
    legacy_history.mkdir(parents=True)
    legacy_database = legacy_security / "authentication.db"
    with sqlite3.connect(legacy_database) as connection:
        connection.execute("CREATE TABLE users(id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO users(id) VALUES ('existing-user')")
        connection.commit()
    (legacy_history / "alert_history.csv").write_text(
        "historique_id,statut\n1,Non traitee\n",
        encoding="utf-8",
    )

    data_migration.import_existing_data()
    with sqlite3.connect(active_security / "authentication.db") as connection:
        journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        existing_user = connection.execute("SELECT id FROM users").fetchone()[0]
    assert journal_mode.lower() == "wal"
    assert existing_user == "existing-user"
    assert (active_history / "alert_history.csv").exists()

    with sqlite3.connect(legacy_database) as connection:
        connection.execute("DELETE FROM users")
        connection.execute("INSERT INTO users(id) VALUES ('legacy-modified')")
        connection.commit()
    data_migration.import_existing_data()
    with sqlite3.connect(active_security / "authentication.db") as connection:
        existing_user = connection.execute("SELECT id FROM users").fetchone()[0]
    assert existing_user == "existing-user"

    with sqlite3.connect(active_security / "authentication.db") as connection:
        connection.execute("UPDATE users SET id = 'v10-1-user'")
        connection.commit()
    (legacy_security / "authentication.db-shm").write_bytes(b"stale-shm")
    (active_history / "alert_history.csv").write_text(
        "historique_id,statut\n1,Traitee\n",
        encoding="utf-8",
    )
    data_migration.export_current_data()
    for sidecar_name in ("authentication.db-wal", "authentication.db-shm"):
        active_sidecar = active_security / sidecar_name
        legacy_sidecar = legacy_security / sidecar_name
        assert active_sidecar.exists() == legacy_sidecar.exists()
        if active_sidecar.exists():
            assert active_sidecar.read_bytes() == legacy_sidecar.read_bytes()
    with sqlite3.connect(legacy_database) as connection:
        exported_user = connection.execute("SELECT id FROM users").fetchone()[0]
    assert exported_user == "v10-1-user"
    assert "Traitee" in (legacy_history / "alert_history.csv").read_text(
        encoding="utf-8"
    )

    print("DATA MIGRATION TESTS PASSED")


if __name__ == "__main__":
    run()
