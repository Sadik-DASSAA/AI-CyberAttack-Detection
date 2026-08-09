from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


ACTIVE_SECURITY_DIR = Path(
    os.getenv("ACTIVE_SECURITY_DIR", "/app/security")
).resolve()
ACTIVE_HISTORY_DIR = Path(
    os.getenv("ACTIVE_HISTORY_DIR", "/app/history")
).resolve()
LEGACY_SECURITY_DIR = Path(
    os.getenv("LEGACY_SECURITY_DIR", "/legacy/security")
).resolve()
LEGACY_HISTORY_DIR = Path(
    os.getenv("LEGACY_HISTORY_DIR", "/legacy/history")
).resolve()


def copy_regular_files(
    source: Path,
    destination: Path,
    *,
    overwrite: bool,
) -> int:
    """Copie les fichiers ordinaires sans suivre les liens symboliques."""
    if not source.exists():
        return 0

    destination.mkdir(parents=True, exist_ok=True)
    copied = 0

    for source_path in sorted(source.rglob("*")):
        if source_path.is_symlink():
            continue

        relative_path = source_path.relative_to(source)
        destination_path = destination / relative_path

        if source_path.is_dir():
            destination_path.mkdir(parents=True, exist_ok=True)
            continue

        if not source_path.is_file():
            continue

        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if destination_path.exists() and not overwrite:
            continue

        temporary_path = destination_path.with_name(
            f".{destination_path.name}.migration.tmp"
        )
        shutil.copyfile(source_path, temporary_path)
        os.replace(temporary_path, destination_path)
        copied += 1

    return copied


def set_runtime_owner(path: Path, uid: int, gid: int) -> None:
    """Attribue les volumes actifs à l'utilisateur non-root de l'API."""
    if os.name != "posix" or os.geteuid() != 0:
        return

    candidates = [path]
    if path.exists():
        candidates.extend(path.rglob("*"))

    for candidate in candidates:
        if candidate.is_symlink():
            continue

        private_mode = 0o750 if candidate.is_dir() else 0o640
        fallback_mode = 0o777 if candidate.is_dir() else 0o666

        try:
            os.chown(candidate, uid, gid)
            os.chmod(candidate, private_mode)
        except OSError:
            # Certains systèmes de fichiers virtualisés de Docker Desktop ne
            # prennent pas en charge chown. Le volume reste privé aux services
            # Compose ; ce repli permet uniquement l'écriture dans ce volume.
            os.chmod(candidate, fallback_mode)


def import_existing_data() -> None:
    ACTIVE_SECURITY_DIR.mkdir(parents=True, exist_ok=True)
    ACTIVE_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    authentication_db = ACTIVE_SECURITY_DIR / "authentication.db"
    imported_security = 0
    if not authentication_db.exists():
        imported_security = copy_regular_files(
            LEGACY_SECURITY_DIR,
            ACTIVE_SECURITY_DIR,
            overwrite=False,
        )

    imported_history = copy_regular_files(
        LEGACY_HISTORY_DIR,
        ACTIVE_HISTORY_DIR,
        overwrite=False,
    )

    uid = int(os.getenv("DATA_UID", "10001"))
    gid = int(os.getenv("DATA_GID", "10001"))
    set_runtime_owner(ACTIVE_SECURITY_DIR, uid, gid)
    set_runtime_owner(ACTIVE_HISTORY_DIR, uid, gid)

    print(
        "Migration initiale terminee : "
        f"security={imported_security}, history={imported_history}"
    )


def export_current_data() -> None:
    LEGACY_SECURITY_DIR.mkdir(parents=True, exist_ok=True)
    LEGACY_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    exported_security = copy_regular_files(
        ACTIVE_SECURITY_DIR,
        LEGACY_SECURITY_DIR,
        overwrite=True,
    )
    exported_history = copy_regular_files(
        ACTIVE_HISTORY_DIR,
        LEGACY_HISTORY_DIR,
        overwrite=True,
    )

    # Après un arrêt SQLite propre, les fichiers WAL/SHM peuvent avoir été
    # supprimés du volume actif. Une ancienne copie locale ne doit pas rester
    # à côté de la nouvelle base, sous peine d'être réimportée ultérieurement.
    for sidecar_name in ("authentication.db-wal", "authentication.db-shm"):
        active_sidecar = ACTIVE_SECURITY_DIR / sidecar_name
        legacy_sidecar = LEGACY_SECURITY_DIR / sidecar_name
        if not active_sidecar.exists() and legacy_sidecar.exists():
            legacy_sidecar.unlink()

    print(
        "Sauvegarde locale terminee : "
        f"security={exported_security}, history={exported_history}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migration sûre des données persistantes SOC."
    )
    parser.add_argument("mode", choices=("import", "export"))
    arguments = parser.parse_args()

    if arguments.mode == "import":
        import_existing_data()
    else:
        export_current_data()


if __name__ == "__main__":
    main()
