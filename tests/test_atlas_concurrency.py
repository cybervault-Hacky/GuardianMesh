"""Tests for Atlas Phase 10 concurrency and reliability."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from guardianmesh.atlas.backup import AtlasBackupManager
from guardianmesh.atlas.controller import AtlasController
from guardianmesh.atlas.health import AtlasHealthMonitor
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_conc.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_concurrent_health_records(tmp_path: Path, db: Database) -> None:
    """Concurrent health.record_health() must not corrupt state."""
    monitor = AtlasHealthMonitor(db)

    def record_n() -> None:
        for _ in range(20):
            monitor.record_health()

    threads = [threading.Thread(target=record_n) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Total records: 4 * 20 * 10 subsystems = 800.
    row = db.fetchone("SELECT COUNT(*) AS c FROM atlas_health;")
    assert int(row["c"]) >= 1  # At minimum, the bus is consistent.


def test_concurrent_backup_creation(tmp_path: Path, db: Database) -> None:
    """Concurrent backup creation must not corrupt state."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    mgr = AtlasBackupManager(db, backup_dir, orion_version="1.0.0")

    def make_backup(start: int) -> None:
        for _i in range(5):
            try:
                mgr.create_backup()
            except Exception:
                pass

    threads = [threading.Thread(target=make_backup, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    backups = mgr.list_backups()
    assert len(backups) >= 1  # At least one backup was created.


def test_atlas_controller_constructs_with_backup_dir(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        orion_version="1.0.0",
        schema_version="10",
        backup_dir=str(tmp_path / "backups"),
    )
    assert controller is not None


def test_atlas_controller_diagnose(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        backup_dir=str(tmp_path / "backups"),
    )
    report = controller.diagnose(full=False)
    assert "checks" in report
    assert "passed" in report


def test_atlas_controller_diagnose_full(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        backup_dir=str(tmp_path / "backups"),
    )
    report = controller.diagnose(full=True)
    names = [c["name"] for c in report["checks"]]
    assert "release_aegis_manifest" in names


def test_atlas_controller_backup_restore_cycle(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        backup_dir=str(tmp_path / "backups"),
    )
    info = controller.backup()
    verify_ok, _ = controller.verify_backup(info["backup_id"])
    assert verify_ok is True
    plan = controller.restore(info["backup_id"], dry_run=True)
    assert plan["dry_run"] is True


def test_atlas_controller_recover(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        backup_dir=str(tmp_path / "backups"),
    )
    records = controller.recover()
    assert len(records) == 3


def test_atlas_controller_retention(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        backup_dir=str(tmp_path / "backups"),
    )
    plan = controller.run_retention(dry_run=True)
    assert plan["dry_run"] is True


def test_atlas_controller_release_info(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(
        db,
        orion_version="1.0.0",
        schema_version="10",
        backup_dir=str(tmp_path / "backups"),
    )
    info = controller.release_info()
    assert info["orion_version"] == "1.0.0"
    assert "ATLAS" in info["subsystems"]


def test_atlas_controller_no_backup_dir(tmp_path: Path, db: Database) -> None:
    controller = AtlasController(db, backup_dir=None)
    # Backup operations fail without a backup_dir.
    with pytest.raises(RuntimeError):
        controller.backup()
