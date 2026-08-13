"""Tests for Atlas Phase 10 restore system."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.backup import AtlasBackupManager
from guardianmesh.atlas.errors import AtlasCompatibilityError
from guardianmesh.atlas.restore import AtlasRestoreManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_restore.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


@pytest.fixture
def managers(db: Database, tmp_path: Path) -> tuple[AtlasBackupManager, AtlasRestoreManager]:
    backup = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
        schema_version="10",
    )
    restore = AtlasRestoreManager(
        db,
        backup,
        current_orion_version="1.0.0",
        current_schema_version="10",
    )
    return backup, restore


def test_verify_compatibility_passes_for_valid_backup(
    managers: tuple[AtlasBackupManager, AtlasRestoreManager],
) -> None:
    backup, restore = managers
    info = backup.create_backup()
    ok, msg, info_dict = restore.verify_compatibility(info.backup_id)
    assert ok is True
    assert info_dict is not None
    assert info_dict["backup_id"] == info.backup_id


def test_restore_dry_run_does_not_modify_state(
    managers: tuple[AtlasBackupManager, AtlasRestoreManager],
) -> None:
    backup, restore = managers
    info = backup.create_backup()
    plan = restore.restore(info.backup_id, dry_run=True)
    assert plan["dry_run"] is True
    assert plan["applied"] is False
    assert "tables_to_restore" in plan


def test_restore_rejects_unknown_backup(
    managers: tuple[AtlasBackupManager, AtlasRestoreManager],
) -> None:
    _backup, restore = managers
    with pytest.raises(AtlasCompatibilityError):
        restore.restore("BAK-NOPE")


def test_restore_rejects_incompatible_schema(
    managers: tuple[AtlasBackupManager, AtlasRestoreManager],
) -> None:
    backup, restore = managers
    info = backup.create_backup()
    # Update the manifest's schema_version to an incompatible one.
    backup._db.execute(
        "UPDATE atlas_backups SET schema_version = '99' WHERE backup_id = ?;",
        (info.backup_id,),
    )
    with pytest.raises(AtlasCompatibilityError):
        restore.restore(info.backup_id)
