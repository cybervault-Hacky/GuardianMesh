"""Tests for Atlas Phase 10 backup system."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardianmesh.atlas.backup import (
    BACKUP_ALLOWED_TABLES,
    BACKUP_FORBIDDEN_COLUMNS,
    AtlasBackupManager,
)
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_backup.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


@pytest.fixture
def manager(db: Database, tmp_path: Path) -> AtlasBackupManager:
    return AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
        schema_version="10",
    )


def test_allowed_tables_constant() -> None:
    for t in (
        "identities",
        "trusted_devices",
        "orion_actions",
        "atlas_backups",
        "atlas_health",
    ):
        assert t in BACKUP_ALLOWED_TABLES


def test_forbidden_columns_constant() -> None:
    assert "private_key_pem" in BACKUP_FORBIDDEN_COLUMNS["identities"]


def test_create_backup_succeeds(manager: AtlasBackupManager) -> None:
    info = manager.create_backup()
    assert info.backup_id.startswith("BAK-")
    assert info.integrity_digest.startswith("sha256:")
    assert info.size_bytes > 0
    assert info.status == "VALID"


def test_create_backup_persists_manifest(manager: AtlasBackupManager) -> None:
    info = manager.create_backup()
    fetched = manager.get_backup(info.backup_id)
    assert fetched is not None
    assert fetched.backup_id == info.backup_id


def test_list_backups_empty_initially(manager: AtlasBackupManager) -> None:
    assert manager.list_backups() == []


def test_list_backups_returns_after_create(manager: AtlasBackupManager) -> None:
    manager.create_backup()
    manager.create_backup()
    backups = manager.list_backups()
    assert len(backups) == 2


def test_verify_backup_succeeds(manager: AtlasBackupManager) -> None:
    info = manager.create_backup()
    ok, msg = manager.verify_backup(info.backup_id)
    assert ok is True
    assert msg == "OK"


def test_verify_backup_not_found(manager: AtlasBackupManager) -> None:
    ok, msg = manager.verify_backup("BAK-DOES-NOT-EXIST")
    assert ok is False
    assert "not found" in msg


def test_verify_backup_detects_corruption(manager: AtlasBackupManager) -> None:
    info = manager.create_backup()
    # Corrupt the backup file.
    path = manager._backup_dir / f"{info.backup_id}.json"
    path.write_bytes(b"corrupted content")
    ok, msg = manager.verify_backup(info.backup_id)
    assert ok is False
    assert "mismatch" in msg or "not valid" in msg


def test_get_backup_returns_none_for_unknown(manager: AtlasBackupManager) -> None:
    assert manager.get_backup("BAK-X") is None


def test_backup_metadata_never_contains_secrets(manager: AtlasBackupManager) -> None:
    info = manager.create_backup()
    d = info.to_dict()
    for forbidden in ("password", "private_key", "secret", "frame", "keylog", "token"):
        assert forbidden not in json.dumps(d).lower()
