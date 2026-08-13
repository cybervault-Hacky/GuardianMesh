"""Tests for Atlas Phase 10 release validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.release import (
    AEGIS_FORBIDDEN_PERMISSIONS,
    AtlasReleaseValidator,
)
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_release.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_forbidden_permissions_constant_includes_surveillance() -> None:
    for forbidden in (
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ):
        assert forbidden in AEGIS_FORBIDDEN_PERMISSIONS


def test_basic_checks_pass_on_clean_db(db: Database) -> None:
    v = AtlasReleaseValidator(db)
    checks = v.basic_checks()
    assert len(checks) == 3
    assert all(c.ok for c in checks)


def test_check_version_consistency(db: Database) -> None:
    v = AtlasReleaseValidator(db)
    check = v.check_version_consistency()
    assert check.ok is True


def test_check_migration_state(db: Database) -> None:
    v = AtlasReleaseValidator(db)
    check = v.check_migration_state()
    assert check.ok is True


def test_check_audit_event_classes(db: Database) -> None:
    v = AtlasReleaseValidator(db)
    check = v.check_audit_event_classes()
    assert check.ok is True


def test_check_aegis_manifest_clean(db: Database) -> None:
    v = AtlasReleaseValidator(db)
    check = v.check_aegis_manifest_permissions()
    assert check.ok is True


def test_deep_checks_include_manifest_check(db: Database) -> None:
    v = AtlasReleaseValidator(db)
    checks = v.deep_checks()
    names = [c.name for c in checks]
    assert "release_aegis_manifest" in names


def test_check_aegis_manifest_reports_missing(tmp_path: Path, db: Database) -> None:
    """If the manifest is moved, the check reports a Notice (not a failure)."""
    # The check is robust to a missing manifest: it returns ok=True
    # with a reason.
    v = AtlasReleaseValidator(db)
    # Move the manifest temporarily.
    import os
    import shutil

    manifest_path = "android/aegis/app/src/main/AndroidManifest.xml"
    backup_path = None
    if os.path.exists(manifest_path):
        backup_path = str(tmp_path / "manifest.xml.bak")
        shutil.move(manifest_path, backup_path)
    try:
        check = v.check_aegis_manifest_permissions()
        # The check returns ok=True (with a Notice) when the manifest
        # is absent.
        assert check.ok is True
    finally:
        if backup_path and os.path.exists(backup_path):
            shutil.move(backup_path, manifest_path)
