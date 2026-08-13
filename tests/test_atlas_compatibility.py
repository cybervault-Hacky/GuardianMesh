"""Tests for Atlas Phase 10 compatibility checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.compatibility import (
    CURRENT_SCHEMA_VERSION,
    AtlasCompatibilityChecker,
)
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_compat.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_current_schema_version_constant() -> None:
    assert CURRENT_SCHEMA_VERSION == 10


def test_check_schema_version_passes(db: Database) -> None:
    checker = AtlasCompatibilityChecker(db)
    ok, msg = checker.check_schema_version()
    assert ok is True
    assert "up to date" in msg


def test_check_migration_chain_passes(db: Database) -> None:
    checker = AtlasCompatibilityChecker(db)
    ok, msg = checker.check_migration_chain()
    assert ok is True
    assert "consistent" in msg


def test_check_expected_tables_passes(db: Database) -> None:
    checker = AtlasCompatibilityChecker(db)
    ok, msg = checker.check_expected_tables()
    assert ok is True
    assert "present" in msg


def test_run_all_returns_three_results(db: Database) -> None:
    checker = AtlasCompatibilityChecker(db)
    results = checker.run_all()
    assert len(results) == 3
    for _name, ok, msg in results:
        assert ok is True
        assert msg
