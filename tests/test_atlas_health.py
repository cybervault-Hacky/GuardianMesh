"""Tests for Atlas Phase 10 health monitoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.health import SUBSYSTEM_TABLES, AtlasHealthMonitor
from guardianmesh.atlas.models import AtlasSubsystem
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_health.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_subsystem_tables_constant_covers_every_subsystem() -> None:
    for sub in AtlasSubsystem:
        assert sub in SUBSYSTEM_TABLES
        assert len(SUBSYSTEM_TABLES[sub]) > 0


def test_check_all_returns_every_subsystem(db: Database) -> None:
    monitor = AtlasHealthMonitor(db)
    snapshot = monitor.check_all()
    for sub in AtlasSubsystem:
        assert sub.value in snapshot
        assert "status" in snapshot[sub.value]


def test_check_all_healthy_after_migration(db: Database) -> None:
    monitor = AtlasHealthMonitor(db)
    snapshot = monitor.check_all()
    for sub, info in snapshot.items():
        assert info["status"] == "OK", f"{sub} not OK: {info}"


def test_record_health_persists_snapshot(db: Database) -> None:
    monitor = AtlasHealthMonitor(db)
    result = monitor.record_health()
    assert result["written"] == len(list(AtlasSubsystem))
    rows = db.fetchall("SELECT COUNT(*) AS c FROM atlas_health;")
    assert int(rows[0]["c"]) > 0


def test_latest_health_returns_records(db: Database) -> None:
    monitor = AtlasHealthMonitor(db)
    monitor.record_health()
    rows = monitor.latest_health(limit=10)
    assert len(rows) >= 1
