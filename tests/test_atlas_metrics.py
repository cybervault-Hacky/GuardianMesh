"""Tests for Atlas Phase 10 metrics aggregator."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.metrics import AtlasMetrics
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_metrics.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_metrics_collect_returns_summary(db: Database) -> None:
    m = AtlasMetrics(db)
    result = m.collect()
    assert "health" in result
    assert "observability" in result
    assert "summary" in result
    assert "failed_subsystems" in result["summary"]
    assert "degraded_subsystems" in result["summary"]
    assert "total_subsystems" in result["summary"]


def test_metrics_collect_no_failures_on_clean_db(db: Database) -> None:
    m = AtlasMetrics(db)
    result = m.collect()
    assert result["summary"]["failed_subsystems"] == []
    assert result["summary"]["total_subsystems"] == 10
