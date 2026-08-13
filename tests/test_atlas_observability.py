"""Tests for Atlas Phase 10 observability."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_obs.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_collect_returns_subsystem_metrics(db: Database) -> None:
    obs = AtlasObservability(db)
    metrics = obs.collect()
    assert "genesis" in metrics
    assert "link" in metrics
    assert "pulse" in metrics
    assert "sentinel" in metrics
    assert "nexus" in metrics
    assert "vista" in metrics
    assert "aegis" in metrics
    assert "orion" in metrics
    assert "atlas" in metrics
    assert "generated_at" in metrics


def test_collect_includes_count_metrics(db: Database) -> None:
    obs = AtlasObservability(db)
    metrics = obs.collect()
    # Empty database — all counts are 0.
    assert metrics["genesis"]["identity_count"] == 0
    assert metrics["genesis"]["audit_event_count"] == 0


def test_collect_handles_missing_tables(db: Database) -> None:
    """A missing table is acceptable; the count is reported as 0."""
    # Drop one table.
    db.execute("DROP TABLE IF EXISTS audit_events;")
    obs = AtlasObservability(db)
    metrics = obs.collect()
    assert metrics["genesis"]["audit_event_count"] == 0


def test_collect_no_secrets_in_output(db: Database) -> None:
    obs = AtlasObservability(db)
    metrics = obs.collect()
    text = str(metrics).lower()
    for forbidden in ("password", "private_key", "secret", "token", "frame"):
        assert forbidden not in text
