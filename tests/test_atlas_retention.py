"""Tests for Atlas Phase 10 retention manager."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.atlas.retention import (
    DEFAULT_RETENTION_DAYS,
    AtlasRetentionManager,
)
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_retention.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_default_retention_days_constant_covers_expected_tables() -> None:
    for t in (
        "audit_events",
        "telemetry_events",
        "orion_events",
        "orion_actions",
        "atlas_health",
    ):
        assert t in DEFAULT_RETENTION_DAYS


def test_list_policies_empty_initially(db: Database) -> None:
    mgr = AtlasRetentionManager(db)
    assert mgr.list_policies() == []


def test_ensure_defaults_creates_policies(db: Database) -> None:
    mgr = AtlasRetentionManager(db)
    created = mgr.ensure_defaults()
    assert len(created) >= 1
    listed = mgr.list_policies()
    assert len(listed) >= 1


def test_ensure_defaults_is_idempotent(db: Database) -> None:
    mgr = AtlasRetentionManager(db)
    mgr.ensure_defaults()
    first_count = len(mgr.list_policies())
    mgr.ensure_defaults()
    second_count = len(mgr.list_policies())
    assert first_count == second_count


def test_apply_dry_run_returns_plan(db: Database) -> None:
    mgr = AtlasRetentionManager(db)
    mgr.ensure_defaults()
    plan = mgr.apply(dry_run=True)
    assert plan["dry_run"] is True
    assert "tables" in plan


def test_apply_dry_run_does_not_modify(db: Database) -> None:
    # Insert a stale row.
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1000)).isoformat()
    db.execute(
        "INSERT INTO audit_events (event_type, details, timestamp, actor_id, success) "
        "VALUES (?, ?, ?, ?, ?);",
        ("TEST", "{}", past, "GM-P-00000001", 1),
    )
    before = db.fetchone("SELECT COUNT(*) AS c FROM audit_events;")["c"]
    mgr = AtlasRetentionManager(db)
    mgr.ensure_defaults()
    plan = mgr.apply(dry_run=True)
    after = db.fetchone("SELECT COUNT(*) AS c FROM audit_events;")["c"]
    assert before == after
    assert plan["dry_run"] is True


def test_apply_real_deletes_stale_rows(db: Database) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1000)).isoformat()
    db.execute(
        "INSERT INTO audit_events (event_type, details, timestamp, actor_id, success) "
        "VALUES (?, ?, ?, ?, ?);",
        ("TEST", "{}", past, "GM-P-00000001", 1),
    )
    before = db.fetchone("SELECT COUNT(*) AS c FROM audit_events;")["c"]
    mgr = AtlasRetentionManager(db)
    mgr.ensure_defaults()
    plan = mgr.apply(dry_run=False)
    after = db.fetchone("SELECT COUNT(*) AS c FROM audit_events;")["c"]
    assert after < before
    assert plan["dry_run"] is False
