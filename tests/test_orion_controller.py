"""Tests for the Orion Phase 9 high-level coordinator.

Covers lifecycle, publish, submit, reconcile, and metrics.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.orion.actions import OrionActionType
from guardianmesh.orion.coordinator import OrionCoordinator
from guardianmesh.orion.errors import OrionError
from guardianmesh.orion.events import OrionEvent, OrionEventType
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "orion_coord.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def _ev(event_id: str = "OEV-00000001") -> OrionEvent:
    return OrionEvent(
        event_id=event_id,
        event_type=OrionEventType.DEVICE_CONNECTED,
        source="test",
        device_id="GM-C-19A84E72",
        created_at=datetime.datetime.now(datetime.UTC).isoformat(),
        correlation_id=f"OCR-{event_id}",
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_coordinator_constructs(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    assert coord is not None


def test_coordinator_rejects_non_database() -> None:
    with pytest.raises(OrionError):
        OrionCoordinator(db="not a db")  # type: ignore[arg-type]


def test_coordinator_exposes_subsystems(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    assert coord.bus is not None
    assert coord.queue is not None
    assert coord.executor is not None
    assert coord.scheduler is not None
    assert coord.capabilities is not None
    assert coord.registry is not None
    assert coord.reconciler is not None
    assert coord.consent_validator is not None


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_coordinator_lifecycle(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    assert coord.is_running() is False
    coord.start()
    assert coord.is_running() is True
    coord.stop()
    assert coord.is_running() is False


def test_coordinator_start_is_idempotent(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    coord.start()
    coord.start()  # should not raise
    coord.stop()


def test_coordinator_stop_without_start_is_silent(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    coord.stop()  # should not raise


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------


def test_publish_event(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    accepted = coord.publish(_ev("OEV-A"))
    assert accepted is True


def test_publish_dedup(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    coord.publish(_ev("OEV-DUP"))
    second = coord.publish(_ev("OEV-DUP"))
    # Duplicate is silently dropped.
    assert second is False


# ---------------------------------------------------------------------------
# submit
# ---------------------------------------------------------------------------


def test_submit_action(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    accepted = coord.submit(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
    )
    assert accepted is True


def test_submit_with_idempotency_key(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    first = coord.submit(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        idempotency_key="IDEMP-COORD",
    )
    second = coord.submit(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        idempotency_key="IDEMP-COORD",
    )
    assert first is True
    assert second is False


# ---------------------------------------------------------------------------
# reconcile
# ---------------------------------------------------------------------------


def test_reconcile_returns_report(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    report = coord.reconcile("GM-C-19A84E72")
    assert report.device_id == "GM-C-19A84E72"
    assert report.completed_at is not None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_aggregates_all(db: Database) -> None:
    coord = OrionCoordinator(db=db)
    m = coord.metrics()
    assert "scheduler" in m
    assert "capabilities" in m
    assert "registry" in m
    assert "running" in m
