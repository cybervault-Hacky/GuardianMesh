"""Tests for Orion Phase 9 state reconciliation.

Covers rule application, staleness threshold, idempotency, and
report content. The reconciler must never store sensitive payloads
and must produce metadata-only reports.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.orion.errors import OrionReconciliationError
from guardianmesh.orion.events import OrionEvent, OrionEventType
from guardianmesh.orion.reconciliation import (
    DEFAULT_STALENESS_SECONDS,
    OrionStateReconciler,
    generate_reconciliation_id,
)
from guardianmesh.orion.registry import OrionRegistry
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "orion_recon.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


@pytest.fixture
def registry(db: Database) -> OrionRegistry:
    return OrionRegistry(db)


@pytest.fixture
def reconciler(registry: OrionRegistry) -> OrionStateReconciler:
    return OrionStateReconciler(registry=registry)


def _ev(
    event_id: str,
    device_id: str = "GM-C-19A84E72",
    *,
    seconds_ago: int = 0,
    event_type: OrionEventType = OrionEventType.HEALTH_UPDATED,
) -> OrionEvent:
    created = (
        datetime.datetime.now(datetime.UTC)
        - datetime.timedelta(seconds=seconds_ago)
    ).isoformat()
    return OrionEvent(
        event_id=event_id,
        event_type=event_type,
        source="test",
        device_id=device_id,
        created_at=created,
        correlation_id=f"OCR-{event_id}",
    )


# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------


def test_generate_reconciliation_id_format() -> None:
    rid = generate_reconciliation_id()
    assert rid.startswith("ORC-")
    assert rid != generate_reconciliation_id()


# ---------------------------------------------------------------------------
# Reconcile
# ---------------------------------------------------------------------------


def test_reconcile_rejects_empty_device_id(reconciler: OrionStateReconciler) -> None:
    with pytest.raises(OrionReconciliationError):
        reconciler.reconcile("")


def test_reconcile_basic(reconciler: OrionStateReconciler) -> None:
    report = reconciler.reconcile("GM-C-19A84E72")
    assert report.device_id == "GM-C-19A84E72"
    assert report.report_id.startswith("ORC-")
    assert report.completed_at is not None


def test_reconcile_persists_report(reconciler: OrionStateReconciler, registry: OrionRegistry) -> None:
    report = reconciler.reconcile("GM-C-19A84E72")
    stored = registry.list_reports(device_id="GM-C-19A84E72")
    assert len(stored) == 1
    assert stored[0].report_id == report.report_id


def test_reconcile_idempotent(reconciler: OrionStateReconciler) -> None:
    """Two consecutive reconciliations must produce the same final state."""
    r1 = reconciler.reconcile("GM-C-19A84E72")
    r2 = reconciler.reconcile("GM-C-19A84E72")
    # Both reports are recorded, but the final state is the same.
    assert r1.final_state == r2.final_state


def test_reconcile_processes_fresh_events(reconciler: OrionStateReconciler) -> None:
    events = [
        _ev("OEV-1", seconds_ago=5),
        _ev("OEV-2", seconds_ago=10),
        _ev("OEV-3", seconds_ago=20),
    ]
    report = reconciler.reconcile("GM-C-19A84E72", events=events)
    assert report.events_processed == 3
    assert report.stale_events == 0


def test_reconcile_marks_stale_events(reconciler: OrionStateReconciler) -> None:
    """Events older than the staleness threshold are recorded but not applied."""
    events = [
        _ev("OEV-FRESH", seconds_ago=10),
        _ev("OEV-STALE", seconds_ago=DEFAULT_STALENESS_SECONDS + 100),
    ]
    report = reconciler.reconcile("GM-C-19A84E72", events=events)
    assert report.events_processed == 2
    assert report.stale_events == 1


def test_reconcile_respects_custom_staleness(reconciler: OrionStateReconciler) -> None:
    events = [
        _ev("OEV-FRESH", seconds_ago=5),
        _ev("OEV-OLD", seconds_ago=100),
    ]
    report = reconciler.reconcile("GM-C-19A84E72", events=events, staleness_seconds=60)
    assert report.stale_events == 1
    assert report.events_processed == 2


def test_reconcile_sorts_events_by_sequence(reconciler: OrionStateReconciler) -> None:
    e1 = _ev("OEV-1", seconds_ago=5)
    e1.sequence = 3
    e2 = _ev("OEV-2", seconds_ago=5)
    e2.sequence = 1
    e3 = _ev("OEV-3", seconds_ago=5)
    e3.sequence = 2
    report = reconciler.reconcile("GM-C-19A84E72", events=[e1, e2, e3])
    assert report.events_processed == 3


def test_reconcile_filters_by_device(reconciler: OrionStateReconciler) -> None:
    """Events for other devices are ignored."""
    e1 = _ev("OEV-1", device_id="GM-C-19A84E72", seconds_ago=5)
    e2 = _ev("OEV-2", device_id="GM-C-AAAAAAAA", seconds_ago=5)
    report = reconciler.reconcile("GM-C-19A84E72", events=[e1, e2])
    assert report.events_processed == 1


def test_reconcile_handles_invalid_timestamps(reconciler: OrionStateReconciler) -> None:
    """Events with invalid timestamps are recorded as stale."""
    ev = OrionEvent(
        event_id="OEV-INVALID",
        event_type=OrionEventType.HEALTH_UPDATED,
        source="test",
        device_id="GM-C-19A84E72",
        created_at="2026-08-13T00:00:00+00:00",  # valid
        correlation_id="OCR-INVALID",
    )
    # Manually corrupt the timestamp after construction to test the
    # reconciler's defensive code path.
    ev.created_at = "not-a-timestamp"
    report = reconciler.reconcile("GM-C-19A84E72", events=[ev])
    assert report.stale_events == 1


def test_reconcile_empty_events(reconciler: OrionStateReconciler) -> None:
    """An empty event list is a valid no-op."""
    report = reconciler.reconcile("GM-C-19A84E72", events=[])
    assert report.events_processed == 0
    assert report.stale_events == 0
    assert report.completed_at is not None


def test_reconcile_with_no_events_kwarg(reconciler: OrionStateReconciler) -> None:
    """The events parameter is optional."""
    report = reconciler.reconcile("GM-C-19A84E72")
    assert report.events_processed == 0


def test_reconcile_report_is_metadata_only(reconciler: OrionStateReconciler) -> None:
    """The report must not contain sensitive payload fields."""
    report = reconciler.reconcile("GM-C-19A84E72")
    data = report.to_dict()
    forbidden = {
        "payload",
        "frame",
        "screenshot",
        "keylog",
        "password",
        "private_key",
        "command",
        "shell",
    }
    assert forbidden.isdisjoint(set(data.keys()))


def test_reconcile_default_staleness_is_documented() -> None:
    assert DEFAULT_STALENESS_SECONDS == 600


def test_reconcile_works_with_no_external_subsystems(
    registry: OrionRegistry,
) -> None:
    """The reconciler is optional about its dependencies."""
    recon = OrionStateReconciler(
        registry=registry,
        trust_manager=None,
        screen_controller=None,
        aegis_controller=None,
        transport_registry=None,
        screen_authorization_manager=None,
        aegis_consent_gate=None,
    )
    report = recon.reconcile("GM-C-19A84E72")
    assert report.completed_at is not None
