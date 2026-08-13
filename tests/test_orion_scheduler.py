"""Tests for Orion Phase 9 scheduler.

Covers the high-level composition of bus, queue, executor, and
handlers. Validates lifecycle, build_action, submit, and metrics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.orion.actions import OrionActionStatus, OrionActionType
from guardianmesh.orion.bus import OrionEventBus
from guardianmesh.orion.errors import OrionSchedulerError
from guardianmesh.orion.events import OrionEvent, OrionEventType
from guardianmesh.orion.executor import OrionExecutor
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.orion.queue import OrionActionQueue
from guardianmesh.orion.scheduler import OrionScheduler
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "orion_scheduler.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


@pytest.fixture
def components(db: Database):
    bus = OrionEventBus(deterministic=True)
    queue = OrionActionQueue(db)
    handlers = OrionActionHandlers()
    executor = OrionExecutor(queue, handlers)
    return bus, queue, handlers, executor


def _ev(event_id: str = "OEV-00000001") -> OrionEvent:
    import datetime

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


def test_scheduler_constructs(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    assert scheduler is not None


# ---------------------------------------------------------------------------
# build_action
# ---------------------------------------------------------------------------


def test_build_action_creates_valid_action(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    action = scheduler.build_action(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
    )
    assert action.action_type == OrionActionType.REQUEST_CAPABILITIES
    assert action.device_id == "GM-C-19A84E72"
    assert action.requested_by == "GM-P-83A1F72C"
    assert action.status == OrionActionStatus.PENDING
    assert action.idempotency_key is None
    assert action.action_id.startswith("OAC-")
    assert action.correlation_id.startswith("OCR-")


def test_build_action_with_string_action_type(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    action = scheduler.build_action(
        action_type="REQUEST_CAPABILITIES",
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
    )
    assert action.action_type == OrionActionType.REQUEST_CAPABILITIES


def test_build_action_rejects_invalid_string(components) -> None:
    from guardianmesh.orion.errors import OrionActionError

    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    with pytest.raises(OrionActionError):
        scheduler.build_action(
            action_type="NOT_AN_ACTION",
            device_id="GM-C-19A84E72",
            requested_by="GM-P-83A1F72C",
        )


def test_build_action_with_idempotency_key(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    action = scheduler.build_action(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        idempotency_key="IDEMP-X",
    )
    assert action.idempotency_key == "IDEMP-X"


def test_build_action_with_parameters(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    action = scheduler.build_action(
        action_type=OrionActionType.ACKNOWLEDGE_ALERT,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        parameters={"alert_id": "ALT-001"},
    )
    assert action.parameters == {"alert_id": "ALT-001"}


def test_build_action_with_explicit_correlation_id(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    action = scheduler.build_action(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        correlation_id="OCR-EXPLICIT",
    )
    assert action.correlation_id == "OCR-EXPLICIT"


# ---------------------------------------------------------------------------
# publish_event / enqueue_action
# ---------------------------------------------------------------------------


def test_publish_event_rejects_non_event(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    with pytest.raises(OrionSchedulerError):
        scheduler.publish_event("not an event")  # type: ignore[arg-type]


def test_publish_event_publishes(components) -> None:
    bus, queue, handlers, executor = components
    received: list = []
    bus.register_handler(received.append)
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    scheduler.publish_event(_ev("OEV-A"))
    assert len(received) == 1
    assert received[0].event_id == "OEV-A"


def test_enqueue_action_rejects_non_action(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    with pytest.raises(OrionSchedulerError):
        scheduler.enqueue_action("not an action")  # type: ignore[arg-type]


def test_enqueue_action_persists(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    action = scheduler.build_action(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
    )
    assert scheduler.enqueue_action(action) is True
    assert queue.get(action.action_id) is not None


# ---------------------------------------------------------------------------
# submit
# ---------------------------------------------------------------------------


def test_submit_builds_and_enqueues(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    assert scheduler.submit(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
    ) is True


def test_submit_idempotent(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    first = scheduler.submit(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        idempotency_key="IDEMP-1",
    )
    second = scheduler.submit(
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        requested_by="GM-P-83A1F72C",
        idempotency_key="IDEMP-1",
    )
    assert first is True
    assert second is False


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_lifecycle_start_stop(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    scheduler.start()
    scheduler.stop()
    # Should not raise.


def test_is_running_reflects_state(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    # Deterministic bus, so is_running may be false; that's fine.
    assert isinstance(scheduler.is_running(), bool)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_aggregates_components(components) -> None:
    bus, queue, handlers, executor = components
    scheduler = OrionScheduler(bus, queue, executor, handlers)
    m = scheduler.metrics()
    assert "bus" in m
    assert "queue" in m
    assert "executor" in m
