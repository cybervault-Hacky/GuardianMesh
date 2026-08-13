"""Tests for the Orion Phase 9 persistent action queue.

Covers enqueue, idempotency, status transitions, expiration sweep,
bounded size, and metrics.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.orion.actions import (
    OrionAction,
    OrionActionStatus,
    OrionActionType,
)
from guardianmesh.orion.errors import OrionActionError, OrionQueueError
from guardianmesh.orion.queue import OrionActionQueue
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "orion_queue.db"


@pytest.fixture
def db(db_path: Path) -> Database:
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def _make_action(
    action_id: str = "OAC-00000001",
    *,
    device_id: str = "GM-C-19A84E72",
    action_type: OrionActionType = OrionActionType.REFRESH_HEALTH,
    status: OrionActionStatus = OrionActionStatus.PENDING,
    ttl_seconds: int = 300,
    idempotency_key: str | None = None,
    parameters: dict | None = None,
) -> OrionAction:
    now = datetime.datetime.now(datetime.UTC)
    return OrionAction(
        action_id=action_id,
        action_type=action_type,
        device_id=device_id,
        created_at=now.isoformat(),
        expires_at=(now + datetime.timedelta(seconds=ttl_seconds)).isoformat(),
        correlation_id="OCR-00000001",
        requested_by="GM-P-83A1F72C",
        status=status,
        parameters=parameters or {},
        idempotency_key=idempotency_key,
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_queue_rejects_zero_max_size() -> None:
    from guardianmesh.core.errors import ValidationError

    db_path = Path("/tmp/orion_zero.db")
    Database(db_path)  # ensure file exists
    try:
        with pytest.raises(ValidationError):
            OrionActionQueue(Database(db_path), max_size=0)
    finally:
        try:
            db_path.unlink()
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------


def test_enqueue_creates_action(db: Database) -> None:
    q = OrionActionQueue(db)
    action = _make_action()
    assert q.enqueue(action) is True
    assert q.get("OAC-00000001") is not None


def test_enqueue_rejects_non_action(db: Database) -> None:
    q = OrionActionQueue(db)
    with pytest.raises(OrionActionError):
        q.enqueue("not an action")  # type: ignore[arg-type]


def test_enqueue_idempotency_key_silently_ignored(db: Database) -> None:
    q = OrionActionQueue(db)
    a1 = _make_action(idempotency_key="IDEMP-X")
    a2 = _make_action(action_id="OAC-00000002", idempotency_key="IDEMP-X")
    assert q.enqueue(a1) is True
    # The second enqueue with the same idempotency_key returns False
    # without raising (idempotent by design).
    assert q.enqueue(a2) is False


def test_enqueue_at_capacity_raises(db: Database) -> None:
    q = OrionActionQueue(db, max_size=2)
    q.enqueue(_make_action("OAC-1"))
    q.enqueue(_make_action("OAC-2"))
    with pytest.raises(OrionQueueError):
        q.enqueue(_make_action("OAC-3"))


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def test_get_missing_returns_none(db: Database) -> None:
    q = OrionActionQueue(db)
    assert q.get("DOES-NOT-EXIST") is None


def test_list_by_status_filters(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action("OAC-1", status=OrionActionStatus.PENDING))
    q.enqueue(_make_action("OAC-2", status=OrionActionStatus.PENDING))
    q.enqueue(_make_action("OAC-3", status=OrionActionStatus.SUCCEEDED))
    pending = q.list_by_status(OrionActionStatus.PENDING)
    assert len(pending) == 2
    succeeded = q.list_by_status(OrionActionStatus.SUCCEEDED)
    assert len(succeeded) == 1


def test_list_by_status_with_string(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action("OAC-1"))
    pending = q.list_by_status("pending")
    assert len(pending) == 1


def test_list_by_status_with_device_filter(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action("OAC-1", device_id="GM-C-11111111"))
    q.enqueue(_make_action("OAC-2", device_id="GM-C-22222222"))
    q.enqueue(_make_action("OAC-3", device_id="GM-C-11111111"))
    out = q.list_by_status(None, device_id="GM-C-11111111")
    assert len(out) == 2


def test_list_by_status_respects_limit(db: Database) -> None:
    q = OrionActionQueue(db)
    for i in range(10):
        q.enqueue(_make_action(f"OAC-{i:08d}"))
    out = q.list_by_status(limit=3)
    assert len(out) == 3


def test_list_all(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action("OAC-1"))
    q.enqueue(_make_action("OAC-2"))
    assert len(q.list_all()) == 2


# ---------------------------------------------------------------------------
# Status transitions
# ---------------------------------------------------------------------------


def test_mark_running(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action())
    q.mark_running("OAC-00000001")
    assert q.get("OAC-00000001").status == OrionActionStatus.RUNNING


def test_mark_succeeded_records_result(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action())
    q.mark_succeeded("OAC-00000001", result={"key": "value"})
    a = q.get("OAC-00000001")
    assert a.status == OrionActionStatus.SUCCEEDED
    assert a.result == {"key": "value"}


def test_mark_failed_with_retry_keeps_pending(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action())
    q.mark_failed("OAC-00000001", "transient error", retry=True)
    a = q.get("OAC-00000001")
    assert a.status == OrionActionStatus.PENDING
    assert a.retry_count == 1
    assert a.last_error == "transient error"
    assert a.next_attempt_at is not None


def test_mark_failed_without_retry_marks_failed(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action())
    q.mark_failed("OAC-00000001", "fatal", retry=False)
    a = q.get("OAC-00000001")
    assert a.status == OrionActionStatus.FAILED
    assert a.last_error == "fatal"


def test_mark_failed_max_retries_exhausted(db: Database) -> None:
    q = OrionActionQueue(db)
    # Build action with retry_count=3, max_retries=3 (boundary)
    action = _make_action()
    action.retry_count = 3
    action.max_retries = 3
    q.enqueue(action)
    # can_retry is False, so should mark FAILED
    q.mark_failed("OAC-00000001", "exhausted", retry=True)
    a = q.get("OAC-00000001")
    assert a.status == OrionActionStatus.FAILED


def test_mark_expired(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action())
    q.mark_expired("OAC-00000001")
    assert q.get("OAC-00000001").status == OrionActionStatus.EXPIRED


def test_mark_cancelled(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action())
    q.mark_cancelled("OAC-00000001")
    assert q.get("OAC-00000001").status == OrionActionStatus.CANCELLED


def test_update_missing_action_is_silent(db: Database) -> None:
    q = OrionActionQueue(db)
    # Should not raise.
    q.mark_running("DOES-NOT-EXIST")
    q.mark_succeeded("DOES-NOT-EXIST")
    q.mark_failed("DOES-NOT-EXIST", "err")
    q.mark_expired("DOES-NOT-EXIST")
    q.mark_cancelled("DOES-NOT-EXIST")


# ---------------------------------------------------------------------------
# Expiration sweep
# ---------------------------------------------------------------------------


def test_sweep_expired_marks_past_due_actions(db: Database) -> None:
    q = OrionActionQueue(db)
    # An action with a past expiration_at.
    past_action = _make_action("OAC-PAST", ttl_seconds=-1)
    # Manually insert: __post_init__ rejects is_expired=True if the
    # time is in the past, but is_expired() is computed at call time,
    # not at construction. Let me check.
    q.enqueue(past_action)
    expired = q.sweep_expired()
    assert "OAC-PAST" in expired
    assert q.get("OAC-PAST").status == OrionActionStatus.EXPIRED


def test_sweep_expired_does_not_touch_future_actions(db: Database) -> None:
    q = OrionActionQueue(db)
    future_action = _make_action("OAC-FUT", ttl_seconds=3600)
    q.enqueue(future_action)
    expired = q.sweep_expired()
    assert "OAC-FUT" not in expired
    assert q.get("OAC-FUT").status == OrionActionStatus.PENDING


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_counts_by_status(db: Database) -> None:
    q = OrionActionQueue(db)
    q.enqueue(_make_action("OAC-1", status=OrionActionStatus.PENDING))
    q.enqueue(_make_action("OAC-2", status=OrionActionStatus.PENDING))
    q.enqueue(_make_action("OAC-3", status=OrionActionStatus.SUCCEEDED))
    m = q.metrics()
    assert m["total"] == 3
    assert m["by_status"]["PENDING"] == 2
    assert m["by_status"]["SUCCEEDED"] == 1
    assert m["max_size"] == 10_000
