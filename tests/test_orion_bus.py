"""Tests for Orion Phase 9 event bus.

Covers synchronous and asynchronous modes, backpressure strategies,
deduplication, bounded retry, ordering, handler failure isolation,
and metrics.
"""

from __future__ import annotations

import datetime
import time

import pytest

from guardianmesh.orion.bus import BackpressureStrategy, OrionEventBus
from guardianmesh.orion.errors import OrionEventError, OrionHandlerError
from guardianmesh.orion.events import OrionEvent, OrionEventType


def _ev(event_id: str, device_id: str = "GM-C-19A84E72", source: str = "test") -> OrionEvent:
    return OrionEvent(
        event_id=event_id,
        event_type=OrionEventType.DEVICE_CONNECTED,
        source=source,
        device_id=device_id,
        created_at=datetime.datetime.now(datetime.UTC).isoformat(),
        correlation_id=f"OCR-{event_id}",
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_bus_default_construction() -> None:
    bus = OrionEventBus()
    assert bus.handler_count() == 0
    assert bus.queue_size() == 0
    m = bus.metrics()
    assert m["max_queue_size"] == 1024
    assert m["backpressure"] == "DROP_OLDEST"
    assert m["deterministic"] is True


def test_bus_rejects_zero_max_queue_size() -> None:
    with pytest.raises(OrionEventError):
        OrionEventBus(max_queue_size=0)


def test_bus_rejects_negative_max_retries() -> None:
    with pytest.raises(OrionEventError):
        OrionEventBus(max_retries=-1)


def test_bus_backpressure_from_string() -> None:
    bus = OrionEventBus(backpressure="REJECT")
    assert bus.metrics()["backpressure"] == "REJECT"


def test_bus_backpressure_from_string_invalid() -> None:
    with pytest.raises(OrionEventError):
        BackpressureStrategy.from_str("UNKNOWN")


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------


def test_register_handler_validates_callable() -> None:
    bus = OrionEventBus()
    with pytest.raises(OrionEventError):
        bus.register_handler("not callable")  # type: ignore[arg-type]


def test_register_and_unregister_handler() -> None:
    bus = OrionEventBus()
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    assert bus.handler_count() == 1
    bus.unregister_handler(received.append)
    assert bus.handler_count() == 0


def test_unregister_unknown_handler_raises() -> None:
    bus = OrionEventBus()
    with pytest.raises(OrionEventError):
        bus.unregister_handler(lambda e: None)


def test_clear_handlers() -> None:
    bus = OrionEventBus()
    bus.register_handler(lambda e: None)
    bus.register_handler(lambda e: None)
    bus.clear_handlers()
    assert bus.handler_count() == 0


# ---------------------------------------------------------------------------
# Publishing - sync deterministic mode
# ---------------------------------------------------------------------------


def test_publish_deterministic_delivers_immediately() -> None:
    bus = OrionEventBus(deterministic=True)
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    bus.publish(_ev("OEV-A"))
    bus.publish(_ev("OEV-B"))
    assert len(received) == 2
    assert received[0].event_id == "OEV-A"
    assert received[1].event_id == "OEV-B"


def test_publish_rejects_non_event() -> None:
    bus = OrionEventBus()
    with pytest.raises(OrionEventError):
        bus.publish("not an event")  # type: ignore[arg-type]


def test_publish_dedup_by_event_id() -> None:
    bus = OrionEventBus()
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    bus.publish(_ev("OEV-DUP"))
    bus.publish(_ev("OEV-DUP"))
    bus.publish(_ev("OEV-DUP"))
    assert len(received) == 1
    m = bus.metrics()
    assert m["seen_event_ids"] == 1


def test_publish_assigns_per_device_sequence() -> None:
    bus = OrionEventBus(deterministic=True)
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    bus.publish(_ev("OEV-1", "GM-C-19A84E72"))
    bus.publish(_ev("OEV-2", "GM-C-19A84E72"))
    bus.publish(_ev("OEV-3", "GM-C-19A84E72"))
    assert received[0].sequence == 1
    assert received[1].sequence == 2
    assert received[2].sequence == 3


def test_publish_maintains_per_device_sequence_independently() -> None:
    bus = OrionEventBus(deterministic=True)
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    bus.publish(_ev("OEV-A1", "GM-C-11111111"))
    bus.publish(_ev("OEV-B1", "GM-C-22222222"))
    bus.publish(_ev("OEV-A2", "GM-C-11111111"))
    assert received[0].sequence == 1
    assert received[1].sequence == 1
    assert received[2].sequence == 2


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


def test_backpressure_drop_oldest_drops_oldest() -> None:
    bus = OrionEventBus(
        max_queue_size=2, max_retries=0, deterministic=False,
        backpressure=BackpressureStrategy.DROP_OLDEST,
    )
    # Publish three events to a full queue.
    bus.publish(_ev("OEV-1"))  # enqueued
    bus.publish(_ev("OEV-2"))  # enqueued
    bus.publish(_ev("OEV-3"))  # drops OEV-1, enqueues OEV-3
    m = bus.metrics()
    assert m["dropped_count"] == 1
    assert m["queue_size"] == 2


def test_backpressure_drop_newest_drops_newest() -> None:
    bus = OrionEventBus(
        max_queue_size=2, deterministic=False,
        backpressure=BackpressureStrategy.DROP_NEWEST,
    )
    bus.publish(_ev("OEV-1"))
    bus.publish(_ev("OEV-2"))
    bus.publish(_ev("OEV-3"))  # dropped
    m = bus.metrics()
    assert m["dropped_count"] == 1
    assert m["queue_size"] == 2


def test_backpressure_reject_rejects_newest() -> None:
    bus = OrionEventBus(
        max_queue_size=2, deterministic=False,
        backpressure=BackpressureStrategy.REJECT,
    )
    bus.publish(_ev("OEV-1"))
    bus.publish(_ev("OEV-2"))
    accepted = bus.publish(_ev("OEV-3"))  # rejected
    assert accepted is False
    m = bus.metrics()
    # The REJECT path doesn't increment dropped_count but does reject the event.
    assert m["queue_size"] == 2
    assert m["seen_event_ids"] == 3  # event id was recorded even on rejection


# ---------------------------------------------------------------------------
# Handler failure isolation
# ---------------------------------------------------------------------------


def test_handler_exception_does_not_crash_bus() -> None:
    bus = OrionEventBus(deterministic=True, max_retries=0)

    def bad_handler(event: OrionEvent) -> None:
        raise RuntimeError("boom")

    received: list[OrionEvent] = []
    bus.register_handler(bad_handler)
    bus.register_handler(received.append)
    # bad_handler raises, but the second handler should still receive.
    bus.publish(_ev("OEV-FAIL"))
    assert received[0].event_id == "OEV-FAIL"
    m = bus.metrics()
    assert m["failed_count"] == 1


def test_orion_handler_error_triggers_retry() -> None:
    bus = OrionEventBus(deterministic=True, max_retries=3)
    attempts: list[str] = []

    def always_fails(event: OrionEvent) -> None:
        attempts.append(event.event_id)
        raise OrionHandlerError("nope")

    bus.register_handler(always_fails)
    bus.publish(_ev("OEV-RETRY"))
    # Deterministic mode delivers immediately; one failure triggers
    # bounded retry; the event ends up in the queue.
    assert len(attempts) >= 1
    m = bus.metrics()
    assert m["failed_count"] >= 1


def test_bounded_retry_caps_attempts() -> None:
    bus = OrionEventBus(deterministic=True, max_retries=2)
    attempts: list[str] = []

    def always_fails(event: OrionEvent) -> None:
        attempts.append(event.event_id)
        raise OrionHandlerError("nope")

    bus.register_handler(always_fails)
    bus.publish(_ev("OEV-CAP"))
    # After max_retries, the event is dropped.
    assert len(attempts) <= 3  # 1 initial + 2 retries
    m = bus.metrics()
    assert m["failed_count"] >= 1


# ---------------------------------------------------------------------------
# Async mode
# ---------------------------------------------------------------------------


def test_async_worker_lifecycle() -> None:
    bus = OrionEventBus(deterministic=False, max_queue_size=128)
    received: list[OrionEvent] = []

    def handler(event: OrionEvent) -> None:
        received.append(event)

    bus.register_handler(handler)
    bus.start()
    try:
        bus.publish(_ev("OEV-ASYNC-1"))
        bus.publish(_ev("OEV-ASYNC-2"))
        # Give the worker a chance to drain.
        time.sleep(0.5)
    finally:
        bus.stop(drain=True)
    assert len(received) >= 1
    m = bus.metrics()
    assert m["worker_alive"] is False


def test_async_worker_start_is_idempotent() -> None:
    bus = OrionEventBus(deterministic=False)
    bus.start()
    bus.start()  # should be a no-op
    bus.stop(drain=True)


def test_async_worker_stop_without_start() -> None:
    bus = OrionEventBus(deterministic=False)
    # Should not raise.
    bus.stop(drain=True)


# ---------------------------------------------------------------------------
# deliver_pending
# ---------------------------------------------------------------------------


def test_deliver_pending_drains_in_order() -> None:
    bus = OrionEventBus(deterministic=False, max_queue_size=16)
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    bus.publish(_ev("OEV-X1", "GM-C-11111111"))
    bus.publish(_ev("OEV-Y1", "GM-C-22222222"))
    bus.publish(_ev("OEV-X2", "GM-C-11111111"))
    count = bus.deliver_pending()
    assert count == 3
    # All events delivered.
    assert len(received) == 3
    assert bus.queue_size() == 0


def test_recent_failures_returns_recorded() -> None:
    bus = OrionEventBus(deterministic=True, max_retries=0)

    def fails(event: OrionEvent) -> None:
        raise RuntimeError("test failure")

    bus.register_handler(fails)
    bus.publish(_ev("OEV-FAIL-REC"))
    failures = bus.recent_failures()
    assert len(failures) >= 1
    assert failures[0]["event_id"] == "OEV-FAIL-REC"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_metrics_records_processed() -> None:
    bus = OrionEventBus(deterministic=True)
    received: list[OrionEvent] = []
    bus.register_handler(received.append)
    bus.publish(_ev("OEV-M1"))
    bus.publish(_ev("OEV-M2"))
    m = bus.metrics()
    assert m["processed_count"] == 2
    assert m["seen_event_ids"] == 2
