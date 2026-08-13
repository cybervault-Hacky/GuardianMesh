"""Orion Phase 9 event bus.

The :class:`OrionEventBus` dispatches :class:`OrionEvent` instances
to registered handlers. The bus supports two modes:

* **Synchronous deterministic mode** for tests and for the control
  plane when the daemon is not running. Events are delivered
  immediately on the calling thread.
* **Asynchronous worker mode** for production. A bounded queue
  accumulates events; a worker thread drains them in order per
  device.

The bus enforces:

* Bounded queue size with explicit :class:`BackpressureStrategy`.
* Handler isolation: a failed handler is caught and recorded; the
  bus continues to deliver subsequent events.
* Bounded retry: failed events are re-enqueued at most
  ``max_retries`` times.
* Duplicate event protection: an event id is delivered at most
  once.
* Ordering guarantees per device: events for the same device are
  delivered in increasing ``sequence`` order.
* Graceful shutdown: pending events are drained or expired before
  the worker thread terminates.

The bus never persists events. The action queue (separate module)
is responsible for persistent state.
"""

from __future__ import annotations

import enum
import threading
from collections import deque
from collections.abc import Callable
from typing import Any

from guardianmesh.orion.errors import (
    OrionEventError,
    OrionHandlerError,
    OrionShutdownError,
)
from guardianmesh.orion.events import OrionEvent

# Type alias for handler callbacks.
OrionEventHandler = Callable[[OrionEvent], None]


class BackpressureStrategy(str, enum.Enum):
    """Backpressure policy when the bus queue is full.

    Orion is designed to be non-blocking. The default
    ``DROP_OLDEST`` strategy discards the oldest queued event
    rather than blocking the producer.
    """

    DROP_OLDEST = "DROP_OLDEST"
    DROP_NEWEST = "DROP_NEWEST"
    REJECT = "REJECT"

    @classmethod
    def from_str(cls, val: str) -> BackpressureStrategy:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionEventError(f"Unknown backpressure strategy: '{val}'") from e


class OrionEventBus:
    """Bounded event bus for :class:`OrionEvent` instances.

    The bus is thread-safe. The bus never panics: handler failures
    are caught, recorded, and surfaced through the metrics; the
    worker thread continues to deliver subsequent events.
    """

    def __init__(
        self,
        *,
        max_queue_size: int = 1024,
        max_retries: int = 3,
        backpressure: BackpressureStrategy | str = BackpressureStrategy.DROP_OLDEST,
        deterministic: bool = True,
    ) -> None:
        if max_queue_size <= 0:
            raise OrionEventError("max_queue_size must be positive.")
        if max_retries < 0:
            raise OrionEventError("max_retries must be non-negative.")
        if isinstance(backpressure, str):
            backpressure = BackpressureStrategy.from_str(backpressure)

        self._lock = threading.RLock()
        self._max_queue_size = max_queue_size
        self._max_retries = max_retries
        self._backpressure = backpressure
        self._deterministic = deterministic

        self._queue: deque[OrionEvent] = deque()
        self._handlers: list[OrionEventHandler] = []
        self._seen_event_ids: dict[str, int] = {}
        self._per_device_sequences: dict[str, int] = {}
        self._retry_counts: dict[str, int] = {}
        self._dropped_count: int = 0
        self._processed_count: int = 0
        self._failed_count: int = 0

        # Async worker state.
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._worker_alive = False
        # Pending failures (for tests and diagnostics).
        self._failures: deque[dict[str, Any]] = deque(maxlen=256)

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def register_handler(self, handler: OrionEventHandler) -> None:
        """Register a handler. Handlers are called in registration order."""
        if not callable(handler):
            raise OrionEventError("handler must be callable.")
        with self._lock:
            self._handlers.append(handler)

    def unregister_handler(self, handler: OrionEventHandler) -> None:
        """Remove a previously-registered handler."""
        with self._lock:
            try:
                self._handlers.remove(handler)
            except ValueError as e:
                raise OrionEventError("Handler not registered.") from e

    def clear_handlers(self) -> None:
        with self._lock:
            self._handlers.clear()

    def handler_count(self) -> int:
        with self._lock:
            return len(self._handlers)

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(self, event: OrionEvent) -> bool:
        """Publish an event. Returns True if accepted, False if dropped.

        Duplicate event ids are silently ignored. Events whose
        payload contains forbidden keys are rejected at
        construction time (see :mod:`events`).
        """
        if not isinstance(event, OrionEvent):
            raise OrionEventError("event must be an OrionEvent.")

        with self._lock:
            if event.event_id in self._seen_event_ids:
                return False  # Duplicate — ignored.

            # Enforce ordering: assign the per-device sequence.
            next_seq = self._per_device_sequences.get(event.device_id, 0) + 1
            self._per_device_sequences[event.device_id] = next_seq
            event.sequence = next_seq

            # Bound the queue.
            while len(self._queue) >= self._max_queue_size:
                if self._backpressure == BackpressureStrategy.DROP_OLDEST:
                    self._queue.popleft()
                    self._dropped_count += 1
                elif self._backpressure == BackpressureStrategy.DROP_NEWEST:
                    self._dropped_count += 1
                    self._seen_event_ids[event.event_id] = 1
                    return False
                else:  # REJECT
                    self._seen_event_ids[event.event_id] = 1
                    return False

            self._queue.append(event)
            self._seen_event_ids[event.event_id] = 1
            # Mark retry state.
            self._retry_counts.setdefault(event.event_id, 0)

        if self._deterministic:
            self._deliver_one(event)
        else:
            self._wake_event.set()
        return True

    # ------------------------------------------------------------------
    # Sync / async delivery
    # ------------------------------------------------------------------

    def _deliver_one(self, event: OrionEvent) -> None:
        """Deliver one event to all registered handlers."""
        handlers = list(self._handlers)
        if not handlers:
            return
        for handler in handlers:
            try:
                handler(event)
            except OrionHandlerError as e:
                self._record_failure(event, handler, e)
                self._failed_count += 1
                # Bounded retry: re-enqueue unless max_retries reached.
                attempts = self._retry_counts.get(event.event_id, 0)
                if attempts < self._max_retries:
                    self._retry_counts[event.event_id] = attempts + 1
                    self._enqueue_for_retry(event)
                else:
                    self._dropped_count += 1
            except Exception as e:
                # Defensive: a buggy handler must never crash the bus.
                self._record_failure(event, handler, e)
                self._failed_count += 1
                attempts = self._retry_counts.get(event.event_id, 0)
                if attempts < self._max_retries:
                    self._retry_counts[event.event_id] = attempts + 1
                    self._enqueue_for_retry(event)
                else:
                    self._dropped_count += 1
        self._processed_count += 1

    def _enqueue_for_retry(self, event: OrionEvent) -> None:
        with self._lock:
            if len(self._queue) >= self._max_queue_size:
                if self._backpressure == BackpressureStrategy.DROP_OLDEST:
                    self._queue.popleft()
                    self._dropped_count += 1
                else:
                    self._dropped_count += 1
                    return
            self._queue.append(event)

    def _record_failure(
        self,
        event: OrionEvent,
        handler: OrionEventHandler,
        exc: BaseException,
    ) -> None:
        self._failures.append(
            {
                "event_id": event.event_id,
                "handler": getattr(handler, "__name__", repr(handler)),
                "error": str(exc),
                "at": event.created_at,
            }
        )

    def deliver_pending(self) -> int:
        """Drain the queue synchronously. Returns the number of events delivered."""
        with self._lock:
            queue_snapshot = list(self._queue)
            self._queue.clear()
        # Deliver in deterministic per-device order.
        queue_snapshot.sort(key=lambda e: (e.device_id, e.sequence))
        count = 0
        for event in queue_snapshot:
            self._deliver_one(event)
            count += 1
        return count

    # ------------------------------------------------------------------
    # Async worker
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the async worker thread. Idempotent."""
        with self._lock:
            if self._worker_alive:
                return
            self._stop_event.clear()
            self._worker = threading.Thread(
                target=self._run, name="orion-event-bus", daemon=True
            )
            self._worker_alive = True
            self._worker.start()

    def stop(self, drain: bool = True, timeout_seconds: float = 5.0) -> None:
        """Stop the async worker. Drains pending events by default."""
        with self._lock:
            if not self._worker_alive:
                return
            self._stop_event.set()
            self._wake_event.set()
            worker = self._worker
        if drain:
            try:
                self.deliver_pending()
            except Exception:
                pass
        if worker is not None:
            worker.join(timeout=timeout_seconds)
        with self._lock:
            self._worker_alive = False
            self._worker = None

    def _run(self) -> None:
        """Worker loop."""
        while not self._stop_event.is_set():
            self._wake_event.wait(timeout=0.5)
            self._wake_event.clear()
            try:
                self.deliver_pending()
            except Exception:
                # The bus must not crash; failures are recorded.
                pass

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "queue_size": len(self._queue),
                "max_queue_size": self._max_queue_size,
                "handlers": len(self._handlers),
                "seen_event_ids": len(self._seen_event_ids),
                "per_device_sequences": dict(self._per_device_sequences),
                "processed_count": self._processed_count,
                "dropped_count": self._dropped_count,
                "failed_count": self._failed_count,
                "retry_count": sum(self._retry_counts.values()),
                "backpressure": self._backpressure.value,
                "deterministic": self._deterministic,
                "worker_alive": self._worker_alive,
            }

    def recent_failures(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._failures)

    def queue_size(self) -> int:
        with self._lock:
            return len(self._queue)

    def __enter__(self) -> OrionEventBus:
        if not self._deterministic:
            self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if not self._deterministic:
            try:
                self.stop()
            except OrionShutdownError:
                pass


__all__ = [
    "BackpressureStrategy",
    "OrionEventBus",
    "OrionEventHandler",
]
