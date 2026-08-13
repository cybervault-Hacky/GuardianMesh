"""Orion Phase 9 scheduler.

The :class:`OrionScheduler` is a thin wrapper that ties together
the event bus, the action queue, and the executor. It runs the
event bus (in async mode) and the action executor as background
threads and exposes a single start/stop API.

The scheduler is intentionally small. Its job is to:

1. start and stop the bus and the executor together,
2. publish a :class:`OrionEvent` to the bus,
3. enqueue an :class:`OrionAction` to the queue,
4. surface metrics for the console.

The scheduler does not invent new logic; it composes existing
components.
"""

from __future__ import annotations

import datetime
import threading
from typing import Any

from guardianmesh.orion.actions import OrionAction, OrionActionType, required_consents
from guardianmesh.orion.bus import OrionEventBus
from guardianmesh.orion.errors import OrionSchedulerError
from guardianmesh.orion.events import OrionEvent
from guardianmesh.orion.executor import OrionExecutor
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.orion.queue import OrionActionQueue


class OrionScheduler:
    """Composes the bus, queue, executor, and handlers into a single
    background coordinator.
    """

    def __init__(
        self,
        bus: OrionEventBus,
        queue: OrionActionQueue,
        executor: OrionExecutor,
        handlers: OrionActionHandlers,
    ) -> None:
        self._bus = bus
        self._queue = queue
        self._executor = executor
        self._handlers = handlers
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            self._bus.start()
            self._executor.start()

    def stop(self, drain: bool = False) -> None:
        with self._lock:
            try:
                self._executor.stop(drain=drain)
            except Exception:
                pass
            try:
                self._bus.stop(drain=drain)
            except Exception:
                pass

    def is_running(self) -> bool:
        return self._executor.is_running() or (
            # The bus's worker is not exposed directly, so we check
            # the metrics instead.
            self._bus.metrics().get("worker_alive", False)
        )

    # ------------------------------------------------------------------
    # Publish / enqueue
    # ------------------------------------------------------------------

    def publish_event(self, event: OrionEvent) -> bool:
        """Publish an event to the bus."""
        if not isinstance(event, OrionEvent):
            raise OrionSchedulerError("event must be an OrionEvent.")
        return self._bus.publish(event)

    def enqueue_action(self, action: OrionAction) -> bool:
        """Persist an action to the queue."""
        if not isinstance(action, OrionAction):
            raise OrionSchedulerError("action must be an OrionAction.")
        return self._queue.enqueue(action)

    # ------------------------------------------------------------------
    # Convenience: build and enqueue an action from a request
    # ------------------------------------------------------------------

    def build_action(
        self,
        action_type: OrionActionType | str,
        device_id: str,
        requested_by: str,
        correlation_id: str | None = None,
        parameters: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        ttl_seconds: int = 300,
    ) -> OrionAction:
        """Build a safe, well-formed action.

        The action's consent requirements are derived from the
        documented map. The action's expiration is set to
        ``now + ttl_seconds``.
        """
        from guardianmesh.orion.actions import (
            OrionActionStatus,
        )
        from guardianmesh.orion.actions import (
            generate_action_id as _aid,
        )
        from guardianmesh.orion.events import generate_correlation_id

        if isinstance(action_type, str):
            action_type = OrionActionType.from_str(action_type)
        if not isinstance(action_type, OrionActionType):
            raise OrionSchedulerError("action_type must be an OrionActionType.")
        # Cross-check that the action has known consent requirements.
        # The map is exhaustive; any unknown action would raise
        # KeyError here, which is a developer error.
        _ = required_consents(action_type)

        now = datetime.datetime.now(datetime.UTC)
        expires = now + datetime.timedelta(seconds=ttl_seconds)
        # We reuse the events generator for correlation_id to avoid
        # duplicating the format. If the caller passes a correlation_id,
        # we use it as-is.
        if correlation_id is None:
            correlation_id = generate_correlation_id()
        return OrionAction(
            action_id=_aid(),
            action_type=action_type,
            device_id=device_id,
            created_at=now.isoformat(),
            expires_at=expires.isoformat(),
            correlation_id=correlation_id,
            requested_by=requested_by,
            status=OrionActionStatus.PENDING,
            parameters=parameters or {},
            idempotency_key=idempotency_key,
        )

    def submit(
        self,
        action_type: OrionActionType | str,
        device_id: str,
        requested_by: str,
        correlation_id: str | None = None,
        parameters: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        ttl_seconds: int = 300,
    ) -> bool:
        """Build and enqueue an action in one call."""
        action = self.build_action(
            action_type=action_type,
            device_id=device_id,
            requested_by=requested_by,
            correlation_id=correlation_id,
            parameters=parameters,
            idempotency_key=idempotency_key,
            ttl_seconds=ttl_seconds,
        )
        return self.enqueue_action(action)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.is_running(),
                "bus": self._bus.metrics(),
                "queue": self._queue.metrics(),
                "executor": self._executor.metrics(),
            }


__all__ = ["OrionScheduler"]
