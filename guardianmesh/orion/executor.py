"""Orion Phase 9 action executor.

The :class:`OrionExecutor` dispatches actions to the
:class:`OrionActionHandlers` registry and updates the persistent
queue with the resulting status. The executor is intentionally thin:
the heavy lifting is done by the handlers; the executor only:

1. pulls the next runnable action from the queue,
2. dispatches it to the handler,
3. records the outcome (SUCCEEDED, FAILED, EXPIRED, CANCELLED),
4. applies bounded retry on transient failures,
5. stops the queue on graceful shutdown.
"""

from __future__ import annotations

import threading
from typing import Any

from guardianmesh.orion.errors import OrionActionError
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.orion.queue import OrionActionQueue


class OrionExecutor:
    """Sequential action executor with bounded retry and graceful shutdown."""

    def __init__(
        self,
        queue: OrionActionQueue,
        handlers: OrionActionHandlers,
        *,
        max_consecutive_failures: int = 32,
    ) -> None:
        if max_consecutive_failures <= 0:
            raise OrionActionError("max_consecutive_failures must be positive.")
        self._queue = queue
        self._handlers = handlers
        self._max_consecutive_failures = max_consecutive_failures
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._consecutive_failures = 0
        self._processed = 0
        self._succeeded = 0
        self._failed = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="orion-action-executor", daemon=True
            )
            self._thread.start()

    def stop(self, drain: bool = False, timeout_seconds: float = 5.0) -> None:
        with self._lock:
            if self._thread is None:
                return
            self._stop.set()
            thread = self._thread
        if drain:
            try:
                self._drain_once()
            except Exception:
                pass
        if thread is not None:
            thread.join(timeout=timeout_seconds)
        with self._lock:
            self._thread = None

    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._drain_once()
            except Exception:
                pass
            # Cooperative sleep so we can be stopped promptly.
            self._stop.wait(timeout=0.25)

    # ------------------------------------------------------------------
    # Drain
    # ------------------------------------------------------------------

    def _drain_once(self) -> int:
        """Process one batch of runnable actions. Returns the count processed."""
        # Expire any pending expired actions first.
        self._queue.sweep_expired()

        runnable = self._queue.list_by_status("PENDING", limit=64)
        if not runnable:
            return 0
        processed = 0
        for action in runnable:
            if self._stop.is_set():
                break
            self._execute_action(action)
            processed += 1
        return processed

    def _execute_action(self, action: Any) -> None:
        try:
            self._queue.mark_running(action.action_id)
        except Exception:
            return
        try:
            result = self._handlers.execute(action)
        except Exception as e:
            self._queue.mark_failed(
                action.action_id,
                str(e),
                retry=action.can_retry()
                and self._consecutive_failures < self._max_consecutive_failures,
            )
            self._failed += 1
            self._consecutive_failures += 1
            self._processed += 1
            return
        try:
            self._queue.mark_succeeded(action.action_id, result=result)
        except Exception:
            pass
        self._succeeded += 1
        self._consecutive_failures = 0
        self._processed += 1

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.is_running(),
                "consecutive_failures": self._consecutive_failures,
                "max_consecutive_failures": self._max_consecutive_failures,
                "processed": self._processed,
                "succeeded": self._succeeded,
                "failed": self._failed,
                "queue": self._queue.metrics(),
            }


__all__ = ["OrionExecutor"]
