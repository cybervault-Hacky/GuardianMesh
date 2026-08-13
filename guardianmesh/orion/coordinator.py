"""Orion Phase 9 high-level coordinator.

The :class:`OrionCoordinator` is the entry point for the rest of
GuardianMesh. It owns the bus, queue, executor, scheduler, and
consent validator, and exposes the high-level operations that the
console, CLI, and tests use.

The coordinator is the only Orion object that callers need to
construct; the rest of the subsystem is composed by it.
"""

from __future__ import annotations

import threading
from typing import Any

from guardianmesh.aegis.consent import SystemConsentGate
from guardianmesh.orion.bus import BackpressureStrategy, OrionEventBus
from guardianmesh.orion.capabilities import OrionCapabilityRegistry
from guardianmesh.orion.consent import OrionConsentValidator
from guardianmesh.orion.errors import OrionError
from guardianmesh.orion.events import OrionEvent
from guardianmesh.orion.executor import OrionExecutor
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.orion.queue import OrionActionQueue
from guardianmesh.orion.reconciliation import OrionStateReconciler
from guardianmesh.orion.registry import OrionRegistry
from guardianmesh.orion.scheduler import OrionScheduler
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.screen.authorization import ScreenAuthorizationManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database


class OrionCoordinator:
    """High-level Orion coordinator.

    The coordinator wires together the bus, queue, executor,
    scheduler, and consent validator. Callers can either use the
    high-level ``publish`` / ``submit`` / ``reconcile`` methods, or
    reach into the individual components for tests.
    """

    def __init__(
        self,
        db: Database,
        *,
        audit_logger: AuditLogger | None = None,
        trust_manager: TrustManager | None = None,
        screen_authorization_manager: ScreenAuthorizationManager | None = None,
        aegis_consent_gate: SystemConsentGate | None = None,
        bus: OrionEventBus | None = None,
        queue: OrionActionQueue | None = None,
        handlers: OrionActionHandlers | None = None,
        executor: OrionExecutor | None = None,
        registry: OrionRegistry | None = None,
        capabilities: OrionCapabilityRegistry | None = None,
        reconciler: OrionStateReconciler | None = None,
    ) -> None:
        if not isinstance(db, Database):
            raise OrionError("db must be a Database.")

        self._db = db
        self._audit_logger = audit_logger
        self._trust_manager = trust_manager
        self._screen_authorization_manager = screen_authorization_manager
        self._aegis_consent_gate = aegis_consent_gate

        self._registry = registry or OrionRegistry(db)
        self._capabilities = capabilities or OrionCapabilityRegistry()
        self._queue = queue or OrionActionQueue(db)
        self._bus = bus or OrionEventBus(
            max_queue_size=1024,
            backpressure=BackpressureStrategy.DROP_OLDEST,
            deterministic=False,
        )
        self._handlers = handlers or OrionActionHandlers(audit_logger=audit_logger)
        self._executor = executor or OrionExecutor(self._queue, self._handlers)
        self._scheduler = OrionScheduler(
            self._bus, self._queue, self._executor, self._handlers
        )
        self._consent_validator = OrionConsentValidator(
            trust_manager=trust_manager,
            screen_authorization_manager=screen_authorization_manager,
            aegis_consent_gate=aegis_consent_gate,
        )
        self._reconciler = reconciler or OrionStateReconciler(
            registry=self._registry,
            trust_manager=trust_manager,
            screen_authorization_manager=screen_authorization_manager,
            aegis_consent_gate=aegis_consent_gate,
        )
        self._lock = threading.RLock()
        self._running = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def bus(self) -> OrionEventBus:
        return self._bus

    @property
    def queue(self) -> OrionActionQueue:
        return self._queue

    @property
    def executor(self) -> OrionExecutor:
        return self._executor

    @property
    def scheduler(self) -> OrionScheduler:
        return self._scheduler

    @property
    def capabilities(self) -> OrionCapabilityRegistry:
        return self._capabilities

    @property
    def registry(self) -> OrionRegistry:
        return self._registry

    @property
    def reconciler(self) -> OrionStateReconciler:
        return self._reconciler

    @property
    def consent_validator(self) -> OrionConsentValidator:
        return self._consent_validator

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._scheduler.start()
            self._running = True

    def stop(self, drain: bool = False) -> None:
        with self._lock:
            if not self._running:
                return
            self._scheduler.stop(drain=drain)
            self._running = False

    def is_running(self) -> bool:
        with self._lock:
            return self._running

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def publish(self, event: OrionEvent) -> bool:
        return self._scheduler.publish_event(event)

    def submit(
        self,
        action_type: Any,
        device_id: str,
        requested_by: str,
        correlation_id: str | None = None,
        parameters: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        ttl_seconds: int = 300,
    ) -> bool:
        return self._scheduler.submit(
            action_type=action_type,
            device_id=device_id,
            requested_by=requested_by,
            correlation_id=correlation_id,
            parameters=parameters,
            idempotency_key=idempotency_key,
            ttl_seconds=ttl_seconds,
        )

    def reconcile(self, device_id: str) -> Any:
        return self._reconciler.reconcile(device_id)

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "scheduler": self._scheduler.metrics(),
                "capabilities": self._capabilities.metrics(),
                "registry": self._registry.metrics(),
            }


__all__ = ["OrionCoordinator"]
