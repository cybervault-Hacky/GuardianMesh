"""Orion Phase 9 exception hierarchy.

All Orion errors derive from :class:`OrionError`, which itself
derives from :class:`guardianmesh.core.errors.GuardianMeshError`.

The hierarchy is intentionally narrow: the spec defines a small
number of failure modes and Orion never invents new ones.
"""

from __future__ import annotations

from guardianmesh.core.errors import GuardianMeshError


class OrionError(GuardianMeshError):
    """Base exception for the Orion orchestration subsystem."""


class OrionEventError(OrionError):
    """Raised when an event is malformed, out-of-order, or rejected."""


class OrionActionError(OrionError):
    """Raised when an action cannot be created, executed, or cancelled."""


class OrionQueueError(OrionError):
    """Raised when the persistent action queue cannot accept or persist an action."""


class OrionHandlerError(OrionError):
    """Raised by a handler to signal a per-event processing failure.

    The bus catches :class:`OrionHandlerError` and applies the
    bounded retry policy. It does NOT crash the bus.
    """


class OrionReconciliationError(OrionError):
    """Raised when state reconciliation encounters an unrecoverable conflict."""


class OrionConsentViolationError(OrionError):
    """Raised when an action would bypass or weaken an existing consent boundary.

    Orion MUST never weaken consent. The enforcement point is the
    :class:`OrionConsentValidator`; this error is what it raises.
    """


class OrionCapabilityError(OrionError):
    """Raised when a capability is unknown or unsafe to assume."""


class OrionShutdownError(OrionError):
    """Raised when a graceful shutdown cannot be completed."""


class OrionSchedulerError(OrionError):
    """Raised when a scheduled action cannot be enqueued or dispatched."""


__all__ = [
    "OrionActionError",
    "OrionCapabilityError",
    "OrionConsentViolationError",
    "OrionError",
    "OrionEventError",
    "OrionHandlerError",
    "OrionQueueError",
    "OrionReconciliationError",
    "OrionSchedulerError",
    "OrionShutdownError",
]
