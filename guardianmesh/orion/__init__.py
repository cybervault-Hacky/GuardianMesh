"""GuardianMesh Orion Phase 9 (v0.9.0).

Consent-Aware Orchestration & State Reconciliation.

Orion transforms GuardianMesh from a collection of independent
subsystems into a deterministic, event-driven orchestration platform
that:

* coordinates Pulse health telemetry, Sentinel policies and alerts,
  Console state, Nexus transport, Vista screen sessions, Aegis
  Android companion state, and Trust/revocation state;
* uses an explicit, allowlisted Event model with deterministic
  serialization;
* uses an explicit, allowlisted Action model with persistent
  idempotent queueing and bounded retry;
* reuses — never weakens or bypasses — the existing consent
  mechanisms (TrustManager, Vista authorization, Aegis
  SystemConsentGate);
* performs deterministic state reconciliation after reconnect;
* tracks device capabilities through explicit discovery (never
  inferred from the platform);
* never implements covert monitoring, remote input, shell
  execution, or hidden screen capture.

The Python control-plane implementation lives in this module. A
production orchestration daemon would extend the same contracts.
"""

from __future__ import annotations

from guardianmesh.orion.actions import (
    ACTION_CONSENT_REQUIREMENTS,
    FORBIDDEN_ACTION_NAMES,
    FORBIDDEN_ACTION_PARAM_KEYS,
    OrionAction,
    OrionActionStatus,
    OrionActionType,
    OrionConsentRequirement,
    assert_safe_action_params,
    assert_safe_action_type_name,
    generate_action_id,
    required_consents,
)
from guardianmesh.orion.actions import (
    SCHEMA_VERSION as ACTION_SCHEMA_VERSION,
)
from guardianmesh.orion.bus import BackpressureStrategy, OrionEventBus
from guardianmesh.orion.capabilities import OrionCapabilityRegistry
from guardianmesh.orion.consent import OrionConsentValidator
from guardianmesh.orion.coordinator import OrionCoordinator
from guardianmesh.orion.errors import (
    OrionActionError,
    OrionCapabilityError,
    OrionConsentViolationError,
    OrionError,
    OrionEventError,
    OrionHandlerError,
    OrionQueueError,
    OrionReconciliationError,
    OrionSchedulerError,
    OrionShutdownError,
)
from guardianmesh.orion.events import (
    FORBIDDEN_EVENT_NAMES,
    FORBIDDEN_PAYLOAD_KEYS,
    OrionEvent,
    OrionEventPriority,
    OrionEventType,
    assert_safe_event_type_name,
    assert_safe_payload,
    generate_correlation_id,
    generate_event_id,
)
from guardianmesh.orion.events import (
    SCHEMA_VERSION as EVENT_SCHEMA_VERSION,
)
from guardianmesh.orion.executor import OrionExecutor
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.orion.models import (
    DEFAULT_CONTROL_PLANE_CAPABILITIES,
    OrionCapability,
    OrionDeviceCapabilities,
    OrionReconciliationReport,
    generate_capability_id,
)
from guardianmesh.orion.models import (
    SCHEMA_VERSION as MODEL_SCHEMA_VERSION,
)
from guardianmesh.orion.queue import OrionActionQueue
from guardianmesh.orion.reconciliation import (
    DEFAULT_STALENESS_SECONDS,
    OrionStateReconciler,
    generate_reconciliation_id,
)
from guardianmesh.orion.registry import OrionRegistry
from guardianmesh.orion.scheduler import OrionScheduler

__all__ = [
    "ACTION_CONSENT_REQUIREMENTS",
    "ACTION_SCHEMA_VERSION",
    "DEFAULT_CONTROL_PLANE_CAPABILITIES",
    "DEFAULT_STALENESS_SECONDS",
    "EVENT_SCHEMA_VERSION",
    "FORBIDDEN_ACTION_NAMES",
    "FORBIDDEN_ACTION_PARAM_KEYS",
    "FORBIDDEN_EVENT_NAMES",
    "FORBIDDEN_PAYLOAD_KEYS",
    "MODEL_SCHEMA_VERSION",
    "BackpressureStrategy",
    "OrionAction",
    "OrionActionError",
    "OrionActionHandlers",
    "OrionActionQueue",
    "OrionActionStatus",
    "OrionActionType",
    "OrionCapability",
    "OrionCapabilityError",
    "OrionCapabilityRegistry",
    "OrionConsentRequirement",
    "OrionConsentValidator",
    "OrionConsentViolationError",
    "OrionCoordinator",
    "OrionDeviceCapabilities",
    "OrionError",
    "OrionEvent",
    "OrionEventBus",
    "OrionEventError",
    "OrionEventPriority",
    "OrionEventType",
    "OrionExecutor",
    "OrionHandlerError",
    "OrionQueueError",
    "OrionReconciliationError",
    "OrionReconciliationReport",
    "OrionRegistry",
    "OrionScheduler",
    "OrionSchedulerError",
    "OrionShutdownError",
    "OrionStateReconciler",
    "assert_safe_action_params",
    "assert_safe_action_type_name",
    "assert_safe_event_type_name",
    "assert_safe_payload",
    "generate_action_id",
    "generate_capability_id",
    "generate_correlation_id",
    "generate_event_id",
    "generate_reconciliation_id",
    "required_consents",
]
