"""Telemetry and device health subsystem for GuardianMesh (Phase 3: Pulse)."""

from __future__ import annotations

from guardianmesh.telemetry.models import (
    ALLOWED_HEALTH_FIELDS,
    FORBIDDEN_FIELDS,
    ConnectivityState,
    DeviceHealthState,
    DeviceHealthSummary,
    HealthSnapshot,
    TelemetryEnvelope,
    validate_health_payload,
)
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.telemetry.scheduler import TelemetryScheduler
from guardianmesh.telemetry.sequence import SequenceManager
from guardianmesh.telemetry.transport import (
    FutureNetworkTransport,
    LocalTransport,
    TestTransport,
    Transport,
)

__all__ = [
    "ALLOWED_HEALTH_FIELDS",
    "FORBIDDEN_FIELDS",
    "ConnectivityState",
    "DeviceHealthState",
    "DeviceHealthSummary",
    "FutureNetworkTransport",
    "HealthSnapshot",
    "LocalTransport",
    "SequenceManager",
    "TelemetryEnvelope",
    "TelemetryProcessor",
    "TelemetryScheduler",
    "TestTransport",
    "Transport",
    "validate_health_payload",
]
