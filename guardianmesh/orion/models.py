"""Orion Phase 9 capability discovery and state model.

The :class:`OrionCapability` enum is the strict allowlist of legal
capabilities. Forbidden capabilities (e.g. ``MICROPHONE``,
``CAMERA``, ``REMOTE_INPUT``, ``REMOTE_SHELL``) are NEVER in the
allowlist — they are negative defaults.

The :class:`OrionDeviceCapabilities` model records, per device, the
documented capabilities. A device's capability set is discovered
through explicit protocol negotiation; Orion never infers a
capability from the platform alone.
"""

from __future__ import annotations

import datetime
import enum
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from guardianmesh.identity.models import validate_identity_id
from guardianmesh.orion.errors import OrionCapabilityError, OrionError

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Capability enum
# ---------------------------------------------------------------------------


class OrionCapability(str, enum.Enum):
    """Strict allowlist of Orion capabilities.

    A capability describes what a device can do for Orion. The
    enum is split into positive capabilities (which may be True) and
    negative defaults (which are ALWAYS False).

    Orion never infers a capability from the platform. Every
    capability must be discovered through the explicit protocol
    negotiation implemented in
    :func:`OrionDeviceCapabilities.discover`.
    """

    # Positive capabilities (the device CAN do these).
    HEALTH_TELEMETRY = "HEALTH_TELEMETRY"
    POLICIES = "POLICIES"
    ALERTS = "ALERTS"
    SECURE_TRANSPORT = "SECURE_TRANSPORT"
    SCREEN_SESSION = "SCREEN_SESSION"
    SYSTEM_CONSENT = "SYSTEM_CONSENT"
    ORCHESTRATION = "ORCHESTRATION"

    # Negative defaults (the device CANNOT do these — always False).
    # The enum exists only to make the negative explicit; no value
    # of these is ever True.
    AUDIO_CAPTURE = "AUDIO_CAPTURE"
    CAMERA_CAPTURE = "CAMERA_CAPTURE"
    REMOTE_INPUT = "REMOTE_INPUT"
    REMOTE_SHELL = "REMOTE_SHELL"
    KEYLOGGING = "KEYLOGGING"
    LOCATION_TRACKING = "LOCATION_TRACKING"
    CLIPBOARD_ACCESS = "CLIPBOARD_ACCESS"
    MESSAGE_COLLECTION = "MESSAGE_COLLECTION"
    BROWSER_HISTORY = "BROWSER_HISTORY"
    HIDDEN_SCREEN_CAPTURE = "HIDDEN_SCREEN_CAPTURE"

    @classmethod
    def from_str(cls, val: str) -> OrionCapability:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionCapabilityError(f"Unknown capability: '{val}'") from e

    @property
    def is_negative_default(self) -> bool:
        """Return True if this capability is always False."""
        return self in _NEGATIVE_CAPABILITIES


# Capabilities that are ALWAYS False on every device. The enum
# entries exist so that callers can explicitly assert that the
# capability is unsupported; they never appear as True in a
# capabilities report.
_NEGATIVE_CAPABILITIES: frozenset[OrionCapability] = frozenset(
    {
        OrionCapability.AUDIO_CAPTURE,
        OrionCapability.CAMERA_CAPTURE,
        OrionCapability.REMOTE_INPUT,
        OrionCapability.REMOTE_SHELL,
        OrionCapability.KEYLOGGING,
        OrionCapability.LOCATION_TRACKING,
        OrionCapability.CLIPBOARD_ACCESS,
        OrionCapability.MESSAGE_COLLECTION,
        OrionCapability.BROWSER_HISTORY,
        OrionCapability.HIDDEN_SCREEN_CAPTURE,
    }
)


# Default capability profile for a Linux/Termux control-plane host
# that has no real Android companion. The control plane is a
# meta-device that drives the orchestration; it does not implement
# any of the device-side capabilities.
DEFAULT_CONTROL_PLANE_CAPABILITIES: dict[OrionCapability, bool] = {
    OrionCapability.HEALTH_TELEMETRY: True,
    OrionCapability.POLICIES: True,
    OrionCapability.ALERTS: True,
    OrionCapability.SECURE_TRANSPORT: True,
    OrionCapability.ORCHESTRATION: True,
    OrionCapability.SCREEN_SESSION: False,  # control plane does not capture
    OrionCapability.SYSTEM_CONSENT: False,  # control plane does not capture
    # Negative defaults are always False.
    OrionCapability.AUDIO_CAPTURE: False,
    OrionCapability.CAMERA_CAPTURE: False,
    OrionCapability.REMOTE_INPUT: False,
    OrionCapability.REMOTE_SHELL: False,
    OrionCapability.KEYLOGGING: False,
    OrionCapability.LOCATION_TRACKING: False,
    OrionCapability.CLIPBOARD_ACCESS: False,
    OrionCapability.MESSAGE_COLLECTION: False,
    OrionCapability.BROWSER_HISTORY: False,
    OrionCapability.HIDDEN_SCREEN_CAPTURE: False,
}


def generate_capability_id() -> str:
    """Generate a unique capability-record identifier."""
    return f"OCP-{secrets.token_hex(6).upper()}"


# ---------------------------------------------------------------------------
# Device capability record
# ---------------------------------------------------------------------------


@dataclass
class OrionDeviceCapabilities:
    """Per-device capability record.

    The record is metadata only. It records whether a device supports
    a given capability. A device that does not declare a capability
    is assumed to NOT support it.
    """

    device_id: str
    capabilities: dict[OrionCapability, bool] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    updated_at: str | None = None
    source: str = "explicit-discovery"
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.device_id:
            raise OrionCapabilityError("device_id is required.")
        if self.device_id not in {"SYSTEM", "BUS", "ORION"}:
            ok, err = validate_identity_id(self.device_id)
            if not ok:
                raise OrionCapabilityError(f"Invalid device_id: {err}")
        if not isinstance(self.capabilities, dict):
            raise OrionCapabilityError("capabilities must be a dict.")
        # Negative defaults are always False. We refuse to set them
        # to True.
        for cap, value in self.capabilities.items():
            if cap.is_negative_default and value is True:
                raise OrionCapabilityError(
                    f"Negative default capability '{cap.value}' cannot be True."
                )

    def supports(self, capability: OrionCapability | str) -> bool:
        """Return True only if the capability is explicitly enabled."""
        if isinstance(capability, str):
            capability = OrionCapability.from_str(capability)
        if capability.is_negative_default:
            return False
        return bool(self.capabilities.get(capability, False))

    def enable(self, capability: OrionCapability | str) -> None:
        """Enable a positive capability for this device."""
        if isinstance(capability, str):
            capability = OrionCapability.from_str(capability)
        if capability.is_negative_default:
            raise OrionCapabilityError(
                f"Negative default capability '{capability.value}' cannot be enabled."
            )
        self.capabilities[capability] = True
        self.updated_at = datetime.datetime.now(datetime.UTC).isoformat()

    def disable(self, capability: OrionCapability | str) -> None:
        """Disable a capability for this device."""
        if isinstance(capability, str):
            capability = OrionCapability.from_str(capability)
        self.capabilities[capability] = False
        self.updated_at = datetime.datetime.now(datetime.UTC).isoformat()

    def positive_capabilities(self) -> list[OrionCapability]:
        """Return the list of positive capabilities the device supports."""
        return [c for c, v in self.capabilities.items() if v and not c.is_negative_default]

    def negative_capabilities(self) -> list[OrionCapability]:
        """Return the list of negative-default capabilities (always False)."""
        return sorted(_NEGATIVE_CAPABILITIES, key=lambda c: c.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "capabilities": {c.value: v for c, v in self.capabilities.items()},
            "schema_version": self.schema_version,
            "discovered_at": self.discovered_at,
            "updated_at": self.updated_at,
            "source": self.source,
            "notes": self.notes,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrionDeviceCapabilities:
        if not isinstance(data, dict):
            raise OrionCapabilityError("Capabilities data must be a dict.")
        raw_caps = data.get("capabilities", {})
        if not isinstance(raw_caps, dict):
            raise OrionCapabilityError("capabilities must be a dict.")
        capabilities: dict[OrionCapability, bool] = {}
        for k, v in raw_caps.items():
            capabilities[OrionCapability.from_str(str(k))] = bool(v)
        return cls(
            device_id=str(data.get("device_id", "")),
            capabilities=capabilities,
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
            discovered_at=str(data.get("discovered_at", "")),
            updated_at=data.get("updated_at"),
            source=str(data.get("source", "explicit-discovery")),
            notes=str(data.get("notes", "")),
        )

    @classmethod
    def discover(
        cls,
        device_id: str,
        *,
        health_telemetry: bool = False,
        policies: bool = False,
        alerts: bool = False,
        secure_transport: bool = False,
        screen_session: bool = False,
        system_consent: bool = False,
        orchestration: bool = False,
        source: str = "explicit-discovery",
        notes: str = "",
    ) -> OrionDeviceCapabilities:
        """Construct a capability record from explicit arguments.

        Every flag defaults to False. Orion never infers a
        capability from the platform. A capability is enabled only
        if the caller passes ``True`` explicitly.
        """
        capabilities: dict[OrionCapability, bool] = {
            OrionCapability.HEALTH_TELEMETRY: health_telemetry,
            OrionCapability.POLICIES: policies,
            OrionCapability.ALERTS: alerts,
            OrionCapability.SECURE_TRANSPORT: secure_transport,
            OrionCapability.SCREEN_SESSION: screen_session,
            OrionCapability.SYSTEM_CONSENT: system_consent,
            OrionCapability.ORCHESTRATION: orchestration,
        }
        return cls(
            device_id=device_id,
            capabilities=capabilities,
            source=source,
            notes=notes,
        )


# ---------------------------------------------------------------------------
# Reconciliation report
# ---------------------------------------------------------------------------


@dataclass
class OrionReconciliationReport:
    """Metadata-only summary of a reconciliation cycle.

    The report is metadata only. It never contains screen frames,
    commands, secrets, or private user content.
    """

    report_id: str
    device_id: str
    started_at: str
    completed_at: str | None
    events_processed: int = 0
    conflicts_detected: int = 0
    conflicts_resolved: int = 0
    stale_events: int = 0
    failed_actions: int = 0
    final_state: str = "SYNCED"
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.report_id:
            raise OrionError("report_id is required.")
        if not self.device_id:
            raise OrionError("device_id is required.")
        if not self.started_at:
            raise OrionError("started_at is required.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "device_id": self.device_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "events_processed": self.events_processed,
            "conflicts_detected": self.conflicts_detected,
            "conflicts_resolved": self.conflicts_resolved,
            "stale_events": self.stale_events,
            "failed_actions": self.failed_actions,
            "final_state": self.final_state,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrionReconciliationReport:
        if not isinstance(data, dict):
            raise OrionError("Reconciliation report data must be a dict.")
        return cls(
            report_id=str(data.get("report_id", "")),
            device_id=str(data.get("device_id", "")),
            started_at=str(data.get("started_at", "")),
            completed_at=data.get("completed_at"),
            events_processed=int(data.get("events_processed", 0)),
            conflicts_detected=int(data.get("conflicts_detected", 0)),
            conflicts_resolved=int(data.get("conflicts_resolved", 0)),
            stale_events=int(data.get("stale_events", 0)),
            failed_actions=int(data.get("failed_actions", 0)),
            final_state=str(data.get("final_state", "SYNCED")),
            notes=str(data.get("notes", "")),
        )


__all__ = [
    "DEFAULT_CONTROL_PLANE_CAPABILITIES",
    "SCHEMA_VERSION",
    "OrionCapability",
    "OrionDeviceCapabilities",
    "OrionReconciliationReport",
    "generate_capability_id",
]
