"""Orion Phase 9 event model.

Every event flowing through the Orion bus is an :class:`OrionEvent`.
Events are strongly typed, deterministic, and contain only metadata
— never frame bytes, secrets, or private user content.

The :class:`OrionEventType` enum is the strict allowlist of legal
event types. Adding a new event type requires:

1. Adding a value to :class:`OrionEventType`.
2. Adding at least one handler in :mod:`guardianmesh.orion.handlers`.
3. Adding the corresponding audit event in
   :mod:`guardianmesh.storage.audit`.

The forbidden event names (``KEYSTROKE``, ``MESSAGE``, ``CLIPBOARD``,
``MICROPHONE``, ``CAMERA``, ``LOCATION``, ``SHELL_COMMAND``, etc.)
are rejected at construction time.
"""

from __future__ import annotations

import datetime
import enum
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from guardianmesh.identity.models import validate_identity_id
from guardianmesh.orion.errors import OrionEventError

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Event type enum
# ---------------------------------------------------------------------------


class OrionEventType(str, enum.Enum):
    """Strict allowlist of legal Orion event types.

    No remote-control, no payload-capture, no shell-execution event
    type exists in this enum. Adding a forbidden name raises
    :class:`ValueError` at construction time.
    """

    # Device lifecycle
    DEVICE_CONNECTED = "DEVICE_CONNECTED"
    DEVICE_DISCONNECTED = "DEVICE_DISCONNECTED"

    # Health (Phase 3 / Pulse)
    HEALTH_UPDATED = "HEALTH_UPDATED"
    HEALTH_DEGRADED = "HEALTH_DEGRADED"
    HEALTH_RECOVERED = "HEALTH_RECOVERED"

    # Alerts (Phase 4 / Sentinel)
    ALERT_CREATED = "ALERT_CREATED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"

    # Policies (Phase 4 / Sentinel)
    POLICY_CHANGED = "POLICY_CHANGED"

    # Trust (Phase 2 / Link)
    TRUST_ESTABLISHED = "TRUST_ESTABLISHED"
    TRUST_REVOKED = "TRUST_REVOKED"

    # Transport (Phase 6 / Nexus)
    TRANSPORT_CONNECTED = "TRANSPORT_CONNECTED"
    TRANSPORT_DISCONNECTED = "TRANSPORT_DISCONNECTED"
    TRANSPORT_RECONNECTED = "TRANSPORT_RECONNECTED"
    TRANSPORT_RECONCILED = "TRANSPORT_RECONCILED"
    TRANSPORT_REVOKED = "TRANSPORT_REVOKED"

    # Vista (Phase 7)
    SCREEN_AUTHORIZED = "SCREEN_AUTHORIZED"
    SCREEN_STARTED = "SCREEN_STARTED"
    SCREEN_STOPPED = "SCREEN_STOPPED"
    SCREEN_EXPIRED = "SCREEN_EXPIRED"
    SCREEN_DENIED = "SCREEN_DENIED"

    # Aegis (Phase 8)
    AEGIS_SESSION_CREATED = "AEGIS_SESSION_CREATED"
    AEGIS_CONSENT_GRANTED = "AEGIS_CONSENT_GRANTED"
    AEGIS_CONSENT_DENIED = "AEGIS_CONSENT_DENIED"
    AEGIS_CONSENT_EXPIRED = "AEGIS_CONSENT_EXPIRED"
    AEGIS_CAPTURE_STARTED = "AEGIS_CAPTURE_STARTED"
    AEGIS_STOPPED = "AEGIS_STOPPED"

    # Capability discovery
    CAPABILITY_CHANGED = "CAPABILITY_CHANGED"

    # Reconciliation
    RECONCILIATION_STARTED = "RECONCILIATION_STARTED"
    RECONCILIATION_COMPLETED = "RECONCILIATION_COMPLETED"
    CONFLICT_RESOLVED = "CONFLICT_RESOLVED"

    @classmethod
    def from_str(cls, val: str) -> OrionEventType:
        """Parse a string into an :class:`OrionEventType` with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionEventError(f"Unknown Orion event type: '{val}'") from e


# Forbidden event names that Orion must never accept. The set is
# validated at module import time and at event construction time.
FORBIDDEN_EVENT_NAMES = frozenset(
    {
        "KEYSTROKE",
        "KEY_LOG",
        "KEYLOG",
        "MESSAGE",
        "MESSAGES",
        "SMS",
        "EMAIL",
        "CLIPBOARD",
        "MICROPHONE",
        "MIC",
        "AUDIO",
        "CAMERA",
        "VIDEO_FRAME_RAW",
        "LOCATION",
        "GPS",
        "BROWSER_HISTORY",
        "CONTACT",
        "CONTACTS",
        "PHOTO",
        "PHOTOS",
        "FILE_LISTING",
        "SHELL",
        "SHELL_COMMAND",
        "EXEC",
        "EXECUTE",
        "REMOTE_INPUT",
        "REMOTE_TAP",
        "REMOTE_CLICK",
        "REMOTE_SWIPE",
        "REMOTE_GESTURE",
        "ACCESSIBILITY_ACTION",
    }
)


def assert_safe_event_type_name(name: str) -> None:
    """Raise :class:`OrionEventError` if ``name`` is forbidden.

    This guard is invoked at every boundary that ingests a string
    event type (CLI, bus, reconciliation, tests).
    """
    if name.strip().upper() in FORBIDDEN_EVENT_NAMES:
        raise OrionEventError(
            f"Orion event type '{name}' is forbidden: surveillance-style events "
            f"are not part of the Orion privacy model."
        )


# ---------------------------------------------------------------------------
# Event priority
# ---------------------------------------------------------------------------


class OrionEventPriority(str, enum.Enum):
    """Priority level for an :class:`OrionEvent`.

    Higher-priority events are processed before lower-priority events
    when the bus is operating in async mode.
    """

    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_str(cls, val: str) -> OrionEventPriority:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionEventError(f"Unknown event priority: '{val}'") from e


# ---------------------------------------------------------------------------
# Event payload
# ---------------------------------------------------------------------------


# Keys that must never appear in any event payload. The bus rejects
# events whose payload contains these keys at construction time.
FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "payload",  # screen frame bytes
        "frame",
        "frame_bytes",
        "screenshot",
        "image",
        "raw_pixels",
        "keylog",
        "keystrokes",
        "messages",
        "sms",
        "email",
        "clipboard",
        "microphone",
        "audio",
        "camera",
        "video",
        "location",
        "gps",
        "browser_history",
        "contacts",
        "photos",
        "files",
        "command",
        "shell",
        "exec",
        "execute",
        "remote_input",
        "remote_tap",
        "remote_click",
        "password",
        "private_key",
        "secret",
        "token",
        "auth_token",
        "otp",
    }
)


def assert_safe_payload(payload: dict[str, Any]) -> None:
    """Raise :class:`OrionEventError` if ``payload`` contains a forbidden key."""
    for key in payload.keys():
        if str(key).lower() in FORBIDDEN_PAYLOAD_KEYS:
            raise OrionEventError(
                f"Orion event payload key '{key}' is forbidden: "
                f"surveillance-style or sensitive content must never enter the bus."
            )


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------


def generate_event_id() -> str:
    """Generate a unique event identifier (e.g. ``OEV-...``)."""
    return f"OEV-{secrets.token_hex(6).upper()}"


def generate_correlation_id() -> str:
    """Generate a unique correlation identifier (e.g. ``OCR-...``)."""
    return f"OCR-{secrets.token_hex(6).upper()}"


@dataclass
class OrionEvent:
    """A strongly typed, deterministic Orion event.

    The event carries only metadata. Sensitive payloads are rejected
    at construction time by :func:`assert_safe_payload`.
    """

    event_id: str
    event_type: OrionEventType
    source: str
    device_id: str
    created_at: str
    correlation_id: str
    schema_version: str = SCHEMA_VERSION
    payload: dict[str, Any] = field(default_factory=dict)
    priority: OrionEventPriority = OrionEventPriority.NORMAL
    sequence: int = 0  # Per-device monotonic sequence, set by the bus.

    def __post_init__(self) -> None:
        if not self.event_id:
            raise OrionEventError("event_id is required.")
        if not isinstance(self.event_type, OrionEventType):
            raise OrionEventError("event_type must be an OrionEventType.")
        if not self.source:
            raise OrionEventError("source is required.")
        if not self.device_id:
            raise OrionEventError("device_id is required.")
        # device_id must be a valid GuardianMesh identity id, unless
        # this is a system-level event with the special device id
        # ``SYSTEM`` or ``BUS``.
        if self.device_id not in {"SYSTEM", "BUS", "ORION"}:
            ok, err = validate_identity_id(self.device_id)
            if not ok:
                raise OrionEventError(f"Invalid device_id: {err}")
        if not self.correlation_id:
            raise OrionEventError("correlation_id is required.")
        if not isinstance(self.priority, OrionEventPriority):
            raise OrionEventError("priority must be an OrionEventPriority.")
        if not isinstance(self.payload, dict):
            raise OrionEventError("payload must be a dict.")
        if self.schema_version != SCHEMA_VERSION:
            raise OrionEventError(
                f"Unsupported schema version '{self.schema_version}' "
                f"(expected '{SCHEMA_VERSION}')."
            )
        # Reject surveillance-style and sensitive payload keys.
        assert_safe_payload(self.payload)
        # Validate the timestamp.
        try:
            datetime.datetime.fromisoformat(self.created_at)
        except ValueError as e:
            raise OrionEventError(f"Invalid created_at: {e}") from e
        if self.sequence < 0:
            raise OrionEventError("sequence must be non-negative.")

    @classmethod
    def create(
        cls,
        event_type: OrionEventType | str,
        source: str,
        device_id: str,
        correlation_id: str | None = None,
        payload: dict[str, Any] | None = None,
        priority: OrionEventPriority | str = OrionEventPriority.NORMAL,
        event_id: str | None = None,
        created_at: str | None = None,
    ) -> OrionEvent:
        """Factory method that constructs and validates a new event."""
        if isinstance(event_type, str):
            assert_safe_event_type_name(event_type)
            event_type = OrionEventType.from_str(event_type)
        if isinstance(priority, str):
            priority = OrionEventPriority.from_str(priority)
        return cls(
            event_id=event_id or generate_event_id(),
            event_type=event_type,
            source=source,
            device_id=device_id,
            created_at=created_at or datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id=correlation_id or generate_correlation_id(),
            payload=payload or {},
            priority=priority,
        )

    def to_dict(self) -> dict[str, Any]:
        """Deterministic JSON-safe serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source": self.source,
            "device_id": self.device_id,
            "created_at": self.created_at,
            "correlation_id": self.correlation_id,
            "schema_version": self.schema_version,
            "payload": self.payload,
            "priority": self.priority.value,
            "sequence": self.sequence,
        }

    def to_canonical_json(self) -> str:
        """Deterministic JSON serialization (sorted keys, compact)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrionEvent:
        """Deserialize a dict back into an :class:`OrionEvent`."""
        if not isinstance(data, dict):
            raise OrionEventError("Event data must be a dict.")
        return cls(
            event_id=str(data.get("event_id", "")),
            event_type=OrionEventType.from_str(str(data.get("event_type", ""))),
            source=str(data.get("source", "")),
            device_id=str(data.get("device_id", "")),
            created_at=str(data.get("created_at", "")),
            correlation_id=str(data.get("correlation_id", "")),
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
            payload=data.get("payload", {}) if isinstance(data.get("payload"), dict) else {},
            priority=OrionEventPriority.from_str(
                str(data.get("priority", OrionEventPriority.NORMAL.value))
            ),
            sequence=int(data.get("sequence", 0)),
        )


__all__ = [
    "FORBIDDEN_EVENT_NAMES",
    "FORBIDDEN_PAYLOAD_KEYS",
    "SCHEMA_VERSION",
    "OrionEvent",
    "OrionEventPriority",
    "OrionEventType",
    "assert_safe_event_type_name",
    "assert_safe_payload",
    "generate_correlation_id",
    "generate_event_id",
]
