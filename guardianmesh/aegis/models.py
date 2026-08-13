"""Aegis Phase 8 data models.

This module defines the canonical data structures for the Aegis
production Android companion. It extends the Phase 7 Vista state
machine with two new states:

* ``SYSTEM_CONSENT_REQUIRED`` - the child has approved the view in
  GuardianMesh but the Android system capture-consent dialog has not yet
  been shown to the child.
* ``SYSTEM_CONSENT_GRANTED`` - the Android system consent dialog has
  been shown and the child has tapped "Allow". Capture may begin.

All Aegis models are deterministic, strictly validated, and never
contain frame bytes, screenshot blobs, or any captured pixel data.
"""

from __future__ import annotations

import datetime
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.aegis.errors import AegisError
from guardianmesh.identity.models import validate_identity_id

# ---------------------------------------------------------------------------
# Protocol version + identifier generation
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "1.0"


def generate_aegis_session_id() -> str:
    """Generate a unique Aegis capture-session identifier (e.g. ``AEG-...``)."""
    return f"AEG-{secrets.token_hex(6).upper()}"


def generate_consent_token() -> str:
    """Generate a unique single-use system-consent token (e.g. ``ACN-...``)."""
    return f"ACN-{secrets.token_hex(6).upper()}"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AegisPlatform(str, Enum):
    """Supported platforms for the Aegis screen-capture subsystem.

    * ``ANDROID`` - real Android companion (APK).
    * ``LINUX``   - Linux development host (no real capture).
    * ``TERMUX``  - Termux on Android (no real capture from Python).
    * ``UNKNOWN`` - platform not yet determined.
    """

    ANDROID = "ANDROID"
    LINUX = "LINUX"
    TERMUX = "TERMUX"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> AegisPlatform:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AegisError(f"Unknown Aegis platform: '{val}'") from e

    @property
    def supports_real_capture(self) -> bool:
        """Only a real Android companion can produce real screen capture."""
        return self == AegisPlatform.ANDROID


class SystemConsentState(str, Enum):
    """State of the Android ``MediaProjection`` system-consent dialog.

    The state machine is intentionally separate from the screen-session
    state machine. The two coordinate through
    :class:`guardianmesh.aegis.consent.SystemConsentGate`.
    """

    NOT_REQUESTED = "NOT_REQUESTED"
    REQUESTED = "REQUESTED"
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"

    @classmethod
    def from_str(cls, val: str) -> SystemConsentState:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AegisError(f"Unknown system consent state: '{val}'") from e


class FramePipelineStage(str, Enum):
    """Stages of the Aegis frame pipeline.

    Used for metric attribution and audit events. No frame content is
    associated with a stage; the stage is just a label.
    """

    CAPTURED = "CAPTURED"
    NORMALIZED = "NORMALIZED"
    ENCODED = "ENCODED"
    QUEUED = "QUEUED"
    TRANSMITTED = "TRANSMITTED"
    DROPPED = "DROPPED"

    @classmethod
    def from_str(cls, val: str) -> FramePipelineStage:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AegisError(f"Unknown frame pipeline stage: '{val}'") from e


class EncoderBackend(str, Enum):
    """Allowlist of screen-encoder backends.

    * ``MEDIA_CODEC`` - Android ``MediaCodec`` (preferred for production).
    * ``TEST``        - deterministic test encoder (no real encoding).
    """

    MEDIA_CODEC = "MEDIA_CODEC"
    TEST = "TEST"

    @classmethod
    def from_str(cls, val: str) -> EncoderBackend:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AegisError(f"Unknown encoder backend: '{val}'") from e

    @property
    def is_production(self) -> bool:
        return self == EncoderBackend.MEDIA_CODEC


# ---------------------------------------------------------------------------
# Provider capabilities
# ---------------------------------------------------------------------------


@dataclass
class ProviderCapabilities:
    """Read-only description of what a screen-capture provider can do.

    Aegis uses this metadata to decide whether real capture is possible
    on the current platform. The capability set is enforced at
    construction time and cannot be modified.
    """

    platform: AegisPlatform
    backend: EncoderBackend
    max_width: int
    max_height: int
    max_fps: int
    supports_foreground_service: bool
    supports_media_projection: bool
    notes: str = ""

    def __post_init__(self) -> None:
        if self.max_width <= 0 or self.max_height <= 0:
            raise AegisError("max_width and max_height must be positive.")
        if self.max_fps <= 0:
            raise AegisError("max_fps must be positive.")
        # Defensive invariant: only ANDROID can report real MediaProjection.
        if self.supports_media_projection and not self.platform.supports_real_capture:
            raise AegisError(
                f"Platform {self.platform.value} cannot support real MediaProjection."
            )

    @property
    def supports_real_capture(self) -> bool:
        """Return True only if the platform can perform real MediaProjection."""
        return self.platform.supports_real_capture and self.supports_media_projection

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform.value,
            "backend": self.backend.value,
            "max_width": self.max_width,
            "max_height": self.max_height,
            "max_fps": self.max_fps,
            "supports_foreground_service": self.supports_foreground_service,
            "supports_media_projection": self.supports_media_projection,
            "is_real_capture": self.platform.supports_real_capture,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Foreground service notification
# ---------------------------------------------------------------------------


@dataclass
class ForegroundServiceNotification:
    """Metadata model for the child-side visible notification.

    Aegis requires that an Android foreground-service notification is
    visible for the entire active capture session. The notification
    exposes a ``STOP SHARING`` action that performs an immediate local
    cancellation.

    The notification is metadata only; no frame content is included.
    """

    title: str = "GuardianMesh screen sharing is active"
    body: str = "Tap STOP to end sharing immediately."
    stop_action_label: str = "STOP SHARING"
    notification_channel_id: str = "guardianmesh.aegis.capture"
    notification_id: int = 8421  # Stable, deterministic across the build.
    show_when: bool = True
    ongoing: bool = True
    high_priority: bool = True

    def __post_init__(self) -> None:
        if not self.title:
            raise AegisError("Notification title cannot be empty.")
        if not self.stop_action_label:
            raise AegisError("Notification stop action label cannot be empty.")
        # Privacy: the title and body must never contain a captured frame
        # or any other screen content. The default values are sanitized
        # and a setter path that introduces user-controlled content is
        # explicitly out of scope.
        for forbidden in ("\x00", "\r", "\n"):
            if forbidden in self.title or forbidden in self.body:
                raise AegisError(
                    "Notification title/body must not contain control characters."
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "body": self.body,
            "stop_action_label": self.stop_action_label,
            "notification_channel_id": self.notification_channel_id,
            "notification_id": self.notification_id,
            "show_when": self.show_when,
            "ongoing": self.ongoing,
            "high_priority": self.high_priority,
        }


# ---------------------------------------------------------------------------
# Frame metrics
# ---------------------------------------------------------------------------


@dataclass
class FrameMetrics:
    """Bounded counters and timing aggregates for the frame pipeline.

    Aegis records metrics for visibility into capture throughput, encode
    latency, transport failures, and queue depth. Metrics NEVER contain
    frame bytes, screenshot blobs, or any captured pixel data.

    The :class:`FrameMetricsSnapshot` is the immutable, dict-serializable
    view exposed through ``guardian screen diagnostics`` and the audit
    log.
    """

    frames_captured: int = 0
    frames_normalized: int = 0
    frames_encoded: int = 0
    frames_queued: int = 0
    frames_transmitted: int = 0
    frames_dropped: int = 0
    queue_depth: int = 0
    queue_capacity: int = 0
    encode_latency_total_ms: int = 0
    encode_latency_count: int = 0
    transport_failures: int = 0
    projection_failures: int = 0
    encoder_failures: int = 0
    last_frame_sequence: int = 0

    def record_capture(self) -> None:
        self.frames_captured += 1

    def record_normalize(self) -> None:
        self.frames_normalized += 1

    def record_encode(self, latency_ms: int) -> None:
        self.frames_encoded += 1
        if latency_ms < 0:
            latency_ms = 0
        self.encode_latency_total_ms += int(latency_ms)
        self.encode_latency_count += 1

    def record_queue(self) -> None:
        self.frames_queued += 1

    def record_transmit(self) -> None:
        self.frames_transmitted += 1

    def record_drop(self) -> None:
        self.frames_dropped += 1

    def record_projection_failure(self) -> None:
        self.projection_failures += 1

    def record_encoder_failure(self) -> None:
        self.encoder_failures += 1

    def record_transport_failure(self) -> None:
        self.transport_failures += 1

    def set_queue_depth(self, depth: int, capacity: int) -> None:
        self.queue_depth = max(0, int(depth))
        self.queue_capacity = max(0, int(capacity))

    def set_last_sequence(self, sequence: int) -> None:
        if sequence < 0:
            return
        self.last_frame_sequence = int(sequence)

    def average_encode_latency_ms(self) -> float:
        if self.encode_latency_count <= 0:
            return 0.0
        return self.encode_latency_total_ms / float(self.encode_latency_count)

    def snapshot(self) -> FrameMetricsSnapshot:
        return FrameMetricsSnapshot(
            frames_captured=self.frames_captured,
            frames_normalized=self.frames_normalized,
            frames_encoded=self.frames_encoded,
            frames_queued=self.frames_queued,
            frames_transmitted=self.frames_transmitted,
            frames_dropped=self.frames_dropped,
            queue_depth=self.queue_depth,
            queue_capacity=self.queue_capacity,
            average_encode_latency_ms=self.average_encode_latency_ms(),
            transport_failures=self.transport_failures,
            projection_failures=self.projection_failures,
            encoder_failures=self.encoder_failures,
            last_frame_sequence=self.last_frame_sequence,
        )

    def to_dict(self) -> dict[str, Any]:
        return self.snapshot().to_dict()


@dataclass(frozen=True)
class FrameMetricsSnapshot:
    """Immutable view of :class:`FrameMetrics` for serialization."""

    frames_captured: int
    frames_normalized: int
    frames_encoded: int
    frames_queued: int
    frames_transmitted: int
    frames_dropped: int
    queue_depth: int
    queue_capacity: int
    average_encode_latency_ms: float
    transport_failures: int
    projection_failures: int
    encoder_failures: int
    last_frame_sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "frames_captured": self.frames_captured,
            "frames_normalized": self.frames_normalized,
            "frames_encoded": self.frames_encoded,
            "frames_queued": self.frames_queued,
            "frames_transmitted": self.frames_transmitted,
            "frames_dropped": self.frames_dropped,
            "queue_depth": self.queue_depth,
            "queue_capacity": self.queue_capacity,
            "average_encode_latency_ms": round(self.average_encode_latency_ms, 3),
            "transport_failures": self.transport_failures,
            "projection_failures": self.projection_failures,
            "encoder_failures": self.encoder_failures,
            "last_frame_sequence": self.last_frame_sequence,
        }


# ---------------------------------------------------------------------------
# Aegis session model
# ---------------------------------------------------------------------------


@dataclass
class AegisSessionInfo:
    """Metadata-only representation of an Aegis capture session.

    No frame data is ever stored in this model or in the underlying
    database table. The model is intended for diagnostic display and
    for cross-process coordination between the parent CLI and the
    future Android companion.
    """

    aegis_session_id: str
    screen_session_id: str
    device_id: str
    parent_id: str
    authorization_id: str | None = None
    consent_state: SystemConsentState = SystemConsentState.NOT_REQUESTED
    platform: AegisPlatform = AegisPlatform.UNKNOWN
    backend: EncoderBackend = EncoderBackend.TEST
    state: str = "INITIALIZED"  # Free-form, see AegisSessionState enum below.
    transport_session_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    consent_requested_at: str | None = None
    consent_granted_at: str | None = None
    started_at: str | None = None
    stopped_at: str | None = None
    expires_at: str = ""
    last_frame_sequence: int = 0
    stop_reason: str | None = None
    label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        valid_dev, dev_err = validate_identity_id(self.device_id)
        if not valid_dev:
            raise AegisError(f"Invalid device_id: {dev_err}")
        valid_par, par_err = validate_identity_id(self.parent_id)
        if not valid_par:
            raise AegisError(f"Invalid parent_id: {par_err}")
        if not self.aegis_session_id:
            raise AegisError("aegis_session_id is required.")
        if not self.screen_session_id:
            raise AegisError("screen_session_id is required.")
        if not self.expires_at:
            raise AegisError("expires_at is required.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "aegis_session_id": self.aegis_session_id,
            "screen_session_id": self.screen_session_id,
            "device_id": self.device_id,
            "parent_id": self.parent_id,
            "authorization_id": self.authorization_id,
            "consent_state": self.consent_state.value,
            "platform": self.platform.value,
            "backend": self.backend.value,
            "state": self.state,
            "transport_session_id": self.transport_session_id,
            "created_at": self.created_at,
            "consent_requested_at": self.consent_requested_at,
            "consent_granted_at": self.consent_granted_at,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "expires_at": self.expires_at,
            "last_frame_sequence": self.last_frame_sequence,
            "stop_reason": self.stop_reason,
            "label": self.label,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AegisSessionInfo:
        if not isinstance(data, dict):
            raise AegisError("Aegis session data must be a dictionary.")
        return cls(
            aegis_session_id=str(data.get("aegis_session_id", "")),
            screen_session_id=str(data.get("screen_session_id", "")),
            device_id=str(data.get("device_id", "")),
            parent_id=str(data.get("parent_id", "")),
            authorization_id=data.get("authorization_id"),
            consent_state=SystemConsentState.from_str(
                data.get("consent_state", "NOT_REQUESTED")
            ),
            platform=AegisPlatform.from_str(data.get("platform", "UNKNOWN")),
            backend=EncoderBackend.from_str(data.get("backend", "TEST")),
            state=str(data.get("state", "INITIALIZED")),
            transport_session_id=data.get("transport_session_id"),
            created_at=str(data.get("created_at", "")),
            consent_requested_at=data.get("consent_requested_at"),
            consent_granted_at=data.get("consent_granted_at"),
            started_at=data.get("started_at"),
            stopped_at=data.get("stopped_at"),
            expires_at=str(data.get("expires_at", "")),
            last_frame_sequence=int(data.get("last_frame_sequence", 0)),
            stop_reason=data.get("stop_reason"),
            label=data.get("label"),
            metadata=(
                data.get("metadata", {})
                if isinstance(data.get("metadata"), dict)
                else {}
            ),
        )


class AegisSessionState(str, Enum):
    """High-level lifecycle states of an Aegis capture session.

    These are distinct from the underlying screen-session states; they
    capture the Android-specific lifecycle.
    """

    INITIALIZED = "INITIALIZED"
    SYSTEM_CONSENT_REQUIRED = "SYSTEM_CONSENT_REQUIRED"
    SYSTEM_CONSENT_DENIED = "SYSTEM_CONSENT_DENIED"
    SYSTEM_CONSENT_GRANTED = "SYSTEM_CONSENT_GRANTED"
    CAPTURING = "CAPTURING"
    STOPPED = "STOPPED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    FAILED = "FAILED"

    @classmethod
    def from_str(cls, val: str) -> AegisSessionState:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AegisError(f"Unknown Aegis session state: '{val}'") from e


# ---------------------------------------------------------------------------
# System consent gate model
# ---------------------------------------------------------------------------


@dataclass
class SystemConsentRecord:
    """A single Android system-consent grant for a screen session.

    The record is metadata only. It records:

    * the consent token (a one-time opaque identifier)
    * the moment the system dialog was requested and granted
    * the consent state

    It does NOT record any frame, screenshot, or screen content.
    """

    consent_token: str
    screen_session_id: str
    device_id: str
    state: SystemConsentState = SystemConsentState.NOT_REQUESTED
    requested_at: str | None = None
    granted_at: str | None = None
    denied_at: str | None = None
    revoked_at: str | None = None
    expires_at: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "consent_token": self.consent_token,
            "screen_session_id": self.screen_session_id,
            "device_id": self.device_id,
            "state": self.state.value,
            "requested_at": self.requested_at,
            "granted_at": self.granted_at,
            "denied_at": self.denied_at,
            "revoked_at": self.revoked_at,
            "expires_at": self.expires_at,
            "note": self.note,
        }


__all__ = [
    "PROTOCOL_VERSION",
    "AegisPlatform",
    "AegisSessionInfo",
    "AegisSessionState",
    "EncoderBackend",
    "ForegroundServiceNotification",
    "FrameMetrics",
    "FrameMetricsSnapshot",
    "FramePipelineStage",
    "ProviderCapabilities",
    "SystemConsentRecord",
    "SystemConsentState",
    "generate_aegis_session_id",
    "generate_consent_token",
]
