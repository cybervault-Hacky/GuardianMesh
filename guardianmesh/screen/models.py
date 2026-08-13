"""Data models, enumerations, and deterministic serialization for the Vista screen subsystem.

This module contains the canonical model definitions for the consent-based,
view-only screen sharing subsystem introduced in Phase 7. It is intentionally
isolated from any other subsystem and exposes only data structures and
factory functions. All behavioral logic is implemented in dedicated modules
(authorization, session, frames, transport, controller, indicator, etc.).

Strict invariants enforced here:
    * Every screen frame is bound to a specific ``session_id`` and ``device_id``.
    * No remote-control message type is ever exposed through this module.
    * The screen payload is never persisted to disk.
    * All serialized models are deterministic (sorted JSON keys, compact
      separators) so the same logical frame always yields the same bytes.
"""

from __future__ import annotations

import datetime
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.core.errors import ValidationError
from guardianmesh.identity.models import validate_identity_id
from guardianmesh.screen.errors import (
    ScreenAuthorizationDeniedError,
    ScreenAuthorizationError,
    ScreenAuthorizationExpiredError,
    ScreenAuthorizationNotFoundError,
    ScreenCodecError,
    ScreenError,
    ScreenFrameError,
    ScreenFrameOversizedError,
    ScreenFrameSequenceError,
    ScreenFrameValidationError,
    ScreenSessionError,
    ScreenSessionExpiredError,
    ScreenSessionNotFoundError,
    ScreenSessionRevokedError,
    ScreenSessionStateError,
)

# ---------------------------------------------------------------------------
# Protocol version + identifier generation
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "1.0"


def generate_screen_session_id() -> str:
    """Generate a unique screen session identifier (e.g. ``SCN-9F8E7D6C5B4A``)."""
    return f"SCN-{secrets.token_hex(6).upper()}"


def generate_authorization_id() -> str:
    """Generate a unique screen authorization identifier (e.g. ``SCA-9F8E7D6C5B4A``)."""
    return f"SCA-{secrets.token_hex(6).upper()}"


def generate_frame_id() -> str:
    """Generate a unique screen frame identifier (e.g. ``FRM-9F8E7D6C5B4A``)."""
    return f"FRM-{secrets.token_hex(6).upper()}"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ScreenSessionState(str, Enum):
    """Strict allowlist of legal screen session states."""

    REQUESTED = "REQUESTED"
    PENDING_CHILD_APPROVAL = "PENDING_CHILD_APPROVAL"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    STOPPED = "STOPPED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"

    @classmethod
    def from_str(cls, val: str) -> ScreenSessionState:
        """Parse a session state string with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenSessionStateError(f"Unknown screen session state: '{val}'") from e


# Legal state transition graph. Any transition not listed here is rejected.
_LEGAL_TRANSITIONS: dict[ScreenSessionState, frozenset[ScreenSessionState]] = {
    ScreenSessionState.REQUESTED: frozenset(
        {ScreenSessionState.PENDING_CHILD_APPROVAL, ScreenSessionState.DENIED, ScreenSessionState.EXPIRED}
    ),
    ScreenSessionState.PENDING_CHILD_APPROVAL: frozenset(
        {
            ScreenSessionState.APPROVED,
            ScreenSessionState.DENIED,
            ScreenSessionState.EXPIRED,
        }
    ),
    ScreenSessionState.APPROVED: frozenset(
        {ScreenSessionState.ACTIVE, ScreenSessionState.EXPIRED, ScreenSessionState.REVOKED}
    ),
    ScreenSessionState.ACTIVE: frozenset(
        {
            ScreenSessionState.STOPPED,
            ScreenSessionState.EXPIRED,
            ScreenSessionState.REVOKED,
        }
    ),
    ScreenSessionState.STOPPED: frozenset(),
    ScreenSessionState.DENIED: frozenset(),
    ScreenSessionState.EXPIRED: frozenset(),
    ScreenSessionState.REVOKED: frozenset(),
}


def assert_legal_transition(
    current: ScreenSessionState, target: ScreenSessionState
) -> None:
    """Raise :class:`ScreenSessionStateError` if the transition is illegal."""
    if target not in _LEGAL_TRANSITIONS.get(current, frozenset()):
        raise ScreenSessionStateError(
            f"Illegal screen session transition: {current.value} -> {target.value}"
        )


class AuthorizationDecision(str, Enum):
    """Possible child authorization decisions for a screen view request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"

    @classmethod
    def from_str(cls, val: str) -> AuthorizationDecision:
        """Parse an authorization decision from a case-insensitive string."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenAuthorizationError(
                f"Unknown screen authorization decision: '{val}'"
            ) from e


class ScreenCodec(str, Enum):
    """Allowlist of supported screen codecs.

    Only safe, deterministic, well-known codecs are permitted. Custom codecs
    are forbidden by design.
    """

    TEST = "TEST"           # Deterministic test codec (synthetic frames).
    H264 = "H264"           # Future production codec (H.264 / AVC).
    VP8 = "VP8"             # Future production codec.
    VP9 = "VP9"             # Future production codec.
    WEBP = "WEBP"           # Future production codec.

    @classmethod
    def from_str(cls, val: str) -> ScreenCodec:
        """Parse a codec string with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenCodecError(f"Unsupported screen codec: '{val}'") from e

    @property
    def is_production(self) -> bool:
        """True if the codec represents production video encoding."""
        return self != ScreenCodec.TEST


class PixelFormat(str, Enum):
    """Allowlist of supported pixel formats for screen frames."""

    RGB24 = "RGB24"
    RGBA32 = "RGBA32"
    YUV420 = "YUV420"
    BGR24 = "BGR24"
    TEST = "TEST"

    @classmethod
    def from_str(cls, val: str) -> PixelFormat:
        """Parse a pixel format with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenFrameValidationError(f"Unsupported pixel format: '{val}'") from e


class StopReason(str, Enum):
    """Reason codes for screen session termination."""

    CHILD_STOPPED = "CHILD_STOPPED"
    PARENT_STOPPED = "PARENT_STOPPED"
    EXPIRED = "EXPIRED"
    TRANSPORT_LOST = "TRANSPORT_LOST"
    TRUST_REVOKED = "TRUST_REVOKED"
    INACTIVITY = "INACTIVITY"
    ENCODER_ERROR = "ENCODER_ERROR"
    BACKPRESSURE = "BACKPRESSURE"

    @classmethod
    def from_str(cls, val: str) -> StopReason:
        """Parse a stop reason with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenSessionError(f"Unknown screen stop reason: '{val}'") from e


class BackpressureStrategy(str, Enum):
    """Bounded backpressure strategies when downstream is slower than upstream."""

    DROP_OLDEST = "DROP_OLDEST"
    DROP_NEWEST = "DROP_NEWEST"
    BLOCK = "BLOCK"

    @classmethod
    def from_str(cls, val: str) -> BackpressureStrategy:
        """Parse a backpressure strategy with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenFrameError(f"Unknown backpressure strategy: '{val}'") from e


# ---------------------------------------------------------------------------
# Authorization model
# ---------------------------------------------------------------------------


@dataclass
class ScreenAuthorization:
    """Authorization record representing an explicit child-side consent decision.

    The authorization is bound to exactly one :class:`ScreenSession`. It
    expires after a configurable bounded duration and is single-use: once a
    session is STOPPED / EXPIRED / REVOKED, a new authorization must be
    obtained to start another session.
    """

    authorization_id: str
    session_id: str
    device_id: str  # child identity ID
    parent_id: str  # parent identity ID requesting the view
    decision: AuthorizationDecision = AuthorizationDecision.PENDING
    requested_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    approved_at: str | None = None
    denied_at: str | None = None
    expires_at: str = ""
    max_duration_seconds: int = 300
    label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "authorization_id": self.authorization_id,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "parent_id": self.parent_id,
            "decision": self.decision.value,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "denied_at": self.denied_at,
            "expires_at": self.expires_at,
            "max_duration_seconds": self.max_duration_seconds,
            "label": self.label,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScreenAuthorization:
        """Deserialize from a JSON-compatible dictionary."""
        if not isinstance(data, dict):
            raise ScreenAuthorizationError("Authorization data must be a dictionary.")
        try:
            return cls(
                authorization_id=str(data["authorization_id"]),
                session_id=str(data["session_id"]),
                device_id=str(data["device_id"]),
                parent_id=str(data["parent_id"]),
                decision=AuthorizationDecision.from_str(data.get("decision", "PENDING")),
                requested_at=str(data.get("requested_at", "")),
                approved_at=data.get("approved_at"),
                denied_at=data.get("denied_at"),
                expires_at=str(data.get("expires_at", "")),
                max_duration_seconds=int(data.get("max_duration_seconds", 300)),
                label=data.get("label"),
                metadata=data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {},
            )
        except KeyError as e:
            raise ScreenAuthorizationError(
                f"Missing required authorization field: {e.args[0]}"
            ) from e

    def is_expired(self, now: datetime.datetime | None = None) -> bool:
        """Return True if the authorization lifetime has elapsed."""
        if not self.expires_at:
            return False
        try:
            exp_dt = datetime.datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True
        return (now or datetime.datetime.now(datetime.UTC)) > exp_dt

    def validate(self) -> None:
        """Validate identity IDs, durations, and structural fields."""
        valid_dev, dev_err = validate_identity_id(self.device_id)
        if not valid_dev:
            raise ScreenAuthorizationError(f"Invalid child device_id: {dev_err}")
        valid_par, par_err = validate_identity_id(self.parent_id)
        if not valid_par:
            raise ScreenAuthorizationError(f"Invalid parent_id: {par_err}")
        if not self.session_id:
            raise ScreenAuthorizationError("session_id is required.")
        if not self.authorization_id:
            raise ScreenAuthorizationError("authorization_id is required.")
        if self.max_duration_seconds <= 0:
            raise ScreenAuthorizationError("max_duration_seconds must be positive.")
        if self.max_duration_seconds > 86400:
            # Hard cap: a screen session can never be longer than 24 hours.
            raise ScreenAuthorizationError(
                "max_duration_seconds cannot exceed 86400 (24 hours)."
            )


# ---------------------------------------------------------------------------
# Screen session model
# ---------------------------------------------------------------------------


@dataclass
class ScreenSessionInfo:
    """Metadata representation of a screen view session (no frame content)."""

    session_id: str
    device_id: str
    parent_id: str
    authorization_id: str | None = None
    state: ScreenSessionState = ScreenSessionState.REQUESTED
    transport_session_id: str | None = None
    requested_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    approved_at: str | None = None
    started_at: str | None = None
    stopped_at: str | None = None
    expires_at: str = ""
    last_frame_at: str | None = None
    frame_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    width: int = 0
    height: int = 0
    codec: ScreenCodec = ScreenCodec.TEST
    max_fps: int = 10
    stop_reason: StopReason | None = None
    label: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- Computed properties ------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        """True if the session is in a terminal state."""
        return self.state in (
            ScreenSessionState.STOPPED,
            ScreenSessionState.DENIED,
            ScreenSessionState.EXPIRED,
            ScreenSessionState.REVOKED,
        )

    @property
    def is_active(self) -> bool:
        """True if the session is currently streaming frames."""
        return self.state == ScreenSessionState.ACTIVE

    @property
    def remaining_seconds(self) -> int:
        """Return remaining seconds before authorization/session expiration."""
        if not self.expires_at:
            return 0
        try:
            exp_dt = datetime.datetime.fromisoformat(self.expires_at)
        except ValueError:
            return 0
        delta = exp_dt - datetime.datetime.now(datetime.UTC)
        return max(0, int(delta.total_seconds()))

    @property
    def is_expired(self) -> bool:
        """True if the session lifetime has elapsed."""
        if not self.expires_at:
            return False
        try:
            exp_dt = datetime.datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True
        return datetime.datetime.now(datetime.UTC) > exp_dt

    # -- Serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dictionary (no frame content)."""
        return {
            "session_id": self.session_id,
            "device_id": self.device_id,
            "parent_id": self.parent_id,
            "authorization_id": self.authorization_id,
            "state": self.state.value,
            "transport_session_id": self.transport_session_id,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "expires_at": self.expires_at,
            "last_frame_at": self.last_frame_at,
            "frame_count": self.frame_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "width": self.width,
            "height": self.height,
            "codec": self.codec.value,
            "max_fps": self.max_fps,
            "stop_reason": self.stop_reason.value if self.stop_reason else None,
            "remaining_seconds": self.remaining_seconds,
            "is_expired": self.is_expired,
            "is_active": self.is_active,
            "is_terminal": self.is_terminal,
            "label": self.label,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScreenSessionInfo:
        """Deserialize from a JSON-compatible dictionary."""
        if not isinstance(data, dict):
            raise ScreenSessionError("Session info data must be a dictionary.")
        return cls(
            session_id=str(data["session_id"]),
            device_id=str(data["device_id"]),
            parent_id=str(data["parent_id"]),
            authorization_id=data.get("authorization_id"),
            state=ScreenSessionState.from_str(data.get("state", "REQUESTED")),
            transport_session_id=data.get("transport_session_id"),
            requested_at=str(data.get("requested_at", "")),
            approved_at=data.get("approved_at"),
            started_at=data.get("started_at"),
            stopped_at=data.get("stopped_at"),
            expires_at=str(data.get("expires_at", "")),
            last_frame_at=data.get("last_frame_at"),
            frame_count=int(data.get("frame_count", 0)),
            bytes_sent=int(data.get("bytes_sent", 0)),
            bytes_received=int(data.get("bytes_received", 0)),
            width=int(data.get("width", 0)),
            height=int(data.get("height", 0)),
            codec=ScreenCodec.from_str(data.get("codec", "TEST")),
            max_fps=int(data.get("max_fps", 10)),
            stop_reason=(
                StopReason.from_str(data["stop_reason"])
                if data.get("stop_reason")
                else None
            ),
            label=data.get("label"),
            metadata=data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {},
        )


# ---------------------------------------------------------------------------
# Screen frame model
# ---------------------------------------------------------------------------


@dataclass
class ScreenFrame:
    """Versioned, session-bound view-only screen frame.

    Frames are NEVER persisted to disk. They are produced on the child side,
    encrypted through the existing Nexus transport, and consumed by the parent
    viewer. The frame model enforces strict validation: oversized payloads,
    invalid codecs, missing session bindings, and out-of-window sequence
    numbers are all rejected at the boundary.
    """

    protocol_version: str = PROTOCOL_VERSION
    session_id: str = ""
    device_id: str = ""
    frame_id: str = field(default_factory=generate_frame_id)
    sequence: int = 0
    captured_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    width: int = 0
    height: int = 0
    pixel_format: PixelFormat = PixelFormat.TEST
    codec: ScreenCodec = ScreenCodec.TEST
    payload_size: int = 0
    payload: bytes = b""

    # -- Serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize the frame to a JSON-compatible dictionary.

        The frame payload is encoded as a hex string so that the result is
        round-trip safe through JSON. This is used for deterministic
        canonicalization only — frames at rest in this form never exist
        on disk.
        """
        return {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "frame_id": self.frame_id,
            "sequence": self.sequence,
            "captured_at": self.captured_at,
            "width": self.width,
            "height": self.height,
            "pixel_format": self.pixel_format.value,
            "codec": self.codec.value,
            "payload_size": self.payload_size,
            "payload_hex": self.payload.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScreenFrame:
        """Deserialize a frame from a JSON-compatible dictionary."""
        if not isinstance(data, dict):
            raise ScreenFrameValidationError("Frame data must be a dictionary.")
        try:
            payload_hex = data["payload_hex"]
        except KeyError as e:
            raise ScreenFrameValidationError(
                "Missing required frame field: payload_hex"
            ) from e
        try:
            payload = bytes.fromhex(str(payload_hex))
        except ValueError as e:
            raise ScreenFrameValidationError(f"Frame payload is not valid hex: {e}") from e
        return cls(
            protocol_version=str(data.get("protocol_version", PROTOCOL_VERSION)),
            session_id=str(data.get("session_id", "")),
            device_id=str(data.get("device_id", "")),
            frame_id=str(data.get("frame_id", generate_frame_id())),
            sequence=int(data.get("sequence", 0)),
            captured_at=str(data.get("captured_at", "")),
            width=int(data.get("width", 0)),
            height=int(data.get("height", 0)),
            pixel_format=PixelFormat.from_str(data.get("pixel_format", "TEST")),
            codec=ScreenCodec.from_str(data.get("codec", "TEST")),
            payload_size=int(data.get("payload_size", len(payload))),
            payload=payload,
        )

    def to_canonical_json(self) -> str:
        """Deterministic canonical JSON serialization (sorted keys, compact)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def to_canonical_bytes(self) -> bytes:
        """Deterministic canonical bytes representation."""
        return self.to_canonical_json().encode("utf-8")

    # -- Validation ---------------------------------------------------------

    def validate(
        self,
        max_width: int = 1920,
        max_height: int = 1080,
        max_payload_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        """Validate frame structure, dimensions, codec, and payload size.

        Args:
            max_width: Inclusive maximum frame width.
            max_height: Inclusive maximum frame height.
            max_payload_bytes: Inclusive maximum frame payload size.

        Raises:
            ScreenFrameValidationError: If structural fields are invalid.
            ScreenFrameOversizedError: If dimensions or payload exceed limits.
        """
        if self.protocol_version != PROTOCOL_VERSION:
            raise ScreenFrameValidationError(
                f"Unsupported screen protocol version '{self.protocol_version}'."
            )

        valid_dev, dev_err = validate_identity_id(self.device_id)
        if not valid_dev:
            raise ScreenFrameValidationError(f"Invalid device_id: {dev_err}")

        if not self.session_id:
            raise ScreenFrameValidationError("Frame session_id is required.")
        if not self.frame_id:
            raise ScreenFrameValidationError("Frame frame_id is required.")
        if self.sequence <= 0:
            raise ScreenFrameValidationError(
                "Frame sequence must be a positive integer."
            )
        if self.width <= 0 or self.height <= 0:
            raise ScreenFrameValidationError(
                "Frame width and height must be positive integers."
            )
        if self.width > max_width:
            raise ScreenFrameOversizedError(
                f"Frame width {self.width} exceeds maximum {max_width}."
            )
        if self.height > max_height:
            raise ScreenFrameOversizedError(
                f"Frame height {self.height} exceeds maximum {max_height}."
            )
        if len(self.payload) > max_payload_bytes:
            raise ScreenFrameOversizedError(
                f"Frame payload {len(self.payload)} bytes exceeds limit {max_payload_bytes}."
            )
        if self.payload_size != len(self.payload):
            raise ScreenFrameValidationError(
                "Frame payload_size does not match actual payload length."
            )
        try:
            datetime.datetime.fromisoformat(self.captured_at)
        except ValueError as e:
            raise ScreenFrameValidationError(
                f"Invalid captured_at timestamp: {e}"
            ) from e

    def to_summary(self) -> dict[str, Any]:
        """Return a metadata-only summary (NEVER includes the payload)."""
        return {
            "frame_id": self.frame_id,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "sequence": self.sequence,
            "captured_at": self.captured_at,
            "width": self.width,
            "height": self.height,
            "pixel_format": self.pixel_format.value,
            "codec": self.codec.value,
            "payload_size": self.payload_size,
        }


# ---------------------------------------------------------------------------
# Frame queue with bounded backpressure
# ---------------------------------------------------------------------------


@dataclass
class BoundedFrameQueue:
    """Bounded FIFO queue with explicit backpressure handling.

    The queue never grows without bound. When the consumer is slower than the
    producer, the configured :class:`BackpressureStrategy` decides whether to
    drop the oldest frame, drop the newest frame, or block until space is
    available. The total number of dropped frames is tracked for diagnostics.
    """

    max_size: int = 30
    strategy: BackpressureStrategy = BackpressureStrategy.DROP_OLDEST
    _items: list[ScreenFrame] = field(default_factory=list)
    _dropped: int = 0
    _lock: Any = field(default=None)

    def __post_init__(self) -> None:
        import threading

        if self._lock is None:
            self._lock = threading.Lock()
        if self.max_size <= 0:
            raise ScreenFrameError("BoundedFrameQueue max_size must be positive.")

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped

    def size(self) -> int:
        with self._lock:
            return len(self._items)

    def push(self, frame: ScreenFrame) -> bool:
        """Push a frame, applying the configured backpressure strategy.

        Returns:
            True if the frame was added, False if it was dropped.
        """
        with self._lock:
            if len(self._items) < self.max_size:
                self._items.append(frame)
                return True
            if self.strategy == BackpressureStrategy.DROP_OLDEST:
                self._items.pop(0)
                self._items.append(frame)
                self._dropped += 1
                return False
            if self.strategy == BackpressureStrategy.DROP_NEWEST:
                self._dropped += 1
                return False
            if self.strategy == BackpressureStrategy.BLOCK:
                # BLOCK strategy is bounded by max_size and is treated as DROP_OLDEST
                # for safety; we never wait indefinitely here.
                self._items.pop(0)
                self._items.append(frame)
                self._dropped += 1
                return False
            raise ScreenFrameError(
                f"Unhandled backpressure strategy: {self.strategy!r}"
            )

    def pop(self) -> ScreenFrame | None:
        with self._lock:
            if not self._items:
                return None
            return self._items.pop(0)

    def drain(self) -> list[ScreenFrame]:
        """Atomically remove and return all queued frames."""
        with self._lock:
            items = list(self._items)
            self._items.clear()
            return items

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


# ---------------------------------------------------------------------------
# Android screen provider boundary
# ---------------------------------------------------------------------------


@dataclass
class ScreenCaptureRequest:
    """Read-only request to a future Android companion screen provider.

    The request contains only identifiers, target resolution, and codec
    configuration. It does not contain any captured pixel data.
    """

    session_id: str
    width: int
    height: int
    max_fps: int
    codec: ScreenCodec
    pixel_format: PixelFormat

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "width": self.width,
            "height": self.height,
            "max_fps": self.max_fps,
            "codec": self.codec.value,
            "pixel_format": self.pixel_format.value,
        }


@dataclass
class ScreenCaptureResult:
    """Result of a screen capture request.

    The :attr:`captured` flag indicates whether the future Android companion
    actually produced a frame. When False, :attr:`payload` is always empty.
    """

    captured: bool
    width: int
    height: int
    pixel_format: PixelFormat
    codec: ScreenCodec
    payload: bytes = b""
    note: str = ""

    def to_summary(self) -> dict[str, Any]:
        return {
            "captured": self.captured,
            "width": self.width,
            "height": self.height,
            "pixel_format": self.pixel_format.value,
            "codec": self.codec.value,
            "payload_size": len(self.payload),
            "note": self.note,
        }


__all__ = [
    "PROTOCOL_VERSION",
    "AuthorizationDecision",
    "BackpressureStrategy",
    "BoundedFrameQueue",
    "PixelFormat",
    "ScreenAuthorization",
    "ScreenCaptureRequest",
    "ScreenCaptureResult",
    "ScreenCodec",
    "ScreenFrame",
    "ScreenSessionInfo",
    "ScreenSessionState",
    "StopReason",
    "assert_legal_transition",
    "generate_authorization_id",
    "generate_frame_id",
    "generate_screen_session_id",
]


# Re-export the relevant error classes for ergonomic imports. They live in
# ``screen.errors`` but are exposed here for callers that import models
# directly.
__all__ += [
    "ScreenAuthorizationDeniedError",
    "ScreenAuthorizationError",
    "ScreenAuthorizationExpiredError",
    "ScreenAuthorizationNotFoundError",
    "ScreenCodecError",
    "ScreenError",
    "ScreenFrameError",
    "ScreenFrameOversizedError",
    "ScreenFrameSequenceError",
    "ScreenFrameValidationError",
    "ScreenSessionError",
    "ScreenSessionExpiredError",
    "ScreenSessionNotFoundError",
    "ScreenSessionRevokedError",
    "ScreenSessionStateError",
]


# ValidationError is re-exported for completeness in screens that
# want to construct frame model validation errors using the core
# hierarchy. We avoid raising it directly in this module.
_ = ValidationError
