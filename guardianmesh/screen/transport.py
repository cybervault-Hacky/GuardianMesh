"""Transport bridge between the screen subsystem and the existing Nexus transport.

The bridge is a narrow, well-defined adapter that:

* Wraps screen frames in :class:`TransportEnvelope` instances with a
  narrowly-scoped message type allowlist.
* Uses the existing :class:`TransportSession` (Nexus) to encrypt the
  payload with the same AEAD keys as any other transport traffic.
* Forbids any remote-control message type (SCREEN_CONTROL, REMOTE_INPUT,
  EXECUTE, SHELL, COMMAND).

Frames are always sent through Nexus — never in plaintext, never through
a separate encryption system.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.screen.errors import (
    ScreenError,
    ScreenFrameValidationError,
    ScreenRemoteControlError,
)
from guardianmesh.screen.models import ScreenFrame
from guardianmesh.transport.models import (
    MessageType,
    TransportEnvelope,
    generate_message_id,
)

# ---------------------------------------------------------------------------
# Screen-specific message types
# ---------------------------------------------------------------------------


class ScreenMessageType(str, Enum):
    """Strict allowlist of narrowly-scoped Vista protocol message types.

    No remote-control message type exists in this enum. Any attempt to
    instantiate SCREEN_CONTROL, REMOTE_INPUT, EXECUTE, SHELL, or COMMAND
    is rejected at construction time.
    """

    SCREEN_VIEW_REQUEST = "SCREEN_VIEW_REQUEST"
    SCREEN_VIEW_APPROVAL = "SCREEN_VIEW_APPROVAL"
    SCREEN_VIEW_DENIAL = "SCREEN_VIEW_DENIAL"
    SCREEN_SESSION_START = "SCREEN_SESSION_START"
    SCREEN_FRAME = "SCREEN_FRAME"
    SCREEN_SESSION_STOP = "SCREEN_SESSION_STOP"
    SCREEN_SESSION_EXPIRED = "SCREEN_SESSION_EXPIRED"

    @classmethod
    def from_str(cls, val: str) -> ScreenMessageType:
        """Parse a screen message type with case-insensitive tolerance."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise ScreenError(f"Unknown screen message type: '{val}'") from e

    @property
    def is_remote_control(self) -> bool:
        """Defensive: every screen message type must return False here."""
        return False


# Hard-coded deny-list. Construction of these names raises a hard error.
_FORBIDDEN_REMOTE_CONTROL_TYPES = frozenset(
    {
        "SCREEN_CONTROL",
        "REMOTE_INPUT",
        "REMOTE_CLICK",
        "REMOTE_TAP",
        "REMOTE_SWIPE",
        "REMOTE_GESTURE",
        "EXECUTE",
        "SHELL",
        "COMMAND",
        "KEYLOG",
        "KEYSTROKE",
        "MIC",
        "MICROPHONE",
        "CAMERA",
        "GPS",
        "LOCATION",
    }
)


def assert_no_remote_control_type(name: str) -> None:
    """Raise :class:`ScreenRemoteControlError` if ``name`` is forbidden."""
    if name.strip().upper() in _FORBIDDEN_REMOTE_CONTROL_TYPES:
        raise ScreenRemoteControlError(
            f"Message type '{name}' is forbidden: remote control is not part of the "
            f"Vista privacy model."
        )


# ---------------------------------------------------------------------------
# Envelope wrapper
# ---------------------------------------------------------------------------


@dataclass
class ScreenEnvelope:
    """High-level representation of a Vista protocol message.

    This envelope is the *logical* message passed into the transport
    bridge. It is converted into a :class:`TransportEnvelope` before being
    encrypted by the Nexus transport.
    """

    message_type: ScreenMessageType
    session_id: str
    device_id: str
    parent_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    transport_session_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    expires_at: str = field(
        default_factory=lambda: (
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
        ).isoformat()
    )
    message_id: str = field(default_factory=generate_message_id)

    def to_transport_envelope(
        self,
        sender_id: str,
        recipient_id: str,
        sequence: int,
    ) -> TransportEnvelope:
        """Build a Nexus :class:`TransportEnvelope` for this Vista message."""
        envelope = TransportEnvelope(
            protocol_version=TransportEnvelope().protocol_version,
            message_id=self.message_id,
            session_id=self.session_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            message_type=MessageType.from_str(self.message_type.value),
            sequence=sequence,
            created_at=self.created_at,
            expires_at=self.expires_at,
            payload={
                "screen_message_type": self.message_type.value,
                "screen_session_id": self.session_id,
                "screen_device_id": self.device_id,
                "screen_parent_id": self.parent_id,
                "screen_transport_session_id": self.transport_session_id,
                "screen_payload": self.payload,
            },
        )
        return envelope


# ---------------------------------------------------------------------------
# Frame envelope helpers
# ---------------------------------------------------------------------------


def frame_to_envelope_payload(frame: ScreenFrame) -> dict[str, Any]:
    """Convert a :class:`ScreenFrame` into a transport-friendly payload.

    The frame payload is encoded as a hex string to keep the on-wire
    representation JSON-safe. The size is also included for the receiver
    to validate without re-encoding the hex string.
    """
    return {
        "frame_id": frame.frame_id,
        "sequence": frame.sequence,
        "captured_at": frame.captured_at,
        "width": frame.width,
        "height": frame.height,
        "pixel_format": frame.pixel_format.value,
        "codec": frame.codec.value,
        "payload_size": frame.payload_size,
        "payload_hex": frame.payload.hex(),
    }


def envelope_payload_to_frame(payload: dict[str, Any], session_id: str, device_id: str) -> ScreenFrame:
    """Reconstruct a :class:`ScreenFrame` from a transport payload."""
    if not isinstance(payload, dict):
        raise ScreenFrameValidationError("Screen frame payload must be a dictionary.")
    try:
        payload_hex = payload["payload_hex"]
    except KeyError as e:
        raise ScreenFrameValidationError(
            "Screen frame payload missing 'payload_hex' field."
        ) from e
    try:
        raw = bytes.fromhex(str(payload_hex))
    except ValueError as e:
        raise ScreenFrameValidationError(
            f"Screen frame payload is not valid hex: {e}"
        ) from e
    return ScreenFrame(
        protocol_version="1.0",
        session_id=session_id,
        device_id=device_id,
        frame_id=str(payload.get("frame_id", "")),
        sequence=int(payload.get("sequence", 0)),
        captured_at=str(payload.get("captured_at", "")),
        width=int(payload.get("width", 0)),
        height=int(payload.get("height", 0)),
        pixel_format=__import__("guardianmesh.screen.models", fromlist=["PixelFormat"]).PixelFormat.from_str(
            payload.get("pixel_format", "TEST")
        ),
        codec=__import__("guardianmesh.screen.models", fromlist=["ScreenCodec"]).ScreenCodec.from_str(
            payload.get("codec", "TEST")
        ),
        payload_size=int(payload.get("payload_size", len(raw))),
        payload=raw,
    )


# ---------------------------------------------------------------------------
# Allowed screen message type list (for transport validation)
# ---------------------------------------------------------------------------


ALLOWED_SCREEN_MESSAGE_TYPES: frozenset[str] = frozenset(
    t.value for t in ScreenMessageType
)


def is_allowed_screen_message_type(message_type: str) -> bool:
    """Return True if the message type is part of the strict screen allowlist."""
    return str(message_type).strip().upper() in ALLOWED_SCREEN_MESSAGE_TYPES


# ---------------------------------------------------------------------------
# ScreenTransportBridge: thin adapter into Nexus
# ---------------------------------------------------------------------------


@dataclass
class ScreenTransportBridge:
    """Thin adapter that sends screen envelopes over a Nexus transport.

    The bridge is stateless; it only knows how to convert screen messages
    into :class:`TransportEnvelope` instances and hand them to a
    :class:`TransportSession` for AEAD encryption. It never holds keys,
    never accesses the filesystem, and never bypasses the transport's
    envelope validation pipeline.
    """

    def build_envelope(
        self,
        *,
        message: ScreenEnvelope,
        sender_id: str,
        recipient_id: str,
        sequence: int,
    ) -> TransportEnvelope:
        """Build a Nexus :class:`TransportEnvelope` for a screen message."""
        return message.to_transport_envelope(
            sender_id=sender_id,
            recipient_id=recipient_id,
            sequence=sequence,
        )

    def extract_screen_envelope(
        self, transport_envelope: TransportEnvelope
    ) -> dict[str, Any]:
        """Extract the screen-specific metadata from a Nexus envelope payload."""
        payload = transport_envelope.payload or {}
        if not isinstance(payload, dict):
            raise ScreenError("Transport envelope payload is not a dictionary.")
        smt = payload.get("screen_message_type")
        if smt is None:
            raise ScreenError(
                "Transport envelope is not a screen message (missing screen_message_type)."
            )
        if not is_allowed_screen_message_type(str(smt)):
            raise ScreenError(
                f"Screen message type '{smt}' is not in the allowlist."
            )
        return {
            "message_type": ScreenMessageType.from_str(str(smt)),
            "session_id": str(payload.get("screen_session_id", transport_envelope.session_id)),
            "device_id": str(payload.get("screen_device_id", "")),
            "parent_id": str(payload.get("screen_parent_id", "")),
            "transport_session_id": payload.get("screen_transport_session_id"),
            "payload": payload.get("screen_payload", {}),
        }


# ---------------------------------------------------------------------------
# JSON serialization helpers
# ---------------------------------------------------------------------------


def serialize_screen_envelope(env: ScreenEnvelope) -> str:
    """Deterministic JSON serialization of a :class:`ScreenEnvelope`."""
    return json.dumps(
        {
            "message_id": env.message_id,
            "message_type": env.message_type.value,
            "session_id": env.session_id,
            "device_id": env.device_id,
            "parent_id": env.parent_id,
            "payload": env.payload,
            "transport_session_id": env.transport_session_id,
            "created_at": env.created_at,
            "expires_at": env.expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def deserialize_screen_envelope(data: str) -> ScreenEnvelope:
    """Deserialize a JSON-encoded :class:`ScreenEnvelope`."""
    obj = json.loads(data)
    return ScreenEnvelope(
        message_id=str(obj.get("message_id", generate_message_id())),
        message_type=ScreenMessageType.from_str(str(obj["message_type"])),
        session_id=str(obj["session_id"]),
        device_id=str(obj["device_id"]),
        parent_id=str(obj["parent_id"]),
        payload=obj.get("payload", {}) if isinstance(obj.get("payload"), dict) else {},
        transport_session_id=obj.get("transport_session_id"),
        created_at=str(obj.get("created_at", "")),
        expires_at=str(obj.get("expires_at", "")),
    )


__all__ = [
    "ALLOWED_SCREEN_MESSAGE_TYPES",
    "ScreenEnvelope",
    "ScreenMessageType",
    "ScreenTransportBridge",
    "assert_no_remote_control_type",
    "deserialize_screen_envelope",
    "envelope_payload_to_frame",
    "frame_to_envelope_payload",
    "is_allowed_screen_message_type",
    "serialize_screen_envelope",
]
