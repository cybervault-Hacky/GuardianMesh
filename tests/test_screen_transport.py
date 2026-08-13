"""Tests for the screen transport bridge into Nexus (Phase 7: Vista)."""

from __future__ import annotations

import pytest

from guardianmesh.screen.errors import ScreenError, ScreenFrameValidationError, ScreenRemoteControlError
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCodec,
    ScreenFrame,
)
from guardianmesh.screen.transport import (
    ALLOWED_SCREEN_MESSAGE_TYPES,
    ScreenEnvelope,
    ScreenMessageType,
    ScreenTransportBridge,
    assert_no_remote_control_type,
    deserialize_screen_envelope,
    envelope_payload_to_frame,
    frame_to_envelope_payload,
    is_allowed_screen_message_type,
    serialize_screen_envelope,
)
from guardianmesh.transport.models import (
    MessageType,
    TransportEnvelope,
)

# ---------------------------------------------------------------------------
# ScreenMessageType
# ---------------------------------------------------------------------------


def test_screen_message_type_allowlist() -> None:
    """Only documented Vista message types are exposed."""
    expected = {
        "SCREEN_VIEW_REQUEST",
        "SCREEN_VIEW_APPROVAL",
        "SCREEN_VIEW_DENIAL",
        "SCREEN_SESSION_START",
        "SCREEN_FRAME",
        "SCREEN_SESSION_STOP",
        "SCREEN_SESSION_EXPIRED",
    }
    actual = {t.value for t in ScreenMessageType}
    assert actual == expected


def test_remote_control_message_types_not_in_allowlist() -> None:
    """The screen message type allowlist MUST NOT contain remote control names."""
    for forbidden in (
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
    ):
        assert not is_allowed_screen_message_type(forbidden), forbidden


def test_is_remote_control_is_always_false() -> None:
    """Every screen message type must report is_remote_control=False."""
    for t in ScreenMessageType:
        assert t.is_remote_control is False


def test_assert_no_remote_control_rejects() -> None:
    """assert_no_remote_control_type raises for known forbidden names."""
    with pytest.raises(ScreenRemoteControlError):
        assert_no_remote_control_type("SCREEN_CONTROL")
    with pytest.raises(ScreenRemoteControlError):
        assert_no_remote_control_type("REMOTE_INPUT")
    with pytest.raises(ScreenRemoteControlError):
        assert_no_remote_control_type("EXECUTE")
    with pytest.raises(ScreenRemoteControlError):
        assert_no_remote_control_type("SHELL")
    with pytest.raises(ScreenRemoteControlError):
        assert_no_remote_control_type("COMMAND")


def test_assert_no_remote_control_allows_known_types() -> None:
    """assert_no_remote_control_type does not raise for allowed names."""
    for t in (
        "SCREEN_VIEW_REQUEST",
        "SCREEN_VIEW_APPROVAL",
        "SCREEN_FRAME",
        "SCREEN_SESSION_STOP",
    ):
        assert_no_remote_control_type(t)  # No exception.


# ---------------------------------------------------------------------------
# ScreenEnvelope
# ---------------------------------------------------------------------------


def test_screen_envelope_to_transport_envelope() -> None:
    """A ScreenEnvelope serializes into a valid Nexus TransportEnvelope."""
    env = ScreenEnvelope(
        message_type=ScreenMessageType.SCREEN_VIEW_REQUEST,
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        payload={"max_duration_seconds": 120},
    )
    te = env.to_transport_envelope(
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        sequence=1,
    )
    assert te.message_type == MessageType.SCREEN_VIEW_REQUEST
    assert te.payload["screen_message_type"] == "SCREEN_VIEW_REQUEST"
    assert te.payload["screen_session_id"] == "SCN-12345678"
    assert te.payload["screen_device_id"] == "GM-C-19A84E72"
    assert te.payload["screen_parent_id"] == "GM-P-83A1F72C"


def test_screen_envelope_serialization_round_trip() -> None:
    """ScreenEnvelopes round-trip through JSON serialization."""
    env = ScreenEnvelope(
        message_type=ScreenMessageType.SCREEN_FRAME,
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        payload={"frame_id": "FRM-1"},
    )
    data = serialize_screen_envelope(env)
    restored = deserialize_screen_envelope(data)
    assert restored.message_type == ScreenMessageType.SCREEN_FRAME
    assert restored.session_id == "SCN-12345678"
    assert restored.payload == {"frame_id": "FRM-1"}


def test_screen_envelope_default_message_id() -> None:
    """Envelopes auto-generate a unique message_id if not provided."""
    e1 = ScreenEnvelope(
        message_type=ScreenMessageType.SCREEN_VIEW_REQUEST,
        session_id="SCN-A",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    e2 = ScreenEnvelope(
        message_type=ScreenMessageType.SCREEN_VIEW_REQUEST,
        session_id="SCN-B",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    assert e1.message_id != e2.message_id
    assert e1.message_id.startswith("MSG-")


# ---------------------------------------------------------------------------
# Frame <-> payload conversion
# ---------------------------------------------------------------------------


def test_frame_to_envelope_payload_hex_encodes() -> None:
    """Frame payloads are hex-encoded into the transport-friendly payload."""
    f = ScreenFrame(
        session_id="SCN-1",
        device_id="GM-C-19A84E72",
        frame_id="FRM-1",
        sequence=1,
        width=320,
        height=240,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload_size=4,
        payload=b"\x01\x02\x03\x04",
    )
    p = frame_to_envelope_payload(f)
    assert p["payload_hex"] == "01020304"
    assert p["payload_size"] == 4
    assert p["width"] == 320
    assert p["height"] == 240
    assert p["codec"] == "TEST"


def test_envelope_payload_to_frame_reconstructs() -> None:
    """Hex-decoded payload reconstructs an equivalent frame."""
    f = ScreenFrame(
        session_id="SCN-1",
        device_id="GM-C-19A84E72",
        frame_id="FRM-1",
        sequence=1,
        width=320,
        height=240,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload_size=3,
        payload=b"abc",
    )
    p = frame_to_envelope_payload(f)
    restored = envelope_payload_to_frame(p, session_id="SCN-1", device_id="GM-C-19A84E72")
    assert restored.payload == b"abc"
    assert restored.width == 320
    assert restored.height == 240
    assert restored.frame_id == "FRM-1"


def test_envelope_payload_to_frame_rejects_non_dict() -> None:
    """A non-dict payload is rejected."""
    with pytest.raises(ScreenFrameValidationError):
        envelope_payload_to_frame("not a dict", session_id="SCN-1", device_id="GM-C-19A84E72")


def test_envelope_payload_to_frame_rejects_bad_hex() -> None:
    """A non-hex payload is rejected."""
    with pytest.raises(ScreenFrameValidationError):
        envelope_payload_to_frame(
            {"payload_hex": "not-hex"},
            session_id="SCN-1",
            device_id="GM-C-19A84E72",
        )


def test_envelope_payload_to_frame_rejects_missing_payload() -> None:
    """A missing payload_hex is rejected."""
    with pytest.raises(ScreenFrameValidationError):
        envelope_payload_to_frame(
            {"width": 320},
            session_id="SCN-1",
            device_id="GM-C-19A84E72",
        )


# ---------------------------------------------------------------------------
# ScreenTransportBridge
# ---------------------------------------------------------------------------


def test_bridge_build_envelope_preserves_metadata() -> None:
    """The bridge builds a TransportEnvelope that preserves all metadata."""
    bridge = ScreenTransportBridge()
    msg = ScreenEnvelope(
        message_type=ScreenMessageType.SCREEN_SESSION_START,
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    te = bridge.build_envelope(
        message=msg,
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
        sequence=7,
    )
    assert te.sequence == 7
    assert te.payload["screen_message_type"] == "SCREEN_SESSION_START"


def test_bridge_extract_screen_envelope() -> None:
    """The bridge can extract a screen envelope from a Nexus envelope."""
    bridge = ScreenTransportBridge()
    msg = ScreenEnvelope(
        message_type=ScreenMessageType.SCREEN_FRAME,
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    te = bridge.build_envelope(
        message=msg,
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
        sequence=1,
    )
    extracted = bridge.extract_screen_envelope(te)
    assert extracted["message_type"] == ScreenMessageType.SCREEN_FRAME
    assert extracted["session_id"] == "SCN-12345678"
    assert extracted["device_id"] == "GM-C-19A84E72"


def test_bridge_extract_rejects_non_screen_envelope() -> None:
    """A Nexus envelope without screen metadata is rejected."""
    bridge = ScreenTransportBridge()
    te = TransportEnvelope(
        message_type=MessageType.HEARTBEAT,
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
    )
    with pytest.raises(ScreenError):
        bridge.extract_screen_envelope(te)


def test_bridge_extract_rejects_unknown_screen_type() -> None:
    """A Nexus envelope with an unknown screen message type is rejected."""
    bridge = ScreenTransportBridge()
    te = TransportEnvelope(
        message_type=MessageType.SCREEN_FRAME,
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
        payload={"screen_message_type": "UNKNOWN_TYPE"},
    )
    with pytest.raises(ScreenError):
        bridge.extract_screen_envelope(te)


def test_allowed_screen_message_types_constant() -> None:
    """The exported frozenset matches ScreenMessageType values exactly."""
    assert ALLOWED_SCREEN_MESSAGE_TYPES == frozenset(t.value for t in ScreenMessageType)
