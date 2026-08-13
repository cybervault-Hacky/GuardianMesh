"""Tests for screen subsystem models, enums, and serialization (Phase 7: Vista)."""

from __future__ import annotations

import datetime
import json

import pytest

from guardianmesh.screen.errors import (
    ScreenCodecError,
    ScreenFrameValidationError,
    ScreenSessionStateError,
)
from guardianmesh.screen.models import (
    PROTOCOL_VERSION,
    AuthorizationDecision,
    BackpressureStrategy,
    BoundedFrameQueue,
    PixelFormat,
    ScreenAuthorization,
    ScreenCaptureRequest,
    ScreenCaptureResult,
    ScreenCodec,
    ScreenFrame,
    ScreenSessionInfo,
    ScreenSessionState,
    StopReason,
    assert_legal_transition,
    generate_authorization_id,
    generate_frame_id,
    generate_screen_session_id,
)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


def test_enums_have_expected_values() -> None:
    """Enumerations expose the documented set of values."""
    assert ScreenSessionState.REQUESTED.value == "REQUESTED"
    assert ScreenSessionState.PENDING_CHILD_APPROVAL.value == "PENDING_CHILD_APPROVAL"
    assert ScreenSessionState.APPROVED.value == "APPROVED"
    assert ScreenSessionState.ACTIVE.value == "ACTIVE"
    assert ScreenSessionState.STOPPED.value == "STOPPED"
    assert ScreenSessionState.DENIED.value == "DENIED"
    assert ScreenSessionState.EXPIRED.value == "EXPIRED"
    assert ScreenSessionState.REVOKED.value == "REVOKED"

    assert AuthorizationDecision.PENDING.value == "PENDING"
    assert AuthorizationDecision.APPROVED.value == "APPROVED"
    assert AuthorizationDecision.DENIED.value == "DENIED"
    assert AuthorizationDecision.EXPIRED.value == "EXPIRED"
    assert AuthorizationDecision.REVOKED.value == "REVOKED"

    assert ScreenCodec.TEST.value == "TEST"
    assert ScreenCodec.H264.value == "H264"
    assert ScreenCodec.WEBP.value == "WEBP"


def test_enum_from_str_case_insensitive() -> None:
    """All enums support case-insensitive parsing."""
    assert ScreenSessionState.from_str("active") == ScreenSessionState.ACTIVE
    assert AuthorizationDecision.from_str("approved") == AuthorizationDecision.APPROVED
    assert ScreenCodec.from_str("h264") == ScreenCodec.H264
    assert PixelFormat.from_str("rgb24") == PixelFormat.RGB24
    assert BackpressureStrategy.from_str("drop_oldest") == BackpressureStrategy.DROP_OLDEST
    assert StopReason.from_str("child_stopped") == StopReason.CHILD_STOPPED


def test_enum_from_str_invalid() -> None:
    """Unknown values must raise the appropriate domain error."""
    with pytest.raises(ScreenSessionStateError):
        ScreenSessionState.from_str("NOT_A_STATE")
    with pytest.raises(ScreenCodecError):
        ScreenCodec.from_str("XYZ")
    with pytest.raises(ScreenFrameValidationError):
        PixelFormat.from_str("BADFORMAT")


# ---------------------------------------------------------------------------
# State transition graph
# ---------------------------------------------------------------------------


def test_legal_state_transitions() -> None:
    """All documented transitions are accepted by the transition guard."""
    assert_legal_transition(ScreenSessionState.REQUESTED, ScreenSessionState.PENDING_CHILD_APPROVAL)
    assert_legal_transition(
        ScreenSessionState.PENDING_CHILD_APPROVAL, ScreenSessionState.APPROVED
    )
    assert_legal_transition(ScreenSessionState.APPROVED, ScreenSessionState.ACTIVE)
    assert_legal_transition(ScreenSessionState.ACTIVE, ScreenSessionState.STOPPED)
    assert_legal_transition(ScreenSessionState.ACTIVE, ScreenSessionState.REVOKED)
    assert_legal_transition(ScreenSessionState.ACTIVE, ScreenSessionState.EXPIRED)


def test_illegal_state_transitions_rejected() -> None:
    """All undocumented transitions are rejected."""
    with pytest.raises(ScreenSessionStateError):
        assert_legal_transition(ScreenSessionState.REQUESTED, ScreenSessionState.ACTIVE)
    with pytest.raises(ScreenSessionStateError):
        assert_legal_transition(ScreenSessionState.DENIED, ScreenSessionState.ACTIVE)
    with pytest.raises(ScreenSessionStateError):
        assert_legal_transition(ScreenSessionState.STOPPED, ScreenSessionState.ACTIVE)
    with pytest.raises(ScreenSessionStateError):
        assert_legal_transition(ScreenSessionState.EXPIRED, ScreenSessionState.APPROVED)
    with pytest.raises(ScreenSessionStateError):
        assert_legal_transition(ScreenSessionState.REQUESTED, ScreenSessionState.ACTIVE)


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------


def test_identifier_generation_unique() -> None:
    """Generated identifiers must be unique and follow expected format."""
    a = generate_screen_session_id()
    b = generate_screen_session_id()
    assert a != b
    assert a.startswith("SCN-")
    assert b.startswith("SCN-")
    assert len(a) == 16  # SCN- + 12 hex

    fa = generate_frame_id()
    fb = generate_frame_id()
    assert fa != fb
    assert fa.startswith("FRM-")

    aa = generate_authorization_id()
    ab = generate_authorization_id()
    assert aa != ab
    assert aa.startswith("SCA-")


# ---------------------------------------------------------------------------
# ScreenAuthorization
# ---------------------------------------------------------------------------


def test_screen_authorization_validate_rejects_invalid_identity() -> None:
    """Authorization must reject malformed identity IDs."""
    from guardianmesh.screen.errors import ScreenAuthorizationError
    auth = ScreenAuthorization(
        authorization_id="SCA-12345678",
        session_id="SCN-12345678",
        device_id="INVALID",
        parent_id="GM-P-83A1F72C",
    )
    with pytest.raises(ScreenAuthorizationError):
        auth.validate()


def test_screen_authorization_validate_rejects_zero_duration() -> None:
    """Authorization must reject non-positive durations."""
    from guardianmesh.screen.errors import ScreenAuthorizationError
    auth = ScreenAuthorization(
        authorization_id="SCA-12345678",
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=0,
    )
    with pytest.raises(ScreenAuthorizationError):
        auth.validate()


def test_screen_authorization_is_expired() -> None:
    """`is_expired` returns True past expires_at, False otherwise."""
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=10)).isoformat()
    future = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=10)).isoformat()
    auth = ScreenAuthorization(
        authorization_id="SCA-12345678",
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        expires_at=past,
    )
    assert auth.is_expired() is True
    auth.expires_at = future
    assert auth.is_expired() is False


# ---------------------------------------------------------------------------
# ScreenSessionInfo
# ---------------------------------------------------------------------------


def test_screen_session_info_terminal_and_active_flags() -> None:
    """is_terminal / is_active are correctly computed from state."""
    info = ScreenSessionInfo(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        state=ScreenSessionState.ACTIVE,
    )
    assert info.is_active is True
    assert info.is_terminal is False

    info.state = ScreenSessionState.STOPPED
    assert info.is_active is False
    assert info.is_terminal is True

    info.state = ScreenSessionState.DENIED
    assert info.is_terminal is True


def test_screen_session_info_remaining_seconds() -> None:
    """remaining_seconds counts down to 0 once past expiration."""
    future = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=120)).isoformat()
    info = ScreenSessionInfo(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        expires_at=future,
    )
    assert 100 <= info.remaining_seconds <= 120

    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=5)).isoformat()
    info.expires_at = past
    assert info.remaining_seconds == 0


def test_screen_session_info_round_trip() -> None:
    """ScreenSessionInfo can be serialized and deserialized losslessly."""
    info = ScreenSessionInfo(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        state=ScreenSessionState.ACTIVE,
        frame_count=42,
        width=1280,
        height=720,
        codec=ScreenCodec.TEST,
        max_fps=10,
        label="Tablet",
    )
    data = info.to_dict()
    restored = ScreenSessionInfo.from_dict(data)
    assert restored.session_id == info.session_id
    assert restored.state == info.state
    assert restored.frame_count == 42
    assert restored.width == 1280
    assert restored.height == 720
    assert restored.codec == ScreenCodec.TEST


# ---------------------------------------------------------------------------
# ScreenFrame
# ---------------------------------------------------------------------------


def test_screen_frame_to_from_dict() -> None:
    """Frames are round-trippable through to_dict/from_dict."""
    f = ScreenFrame(
        protocol_version=PROTOCOL_VERSION,
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        frame_id="FRM-12345678",
        sequence=1,
        captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
        width=320,
        height=240,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload_size=4,
        payload=b"abcd",
    )
    data = f.to_dict()
    assert data["payload_hex"] == "61626364"
    assert data["payload_size"] == 4

    restored = ScreenFrame.from_dict(data)
    assert restored.payload == b"abcd"
    assert restored.frame_id == f.frame_id
    assert restored.sequence == f.sequence
    assert restored.width == f.width
    assert restored.height == f.height


def test_screen_frame_to_canonical_bytes_deterministic() -> None:
    """Canonical JSON serialization is deterministic for equal frames."""
    f1 = ScreenFrame(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        frame_id="FRM-12345678",
        sequence=1,
        captured_at="2026-08-13T00:00:00+00:00",
        width=320,
        height=240,
        payload_size=0,
        payload=b"",
    )
    f2 = ScreenFrame(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        frame_id="FRM-12345678",
        sequence=1,
        captured_at="2026-08-13T00:00:00+00:00",
        width=320,
        height=240,
        payload_size=0,
        payload=b"",
    )
    assert f1.to_canonical_bytes() == f2.to_canonical_bytes()
    # Parses back as JSON.
    parsed = json.loads(f1.to_canonical_json())
    assert parsed["session_id"] == "SCN-12345678"


def test_screen_frame_validate_rejects_bad_size_mismatch() -> None:
    """Mismatched payload_size and actual payload must be rejected."""
    f = ScreenFrame(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        width=320,
        height=240,
        payload_size=99,
        payload=b"abc",
    )
    with pytest.raises(ScreenFrameValidationError):
        f.validate()


def test_screen_frame_validate_rejects_zero_dimensions() -> None:
    """Zero or negative width/height must be rejected."""
    f = ScreenFrame(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        width=0,
        height=240,
        payload_size=0,
        payload=b"",
    )
    with pytest.raises(ScreenFrameValidationError):
        f.validate()


def test_screen_frame_validate_rejects_oversized() -> None:
    """Dimensions and payload above limits must be rejected."""
    f = ScreenFrame(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        sequence=1,
        width=99999,
        height=240,
        payload_size=0,
        payload=b"",
    )
    from guardianmesh.screen.errors import ScreenFrameOversizedError

    with pytest.raises(ScreenFrameOversizedError):
        f.validate(max_width=1920, max_height=1080)


def test_screen_frame_to_summary_excludes_payload() -> None:
    """to_summary NEVER includes the payload bytes."""
    f = ScreenFrame(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        frame_id="FRM-12345678",
        sequence=1,
        width=320,
        height=240,
        payload_size=8,
        payload=b"abcdefgh",
    )
    s = f.to_summary()
    assert "payload" not in s
    assert "payload_hex" not in s
    assert s["payload_size"] == 8
    assert s["session_id"] == "SCN-12345678"


# ---------------------------------------------------------------------------
# Bounded frame queue
# ---------------------------------------------------------------------------


def test_bounded_frame_queue_drop_oldest() -> None:
    """Bounded queue with DROP_OLDEST must keep the most recent frames."""
    q = BoundedFrameQueue(max_size=2, strategy=BackpressureStrategy.DROP_OLDEST)
    payloads = [b"a", b"b", b"c"]
    for p in payloads:
        f = ScreenFrame(
            session_id="SCN-Q",
            device_id="GM-C-19A84E72",
            sequence=len(p),
            width=1,
            height=1,
            payload_size=len(p),
            payload=p,
        )
        q.push(f)
    assert q.dropped_count == 1
    drained = q.drain()
    assert [f.payload for f in drained] == [b"b", b"c"]


def test_bounded_frame_queue_drop_newest() -> None:
    """Bounded queue with DROP_NEWEST must keep the oldest frames."""
    q = BoundedFrameQueue(max_size=2, strategy=BackpressureStrategy.DROP_NEWEST)
    for i in range(1, 4):
        f = ScreenFrame(
            session_id="SCN-Q",
            device_id="GM-C-19A84E72",
            sequence=i,
            width=1,
            height=1,
            payload_size=1,
            payload=bytes([i]),
        )
        q.push(f)
    assert q.dropped_count == 1
    drained = q.drain()
    assert [f.payload for f in drained] == [b"\x01", b"\x02"]


def test_bounded_frame_queue_invalid_size() -> None:
    """BoundedFrameQueue rejects non-positive sizes."""
    from guardianmesh.screen.errors import ScreenFrameError
    with pytest.raises(ScreenFrameError):
        BoundedFrameQueue(max_size=0)


# ---------------------------------------------------------------------------
# Screen capture request/result
# ---------------------------------------------------------------------------


def test_screen_capture_request_to_dict() -> None:
    """ScreenCaptureRequest serializes to a dict without leaking."""
    req = ScreenCaptureRequest(
        session_id="SCN-12345678",
        width=1280,
        height=720,
        max_fps=10,
        codec=ScreenCodec.TEST,
        pixel_format=PixelFormat.TEST,
    )
    data = req.to_dict()
    assert data["width"] == 1280
    assert data["height"] == 720
    assert data["codec"] == "TEST"


def test_screen_capture_result_summary() -> None:
    """ScreenCaptureResult summary includes only metadata."""
    res = ScreenCaptureResult(
        captured=True,
        width=1280,
        height=720,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload=b"x" * 64,
        note="synthetic",
    )
    s = res.to_summary()
    assert s["payload_size"] == 64
    assert "payload" not in s
    assert s["captured"] is True
