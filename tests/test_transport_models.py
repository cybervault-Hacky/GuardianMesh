"""Tests for Nexus transport models, envelopes, validation, and privacy safety."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import (
    TransportMessageError,
    TransportOversizedMessageError,
    TransportPayloadError,
)
from guardianmesh.transport.models import (
    ConnectionState,
    EncryptedTransportFrame,
    MessageType,
    PeerInfo,
    SessionInfo,
    TransportEnvelope,
    TransportType,
    generate_message_id,
    generate_session_id,
)


def test_message_type_enum() -> None:
    """Test MessageType enum conversions and allowlist validation."""
    assert MessageType.from_str("HELLO") == MessageType.HELLO
    assert MessageType.from_str("session_init") == MessageType.SESSION_INIT
    assert MessageType.from_str("TELEMETRY") == MessageType.TELEMETRY
    assert MessageType.from_str("ALERT") == MessageType.ALERT
    assert MessageType.from_str("GOODBYE") == MessageType.GOODBYE

    with pytest.raises(TransportMessageError):
        MessageType.from_str("SCREEN_STREAM")

    with pytest.raises(TransportMessageError):
        MessageType.from_str("REMOTE_EXEC")


def test_connection_state_and_transport_type() -> None:
    """Test ConnectionState and TransportType parsing and fallbacks."""
    assert ConnectionState.from_str("CONNECTED") == ConnectionState.CONNECTED
    assert ConnectionState.from_str("invalid") == ConnectionState.DISCONNECTED

    assert TransportType.from_str("NETWORK") == TransportType.NETWORK
    assert TransportType.from_str("invalid") == TransportType.LOCAL


def test_transport_envelope_serialization() -> None:
    """Test TransportEnvelope canonical JSON serialization and round-trip."""
    env = TransportEnvelope(
        protocol_version="1.0",
        message_id="MSG-001122334455",
        session_id="SES-AABBCCDDEEFF",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.HEARTBEAT,
        sequence=42,
        created_at="2026-08-13T02:00:00+00:00",
        expires_at="2026-08-13T02:05:00+00:00",
        payload={"uptime_seconds": 1200},
        authentication={"tag": "auth-ok"},
    )

    d = env.to_dict()
    assert d["sequence"] == 42
    assert d["message_type"] == "HEARTBEAT"

    canon_json = env.to_canonical_json()
    assert isinstance(canon_json, str)
    canon_bytes = env.to_canonical_bytes()
    assert isinstance(canon_bytes, bytes)

    restored = TransportEnvelope.from_json(canon_json)
    assert restored.message_id == env.message_id
    assert restored.session_id == env.session_id
    assert restored.sequence == 42
    assert restored.payload == {"uptime_seconds": 1200}
    assert restored.authentication == {"tag": "auth-ok"}


def test_transport_envelope_validation_rules() -> None:
    """Test envelope validation: formats, timestamps, negative sequences, oversized limits."""
    valid_env = TransportEnvelope(
        protocol_version="1.0",
        message_id="MSG-1234567890AB",
        session_id="SES-1234567890AB",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.TELEMETRY,
        sequence=1,
        created_at="2026-08-13T02:00:00+00:00",
        expires_at="2026-08-13T02:05:00+00:00",
        payload={"battery_percent": 85},
    )
    valid_env.validate()

    # Unsupported protocol version
    bad_ver = TransportEnvelope.from_dict(valid_env.to_dict())
    bad_ver.protocol_version = "9.9"
    with pytest.raises(TransportMessageError):
        bad_ver.validate()

    # Invalid sender format
    bad_sender = TransportEnvelope.from_dict(valid_env.to_dict())
    bad_sender.sender_id = "INVALID_SENDER"
    with pytest.raises(TransportMessageError):
        bad_sender.validate()

    # Invalid recipient format
    bad_recip = TransportEnvelope.from_dict(valid_env.to_dict())
    bad_recip.recipient_id = "INVALID_RECIP"
    with pytest.raises(TransportMessageError):
        bad_recip.validate()

    # Negative sequence
    bad_seq = TransportEnvelope.from_dict(valid_env.to_dict())
    bad_seq.sequence = -5
    with pytest.raises(TransportMessageError):
        bad_seq.validate()

    # Expired timestamp (expires_at before created_at)
    bad_time = TransportEnvelope.from_dict(valid_env.to_dict())
    bad_time.expires_at = "2026-08-13T01:50:00+00:00"
    with pytest.raises(TransportMessageError):
        bad_time.validate()

    # Oversized payload
    with pytest.raises(TransportOversizedMessageError):
        valid_env.validate(max_size_bytes=50)


def test_transport_envelope_payload_safety_boundaries() -> None:
    """Prove TransportEnvelope strictly rejects surveillance and executable payloads."""
    forbidden_keys = [
        "exec",
        "eval",
        "shell",
        "command",
        "keystrokes",
        "screen_stream",
        "mic_stream",
        "camera_stream",
        "clipboard_data",
        "browser_history",
        "sms_messages",
        "contacts_list",
        "location_history",
    ]

    for key in forbidden_keys:
        env = TransportEnvelope(
            protocol_version="1.0",
            message_id="MSG-112233445566",
            session_id="SES-112233445566",
            sender_id="GM-P-83A1F72C",
            recipient_id="GM-C-19A84E72",
            message_type=MessageType.TELEMETRY,
            sequence=1,
            created_at="2026-08-13T02:00:00+00:00",
            expires_at="2026-08-13T02:05:00+00:00",
            payload={key: "sensitive_data"},
        )
        with pytest.raises(TransportPayloadError):
            env.validate()


def test_encrypted_transport_frame_serialization() -> None:
    """Test EncryptedTransportFrame serialization and parsing."""
    frame = EncryptedTransportFrame(
        protocol_version="1.0",
        session_id="SES-AABBCCDDEEFF",
        sequence=5,
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type="ENCRYPTED",
        nonce_hex="0102030405060708090a0b0c",
        ciphertext_hex="deadbeefcafebabe",
        created_at="2026-08-13T02:00:00+00:00",
        expires_at="2026-08-13T02:05:00+00:00",
    )

    json_str = frame.to_canonical_json()
    restored = EncryptedTransportFrame.from_json(json_str)
    assert restored.session_id == frame.session_id
    assert restored.sequence == 5
    assert restored.ciphertext_hex == "deadbeefcafebabe"


def test_peer_and_session_info_models() -> None:
    """Test PeerInfo and SessionInfo dataclass models and methods."""
    import datetime

    peer = PeerInfo(
        device_id="GM-C-19A84E72",
        role="CHILD",
        connection_state=ConnectionState.CONNECTED,
        active_session_id="SES-001",
        reconnect_count=2,
    )
    p_dict = peer.to_dict()
    assert p_dict["device_id"] == "GM-C-19A84E72"
    assert p_dict["connection_state"] == "CONNECTED"

    restored_peer = PeerInfo.from_dict(p_dict)
    assert restored_peer.reconnect_count == 2

    now = datetime.datetime.now(datetime.UTC)
    future = (now + datetime.timedelta(hours=1)).isoformat()
    past = (now - datetime.timedelta(hours=1)).isoformat()

    session = SessionInfo(
        session_id="SES-001",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        state=ConnectionState.CONNECTED,
        transport_type=TransportType.LOCAL,
        created_at=now.isoformat(),
        expires_at=future,
    )
    assert session.is_expired is False
    s_dict = session.to_dict()
    assert s_dict["is_expired"] is False

    # Expired session
    expired_sess = SessionInfo(
        session_id="SES-OLD",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        state=ConnectionState.EXPIRED,
        transport_type=TransportType.LOCAL,
        created_at=(now - datetime.timedelta(hours=2)).isoformat(),
        expires_at=past,
    )
    assert expired_sess.is_expired is True


def test_id_generators() -> None:
    """Test message and session ID generator formats."""
    mid = generate_message_id()
    assert mid.startswith("MSG-")
    assert len(mid) == 16

    sid = generate_session_id()
    assert sid.startswith("SES-")
    assert len(sid) == 16
