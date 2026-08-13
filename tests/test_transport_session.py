"""Tests for TransportSession state, monotonic sequences, replay defense, and key wiping."""

from __future__ import annotations

import datetime

import pytest

from guardianmesh.core.errors import (
    TransportConnectionClosedError,
    TransportReplayError,
    TransportSequenceError,
    TransportSessionExpiredError,
)
from guardianmesh.transport.crypto import derive_session_keys, generate_ephemeral_keypair
from guardianmesh.transport.models import (
    ConnectionState,
    MessageType,
    TransportEnvelope,
    TransportType,
)
from guardianmesh.transport.session import TransportSession


def test_session_lifecycle_and_properties() -> None:
    """Test session initialization, activity status, expiration, and info export."""
    now = datetime.datetime.now(datetime.UTC)
    future = (now + datetime.timedelta(hours=1)).isoformat()

    session = TransportSession(
        session_id="SES-1234567890AB",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        transport_type=TransportType.MEMORY,
        state=ConnectionState.CONNECTED,
        created_at=now.isoformat(),
        expires_at=future,
    )

    assert session.is_active is True
    assert session.is_expired is False
    assert session.outbound_sequence == 0
    assert session.inbound_sequence == 0

    info = session.to_info()
    assert info.session_id == "SES-1234567890AB"
    assert info.local_identity_id == "GM-P-83A1F72C"
    assert info.remote_identity_id == "GM-C-19A84E72"
    assert info.state == ConnectionState.CONNECTED

    # Heartbeat touch
    session.touch_heartbeat()
    assert session.last_heartbeat_at is not None


def test_session_monotonic_sequence_flow() -> None:
    """Test atomic sequence advancement."""
    session = TransportSession(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
    )
    assert session.next_outbound_sequence() == 1
    assert session.next_outbound_sequence() == 2
    assert session.next_outbound_sequence() == 3
    assert session.outbound_sequence == 3


def test_session_replay_protection_rejections() -> None:
    """Test rejection of duplicate sequences, duplicate message IDs, and old sequences."""
    session = TransportSession(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        replay_window_size=10,
    )

    # 1. Accept sequence 1
    session.validate_and_advance_inbound_sequence(1, "MSG-1")
    assert session.inbound_sequence == 1

    # 2. Reject duplicate sequence 1
    with pytest.raises(TransportReplayError):
        session.validate_and_advance_inbound_sequence(1, "MSG-2")

    # 3. Reject duplicate message ID
    with pytest.raises(TransportReplayError):
        session.validate_and_advance_inbound_sequence(2, "MSG-1")

    # 4. Reject negative or zero sequence
    with pytest.raises(TransportSequenceError):
        session.validate_and_advance_inbound_sequence(0, "MSG-3")
    with pytest.raises(TransportSequenceError):
        session.validate_and_advance_inbound_sequence(-1, "MSG-4")

    # 5. Advance to sequence 20
    session.validate_and_advance_inbound_sequence(20, "MSG-20")
    assert session.inbound_sequence == 20

    # 6. Reject sequence 5 (older than sliding window boundary 20 - 10 = 10)
    with pytest.raises(TransportReplayError):
        session.validate_and_advance_inbound_sequence(5, "MSG-5")

    # 7. Valid out-of-order sequence within window (15)
    session.validate_and_advance_inbound_sequence(15, "MSG-15")


def test_session_expired_rejections() -> None:
    """Test operations on expired session are rejected."""
    now = datetime.datetime.now(datetime.UTC)
    past = (now - datetime.timedelta(minutes=10)).isoformat()

    expired_session = TransportSession(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        expires_at=past,
    )
    assert expired_session.is_expired is True

    with pytest.raises(TransportSessionExpiredError):
        expired_session.validate_and_advance_inbound_sequence(1, "MSG-1")

    with pytest.raises(TransportSessionExpiredError):
        env = TransportEnvelope(
            sender_id="GM-P-83A1F72C",
            recipient_id="GM-C-19A84E72",
        )
        expired_session.send_key = b"0" * 32
        expired_session.encrypt_envelope(env)


def test_session_encryption_and_decryption_pipeline() -> None:
    """Test session encryption and decryption pipeline between client and server sessions."""
    c_priv, c_pub = generate_ephemeral_keypair()
    s_priv, s_pub = generate_ephemeral_keypair()

    c_shared = c_priv.exchange(s_pub)
    s_shared = s_priv.exchange(c_pub)
    salt = b"test_salt_pipe"

    c_send, c_recv, c_salt = derive_session_keys(c_shared, salt, is_initiator=True)
    s_send, s_recv, s_salt = derive_session_keys(s_shared, salt, is_initiator=False)

    client_session = TransportSession(
        session_id="SES-001",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        send_key=c_send,
        recv_key=c_recv,
        session_salt=c_salt,
        state=ConnectionState.CONNECTED,
    )
    server_session = TransportSession(
        session_id="SES-001",
        local_identity_id="GM-C-19A84E72",
        remote_identity_id="GM-P-83A1F72C",
        send_key=s_send,
        recv_key=s_recv,
        session_salt=s_salt,
        state=ConnectionState.CONNECTED,
    )

    # Client -> Server message
    env1 = TransportEnvelope(
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.HEARTBEAT,
        payload={"ping": True},
    )
    frame1 = client_session.encrypt_envelope(env1)
    assert frame1.sequence == 1
    assert client_session.outbound_sequence == 1

    decrypted1 = server_session.decrypt_frame(frame1)
    assert decrypted1.sequence == 1
    assert decrypted1.payload == {"ping": True}
    assert server_session.inbound_sequence == 1

    # Server -> Client response
    env2 = TransportEnvelope(
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
        message_type=MessageType.PONG,
        payload={"pong": True},
    )
    frame2 = server_session.encrypt_envelope(env2)
    assert frame2.sequence == 1
    assert server_session.outbound_sequence == 1

    decrypted2 = client_session.decrypt_frame(frame2)
    assert decrypted2.sequence == 1
    assert decrypted2.payload == {"pong": True}
    assert client_session.inbound_sequence == 1


def test_session_close_wipes_keys() -> None:
    """Test that closing session zeroes keys in memory."""
    session = TransportSession(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        send_key=b"1" * 32,
        recv_key=b"2" * 32,
        state=ConnectionState.CONNECTED,
    )
    assert session.send_key is not None
    assert session.recv_key is not None

    session.close(reason="User terminated")
    assert session.state == ConnectionState.DISCONNECTED
    assert session.send_key is None
    assert session.recv_key is None
    assert session.closed_at is not None

    env = TransportEnvelope(sender_id="GM-P-83A1F72C", recipient_id="GM-C-19A84E72")
    with pytest.raises(TransportConnectionClosedError):
        session.encrypt_envelope(env)
