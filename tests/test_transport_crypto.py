"""Tests for Nexus cryptographic key exchange, HKDF key derivation, AEAD encryption, and handshakes."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import (
    CryptoError,
    TransportAuthenticationError,
    TransportHandshakeError,
)
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.transport.crypto import (
    create_session_ack,
    create_session_init,
    decrypt_frame_payload,
    derive_session_keys,
    encrypt_envelope_payload,
    ephemeral_public_from_bytes,
    ephemeral_public_to_bytes,
    generate_ephemeral_keypair,
    verify_session_ack,
    verify_session_init,
)
from guardianmesh.transport.models import (
    EncryptedTransportFrame,
    MessageType,
    TransportEnvelope,
)


def test_ephemeral_keypair_generation_and_raw_bytes() -> None:
    """Test X25519 ephemeral key generation and raw byte serialization."""
    priv, pub = generate_ephemeral_keypair()
    raw = ephemeral_public_to_bytes(pub)
    assert len(raw) == 32

    restored_pub = ephemeral_public_from_bytes(raw)
    assert ephemeral_public_to_bytes(restored_pub) == raw

    # Invalid length
    with pytest.raises(CryptoError):
        ephemeral_public_from_bytes(b"short_key")


def test_hkdf_session_key_derivation() -> None:
    """Test ECDH exchange and reciprocal HKDF key derivation."""
    client_priv, client_pub = generate_ephemeral_keypair()
    server_priv, server_pub = generate_ephemeral_keypair()

    client_shared = client_priv.exchange(server_pub)
    server_shared = server_priv.exchange(client_pub)
    assert client_shared == server_shared

    salt = b"test_salt_12345"
    c_send, c_recv, c_salt = derive_session_keys(client_shared, salt, is_initiator=True)
    s_send, s_recv, s_salt = derive_session_keys(server_shared, salt, is_initiator=False)

    # Client send key must equal Server recv key
    assert c_send == s_recv
    # Server send key must equal Client recv key
    assert s_send == c_recv
    # Session salt must match
    assert c_salt == s_salt
    assert len(c_send) == 32
    assert len(s_send) == 32


def test_aes_gcm_envelope_encryption_and_decryption() -> None:
    """Test AES-256-GCM envelope payload encryption and verified decryption."""
    priv, pub = generate_ephemeral_keypair()
    shared = priv.exchange(pub)
    send_key, recv_key, session_salt = derive_session_keys(shared, b"salt", is_initiator=True)

    envelope = TransportEnvelope(
        protocol_version="1.0",
        message_id="MSG-A1B2C3D4E5F6",
        session_id="SES-001122334455",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.TELEMETRY,
        sequence=1,
        created_at="2026-08-13T02:00:00+00:00",
        expires_at="2026-08-13T02:05:00+00:00",
        payload={"battery_percent": 90, "connectivity": "ONLINE"},
        authentication={"source": "agent"},
    )

    frame = encrypt_envelope_payload(send_key, session_salt, envelope)
    assert frame.sequence == 1
    assert frame.session_id == envelope.session_id
    assert frame.ciphertext_hex != ""

    decrypted_env = decrypt_frame_payload(send_key, session_salt, frame)
    assert decrypted_env.message_id == envelope.message_id
    assert decrypted_env.session_id == envelope.session_id
    assert decrypted_env.payload == {"battery_percent": 90, "connectivity": "ONLINE"}
    assert decrypted_env.authentication == {"source": "agent"}


def test_aes_gcm_tamper_detection() -> None:
    """Test that tampering with ciphertext, nonce, or header raises authentication error."""
    priv, pub = generate_ephemeral_keypair()
    shared = priv.exchange(pub)
    send_key, _, session_salt = derive_session_keys(shared, b"salt", is_initiator=True)

    envelope = TransportEnvelope(
        protocol_version="1.0",
        message_id="MSG-A1B2C3D4E5F6",
        session_id="SES-001122334455",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.HEARTBEAT,
        sequence=1,
        created_at="2026-08-13T02:00:00+00:00",
        expires_at="2026-08-13T02:05:00+00:00",
        payload={"time": "2026-08-13T02:00:00Z"},
    )
    frame = encrypt_envelope_payload(send_key, session_salt, envelope)

    # 1. Tamper with ciphertext
    raw_ct = bytearray(bytes.fromhex(frame.ciphertext_hex))
    raw_ct[0] ^= 0xFF
    bad_ct_frame = EncryptedTransportFrame.from_dict(frame.to_dict())
    bad_ct_frame.ciphertext_hex = bytes(raw_ct).hex()
    with pytest.raises(TransportAuthenticationError):
        decrypt_frame_payload(send_key, session_salt, bad_ct_frame)

    # 2. Tamper with nonce
    bad_nonce_frame = EncryptedTransportFrame.from_dict(frame.to_dict())
    bad_nonce_frame.nonce_hex = "00" * 12
    with pytest.raises(TransportAuthenticationError):
        decrypt_frame_payload(send_key, session_salt, bad_nonce_frame)

    # 3. Tamper with associated data (recipient altered in frame)
    bad_recip_frame = EncryptedTransportFrame.from_dict(frame.to_dict())
    bad_recip_frame.recipient_id = "GM-C-99999999"
    with pytest.raises(TransportAuthenticationError):
        decrypt_frame_payload(send_key, session_salt, bad_recip_frame)


def test_handshake_session_init_and_verification() -> None:
    """Test signed SESSION_INIT handshake creation and verification."""
    client_ed_priv, client_ed_pub = generate_keypair()
    client_ed_pem = public_key_to_pem(client_ed_pub).decode("utf-8")

    client_eph_priv, client_eph_pub = generate_ephemeral_keypair()

    init_env, client_nonce = create_session_init(
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
        sender_private_key=client_ed_priv,
        ephemeral_public_key=client_eph_pub,
    )
    assert init_env.message_type == MessageType.SESSION_INIT
    assert "ephemeral_pub_hex" in init_env.payload
    assert "signature_hex" in init_env.authentication

    # Successful verification
    restored_eph, verified_nonce = verify_session_init(
        envelope=init_env,
        sender_public_key_pem=client_ed_pem,
    )
    assert verified_nonce == client_nonce
    assert ephemeral_public_to_bytes(restored_eph) == ephemeral_public_to_bytes(client_eph_pub)

    # Rejection on wrong public key
    _, other_ed_pub = generate_keypair()
    other_pem = public_key_to_pem(other_ed_pub).decode("utf-8")
    with pytest.raises(TransportAuthenticationError):
        verify_session_init(envelope=init_env, sender_public_key_pem=other_pem)

    # Rejection on invalid message type
    bad_type_env = TransportEnvelope.from_dict(init_env.to_dict())
    bad_type_env.message_type = MessageType.HEARTBEAT
    with pytest.raises(TransportHandshakeError):
        verify_session_init(envelope=bad_type_env, sender_public_key_pem=client_ed_pem)


def test_handshake_session_ack_and_verification() -> None:
    """Test signed SESSION_ACK handshake creation and verification."""
    client_eph_priv, client_eph_pub = generate_ephemeral_keypair()
    client_eph_bytes = ephemeral_public_to_bytes(client_eph_pub)
    client_nonce = "client_test_nonce_123"

    server_ed_priv, server_ed_pub = generate_keypair()
    server_ed_pem = public_key_to_pem(server_ed_pub).decode("utf-8")
    server_eph_priv, server_eph_pub = generate_ephemeral_keypair()

    ack_env, server_nonce = create_session_ack(
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        session_id="SES-1234567890AB",
        sender_private_key=server_ed_priv,
        ephemeral_public_key=server_eph_pub,
        client_ephemeral_bytes=client_eph_bytes,
        client_nonce=client_nonce,
    )
    assert ack_env.message_type == MessageType.SESSION_ACK

    # Successful verification
    restored_srv_eph, sess_id, srv_nonce = verify_session_ack(
        envelope=ack_env,
        server_public_key_pem=server_ed_pem,
        expected_client_eph_bytes=client_eph_bytes,
        expected_client_nonce=client_nonce,
    )
    assert sess_id == "SES-1234567890AB"
    assert srv_nonce == server_nonce
    assert ephemeral_public_to_bytes(restored_srv_eph) == ephemeral_public_to_bytes(server_eph_pub)

    # Rejection on wrong client nonce expectation
    with pytest.raises(TransportAuthenticationError):
        verify_session_ack(
            envelope=ack_env,
            server_public_key_pem=server_ed_pem,
            expected_client_eph_bytes=client_eph_bytes,
            expected_client_nonce="wrong_client_nonce",
        )
