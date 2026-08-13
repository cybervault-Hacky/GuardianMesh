"""Cryptographic session key exchange, HKDF derivation, and AEAD encryption for Nexus."""

from __future__ import annotations

import datetime
import secrets
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from guardianmesh.core.errors import (
    CryptoError,
    TransportAuthenticationError,
    TransportHandshakeError,
)
from guardianmesh.security.crypto import public_key_from_pem
from guardianmesh.transport.models import (
    EncryptedTransportFrame,
    MessageType,
    TransportEnvelope,
    generate_message_id,
)

HKDF_INFO_PREFIX = b"GuardianMesh-Nexus-v0.6-AES-GCM-256"


def generate_ephemeral_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate an ephemeral X25519 keypair for forward-secret Diffie-Hellman."""
    try:
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key()
    except Exception as e:
        raise CryptoError(f"Failed to generate ephemeral keypair: {e}") from e


def ephemeral_public_to_bytes(pub: x25519.X25519PublicKey) -> bytes:
    """Serialize X25519 public key to 32 raw bytes."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ephemeral_public_from_bytes(raw: bytes) -> x25519.X25519PublicKey:
    """Deserialize X25519 public key from 32 raw bytes."""
    try:
        if len(raw) != 32:
            raise CryptoError(f"Invalid X25519 public key length: expected 32 bytes, got {len(raw)}")
        return x25519.X25519PublicKey.from_public_bytes(raw)
    except Exception as e:
        raise CryptoError(f"Failed to parse X25519 public key: {e}") from e


def derive_session_keys(
    shared_secret: bytes,
    salt: bytes,
    is_initiator: bool,
    info: bytes = HKDF_INFO_PREFIX,
) -> tuple[bytes, bytes, bytes]:
    """Derive symmetric encryption keys and session IV prefix using HKDF-SHA256.

    Args:
        shared_secret: 32-byte ECDH shared secret.
        salt: Handshake salt / combined nonces.
        is_initiator: True for client (initiator), False for server (responder).
        info: Contextual info string.

    Returns:
        Tuple of (send_key, recv_key, session_salt).
    """
    try:
        # Derive 68 bytes: 32 bytes client_key, 32 bytes server_key, 4 bytes session_salt
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=68,
            salt=salt,
            info=info,
        )
        derived = hkdf.derive(shared_secret)
        client_key = derived[:32]
        server_key = derived[32:64]
        session_salt = derived[64:68]

        if is_initiator:
            return client_key, server_key, session_salt
        else:
            return server_key, client_key, session_salt
    except Exception as e:
        raise CryptoError(f"HKDF key derivation failed: {e}") from e


def construct_nonce(session_salt: bytes, sequence: int) -> bytes:
    """Construct a unique 12-byte nonce from 4-byte session salt and 8-byte uint64 sequence."""
    if len(session_salt) != 4:
        # Pad or truncate to 4 bytes if necessary
        salt_4 = (session_salt + b"\x00\x00\x00\x00")[:4]
    else:
        salt_4 = session_salt
    seq_8 = struct.pack("!Q", sequence)
    return salt_4 + seq_8


def encrypt_envelope_payload(
    send_key: bytes,
    session_salt: bytes,
    envelope: TransportEnvelope,
) -> EncryptedTransportFrame:
    """Encrypt envelope payload and authentication data using AES-256-GCM.

    Args:
        send_key: 32-byte AES key.
        session_salt: 4-byte session salt.
        envelope: Outbound TransportEnvelope.

    Returns:
        EncryptedTransportFrame.
    """
    try:
        aesgcm = AESGCM(send_key)
        nonce = construct_nonce(session_salt, envelope.sequence)

        # Associated data constructed deterministically from frame header fields
        ad_str = (
            f"{envelope.protocol_version}:{envelope.session_id}:{envelope.sequence}:"
            f"{envelope.sender_id}:{envelope.recipient_id}:{envelope.message_type.value}:"
            f"{envelope.created_at}:{envelope.expires_at}"
        )
        ad_bytes = ad_str.encode()

        import json

        plaintext_data = {
            "message_id": envelope.message_id,
            "message_type": envelope.message_type.value,
            "payload": envelope.payload,
            "authentication": envelope.authentication,
        }
        plaintext_bytes = json.dumps(plaintext_data, sort_keys=True).encode()

        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, ad_bytes)

        return EncryptedTransportFrame(
            protocol_version=envelope.protocol_version,
            session_id=envelope.session_id,
            sequence=envelope.sequence,
            sender_id=envelope.sender_id,
            recipient_id=envelope.recipient_id,
            message_type=envelope.message_type.value,
            nonce_hex=nonce.hex(),
            ciphertext_hex=ciphertext.hex(),
            created_at=envelope.created_at,
            expires_at=envelope.expires_at,
        )
    except Exception as e:
        raise CryptoError(f"Encryption failed: {e}") from e


def decrypt_frame_payload(
    recv_key: bytes,
    session_salt: bytes,
    frame: EncryptedTransportFrame,
) -> TransportEnvelope:
    """Decrypt and verify an EncryptedTransportFrame using AES-256-GCM.

    Args:
        recv_key: 32-byte AES key.
        session_salt: 4-byte session salt.
        frame: Inbound EncryptedTransportFrame.

    Returns:
        Decrypted and verified TransportEnvelope.
    """
    try:
        aesgcm = AESGCM(recv_key)
        expected_nonce = construct_nonce(session_salt, frame.sequence)
        actual_nonce = bytes.fromhex(frame.nonce_hex)

        # Verify nonce matches deterministic expectation
        if actual_nonce != expected_nonce:
            raise TransportAuthenticationError(
                "Ciphertext nonce does not match expected sequence derivation."
            )

        # Reconstruct associated data from frame header fields
        ad_str = (
            f"{frame.protocol_version}:{frame.session_id}:{frame.sequence}:"
            f"{frame.sender_id}:{frame.recipient_id}:{frame.message_type}:"
            f"{frame.created_at}:{frame.expires_at}"
        )
        ad_bytes = ad_str.encode()

        ciphertext = bytes.fromhex(frame.ciphertext_hex)

        plaintext_bytes = aesgcm.decrypt(actual_nonce, ciphertext, ad_bytes)
        import json

        data = json.loads(plaintext_bytes.decode("utf-8"))

        return TransportEnvelope(
            protocol_version=frame.protocol_version,
            message_id=str(data.get("message_id", generate_message_id())),
            session_id=frame.session_id,
            sender_id=frame.sender_id,
            recipient_id=frame.recipient_id,
            message_type=MessageType.from_str(data.get("message_type", frame.message_type)),
            sequence=frame.sequence,
            created_at=frame.created_at,
            expires_at=frame.expires_at,
            payload=data.get("payload", {}) if isinstance(data.get("payload"), dict) else {},
            authentication=data.get("authentication", {})
            if isinstance(data.get("authentication"), dict)
            else {},
        )
    except TransportAuthenticationError:
        raise
    except Exception as e:
        raise TransportAuthenticationError(
            f"Authenticated decryption failed or payload was tampered: {e}"
        ) from e


def create_session_init(
    sender_id: str,
    recipient_id: str,
    sender_private_key: ed25519.Ed25519PrivateKey,
    ephemeral_public_key: x25519.X25519PublicKey,
    ttl_seconds: int = 3600,
) -> tuple[TransportEnvelope, str]:
    """Create signed SESSION_INIT handshake envelope.

    Returns:
        Tuple of (TransportEnvelope, client_nonce).
    """
    now = datetime.datetime.now(datetime.UTC)
    created_at = now.isoformat()
    expires_at = (now + datetime.timedelta(seconds=ttl_seconds)).isoformat()
    client_nonce = secrets.token_hex(16)
    eph_bytes = ephemeral_public_to_bytes(ephemeral_public_key)

    proof_str = (
        f"GM-INIT:{sender_id}:{recipient_id}:{eph_bytes.hex()}:{client_nonce}:{created_at}:{expires_at}"
    )
    sig = sender_private_key.sign(proof_str.encode("utf-8"))

    env = TransportEnvelope(
        protocol_version="1.0",
        message_id=generate_message_id(),
        session_id="",
        sender_id=sender_id,
        recipient_id=recipient_id,
        message_type=MessageType.SESSION_INIT,
        sequence=0,
        created_at=created_at,
        expires_at=expires_at,
        payload={
            "ephemeral_pub_hex": eph_bytes.hex(),
            "client_nonce": client_nonce,
        },
        authentication={
            "signature_hex": sig.hex(),
        },
    )
    return env, client_nonce


def verify_session_init(
    envelope: TransportEnvelope,
    sender_public_key_pem: str,
) -> tuple[x25519.X25519PublicKey, str]:
    """Verify signed SESSION_INIT handshake and extract ephemeral public key and nonce."""
    if envelope.message_type != MessageType.SESSION_INIT:
        raise TransportHandshakeError(
            f"Expected SESSION_INIT message type, received '{envelope.message_type.value}'."
        )

    eph_hex = envelope.payload.get("ephemeral_pub_hex")
    client_nonce = envelope.payload.get("client_nonce")
    sig_hex = envelope.authentication.get("signature_hex")

    if not eph_hex or not client_nonce or not sig_hex:
        raise TransportHandshakeError("Malformed SESSION_INIT: missing ephemeral key, nonce, or signature.")

    try:
        eph_bytes = bytes.fromhex(eph_hex)
        eph_pub = ephemeral_public_from_bytes(eph_bytes)
        sig = bytes.fromhex(sig_hex)
    except Exception as e:
        raise TransportHandshakeError(f"Invalid hexadecimal encoding in handshake payload: {e}") from e

    proof_str = (
        f"GM-INIT:{envelope.sender_id}:{envelope.recipient_id}:{eph_hex}:{client_nonce}:"
        f"{envelope.created_at}:{envelope.expires_at}"
    )
    try:
        pub_key = public_key_from_pem(sender_public_key_pem.encode("utf-8"))
        pub_key.verify(sig, proof_str.encode("utf-8"))
    except (InvalidSignature, Exception) as e:
        raise TransportAuthenticationError(f"SESSION_INIT signature verification failed: {e}") from e

    return eph_pub, str(client_nonce)


def create_session_ack(
    sender_id: str,
    recipient_id: str,
    session_id: str,
    sender_private_key: ed25519.Ed25519PrivateKey,
    ephemeral_public_key: x25519.X25519PublicKey,
    client_ephemeral_bytes: bytes,
    client_nonce: str,
    ttl_seconds: int = 3600,
) -> tuple[TransportEnvelope, str]:
    """Create signed SESSION_ACK handshake envelope.

    Returns:
        Tuple of (TransportEnvelope, server_nonce).
    """
    now = datetime.datetime.now(datetime.UTC)
    created_at = now.isoformat()
    expires_at = (now + datetime.timedelta(seconds=ttl_seconds)).isoformat()
    server_nonce = secrets.token_hex(16)
    server_eph_bytes = ephemeral_public_to_bytes(ephemeral_public_key)

    proof_str = (
        f"GM-ACK:{sender_id}:{recipient_id}:{session_id}:{server_eph_bytes.hex()}:"
        f"{client_ephemeral_bytes.hex()}:{client_nonce}:{server_nonce}:{created_at}:{expires_at}"
    )
    sig = sender_private_key.sign(proof_str.encode("utf-8"))

    env = TransportEnvelope(
        protocol_version="1.0",
        message_id=generate_message_id(),
        session_id=session_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        message_type=MessageType.SESSION_ACK,
        sequence=0,
        created_at=created_at,
        expires_at=expires_at,
        payload={
            "session_id": session_id,
            "ephemeral_pub_hex": server_eph_bytes.hex(),
            "server_nonce": server_nonce,
        },
        authentication={
            "signature_hex": sig.hex(),
        },
    )
    return env, server_nonce


def verify_session_ack(
    envelope: TransportEnvelope,
    server_public_key_pem: str,
    expected_client_eph_bytes: bytes,
    expected_client_nonce: str,
) -> tuple[x25519.X25519PublicKey, str, str]:
    """Verify signed SESSION_ACK handshake and extract server ephemeral key, session ID, and nonce."""
    if envelope.message_type != MessageType.SESSION_ACK:
        raise TransportHandshakeError(
            f"Expected SESSION_ACK message type, received '{envelope.message_type.value}'."
        )

    session_id = envelope.payload.get("session_id") or envelope.session_id
    server_eph_hex = envelope.payload.get("ephemeral_pub_hex")
    server_nonce = envelope.payload.get("server_nonce")
    sig_hex = envelope.authentication.get("signature_hex")

    if not session_id or not server_eph_hex or not server_nonce or not sig_hex:
        raise TransportHandshakeError("Malformed SESSION_ACK: missing fields or signature.")

    try:
        server_eph_bytes = bytes.fromhex(server_eph_hex)
        server_eph_pub = ephemeral_public_from_bytes(server_eph_bytes)
        sig = bytes.fromhex(sig_hex)
    except Exception as e:
        raise TransportHandshakeError(f"Invalid hexadecimal encoding in SESSION_ACK payload: {e}") from e

    proof_str = (
        f"GM-ACK:{envelope.sender_id}:{envelope.recipient_id}:{session_id}:{server_eph_hex}:"
        f"{expected_client_eph_bytes.hex()}:{expected_client_nonce}:{server_nonce}:{envelope.created_at}:{envelope.expires_at}"
    )
    try:
        pub_key = public_key_from_pem(server_public_key_pem.encode("utf-8"))
        pub_key.verify(sig, proof_str.encode("utf-8"))
    except (InvalidSignature, Exception) as e:
        raise TransportAuthenticationError(f"SESSION_ACK signature verification failed: {e}") from e

    return server_eph_pub, str(session_id), str(server_nonce)
