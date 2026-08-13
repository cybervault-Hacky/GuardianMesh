"""Cryptographic operations for GuardianMesh using established Ed25519 and SHA-256 primitives."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from guardianmesh.core.errors import CryptoError


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 signing keypair using cryptographically secure entropy.

    Returns:
        A tuple of (private_key, public_key).
    """
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        raise CryptoError(f"Failed to generate Ed25519 keypair: {e}") from e


def private_key_to_pem(
    private_key: ed25519.Ed25519PrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialize an Ed25519 private key to PKCS#8 PEM bytes.

    Args:
        private_key: The private key to serialize.
        password: Optional encryption passphrase.

    Returns:
        PEM formatted bytes.
    """
    try:
        if password:
            encryption: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(
                password
            )
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    except Exception as e:
        raise CryptoError(f"Failed to serialize private key to PEM: {e}") from e


def public_key_to_pem(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to SubjectPublicKeyInfo PEM bytes."""
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as e:
        raise CryptoError(f"Failed to serialize public key to PEM: {e}") from e


def public_key_to_raw_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Export raw 32-byte Ed25519 public key."""
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception as e:
        raise CryptoError(f"Failed to export raw public key: {e}") from e


def private_key_from_pem(
    pem_bytes: bytes,
    password: bytes | None = None,
) -> ed25519.Ed25519PrivateKey:
    """Deserialize an Ed25519 private key from PEM bytes."""
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=password)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise CryptoError("Key is not an Ed25519 private key")
        return key
    except Exception as e:
        raise CryptoError(f"Failed to load private key from PEM: {e}") from e


def public_key_from_pem(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Deserialize an Ed25519 public key from PEM bytes."""
    try:
        key = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise CryptoError("Key is not an Ed25519 public key")
        return key
    except Exception as e:
        raise CryptoError(f"Failed to load public key from PEM: {e}") from e


def sign_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign arbitrary data using an Ed25519 private key.

    Args:
        private_key: The signer's private key.
        data: The message payload to sign.

    Returns:
        64-byte Ed25519 signature.
    """
    try:
        return private_key.sign(data)
    except Exception as e:
        raise CryptoError(f"Signing operation failed: {e}") from e


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify an Ed25519 signature over data.

    Args:
        public_key: The expected signer's public key.
        signature: 64-byte signature to verify.
        data: Message payload.

    Returns:
        True if valid, False if invalid or verification fails.
    """
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hexadecimal digest of input bytes."""
    return hashlib.sha256(data).hexdigest()


def constant_time_compare(a: str | bytes, b: str | bytes) -> bool:
    """Compare two secrets in constant time to prevent timing attacks."""
    a_bytes = a.encode("utf-8") if isinstance(a, str) else a
    b_bytes = b.encode("utf-8") if isinstance(b, str) else b
    return hmac.compare_digest(a_bytes, b_bytes)
