"""Tests for cryptographic primitives: Ed25519 key generation, signing, and verification."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import CryptoError
from guardianmesh.security.crypto import (
    constant_time_compare,
    generate_keypair,
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
    public_key_to_raw_bytes,
    sha256_hex,
    sign_data,
    verify_signature,
)
from guardianmesh.security.fingerprints import (
    compute_public_key_fingerprint,
    compute_public_key_hex_fingerprint,
    compute_short_fingerprint,
)


def test_keypair_generation_and_serialization() -> None:
    """Test generating Ed25519 keypair and PEM serialization roundtrip."""
    priv, pub = generate_keypair()

    priv_pem = private_key_to_pem(priv)
    pub_pem = public_key_to_pem(pub)

    assert b"-----BEGIN PRIVATE KEY-----" in priv_pem
    assert b"-----END PRIVATE KEY-----" in priv_pem
    assert b"-----BEGIN PUBLIC KEY-----" in pub_pem
    assert b"-----END PUBLIC KEY-----" in pub_pem

    # Reload from PEM
    reloaded_priv = private_key_from_pem(priv_pem)
    reloaded_pub = public_key_from_pem(pub_pem)
    assert reloaded_priv is not None

    # Verify matching raw bytes
    assert public_key_to_raw_bytes(pub) == public_key_to_raw_bytes(reloaded_pub)


def test_keypair_with_passphrase() -> None:
    """Test encrypting private key PEM with a passphrase."""
    priv, _ = generate_keypair()
    password = b"strong-test-passphrase-9876"

    enc_pem = private_key_to_pem(priv, password=password)
    assert b"ENCRYPTED PRIVATE KEY" in enc_pem

    # Fails without password
    with pytest.raises(CryptoError):
        private_key_from_pem(enc_pem, password=None)

    # Fails with wrong password
    with pytest.raises(CryptoError):
        private_key_from_pem(enc_pem, password=b"wrong-password")

    # Succeeds with correct password
    loaded = private_key_from_pem(enc_pem, password=password)
    assert loaded is not None


def test_signing_and_verification() -> None:
    """Test signing data with private key and verifying with public key."""
    priv, pub = generate_keypair()
    message = b"GuardianMesh Phase 1 Genesis Authorization Token"

    signature = sign_data(priv, message)
    assert len(signature) == 64  # Ed25519 signature is 64 bytes

    # Verification should succeed
    assert verify_signature(pub, signature, message) is True

    # Tampered message should fail
    tampered_msg = b"GuardianMesh Phase 1 Genesis Tampered Token"
    assert verify_signature(pub, signature, tampered_msg) is False

    # Tampered signature should fail
    tampered_sig = bytearray(signature)
    tampered_sig[0] ^= 0xFF
    assert verify_signature(pub, bytes(tampered_sig), message) is False

    # Wrong public key should fail
    _, other_pub = generate_keypair()
    assert verify_signature(other_pub, signature, message) is False


def test_sha256_and_fingerprints() -> None:
    """Test SHA-256 digests and public key fingerprint formats."""
    data = b"GuardianMesh Genesis Test Payload"
    digest = sha256_hex(data)
    assert len(digest) == 64
    assert isinstance(digest, str)

    _, pub = generate_keypair()
    fp_standard = compute_public_key_fingerprint(pub)
    assert fp_standard.startswith("SHA256:")

    fp_hex = compute_public_key_hex_fingerprint(pub)
    assert ":" in fp_hex
    assert len(fp_hex.split(":")) == 32

    fp_short = compute_short_fingerprint(pub, length=12)
    assert fp_short.startswith("SHA256:")
    assert len(fp_short) == 7 + 12


def test_constant_time_compare() -> None:
    """Test constant time string and bytes comparison."""
    assert constant_time_compare("secret_token_123", "secret_token_123") is True
    assert constant_time_compare("secret_token_123", "secret_token_124") is False
    assert constant_time_compare(b"binary_secret", b"binary_secret") is True
    assert constant_time_compare(b"binary_secret", b"wrong_secret") is False
