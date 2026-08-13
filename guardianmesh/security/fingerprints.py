"""Cryptographic key fingerprinting utilities for GuardianMesh."""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519

from guardianmesh.security.crypto import public_key_to_raw_bytes


def compute_public_key_fingerprint(
    key_material: ed25519.Ed25519PublicKey | bytes | str,
) -> str:
    """Compute SHA-256 fingerprint for a public key.

    Returns string in standard format:
    SHA256:<base64-encoded-digest-without-padding> (similar to OpenSSH).
    """
    raw_bytes: bytes
    if isinstance(key_material, ed25519.Ed25519PublicKey):
        raw_bytes = public_key_to_raw_bytes(key_material)
    elif isinstance(key_material, str):
        raw_bytes = key_material.encode("utf-8")
    else:
        raw_bytes = key_material

    digest = hashlib.sha256(raw_bytes).digest()
    b64_digest = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{b64_digest}"


def compute_public_key_hex_fingerprint(
    key_material: ed25519.Ed25519PublicKey | bytes | str,
) -> str:
    """Compute colon-delimited hexadecimal fingerprint (e.g. 83:A1:F7:...)."""
    raw_bytes: bytes
    if isinstance(key_material, ed25519.Ed25519PublicKey):
        raw_bytes = public_key_to_raw_bytes(key_material)
    elif isinstance(key_material, str):
        raw_bytes = key_material.encode("utf-8")
    else:
        raw_bytes = key_material

    digest = hashlib.sha256(raw_bytes).digest()
    return ":".join(f"{b:02X}" for b in digest)


def compute_short_fingerprint(
    key_material: ed25519.Ed25519PublicKey | bytes | str,
    length: int = 12,
) -> str:
    """Compute a compact fingerprint suitable for status displays and audit logs."""
    raw_bytes: bytes
    if isinstance(key_material, ed25519.Ed25519PublicKey):
        raw_bytes = public_key_to_raw_bytes(key_material)
    elif isinstance(key_material, str):
        raw_bytes = key_material.encode("utf-8")
    else:
        raw_bytes = key_material

    digest = hashlib.sha256(raw_bytes).hexdigest().upper()
    return f"SHA256:{digest[:length]}"
