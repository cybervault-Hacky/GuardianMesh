"""Cryptographically secure OTP generation, verifier hashing, and validation."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import re
import secrets

from guardianmesh.core.errors import ValidationError

OTP_REGEX = re.compile(r"^\d{6}$")


def generate_otp_code() -> str:
    """Generate a 6-digit numeric one-time passcode using system CSPRNG."""
    number = secrets.randbelow(1_000_000)
    return f"{number:06d}"


def generate_otp_salt() -> str:
    """Generate a cryptographically secure salt for OTP verifier computation."""
    return secrets.token_hex(16)


def compute_otp_verifier(session_id: str, otp_code: str, salt: str) -> str:
    """Compute a salted cryptographic verifier for an OTP.

    Plaintext OTPs are NEVER stored. Only this salted verifier hash is persisted.
    """
    clean_code = otp_code.strip()
    payload = f"{salt}:{session_id}:{clean_code}".encode()
    return hashlib.sha256(payload).hexdigest()


def verify_otp_code(
    session_id: str,
    entered_code: str,
    salt: str | None,
    expected_verifier: str | None,
) -> bool:
    """Validate an entered OTP code against the stored salted verifier in constant time."""
    if not salt or not expected_verifier:
        return False

    normalized_code = entered_code.replace(" ", "").replace("-", "").strip()
    if not OTP_REGEX.match(normalized_code):
        return False

    computed = compute_otp_verifier(session_id, normalized_code, salt)
    return hmac.compare_digest(computed, expected_verifier)


def calculate_expiry_iso(lifetime_seconds: int = 300) -> str:
    """Compute an ISO 8601 UTC timestamp for future expiration."""
    now = datetime.datetime.now(datetime.UTC)
    expiry = now + datetime.timedelta(seconds=lifetime_seconds)
    return expiry.isoformat()


def validate_otp_format(code: str) -> str:
    """Normalize and validate 6-digit OTP format."""
    cleaned = code.replace(" ", "").replace("-", "").strip()
    if not OTP_REGEX.match(cleaned):
        raise ValidationError("Verification code must be exactly 6 digits.")
    return cleaned
