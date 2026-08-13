"""Tests for cryptographically secure OTP generation, salt hashing, and verification."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import ValidationError
from guardianmesh.pairing.otp import (
    OTP_REGEX,
    calculate_expiry_iso,
    compute_otp_verifier,
    generate_otp_code,
    generate_otp_salt,
    validate_otp_format,
    verify_otp_code,
)


def test_generate_otp_code_format() -> None:
    """Test OTP code is exactly 6 digits."""
    for _ in range(100):
        code = generate_otp_code()
        assert len(code) == 6
        assert code.isdigit()
        assert OTP_REGEX.match(code)


def test_generate_otp_salt() -> None:
    """Test salt generation produces unique 32-char hex strings."""
    salts = {generate_otp_salt() for _ in range(50)}
    assert len(salts) == 50
    for s in salts:
        assert len(s) == 32


def test_compute_and_verify_otp() -> None:
    """Test verifier computation and constant-time code verification."""
    session_id = "PAIR-A1B2C3"
    code = "483921"
    salt = generate_otp_salt()

    verifier = compute_otp_verifier(session_id, code, salt)
    assert len(verifier) == 64  # SHA-256 hex digest
    assert isinstance(verifier, str)

    # Correct code succeeds
    assert verify_otp_code(session_id, code, salt, verifier) is True

    # Code with whitespace/hyphens normalizes and succeeds
    assert verify_otp_code(session_id, " 483 921 ", salt, verifier) is True
    assert verify_otp_code(session_id, "483-921", salt, verifier) is True

    # Wrong code fails
    assert verify_otp_code(session_id, "123456", salt, verifier) is False

    # Wrong session fails (session binding)
    assert verify_otp_code("PAIR-DIFFERENT", code, salt, verifier) is False

    # Missing salt or verifier fails safely
    assert verify_otp_code(session_id, code, None, verifier) is False
    assert verify_otp_code(session_id, code, salt, None) is False

    # Non-digit input fails
    assert verify_otp_code(session_id, "abcdef", salt, verifier) is False


def test_validate_otp_format() -> None:
    """Test OTP format validator."""
    assert validate_otp_format("123456") == "123456"
    assert validate_otp_format(" 987 654 ") == "987654"
    assert validate_otp_format("987-654") == "987654"

    with pytest.raises(ValidationError):
        validate_otp_format("12345")  # 5 digits

    with pytest.raises(ValidationError):
        validate_otp_format("1234567")  # 7 digits

    with pytest.raises(ValidationError):
        validate_otp_format("abcdef")


def test_calculate_expiry_iso() -> None:
    """Test ISO timestamp expiry generator."""
    exp = calculate_expiry_iso(300)
    assert "T" in exp
    assert exp.endswith("+00:00") or "Z" in exp or ":" in exp
