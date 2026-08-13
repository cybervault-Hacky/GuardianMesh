"""Tests for AuditLogger and sensitive data sanitization/redaction."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.core.logging import redact_sensitive_data
from guardianmesh.storage.audit import AuditEventType, AuditLogger, sanitize_audit_details
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_redact_sensitive_data_helper() -> None:
    """Test text redaction of private keys, tokens, and passwords."""
    raw_pem = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIP8...
-----END PRIVATE KEY-----
"""
    scrubbed = redact_sensitive_data(raw_pem)
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed
    assert "MC4CAQA" not in scrubbed

    kv_text = "User entered password: 'SecretPassword123!' during login"
    scrubbed_kv = redact_sensitive_data(kv_text)
    assert "password=[REDACTED]" in scrubbed_kv
    assert "SecretPassword123!" not in scrubbed_kv

    otp_text = "Generated otp: 849201 for device auth"
    scrubbed_otp = redact_sensitive_data(otp_text)
    assert "[REDACTED" in scrubbed_otp
    assert "849201" not in scrubbed_otp

    pin_text = "Verification pin: 991823"
    scrubbed_pin = redact_sensitive_data(pin_text)
    assert "[REDACTED" in scrubbed_pin
    assert "991823" not in scrubbed_pin


def test_sanitize_audit_details_dict() -> None:
    """Test dictionary sanitization for audit logs."""
    details = {
        "action": "login_attempt",
        "actor": "GM-P-83A1F72C",
        "password": "ClearTextPassword",
        "token": "secret_session_token_xyz",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
        "otp_code": "123456",
        "nested": {
            "auth_token": "bearer 1234",
            "safe_counter": 42,
        },
    }

    sanitized = sanitize_audit_details(details)
    assert sanitized["action"] == "login_attempt"
    assert sanitized["actor"] == "GM-P-83A1F72C"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["private_key_pem"] == "[REDACTED]"
    assert sanitized["otp_code"] == "[REDACTED]"
    assert sanitized["nested"]["auth_token"] == "[REDACTED]"
    assert sanitized["nested"]["safe_counter"] == 42


def test_audit_logger_record_and_query(tmp_path: Path) -> None:
    """Test recording audit events and retrieving sanitized logs."""
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    logger = AuditLogger(db)

    # Record startup event
    ev1_id = logger.record(
        event_type=AuditEventType.STARTUP,
        details={"version": "0.1.0", "platform": "Linux"},
        actor_id=None,
        success=True,
    )
    assert ev1_id > 0

    # Record identity creation with a private key in details (must be redacted)
    ev2_id = logger.record(
        event_type=AuditEventType.IDENTITY_CREATED,
        details={
            "identity_id": "GM-P-83A1F72C",
            "private_key": "raw_private_bytes_should_not_leak",
            "fingerprint": "SHA256:abcd",
        },
        actor_id="GM-P-83A1F72C",
        success=True,
    )
    assert ev2_id > 0

    # Query recent events
    events = logger.get_recent(limit=10)
    assert len(events) == 2

    # Verify order: newest first
    assert events[0]["event_type"] == AuditEventType.IDENTITY_CREATED.value
    assert events[0]["actor_id"] == "GM-P-83A1F72C"
    assert events[0]["details"]["private_key"] == "[REDACTED]"
    assert events[0]["details"]["fingerprint"] == "SHA256:abcd"

    # Filter by event type
    startup_events = logger.get_recent(event_type=AuditEventType.STARTUP)
    assert len(startup_events) == 1
    assert startup_events[0]["event_type"] == AuditEventType.STARTUP.value
