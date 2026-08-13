"""Tests for telemetry allowlists, envelope canonical signing, and health data models."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import TelemetryValidationError
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.telemetry.models import (
    FORBIDDEN_FIELDS,
    DeviceHealthState,
    DeviceHealthSummary,
    TelemetryEnvelope,
    validate_health_payload,
)


def test_privacy_allowlist_enforcement() -> None:
    """Ensure strictly allowlisted technical health fields pass validation."""
    valid_payload = {
        "battery_percent": 80,
        "charging": True,
        "storage_total_bytes": 100_000_000_000,
        "storage_free_bytes": 45_000_000_000,
        "uptime_seconds": 7200,
        "connectivity": "ONLINE",
        "platform": "Linux",
        "agent_version": "0.3.0",
    }
    # Should not raise
    validate_health_payload(valid_payload)


@pytest.mark.parametrize("forbidden_key", list(FORBIDDEN_FIELDS))
def test_privacy_forbidden_fields_rejection(forbidden_key: str) -> None:
    """Aggressively verify that any prohibited surveillance field is immediately rejected."""
    payload = {
        "battery_percent": 80,
        forbidden_key: "forbidden_surveillance_data",
    }
    with pytest.raises(TelemetryValidationError) as excinfo:
        validate_health_payload(payload)
    assert "Privacy violation" in str(excinfo.value) or "prohibited" in str(excinfo.value)


def test_unknown_fields_rejection() -> None:
    """Verify that arbitrary non-allowlisted fields are rejected."""
    payload = {
        "battery_percent": 80,
        "random_custom_telemetry_key": 12345,
    }
    with pytest.raises(TelemetryValidationError) as excinfo:
        validate_health_payload(payload)
    assert "non-allowlisted" in str(excinfo.value)


def test_field_range_validation() -> None:
    """Verify numeric range checks on health fields."""
    with pytest.raises(TelemetryValidationError):
        validate_health_payload({"battery_percent": 150})

    with pytest.raises(TelemetryValidationError):
        validate_health_payload({"battery_percent": -5})

    with pytest.raises(TelemetryValidationError):
        validate_health_payload({"storage_free_bytes": -100})


def test_envelope_canonical_signing_and_verification() -> None:
    """Test TelemetryEnvelope canonical JSON serialization, signing, and Ed25519 verification."""
    priv, pub = generate_keypair()
    pub_pem = public_key_to_pem(pub).decode("utf-8")

    payload = {
        "battery_percent": 75,
        "charging": False,
        "connectivity": "ONLINE",
        "agent_version": "0.3.0",
    }

    envelope = TelemetryEnvelope(
        device_id="GM-C-19A84E72",
        sequence=1,
        payload=payload,
        captured_at="2026-08-12T19:00:00+00:00",
    )

    # Verify canonical bytes are deterministic
    bytes1 = envelope.canonical_bytes()
    bytes2 = envelope.canonical_bytes()
    assert bytes1 == bytes2
    assert b'"device_id":"GM-C-19A84E72"' in bytes1

    # Sign envelope
    envelope.sign(priv)
    assert envelope.signature is not None

    # Verify signature
    assert envelope.verify_signature(pub_pem) is True

    # Tampered payload fails verification
    tampered_envelope = TelemetryEnvelope(
        device_id="GM-C-19A84E72",
        sequence=1,
        payload={
            "battery_percent": 10,
            "charging": False,
            "connectivity": "ONLINE",
            "agent_version": "0.3.0",
        },
        captured_at="2026-08-12T19:00:00+00:00",
        signature=envelope.signature,
    )
    assert tampered_envelope.verify_signature(pub_pem) is False


def test_device_health_summary_helpers() -> None:
    """Test DeviceHealthSummary conversions."""
    summary = DeviceHealthSummary(
        device_id="GM-C-19A84E72",
        health_state=DeviceHealthState.ONLINE,
        battery_percent=88,
        storage_free_bytes=42_949_672_960,  # exactly 40 GB
        uptime_seconds=3665,  # 1h 1m
    )
    assert summary.storage_free_gb == 40.0
    assert summary.uptime_display == "1h 1m"
