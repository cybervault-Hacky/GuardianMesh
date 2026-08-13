"""Tests for future pairing delivery provider abstractions and telemetry models."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import ProviderNotConfiguredError
from guardianmesh.pairing import (
    DemoDeliveryProvider,
    EmailDeliveryProvider,
    PairingState,
    SmsDeliveryProvider,
)
from guardianmesh.telemetry import DeviceHealthSummary


def test_pairing_states() -> None:
    """Test pairing state enum definitions."""
    assert PairingState.UNCONFIGURED == "UNCONFIGURED"
    assert PairingState.INITIATED == "INITIATED"
    assert PairingState.AWAITING_VERIFICATION == "AWAITING_VERIFICATION"
    assert PairingState.AUTHORIZED == "AUTHORIZED"
    assert PairingState.REJECTED == "REJECTED"
    assert PairingState.EXPIRED == "EXPIRED"


def test_demo_delivery_provider() -> None:
    """Test demo delivery provider sends and verifies OTP tokens."""
    provider = DemoDeliveryProvider()
    assert provider.get_provider_name() == "Demo / Local Provider"

    dest = "parent@example.com"
    code = "492019"

    assert provider.send_verification_code(dest, code) is True

    # Wrong code fails
    assert provider.verify_code(dest, "000000") is False

    # Correct code succeeds
    assert provider.verify_code(dest, code) is True

    # One-time use: second verification should fail
    assert provider.verify_code(dest, code) is False


def test_phase2_stubs_raise_not_implemented() -> None:
    """Verify that unconfigured Email and SMS delivery providers reject dispatch."""
    email_prov = EmailDeliveryProvider()
    assert "Email" in email_prov.get_provider_name()
    with pytest.raises(ProviderNotConfiguredError):
        email_prov.send_verification_code("user@example.com", "123456")

    sms_prov = SmsDeliveryProvider()
    assert "SMS" in sms_prov.get_provider_name()
    with pytest.raises(ProviderNotConfiguredError):
        sms_prov.send_verification_code("+15550001", "123456")


def test_telemetry_model() -> None:
    """Test device health summary dataclass."""
    summary = DeviceHealthSummary(
        identity_id="GM-C-19A84E72",
        battery_level_pct=85,
        is_charging=True,
        storage_free_mb=12400,
        app_version="0.1.0",
        last_seen_utc="2026-08-12T12:00:00Z",
    )
    assert summary.identity_id == "GM-C-19A84E72"
    assert summary.battery_level_pct == 85
    assert summary.is_charging is True
    assert summary.app_version == "0.1.0"
