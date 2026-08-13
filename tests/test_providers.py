"""Tests for OTP delivery providers: Email (SMTP), SMS, and Demo."""

from __future__ import annotations

import smtplib
from unittest.mock import MagicMock, patch

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import PairingError, ProviderNotConfiguredError, ValidationError
from guardianmesh.pairing.providers import (
    DemoDeliveryProvider,
    EmailDeliveryProvider,
    SmsDeliveryProvider,
    get_delivery_provider,
)


def test_email_provider_unconfigured() -> None:
    """Test Email provider reports unavailable when SMTP host is missing."""
    config = GuardianConfig(smtp_host=None)
    provider = EmailDeliveryProvider(config)
    assert not provider.is_available()

    with pytest.raises(ProviderNotConfiguredError):
        provider.send_verification_code("parent@example.com", "483921")


def test_email_provider_invalid_address() -> None:
    """Test Email provider validates recipient email format."""
    config = GuardianConfig(smtp_host="smtp.example.com")
    provider = EmailDeliveryProvider(config)

    with pytest.raises(ValidationError):
        provider.send_verification_code("not-an-email", "483921")


def test_email_provider_smtp_dispatch() -> None:
    """Test Email provider dispatches message via mock SMTP server."""
    config = GuardianConfig(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="user@example.com",
        smtp_password="test-password-secret",
        smtp_use_tls=True,
        smtp_from_address="noreply@example.com",
    )
    provider = EmailDeliveryProvider(config)
    assert provider.is_available()

    mock_smtp_instance = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp_instance) as mock_smtp_cls:
        success = provider.send_verification_code("parent@example.com", "483921")
        assert success is True
        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=10.0)
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with("user@example.com", "test-password-secret")
        mock_smtp_instance.send_message.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()


def test_email_provider_smtp_error_handling() -> None:
    """Test Email provider handles SMTP errors gracefully."""
    config = GuardianConfig(smtp_host="smtp.example.com")
    provider = EmailDeliveryProvider(config)

    with patch("smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, "Cannot connect")):
        with pytest.raises(PairingError) as excinfo:
            provider.send_verification_code("parent@example.com", "483921")
        assert "SMTP delivery failed" in str(excinfo.value)


def test_sms_provider_optional_status() -> None:
    """Test SMS provider is marked optional and unconfigured."""
    provider = SmsDeliveryProvider()
    assert not provider.is_available()
    assert "SMS" in provider.get_provider_name()

    with pytest.raises(ProviderNotConfiguredError):
        provider.send_verification_code("+15551234567", "483921")


def test_demo_provider_lifecycle(capsys: pytest.CaptureFixture[str]) -> None:
    """Test Demo delivery provider displays banner and stores code for verification."""
    provider = DemoDeliveryProvider()
    assert provider.is_available()
    assert provider.get_provider_name() == "Demo / Local Provider"

    assert provider.send_verification_code("demo@example.com", "483921") is True
    out = capsys.readouterr().out
    assert "DEMO VERIFICATION MODE" in out
    assert "483921" in out

    # Test provider verify_code
    assert provider.verify_code("demo@example.com", "483921") is True
    # Single-use: subsequent check returns False
    assert provider.verify_code("demo@example.com", "483921") is False


def test_get_delivery_provider_resolver() -> None:
    """Test get_delivery_provider factory method."""
    p_email = get_delivery_provider("EMAIL")
    assert isinstance(p_email, EmailDeliveryProvider)

    p_sms = get_delivery_provider("SMS")
    assert isinstance(p_sms, SmsDeliveryProvider)

    p_demo = get_delivery_provider("DEMO")
    assert isinstance(p_demo, DemoDeliveryProvider)

    with pytest.raises(ValidationError):
        get_delivery_provider("UNSUPPORTED_METHOD")
