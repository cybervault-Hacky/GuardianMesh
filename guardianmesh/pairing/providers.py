"""Delivery provider abstractions for out-of-band OTP verification."""

from __future__ import annotations

import abc
import email.message
import re
import smtplib

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import PairingError, ProviderNotConfiguredError, ValidationError

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class DeliveryProvider(abc.ABC):
    """Abstract delivery provider interface for out-of-band verification codes.

    Design Rule: Contact information (email/phone) is solely a delivery conduit
    for one-time verification codes and NEVER serves as the device identity itself.
    """

    @abc.abstractmethod
    def get_provider_name(self) -> str:
        """Return user-facing provider name."""
        raise NotImplementedError

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is configured and available for dispatch."""
        raise NotImplementedError

    @abc.abstractmethod
    def send_verification_code(self, destination: str, code: str) -> bool:
        """Dispatch a one-time verification code to the destination."""
        raise NotImplementedError

    def verify_code(self, destination: str, code: str) -> bool:
        """Optional provider-side code verification (e.g. for demo provider)."""
        return False


class EmailDeliveryProvider(DeliveryProvider):
    """Production-grade SMTP / transactional Email OTP delivery provider."""

    def __init__(self, config: GuardianConfig | None = None) -> None:
        self.config = config or GuardianConfig()

    def get_provider_name(self) -> str:
        return "Email OTP Delivery"

    def is_available(self) -> bool:
        return bool(self.config.smtp_host)

    def send_verification_code(self, destination: str, code: str) -> bool:
        clean_email = destination.strip()
        if not EMAIL_REGEX.match(clean_email):
            raise ValidationError(f"Invalid email address '{destination}'.")

        if not self.is_available():
            raise ProviderNotConfiguredError(
                "Email delivery provider is not configured. "
                "Set SMTP configuration in config.json or environment variables."
            )

        msg = email.message.EmailMessage()
        from_addr = self.config.smtp_from_address or self.config.smtp_username or "noreply@guardianmesh.local"
        msg["From"] = from_addr
        msg["To"] = clean_email
        msg["Subject"] = "GuardianMesh Pairing Verification Code"

        body = (
            "GuardianMesh\n"
            "Secure Pairing Verification\n\n"
            "Your verification code is:\n\n"
            f"{code}\n\n"
            "This code is short-lived and can only be used once.\n\n"
            "If you did not initiate this request,\n"
            "ignore this email.\n"
        )
        msg.set_content(body)

        try:
            host = str(self.config.smtp_host)
            port = int(self.config.smtp_port)
            server = smtplib.SMTP(host, port, timeout=10.0)
            try:
                if self.config.smtp_use_tls:
                    server.starttls()

                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)

                server.send_message(msg)
                return True
            finally:
                server.quit()
        except smtplib.SMTPException as e:
            raise PairingError(f"SMTP delivery failed: {e}") from e
        except OSError as e:
            raise PairingError(f"Network error communicating with SMTP server: {e}") from e


class SmsDeliveryProvider(DeliveryProvider):
    """Optional SMS OTP delivery provider."""

    def __init__(self, config: GuardianConfig | None = None) -> None:
        self.config = config or GuardianConfig()

    def get_provider_name(self) -> str:
        return "SMS OTP Delivery (Optional)"

    def is_available(self) -> bool:
        # SMS requires explicit external SMS gateway configuration in future phases
        return False

    def send_verification_code(self, destination: str, code: str) -> bool:
        raise ProviderNotConfiguredError(
            "SMS delivery provider is optional and not currently configured. "
            "Please use Email or Demo verification."
        )


class DemoDeliveryProvider(DeliveryProvider):
    """Explicitly gated in-memory demo provider for local testing and developer workflows."""

    def __init__(self) -> None:
        self.last_code: str | None = None
        self.last_destination: str | None = None

    def get_provider_name(self) -> str:
        return "Demo / Local Provider"

    def is_available(self) -> bool:
        return True

    def send_verification_code(self, destination: str, code: str) -> bool:
        self.last_code = code
        self.last_destination = destination
        print()
        print("GuardianMesh")
        print("DEMO VERIFICATION MODE")
        print("───────────────────────────")
        print(f"Verification code: {code}")
        print()
        print("Development/testing only.")
        print()
        return True

    def verify_code(self, destination: str, code: str) -> bool:
        if self.last_code and self.last_code == code:
            self.last_code = None
            return True
        return False


def get_delivery_provider(method: str, config: GuardianConfig | None = None) -> DeliveryProvider:
    """Resolve the appropriate delivery provider for a verification method string."""
    norm = method.strip().upper()
    cfg = config or GuardianConfig()

    if norm in ("EMAIL", "MAIL", "1"):
        return EmailDeliveryProvider(cfg)
    elif norm in ("SMS", "PHONE", "2"):
        return SmsDeliveryProvider(cfg)
    elif norm in ("DEMO", "LOCAL", "3"):
        return DemoDeliveryProvider()

    raise ValidationError(f"Unknown verification method '{method}'. Supported methods: EMAIL, SMS, DEMO.")
