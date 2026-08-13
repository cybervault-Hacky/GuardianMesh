"""Structured exception hierarchy for GuardianMesh."""

from __future__ import annotations

from typing import Any


class GuardianMeshError(Exception):
    """Base exception for all GuardianMesh operations."""

    def __init__(
        self,
        message: str,
        code: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigError(GuardianMeshError):
    """Raised when configuration loading, validation, or persistence fails."""


class StorageError(GuardianMeshError):
    """Raised when database or filesystem storage operations encounter an error."""


class DatabaseMigrationError(StorageError):
    """Raised when a database migration fails or schema versioning is invalid."""


class DatabaseIntegrityError(StorageError):
    """Raised when database integrity checks fail."""


class IdentityError(GuardianMeshError):
    """Base exception for identity management operations."""


class InvalidIdentityError(IdentityError):
    """Raised when an identity identifier has an invalid format or checksum."""


class IdentityNotFoundError(IdentityError):
    """Raised when a requested identity cannot be found."""


class SecurityError(GuardianMeshError):
    """Base exception for security and cryptographic operations."""


class CryptoError(SecurityError):
    """Raised when cryptographic key generation, signing, or verification fails."""


class KeyStorageError(SecurityError):
    """Raised when secure key storage, retrieval, or permission verification fails."""


class AuditError(GuardianMeshError):
    """Raised when recording or retrieving audit trail events fails."""


class PlatformError(GuardianMeshError):
    """Raised when platform compatibility checks or environment requirements fail."""


class ValidationError(GuardianMeshError):
    """Raised when input validation fails."""


# ---------------------------------------------------------------------
# Phase 2: Pairing, OTP & Trust Exceptions
# ---------------------------------------------------------------------


class PairingError(GuardianMeshError):
    """Base exception for pairing and verification operations."""


class InvalidStateTransitionError(PairingError):
    """Raised when an illegal pairing session state transition is attempted."""


class PairingSessionNotFoundError(PairingError):
    """Raised when a requested pairing session does not exist."""


class PairingSessionExpiredError(PairingError):
    """Raised when an action is attempted on an expired pairing session."""


class OTPVerificationError(PairingError):
    """Base exception for one-time passcode verification failures."""


class OTPExpiredError(OTPVerificationError):
    """Raised when an entered OTP has passed its expiration time."""


class OTPAttemptLimitExceededError(OTPVerificationError):
    """Raised when maximum allowed OTP verification attempts are exceeded."""


class RateLimitExceededError(PairingError):
    """Raised when OTP generation or resend cooldown rate limits are violated."""


class ChildAuthorizationDeniedError(PairingError):
    """Raised when the child device explicitly rejects or denies pairing authorization."""


class InvalidNonceError(PairingError):
    """Raised when an authorization challenge nonce is missing, invalid, or expired."""


class ReplayedNonceError(InvalidNonceError):
    """Raised when an authorization challenge nonce has already been consumed."""


class ProviderNotConfiguredError(PairingError):
    """Raised when an unconfigured delivery provider is invoked."""


class TrustError(GuardianMeshError):
    """Base exception for device trust management and authentication."""


class TrustRevokedError(TrustError):
    """Raised when an operation is attempted with a revoked trust relationship."""


class DeviceNotTrustedError(TrustError):
    """Raised when a remote device is not in the active trusted device list."""


# ---------------------------------------------------------------------
# Phase 3: Telemetry & Device Health Exceptions
# ---------------------------------------------------------------------


class TelemetryError(GuardianMeshError):
    """Base exception for telemetry collection, processing, and transport."""


class TelemetryValidationError(TelemetryError):
    """Raised when telemetry payload contains non-allowlisted or malformed fields."""


class TelemetryReplayError(TelemetryError):
    """Raised when a telemetry envelope contains an old, duplicate, or replayed sequence number."""


class TelemetrySignatureError(TelemetryError):
    """Raised when a telemetry envelope cryptographic signature verification fails."""


class TelemetryTimestampError(TelemetryError):
    """Raised when telemetry timestamp is expired, corrupted, or violates clock skew tolerance."""


class TelemetryAuthenticationError(TelemetryError):
    """Raised when telemetry arrives from an unknown or revoked device."""


class TelemetryTransportError(TelemetryError):
    """Raised when sending or receiving telemetry over a transport fails."""


class TelemetryDevicePausedError(TelemetryError):
    """Raised when an operation is attempted on a device with paused telemetry collection."""


# ---------------------------------------------------------------------
# Phase 4: Policy, Rule & Alert Exceptions
# ---------------------------------------------------------------------


class PolicyError(GuardianMeshError):
    """Base exception for policy engine and rule management."""


class PolicyNotFoundError(PolicyError):
    """Raised when a requested policy is not found."""


class PolicyValidationError(PolicyError):
    """Raised when policy parameters, thresholds, or configurations are invalid."""


class InvalidRuleError(PolicyError):
    """Raised when a rule configuration has invalid threshold or duration bounds."""


class AlertError(GuardianMeshError):
    """Base exception for alert lifecycle management."""


class AlertNotFoundError(AlertError):
    """Raised when a requested alert cannot be found."""


# ---------------------------------------------------------------------
# Phase 6: Transport & Channel Exceptions (Nexus)
# ---------------------------------------------------------------------


class TransportError(GuardianMeshError):
    """Base exception for transport and encrypted channel operations."""


class TransportAuthenticationError(TransportError):
    """Raised when mutual authentication or identity proof verification fails."""


class TransportHandshakeError(TransportError):
    """Raised when session key agreement or cryptographic handshake fails."""


class TransportSessionExpiredError(TransportError):
    """Raised when an action is attempted on an expired transport session."""


class TransportReplayError(TransportError):
    """Raised when a replayed or duplicate message sequence is detected."""


class TransportSequenceError(TransportError):
    """Raised when an out-of-order or invalid sequence number is detected."""


class TransportConnectionClosedError(TransportError):
    """Raised when an operation is attempted on a closed or terminated transport."""


class TransportTimeoutError(TransportError):
    """Raised when a transport handshake, receive, or heartbeat times out."""


class TransportMessageError(TransportError):
    """Raised when a message envelope is malformed, invalid, or unsupported."""


class TransportPayloadError(TransportError):
    """Raised when an envelope payload fails schema or allowlist validation."""


class TransportRevokedError(TransportError):
    """Raised when transport is attempted with a revoked device."""


class TransportStateError(TransportError):
    """Raised when an invalid transport state transition is attempted."""


class TransportFramingError(TransportError):
    """Raised when stream framing or length-prefix parsing fails."""


class TransportOversizedMessageError(TransportError):
    """Raised when an inbound or outbound message exceeds maximum size limit."""

