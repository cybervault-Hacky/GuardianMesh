"""Screen view subsystem exceptions for GuardianMesh Phase 7 (Vista v0.7.0).

This module defines the structured exception hierarchy for the consent-based,
view-only screen sharing subsystem. All errors raised within the screen module
must derive from :class:`ScreenError` (and ultimately
:class:`guardianmesh.core.errors.GuardianMeshError`).
"""

from __future__ import annotations

from guardianmesh.core.errors import GuardianMeshError, TransportMessageError


class ScreenError(GuardianMeshError):
    """Base exception for the screen view subsystem."""


class ScreenAuthorizationError(ScreenError):
    """Raised when a screen authorization decision is invalid or missing."""


class ScreenAuthorizationDeniedError(ScreenAuthorizationError):
    """Raised when a child explicitly denies a screen view request."""


class ScreenAuthorizationExpiredError(ScreenAuthorizationError):
    """Raised when a screen authorization lifetime has expired."""


class ScreenAuthorizationNotFoundError(ScreenAuthorizationError):
    """Raised when a screen authorization record cannot be located."""


class ScreenSessionError(ScreenError):
    """Base exception for screen session lifecycle operations."""


class ScreenSessionNotFoundError(ScreenSessionError):
    """Raised when a screen session cannot be located in the registry."""


class ScreenSessionStateError(ScreenSessionError):
    """Raised when an invalid state transition is attempted on a screen session."""


class ScreenSessionExpiredError(ScreenSessionError):
    """Raised when a screen session has exceeded its maximum lifetime."""


class ScreenSessionRevokedError(ScreenSessionError):
    """Raised when a screen session is terminated due to trust revocation."""


class ScreenFrameError(ScreenError):
    """Base exception for screen frame validation, parsing, and streaming."""


class ScreenFrameOversizedError(ScreenFrameError):
    """Raised when a frame payload exceeds the configured maximum size."""


class ScreenFrameSequenceError(ScreenFrameError):
    """Raised when a frame sequence number violates ordering, replay, or window rules."""


class ScreenFrameValidationError(ScreenFrameError):
    """Raised when a frame payload, codec, or resolution is invalid."""


class ScreenCodecError(ScreenError):
    """Raised when a screen codec is missing, unsupported, or invalid."""


class ScreenBackpressureError(ScreenError):
    """Raised when frame buffering is forced to drop frames under pressure."""


class ScreenProviderError(ScreenError):
    """Raised when the AndroidScreenProvider adapter cannot fulfil a capture request."""


class ScreenRemoteControlError(ScreenError):
    """Raised when a forbidden remote-control operation is attempted.

    This is a hard prohibition in Phase 7. Any attempt to invoke
    REMOTE_INPUT / SCREEN_CONTROL / SHELL / COMMAND is rejected and
    surfaced through the audit log.
    """

    def __init__(self, message: str = "Remote control is prohibited by the Vista privacy model.") -> None:
        super().__init__(message)


# Re-export for convenience: the existing transport validation handles generic
# envelope issues. The screen subsystem narrows them with a context-specific name.
ScreenTransportError = TransportMessageError


__all__ = [
    "ScreenAuthorizationDeniedError",
    "ScreenAuthorizationError",
    "ScreenAuthorizationExpiredError",
    "ScreenAuthorizationNotFoundError",
    "ScreenBackpressureError",
    "ScreenCodecError",
    "ScreenError",
    "ScreenFrameError",
    "ScreenFrameOversizedError",
    "ScreenFrameSequenceError",
    "ScreenFrameValidationError",
    "ScreenProviderError",
    "ScreenRemoteControlError",
    "ScreenSessionError",
    "ScreenSessionExpiredError",
    "ScreenSessionNotFoundError",
    "ScreenSessionRevokedError",
    "ScreenSessionStateError",
    "ScreenTransportError",
]
