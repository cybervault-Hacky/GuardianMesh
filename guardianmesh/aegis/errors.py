"""Aegis Phase 8 exception hierarchy.

All Aegis-specific errors derive from :class:`AegisError`, which itself
derives from :class:`guardianmesh.core.errors.GuardianMeshError`. This
allows callers to handle Aegis failures uniformly with the rest of the
GuardianMesh exception tree.

The hierarchy enforces the privacy model of Aegis: every error message
contains metadata only and never leaks frame bytes, payloads, or any
other captured screen content.
"""

from __future__ import annotations

from guardianmesh.core.errors import GuardianMeshError


class AegisError(GuardianMeshError):
    """Base exception for the Aegis screen-capture subsystem."""


class AegisPlatformUnavailableError(AegisError):
    """Raised when Aegis is run on a non-Android platform.

    This is the expected outcome on Termux/Linux development hosts.
    Aegis must not attempt to fabricate Android functionality; it must
    report honestly that the platform is unavailable.
    """


class AegisConsentRequiredError(AegisError):
    """Raised when capture is attempted before the Android system consent
    dialog has been granted.

    This error is part of the consent gate and MUST NEVER be swallowed
    or bypassed. The state machine enforces that capture is only
    possible in the ``SYSTEM_CONSENT_GRANTED`` or ``ACTIVE`` states.
    """


class AegisConsentDeniedError(AegisError):
    """Raised when the child explicitly denies the system capture consent
    dialog or revokes consent at any point during a session."""


class AegisConsentRevokedError(AegisError):
    """Raised when consent is revoked mid-session (e.g. via the system
    toggle or by the child revoking the active session)."""


class AegisProjectionError(AegisError):
    """Raised when the MediaProjection object fails or becomes invalid."""


class AegisEncoderError(AegisError):
    """Raised when the screen encoder (MediaCodec / TestCodec) fails or
    reports an unrecoverable error."""


class AegisImageReaderError(AegisError):
    """Raised when the underlying Android ImageReader surface fails or
    reports an unrecoverable error."""


class AegisFramePipelineError(AegisError):
    """Raised when the frame pipeline encounters an unrecoverable error
    outside of projection, encoder, or reader failures."""


class AegisForegroundServiceError(AegisError):
    """Raised when the foreground service cannot be started or stopped
    cleanly. The visible indicator contract requires that the service
    is started before any frame is delivered and stopped immediately
    after capture ends."""


class AegisLifecycleError(AegisError):
    """Raised when an Android lifecycle event (rotation, process death,
    service restart) cannot be handled cleanly. Aegis must never
    silently restart capture after authorization becomes invalid."""


class AegisAuthorizationRequiredError(AegisError):
    """Raised when capture is attempted without a valid Vista authorization.

    Trust alone is never sufficient for capture. This error is the
    enforcement point of the *trust != authorization* invariant.
    """


class AegisFrameDroppedError(AegisError):
    """Raised when the bounded frame queue cannot accept another frame and
    the configured backpressure strategy drops the new frame."""


class AegisSessionError(AegisError):
    """Raised when an Aegis session is in an invalid state or cannot be
    located. The Aegis controller raises this when a session ID does
    not match any in-memory or persisted record."""


__all__ = [
    "AegisAuthorizationRequiredError",
    "AegisConsentDeniedError",
    "AegisConsentRequiredError",
    "AegisConsentRevokedError",
    "AegisEncoderError",
    "AegisError",
    "AegisForegroundServiceError",
    "AegisFrameDroppedError",
    "AegisFramePipelineError",
    "AegisImageReaderError",
    "AegisLifecycleError",
    "AegisPlatformUnavailableError",
    "AegisProjectionError",
    "AegisSessionError",
]
