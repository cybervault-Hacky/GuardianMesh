"""GuardianMesh Vista Phase 7 (v0.7.0) — Consent-based view-only screen sessions.

This subsystem introduces a privacy-preserving, child-authorized, view-only
screen observation protocol. The architecture is intentionally isolated:

* Parent Console
* Nexus Secure Transport (existing, reused — never duplicated)
* Child Authorization
* Child Screen Session
* Encrypted video frames over Nexus
* Parent Viewer

Critical privacy guarantees:

* NO silent capture, NO hidden capture, NO keylogging, NO microphone,
  NO camera, NO clipboard, NO SMS, NO contacts, NO location, NO
  notifications, NO browser history, NO remote control, NO remote input.
* Every screen view requires an explicit, fresh child authorization.
* A visible "SCREEN VIEW ACTIVE" indicator must be displayed on the
  child side for the entire session lifetime.
* The child can revoke at any time; the parent can also stop at any time.
* Frames travel through the existing Nexus transport and are NEVER
  persisted to disk.

The Android ``MediaProjection`` boundary is enforced by
:class:`AndroidScreenProvider`. The current build ships an
:class:`AdapterOnlyScreenProvider` that emits deterministic synthetic
frames; a future Android companion component (an APK) is required to
produce real screen captures. The system never claims production
screen capture is active unless the provider reports
``is_real_capture = True``.
"""

from __future__ import annotations

from guardianmesh.screen.auth_registry import ScreenAuthorizationRegistry
from guardianmesh.screen.authorization import (
    DEFAULT_MAX_DURATION_SECONDS,
    MAX_MAX_DURATION_SECONDS,
    MIN_MAX_DURATION_SECONDS,
    ScreenAuthorization,
    ScreenAuthorizationManager,
    ScreenAuthorizationRequest,
    derive_session_state_from_decision,
)
from guardianmesh.screen.codec import (
    DEFAULT_REGISTRY,
    FutureH264Codec,
    FutureVP8Codec,
    FutureVP9Codec,
    FutureWebPCodec,
    ScreenCodecEncoder,
    ScreenCodecRegistry,
    TestCodec,
    encode_frame,
)
from guardianmesh.screen.controller import (
    ScreenController,
    ScreenControllerDiagnostics,
    ScreenViewRequest,
)
from guardianmesh.screen.errors import (
    ScreenAuthorizationDeniedError,
    ScreenAuthorizationError,
    ScreenAuthorizationExpiredError,
    ScreenAuthorizationNotFoundError,
    ScreenBackpressureError,
    ScreenCodecError,
    ScreenError,
    ScreenFrameError,
    ScreenFrameOversizedError,
    ScreenFrameSequenceError,
    ScreenFrameValidationError,
    ScreenProviderError,
    ScreenRemoteControlError,
    ScreenSessionError,
    ScreenSessionExpiredError,
    ScreenSessionNotFoundError,
    ScreenSessionRevokedError,
    ScreenSessionStateError,
)
from guardianmesh.screen.frames import (
    FrameSequenceTracker,
    FrameStreamBuffer,
    FrameValidator,
)
from guardianmesh.screen.indicator import (
    AdapterOnlyScreenProvider,
    AndroidScreenProvider,
    ScreenIndicator,
)
from guardianmesh.screen.models import (
    PROTOCOL_VERSION,
    AuthorizationDecision,
    BackpressureStrategy,
    BoundedFrameQueue,
    PixelFormat,
    ScreenCaptureRequest,
    ScreenCaptureResult,
    ScreenCodec,
    ScreenFrame,
    ScreenSessionInfo,
    ScreenSessionState,
    StopReason,
    assert_legal_transition,
    generate_authorization_id,
    generate_frame_id,
    generate_screen_session_id,
)
from guardianmesh.screen.registry import ScreenSessionRegistry
from guardianmesh.screen.session import (
    ScreenSession,
    ScreenSessionConfig,
    ScreenSessionManager,
)
from guardianmesh.screen.transport import (
    ALLOWED_SCREEN_MESSAGE_TYPES,
    ScreenEnvelope,
    ScreenMessageType,
    ScreenTransportBridge,
    assert_no_remote_control_type,
    deserialize_screen_envelope,
    envelope_payload_to_frame,
    frame_to_envelope_payload,
    is_allowed_screen_message_type,
    serialize_screen_envelope,
)

__all__ = [
    "ALLOWED_SCREEN_MESSAGE_TYPES",
    "DEFAULT_MAX_DURATION_SECONDS",
    "DEFAULT_REGISTRY",
    "MAX_MAX_DURATION_SECONDS",
    "MIN_MAX_DURATION_SECONDS",
    "PROTOCOL_VERSION",
    "AdapterOnlyScreenProvider",
    "AndroidScreenProvider",
    "AuthorizationDecision",
    "BackpressureStrategy",
    "BoundedFrameQueue",
    "FrameSequenceTracker",
    "FrameStreamBuffer",
    "FrameValidator",
    "FutureH264Codec",
    "FutureVP8Codec",
    "FutureVP9Codec",
    "FutureWebPCodec",
    "PixelFormat",
    "ScreenAuthorization",
    "ScreenAuthorizationDeniedError",
    "ScreenAuthorizationError",
    "ScreenAuthorizationExpiredError",
    "ScreenAuthorizationManager",
    "ScreenAuthorizationNotFoundError",
    "ScreenAuthorizationRegistry",
    "ScreenAuthorizationRequest",
    "ScreenBackpressureError",
    "ScreenCaptureRequest",
    "ScreenCaptureResult",
    "ScreenCodec",
    "ScreenCodecEncoder",
    "ScreenCodecError",
    "ScreenCodecRegistry",
    "ScreenController",
    "ScreenControllerDiagnostics",
    "ScreenEnvelope",
    "ScreenError",
    "ScreenFrame",
    "ScreenFrameError",
    "ScreenFrameOversizedError",
    "ScreenFrameSequenceError",
    "ScreenFrameValidationError",
    "ScreenIndicator",
    "ScreenMessageType",
    "ScreenProviderError",
    "ScreenRemoteControlError",
    "ScreenSession",
    "ScreenSessionConfig",
    "ScreenSessionError",
    "ScreenSessionExpiredError",
    "ScreenSessionInfo",
    "ScreenSessionManager",
    "ScreenSessionNotFoundError",
    "ScreenSessionRegistry",
    "ScreenSessionRevokedError",
    "ScreenSessionState",
    "ScreenSessionStateError",
    "ScreenTransportBridge",
    "ScreenViewRequest",
    "StopReason",
    "TestCodec",
    "assert_legal_transition",
    "assert_no_remote_control_type",
    "derive_session_state_from_decision",
    "deserialize_screen_envelope",
    "encode_frame",
    "envelope_payload_to_frame",
    "frame_to_envelope_payload",
    "generate_authorization_id",
    "generate_frame_id",
    "generate_screen_session_id",
    "is_allowed_screen_message_type",
    "serialize_screen_envelope",
]
