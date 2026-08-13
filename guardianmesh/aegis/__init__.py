"""GuardianMesh Aegis Phase 8 (v0.8.0) — Production Android Companion.

Aegis turns the Phase 7 Vista Android integration boundary into a
real, production-oriented Android companion architecture using
Android's official ``MediaProjection`` consent flow.

The Termux/Linux GuardianMesh project remains the control plane. The
Android companion is the execution/capture plane. Aegis is the
contract between them.

Aegis remains:

* View-only
* Explicitly child-authorized (Phase 7 authorization)
* Android-system-consent gated (Phase 8 ``MediaProjection``)
* Visibly indicated while capture is active
* Time-limited
* Revocable immediately
* Non-persistent for screen frames
* Free of remote-control capabilities
"""

from __future__ import annotations

from guardianmesh.aegis.consent import (
    ConsentDecision,
    SystemConsentGate,
    default_linux_capability,
)
from guardianmesh.aegis.controller import AegisController, AegisViewRequest
from guardianmesh.aegis.encoder import (
    DEFAULT_REGISTRY,
    AndroidMediaCodecEncoder,
    ScreenEncoder,
    ScreenEncoderRegistry,
    TestScreenEncoder,
)
from guardianmesh.aegis.errors import (
    AegisAuthorizationRequiredError,
    AegisConsentDeniedError,
    AegisConsentRequiredError,
    AegisConsentRevokedError,
    AegisEncoderError,
    AegisError,
    AegisForegroundServiceError,
    AegisFrameDroppedError,
    AegisFramePipelineError,
    AegisImageReaderError,
    AegisLifecycleError,
    AegisPlatformUnavailableError,
    AegisProjectionError,
    AegisSessionError,
)
from guardianmesh.aegis.indicator_service import (
    ForegroundServiceIndicator,
    default_linux_indicator,
    new_indicator_session_token,
)
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    FakeMediaProjectionProvider,
    MediaProjectionProvider,
)
from guardianmesh.aegis.models import (
    PROTOCOL_VERSION,
    AegisPlatform,
    AegisSessionInfo,
    AegisSessionState,
    EncoderBackend,
    ForegroundServiceNotification,
    FrameMetrics,
    FrameMetricsSnapshot,
    FramePipelineStage,
    ProviderCapabilities,
    SystemConsentRecord,
    SystemConsentState,
    generate_aegis_session_id,
    generate_consent_token,
)
from guardianmesh.aegis.pipeline import (
    AegisFramePipeline,
    AegisProjectionLikeError,
    FrameLimiter,
    FrameNormalizer,
)
from guardianmesh.aegis.registry import AegisSessionRegistry

__all__ = [
    "DEFAULT_REGISTRY",
    "PROTOCOL_VERSION",
    "AdapterOnlyMediaProjectionProvider",
    "AegisAuthorizationRequiredError",
    "AegisConsentDeniedError",
    "AegisConsentRequiredError",
    "AegisConsentRevokedError",
    "AegisController",
    "AegisEncoderError",
    "AegisError",
    "AegisForegroundServiceError",
    "AegisFrameDroppedError",
    "AegisFramePipeline",
    "AegisFramePipelineError",
    "AegisImageReaderError",
    "AegisLifecycleError",
    "AegisPlatform",
    "AegisPlatformUnavailableError",
    "AegisProjectionError",
    "AegisProjectionLikeError",
    "AegisSessionError",
    "AegisSessionInfo",
    "AegisSessionRegistry",
    "AegisSessionState",
    "AegisViewRequest",
    "AndroidMediaCodecEncoder",
    "ConsentDecision",
    "EncoderBackend",
    "FakeMediaProjectionProvider",
    "ForegroundServiceIndicator",
    "ForegroundServiceNotification",
    "FrameLimiter",
    "FrameMetrics",
    "FrameMetricsSnapshot",
    "FrameNormalizer",
    "FramePipelineStage",
    "MediaProjectionProvider",
    "PixelFormat",
    "ProviderCapabilities",
    "ScreenEncoder",
    "ScreenEncoderRegistry",
    "SystemConsentGate",
    "SystemConsentRecord",
    "SystemConsentState",
    "TestScreenEncoder",
    "default_linux_capability",
    "default_linux_indicator",
    "generate_aegis_session_id",
    "generate_consent_token",
    "new_indicator_session_token",
]


# Re-export the screen PixelFormat through the Aegis public API.
from guardianmesh.screen.models import PixelFormat
