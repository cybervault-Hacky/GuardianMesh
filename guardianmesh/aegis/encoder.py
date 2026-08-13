"""Screen-encoder abstraction for Aegis Phase 8.

The encoder layer is intentionally narrow and platform-agnostic. The
production encoder on the Android companion is
``android.media.MediaCodec`` (H.264 hardware encoder when available).
On the Linux/Termux control plane and in unit tests, a deterministic
test encoder is used.

The encoder is the only place that touches codec-specific APIs. The
rest of Aegis (frame pipeline, transport bridge, metrics) operates on
abstract ``ScreenFrame`` instances and never knows whether the bytes
came from MediaCodec or from the test encoder.

The encoder never writes its output to disk. Output exists only in
memory for the duration of one frame processing cycle.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from abc import ABC, abstractmethod

from guardianmesh.aegis.errors import AegisEncoderError
from guardianmesh.aegis.models import EncoderBackend, ProviderCapabilities
from guardianmesh.screen.models import (
    ScreenCaptureResult,
    ScreenCodec,
    ScreenFrame,
)


class ScreenEncoder(ABC):
    """Abstract screen-encoder boundary.

    Implementations:

    * :class:`AndroidMediaCodecEncoder` - production encoder that wraps
      ``android.media.MediaCodec``. The actual class lives in the
      Aegis Android companion; the Python control plane imports the
      contract only.
    * :class:`TestScreenEncoder` - deterministic test encoder used by
      the unit suite and by the Linux/Termux control plane.
    """

    backend: EncoderBackend

    @abstractmethod
    def encode(
        self,
        capture: ScreenCaptureResult,
        codec: ScreenCodec,
    ) -> ScreenFrame:
        """Encode a captured frame into a :class:`ScreenFrame`.

        The frame payload is codec-specific. The encoder MUST NOT
        persist the payload to disk and MUST NOT include it in any
        log or error message.
        """

    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """Return the encoder capabilities."""

    def release(self) -> None:
        """Release any underlying resources. Idempotent.

        The default implementation is a no-op; encoders that allocate
        native resources override this.
        """
        return None


# ---------------------------------------------------------------------------
# Test encoder
# ---------------------------------------------------------------------------


class TestScreenEncoder(ScreenEncoder):
    """Deterministic screen encoder used by the unit suite.

    The output is a 64-byte synthetic payload derived from SHA-256 over
    the request parameters. The encoder is intentionally fast and
    deterministic. It exists to exercise the frame pipeline end-to-end
    without requiring a real Android encoder.
    """

    backend = EncoderBackend.TEST

    def __init__(self, latency_ms: int = 0) -> None:
        self._salt = secrets.token_bytes(8)
        self._counter = 0
        self._lock = threading.Lock()
        self._latency_ms = max(0, int(latency_ms))
        self._capability = ProviderCapabilities(
            platform=__import__(
                "guardianmesh.aegis.models", fromlist=["AegisPlatform"]
            ).AegisPlatform.LINUX,
            backend=EncoderBackend.TEST,
            max_width=1280,
            max_height=720,
            max_fps=10,
            supports_foreground_service=False,
            supports_media_projection=False,
            notes="TestScreenEncoder is a deterministic test fixture.",
        )

    def capabilities(self) -> ProviderCapabilities:
        return self._capability

    def encode(
        self,
        capture: ScreenCaptureResult,
        codec: ScreenCodec,
    ) -> ScreenFrame:
        if not capture.captured:
            raise AegisEncoderError(
                "Cannot encode a frame that was not captured."
            )
        with self._lock:
            self._counter += 1
            sequence = self._counter
        if self._latency_ms > 0:
            time.sleep(self._latency_ms / 1000.0)
        seed = (
            self._salt
            + f"{capture.width}x{capture.height}|{codec.value}|{sequence}".encode()
        )
        digest = hashlib.sha256(seed).digest()
        payload = digest + digest
        return ScreenFrame(
            protocol_version="1.0",
            session_id="",  # Set by the frame pipeline.
            device_id="",  # Set by the frame pipeline.
            sequence=sequence,
            width=capture.width,
            height=capture.height,
            pixel_format=capture.pixel_format,
            codec=codec,
            payload_size=len(payload),
            payload=payload,
        )


# ---------------------------------------------------------------------------
# Production encoder stub (documented integration point)
# ---------------------------------------------------------------------------


class AndroidMediaCodecEncoder(ScreenEncoder):
    """Production encoder wrapping ``android.media.MediaCodec``.

    This class is documented but NOT executable on the Python control
    plane. The Aegis Android companion provides the actual
    implementation. The Python control plane only references the
    contract to express the production backend.

    Any attempt to instantiate this encoder on a non-Android platform
    raises :class:`AegisEncoderError`. The class exists for two
    reasons:

    * It documents the production integration point.
    * It allows the unit suite to assert that the control plane
      never instantiates a real encoder on Linux/Termux.
    """

    backend = EncoderBackend.MEDIA_CODEC

    def __init__(self) -> None:
        import sys

        if "java" not in sys.platform.lower() and "android" not in sys.platform.lower():
            raise AegisEncoderError(
                "AndroidMediaCodecEncoder is only available inside the Android "
                "Aegis companion. The Python control plane must use "
                "TestScreenEncoder."
            )

    def capabilities(self) -> ProviderCapabilities:
        from guardianmesh.aegis.models import AegisPlatform

        return ProviderCapabilities(
            platform=AegisPlatform.ANDROID,
            backend=EncoderBackend.MEDIA_CODEC,
            max_width=1280,
            max_height=720,
            max_fps=10,
            supports_foreground_service=True,
            supports_media_projection=True,
            notes="Production Android MediaCodec encoder.",
        )

    def encode(
        self,
        capture: ScreenCaptureResult,
        codec: ScreenCodec,
    ) -> ScreenFrame:
        # This code path is never executed in the unit suite; the
        # constructor above rejects non-Android instantiation. The
        # real implementation lives in the Android companion.
        raise AegisEncoderError(
            "AndroidMediaCodecEncoder.encode is implemented in the Android "
            "Aegis companion, not in the Python control plane."
        )


# ---------------------------------------------------------------------------
# Encoder registry
# ---------------------------------------------------------------------------


class ScreenEncoderRegistry:
    """Registry of available :class:`ScreenEncoder` implementations.

    The registry is the single source of truth for which encoder to
    use. On the Python control plane, only :class:`TestScreenEncoder`
    is registered. The Android companion registers
    :class:`AndroidMediaCodecEncoder` at runtime.
    """

    def __init__(self) -> None:
        self._registry: dict[EncoderBackend, ScreenEncoder] = {
            EncoderBackend.TEST: TestScreenEncoder(),
        }

    def register(self, encoder: ScreenEncoder) -> None:
        self._registry[encoder.backend] = encoder

    def get(self, backend: EncoderBackend) -> ScreenEncoder:
        try:
            return self._registry[backend]
        except KeyError as e:
            raise AegisEncoderError(
                f"No encoder registered for backend '{backend.value}'."
            ) from e

    def default(self) -> ScreenEncoder:
        return self._registry[EncoderBackend.TEST]

    def available(self) -> list[EncoderBackend]:
        return list(self._registry.keys())


DEFAULT_REGISTRY: ScreenEncoderRegistry = ScreenEncoderRegistry()


__all__ = [
    "DEFAULT_REGISTRY",
    "AndroidMediaCodecEncoder",
    "ScreenEncoder",
    "ScreenEncoderRegistry",
    "TestScreenEncoder",
]
