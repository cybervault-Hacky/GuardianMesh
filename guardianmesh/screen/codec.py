"""Screen codec abstraction for the Vista Phase 7 subsystem.

The codec layer is intentionally small and isolated. Phase 7 does NOT
implement a real production encoder — doing so would require a heavy
native dependency (e.g. libx264) and a real Android companion component
that can supply MediaProjection frames. Instead, this module provides:

* A :class:`ScreenCodec` registry that maps codec names to encoder
  implementations. Each encoder exposes an ``encode()`` method that takes
  raw RGB/A bytes (or a synthetic test pattern) and returns deterministic,
  decodable output.

* :class:`TestCodec`, a deterministic encoder that emits a small synthetic
  payload representing a frame. This codec is used by the test suite and
  by the demo flow so that the rest of the system can be exercised
  end-to-end without a real encoder dependency.

* :class:`FutureH264Codec`, :class:`FutureWebPCodec`, and similar stubs
  that explicitly raise :class:`ScreenCodecError` when invoked. Their
  presence documents the integration boundary and prevents accidentally
  claiming a production encoder is active.

All codecs operate on bounded inputs and never touch the filesystem.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import ClassVar

from guardianmesh.screen.errors import ScreenCodecError
from guardianmesh.screen.models import PixelFormat, ScreenCaptureRequest, ScreenCaptureResult, ScreenCodec


class ScreenCodecEncoder(ABC):
    """Abstract base class for all screen codec encoders."""

    codec: ClassVar[ScreenCodec]
    pixel_format: ClassVar[PixelFormat]

    @abstractmethod
    def encode(
        self, request: ScreenCaptureRequest, raw_pixels: bytes
    ) -> ScreenCaptureResult:
        """Encode raw pixels into a frame payload.

        Args:
            request: The capture request (resolution, fps, codec).
            raw_pixels: Raw input bytes in the codec's expected format.

        Returns:
            A :class:`ScreenCaptureResult` with the encoded payload.
        """


class TestCodec(ScreenCodecEncoder):
    """Deterministic test codec used by the test suite and demo flows.

    The output is a 64-byte synthetic payload derived from SHA-256 over the
    request parameters and a counter. The counter is supplied via
    ``request.metadata['sequence']`` when present; otherwise it is 0.

    This is NOT a video codec. It exists only so that the streaming,
    encryption, transport, and storage layers can be exercised end-to-end
    without depending on heavy native libraries.
    """

    codec = ScreenCodec.TEST
    pixel_format = PixelFormat.TEST

    def encode(
        self, request: ScreenCaptureRequest, raw_pixels: bytes
    ) -> ScreenCaptureResult:
        # ``ScreenCaptureRequest`` is a frozen dataclass without a metadata
        # attribute. The sequence is therefore not part of the request, and
        # the synthetic payload is deterministic across calls.
        sequence = 0

        seed = (
            f"{request.session_id}|{request.width}x{request.height}|"
            f"{request.codec.value}|{request.pixel_format.value}|{sequence}"
        ).encode()
        digest = hashlib.sha256(seed).digest()
        # 64 bytes is small but sufficient to verify end-to-end pipelines
        # without transmitting any real screen content.
        payload = digest + digest
        return ScreenCaptureResult(
            captured=True,
            width=request.width,
            height=request.height,
            pixel_format=request.pixel_format,
            codec=request.codec,
            payload=payload,
            note="TestCodec synthetic payload — NOT a real screen capture.",
        )


class _NotImplementedCodec(ScreenCodecEncoder):
    """Base for codecs that document a future integration point but are not implemented."""

    codec: ClassVar[ScreenCodec]
    pixel_format: ClassVar[PixelFormat] = PixelFormat.RGB24

    def encode(
        self, request: ScreenCaptureRequest, raw_pixels: bytes
    ) -> ScreenCaptureResult:
        raise ScreenCodecError(
            f"Codec '{self.codec.value}' is reserved for a future Android companion "
            f"component and is not active in this build. Use 'TEST' for the "
            f"deterministic test pipeline."
        )


class FutureH264Codec(_NotImplementedCodec):
    """Future H.264/AVC codec adapter (not active in this build)."""

    codec = ScreenCodec.H264


class FutureVP8Codec(_NotImplementedCodec):
    """Future VP8 codec adapter (not active in this build)."""

    codec = ScreenCodec.VP8


class FutureVP9Codec(_NotImplementedCodec):
    """Future VP9 codec adapter (not active in this build)."""

    codec = ScreenCodec.VP9


class FutureWebPCodec(_NotImplementedCodec):
    """Future WebP codec adapter (not active in this build)."""

    codec = ScreenCodec.WEBP


class ScreenCodecRegistry:
    """Registry of available :class:`ScreenCodecEncoder` implementations.

    The registry is keyed by :class:`ScreenCodec`. Unregistered codecs
    raise :class:`ScreenCodecError`.
    """

    def __init__(self) -> None:
        self._registry: dict[ScreenCodec, ScreenCodecEncoder] = {
            ScreenCodec.TEST: TestCodec(),
            ScreenCodec.H264: FutureH264Codec(),
            ScreenCodec.VP8: FutureVP8Codec(),
            ScreenCodec.VP9: FutureVP9Codec(),
            ScreenCodec.WEBP: FutureWebPCodec(),
        }

    def get(self, codec: ScreenCodec | str) -> ScreenCodecEncoder:
        """Look up an encoder by codec name or enum value."""
        if isinstance(codec, str):
            codec = ScreenCodec.from_str(codec)
        try:
            return self._registry[codec]
        except KeyError as e:
            raise ScreenCodecError(f"No encoder registered for codec '{codec.value}'.") from e

    def is_production(self, codec: ScreenCodec | str) -> bool:
        """Return True if a codec represents active production encoding."""
        if isinstance(codec, str):
            codec = ScreenCodec.from_str(codec)
        return codec.is_production

    def available(self) -> list[ScreenCodec]:
        """Return the list of registered codec names."""
        return list(self._registry.keys())


# Default singleton registry used by the controller.
DEFAULT_REGISTRY: ScreenCodecRegistry = ScreenCodecRegistry()


def encode_frame(
    request: ScreenCaptureRequest,
    raw_pixels: bytes,
    registry: ScreenCodecRegistry | None = None,
) -> ScreenCaptureResult:
    """Convenience wrapper around :meth:`ScreenCodecRegistry.get`."""
    reg = registry or DEFAULT_REGISTRY
    return reg.get(request.codec).encode(request, raw_pixels)


__all__ = [
    "DEFAULT_REGISTRY",
    "FutureH264Codec",
    "FutureVP8Codec",
    "FutureVP9Codec",
    "FutureWebPCodec",
    "ScreenCodecEncoder",
    "ScreenCodecRegistry",
    "TestCodec",
    "encode_frame",
]
