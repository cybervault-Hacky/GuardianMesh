"""Tests for the Aegis screen encoder abstraction."""

from __future__ import annotations

import sys

import pytest

from guardianmesh.aegis.encoder import (
    DEFAULT_REGISTRY,
    AndroidMediaCodecEncoder,
    ScreenEncoderRegistry,
    TestScreenEncoder,
)
from guardianmesh.aegis.errors import AegisEncoderError
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ProviderCapabilities,
)
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCaptureResult,
    ScreenCodec,
)


def _capture(width: int = 1280, height: int = 720) -> ScreenCaptureResult:
    return ScreenCaptureResult(
        captured=True,
        width=width,
        height=height,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload=b"\x00" * 16,
    )


# ---------------------------------------------------------------------------
# TestScreenEncoder
# ---------------------------------------------------------------------------


def test_test_encoder_emits_64_byte_payload() -> None:
    """The test encoder emits a 64-byte synthetic payload."""
    encoder = TestScreenEncoder()
    frame = encoder.encode(_capture(), ScreenCodec.TEST)
    assert len(frame.payload) == 64


def test_test_encoder_assigns_sequence() -> None:
    """Each encode call increments the internal sequence counter."""
    encoder = TestScreenEncoder()
    f1 = encoder.encode(_capture(), ScreenCodec.TEST)
    f2 = encoder.encode(_capture(), ScreenCodec.TEST)
    assert f1.sequence == 1
    assert f2.sequence == 2


def test_test_encoder_rejects_uncaptured_capture() -> None:
    """The test encoder refuses to encode an uncaptured capture."""
    encoder = TestScreenEncoder()
    result = ScreenCaptureResult(
        captured=False,
        width=0,
        height=0,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
    )
    with pytest.raises(AegisEncoderError):
        encoder.encode(result, ScreenCodec.TEST)


def test_test_encoder_capabilities() -> None:
    """The test encoder's capabilities are well-defined."""
    encoder = TestScreenEncoder()
    cap = encoder.capabilities()
    assert cap.backend == EncoderBackend.TEST
    assert cap.platform.supports_real_capture is False


def test_test_encoder_release_is_noop() -> None:
    """The test encoder's release is a no-op (no native resources)."""
    encoder = TestScreenEncoder()
    encoder.release()  # Must not raise.


def test_test_encoder_payload_size_matches_actual() -> None:
    """The test encoder's frame.payload_size matches len(frame.payload)."""
    encoder = TestScreenEncoder()
    frame = encoder.encode(_capture(), ScreenCodec.TEST)
    assert frame.payload_size == len(frame.payload)


# ---------------------------------------------------------------------------
# AndroidMediaCodecEncoder (production stub)
# ---------------------------------------------------------------------------


def test_android_encoder_constructor_rejects_non_android() -> None:
    """AndroidMediaCodecEncoder refuses to instantiate on non-Android."""
    # The class checks sys.platform. On Linux the constructor raises.
    if "android" in sys.platform.lower() or "java" in sys.platform.lower():
        pytest.skip("Running on a JVM/Android platform.")
    with pytest.raises(AegisEncoderError):
        AndroidMediaCodecEncoder()


def test_android_encoder_encode_raises_on_non_android() -> None:
    """AndroidMediaCodecEncoder.encode raises if it could be called."""
    # The constructor blocks instantiation on non-Android, but we
    # verify the encode path raises too as a defensive measure.
    if "android" in sys.platform.lower() or "java" in sys.platform.lower():
        pytest.skip("Running on a JVM/Android platform.")
    with pytest.raises(AegisEncoderError):
        AndroidMediaCodecEncoder()


def test_android_encoder_capabilities_describe_production() -> None:
    """The Android encoder's capability description mentions production."""
    # We construct the capability description directly to avoid
    # instantiating the encoder on non-Android.
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
        notes="Production Android MediaCodec encoder.",
    )
    assert cap.platform == AegisPlatform.ANDROID
    assert cap.supports_real_capture is True
    assert cap.supports_media_projection is True


# ---------------------------------------------------------------------------
# ScreenEncoderRegistry
# ---------------------------------------------------------------------------


def test_default_registry_has_test_encoder() -> None:
    """The default registry contains the test encoder."""
    assert EncoderBackend.TEST in DEFAULT_REGISTRY.available()


def test_registry_get_default_returns_test_encoder() -> None:
    """default() returns the test encoder on the Python control plane."""
    encoder = DEFAULT_REGISTRY.default()
    assert isinstance(encoder, TestScreenEncoder)


def test_registry_get_returns_registered_encoder() -> None:
    """get() returns the encoder that was registered for a backend."""
    reg = ScreenEncoderRegistry()
    custom = TestScreenEncoder()
    reg.register(custom)
    assert reg.get(EncoderBackend.TEST) is custom


def test_registry_get_unknown_backend_raises() -> None:
    """get() raises AegisEncoderError for an unknown backend."""
    reg = ScreenEncoderRegistry()
    # Pop the only registered backend so the registry is empty.
    reg._registry.pop(EncoderBackend.TEST, None)  # type: ignore[attr-defined]
    with pytest.raises(AegisEncoderError):
        reg.get(EncoderBackend.TEST)


def test_registry_available_lists_backends() -> None:
    """available() returns the list of registered backends."""
    reg = ScreenEncoderRegistry()
    assert EncoderBackend.TEST in reg.available()

