"""Tests for the Aegis MediaProjection provider abstraction."""

from __future__ import annotations

import threading

import pytest

from guardianmesh.aegis.errors import (
    AegisPlatformUnavailableError,
    AegisProjectionError,
)
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    FakeMediaProjectionProvider,
    MediaProjectionProvider,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ProviderCapabilities,
)
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCaptureRequest,
    ScreenCodec,
)


def _request(width: int = 1280, height: int = 720) -> ScreenCaptureRequest:
    return ScreenCaptureRequest(
        session_id="SCN-1",
        width=width,
        height=height,
        max_fps=10,
        codec=ScreenCodec.TEST,
        pixel_format=PixelFormat.TEST,
    )


def _android_capability() -> ProviderCapabilities:
    return ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )


# ---------------------------------------------------------------------------
# Abstract boundary
# ---------------------------------------------------------------------------


def test_media_projection_provider_is_abstract() -> None:
    """MediaProjectionProvider cannot be instantiated directly."""
    with pytest.raises(TypeError):
        MediaProjectionProvider()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Adapter only (Linux/Termux)
# ---------------------------------------------------------------------------


def test_adapter_only_provider_never_claims_real_capture() -> None:
    """The adapter provider never reports is_real_capture=True."""
    provider = AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)
    assert provider.is_real_capture is False
    assert provider.is_available is True


def test_adapter_only_provider_capability_reports_linux() -> None:
    """The adapter capability reports the Linux platform."""
    provider = AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)
    cap = provider.capability
    assert cap.platform == AegisPlatform.LINUX
    assert cap.supports_media_projection is False
    assert cap.supports_foreground_service is False


def test_adapter_only_provider_capture_before_start_returns_empty() -> None:
    """capture_frame returns an empty result before start()."""
    provider = AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)
    result = provider.capture_frame(_request())
    assert result.captured is False
    assert result.payload == b""
    assert "not started" in result.note.lower()


def test_adapter_only_provider_capture_after_start_emits_synthetic_frame() -> None:
    """After start(), the adapter returns a synthetic frame."""
    provider = AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)
    provider.start()
    result = provider.capture_frame(_request())
    assert result.captured is True
    assert len(result.payload) > 0


def test_adapter_only_provider_rejects_oversized_dimensions() -> None:
    """The adapter enforces the documented resolution bounds."""
    provider = AdapterOnlyMediaProjectionProvider(
        platform=AegisPlatform.LINUX, max_width=1280, max_height=720
    )
    provider.start()
    result = provider.capture_frame(_request(width=9999, height=9999))
    assert result.captured is False


def test_adapter_only_provider_rejects_excessive_fps() -> None:
    """The adapter enforces the documented FPS bound."""
    provider = AdapterOnlyMediaProjectionProvider(
        platform=AegisPlatform.LINUX, max_fps=10
    )
    provider.start()
    req = ScreenCaptureRequest(
        session_id="SCN-1",
        width=320,
        height=240,
        max_fps=999,
        codec=ScreenCodec.TEST,
        pixel_format=PixelFormat.TEST,
    )
    result = provider.capture_frame(req)
    assert result.captured is False


def test_adapter_only_provider_stop_is_idempotent() -> None:
    """The adapter's stop() can be called multiple times safely."""
    provider = AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)
    provider.start()
    provider.stop()
    provider.stop()  # No-op.


def test_adapter_only_provider_diagnostics_no_payload() -> None:
    """Diagnostics metadata contains no frame content."""
    provider = AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)
    diag = provider.diagnostics()
    assert "payload" not in diag
    assert "frame" not in diag
    assert "screenshot" not in diag
    assert diag["is_real_capture"] is False


# ---------------------------------------------------------------------------
# Fake provider (for unit tests)
# ---------------------------------------------------------------------------


def test_fake_provider_uses_configured_capability() -> None:
    """The fake provider reports the capability passed at construction."""
    fake = FakeMediaProjectionProvider(_android_capability())
    assert fake.capability.platform == AegisPlatform.ANDROID
    assert fake.is_available is True


def test_fake_provider_before_start_returns_empty() -> None:
    """The fake provider refuses to capture before start()."""
    fake = FakeMediaProjectionProvider(_android_capability())
    result = fake.capture_frame(_request())
    assert result.captured is False


def test_fake_provider_after_start_reports_real_capture() -> None:
    """The fake provider reports is_real_capture=True after start()."""
    fake = FakeMediaProjectionProvider(_android_capability())
    fake.start()
    assert fake.is_real_capture is True


def test_fake_provider_can_fail_on_start() -> None:
    """The fake provider can be configured to fail on start()."""
    fake = FakeMediaProjectionProvider(
        _android_capability(), fail_on_start=True
    )
    with pytest.raises(AegisProjectionError):
        fake.start()


def test_fake_provider_emits_synthetic_frame() -> None:
    """The fake provider returns a 64-byte synthetic frame after start()."""
    fake = FakeMediaProjectionProvider(_android_capability())
    fake.start()
    result = fake.capture_frame(_request())
    assert result.captured is True
    assert len(result.payload) == 64
    assert "synthetic" in result.note.lower()


def test_fake_provider_refuses_non_android_real_capture() -> None:
    """The fake provider refuses to perform real capture on non-Android."""
    cap = ProviderCapabilities(
        platform=AegisPlatform.LINUX,
        backend=EncoderBackend.TEST,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=False,
        supports_media_projection=False,
    )
    fake = FakeMediaProjectionProvider(cap)
    fake.start()
    with pytest.raises(AegisPlatformUnavailableError):
        fake.capture_frame(_request())


def test_fake_provider_can_fail_on_capture() -> None:
    """The fake provider can be configured to fail on capture."""
    fake = FakeMediaProjectionProvider(
        _android_capability(), fail_on_capture=True
    )
    fake.start()
    with pytest.raises(AegisProjectionError):
        fake.capture_frame(_request())


def test_fake_provider_is_thread_safe() -> None:
    """The fake provider's capture_frame is safe under concurrent access."""
    fake = FakeMediaProjectionProvider(_android_capability())
    fake.start()

    results: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        r = fake.capture_frame(_request())
        with lock:
            results.append(r.captured)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(results)
    assert len(results) == 8
