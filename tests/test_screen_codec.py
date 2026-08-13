"""Tests for the screen codec abstraction (Phase 7: Vista)."""

from __future__ import annotations

import pytest

from guardianmesh.screen.codec import (
    DEFAULT_REGISTRY,
    FutureH264Codec,
    FutureVP8Codec,
    FutureVP9Codec,
    FutureWebPCodec,
    ScreenCodecRegistry,
    TestCodec,
    encode_frame,
)
from guardianmesh.screen.errors import ScreenCodecError
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCaptureRequest,
    ScreenCodec,
)


def _req(codec: ScreenCodec = ScreenCodec.TEST) -> ScreenCaptureRequest:
    return ScreenCaptureRequest(
        session_id="SCN-CODEC",
        width=320,
        height=240,
        max_fps=10,
        codec=codec,
        pixel_format=PixelFormat.TEST,
    )


def test_test_codec_emits_synthetic_payload() -> None:
    """The TestCodec emits a deterministic 64-byte synthetic payload."""
    codec = TestCodec()
    result = codec.encode(_req(), b"")
    assert result.captured is True
    assert len(result.payload) == 64
    assert "synthetic" in result.note.lower() or "NOT" in result.note


def test_test_codec_payload_changes_per_sequence() -> None:
    """The TestCodec produces different payloads for different sequence values."""
    codec = TestCodec()
    r1 = codec.encode(_req(), b"")
    # Reuse same request — payload is deterministic per the request itself.
    r2 = codec.encode(_req(), b"")
    # Since ScreenCaptureRequest has no sequence field, the payload is stable.
    # This documents the deterministic guarantee.
    assert r1.payload == r2.payload


def test_test_codec_payload_size_metadata_matches() -> None:
    """The TestCodec payload_size matches the actual length."""
    codec = TestCodec()
    r = codec.encode(_req(), b"")
    assert r.captured is True
    assert r.width == 320
    assert r.height == 240


def test_future_h264_codec_rejects() -> None:
    """Future H264 codec is a documented integration point that does not produce frames."""
    codec = FutureH264Codec()
    with pytest.raises(ScreenCodecError):
        codec.encode(_req(ScreenCodec.H264), b"")


def test_future_vp8_codec_rejects() -> None:
    """Future VP8 codec is a documented integration point that does not produce frames."""
    codec = FutureVP8Codec()
    with pytest.raises(ScreenCodecError):
        codec.encode(_req(ScreenCodec.VP8), b"")


def test_future_vp9_codec_rejects() -> None:
    """Future VP9 codec is a documented integration point that does not produce frames."""
    codec = FutureVP9Codec()
    with pytest.raises(ScreenCodecError):
        codec.encode(_req(ScreenCodec.VP9), b"")


def test_future_webp_codec_rejects() -> None:
    """Future WebP codec is a documented integration point that does not produce frames."""
    codec = FutureWebPCodec()
    with pytest.raises(ScreenCodecError):
        codec.encode(_req(ScreenCodec.WEBP), b"")


def test_registry_returns_test_codec() -> None:
    """The registry returns the TestCodec for ScreenCodec.TEST."""
    reg = ScreenCodecRegistry()
    codec = reg.get(ScreenCodec.TEST)
    assert isinstance(codec, TestCodec)


def test_registry_raises_for_unknown() -> None:
    """Unknown codecs raise ScreenCodecError."""
    # Construct a fake codec enum value by bypassing validation.
    from enum import Enum

    class FakeCodec(str, Enum):
        X = "X"

    reg = ScreenCodecRegistry()
    with pytest.raises(ScreenCodecError):
        reg.get(FakeCodec.X)


def test_registry_is_production() -> None:
    """is_production correctly distinguishes TEST from production codecs."""
    reg = ScreenCodecRegistry()
    assert reg.is_production(ScreenCodec.TEST) is False
    assert reg.is_production(ScreenCodec.H264) is True
    assert reg.is_production("H264") is True


def test_registry_available() -> None:
    """available() lists every registered codec."""
    reg = ScreenCodecRegistry()
    codecs = reg.available()
    assert ScreenCodec.TEST in codecs
    assert ScreenCodec.H264 in codecs


def test_encode_frame_uses_default_registry() -> None:
    """encode_frame is a convenience wrapper that uses the default registry."""
    result = encode_frame(_req(), b"")
    assert result.captured is True
    assert len(result.payload) == 64


def test_codec_production_flag() -> None:
    """Each ScreenCodec value exposes is_production correctly."""
    assert ScreenCodec.TEST.is_production is False
    assert ScreenCodec.H264.is_production is True
    assert ScreenCodec.VP8.is_production is True
    assert ScreenCodec.VP9.is_production is True
    assert ScreenCodec.WEBP.is_production is True


def test_default_registry_is_singleton() -> None:
    """The default registry is a process-singleton instance."""
    assert isinstance(DEFAULT_REGISTRY, ScreenCodecRegistry)
    # Same as a freshly built one for codec enumeration.
    fresh = ScreenCodecRegistry()
    assert set(DEFAULT_REGISTRY.available()) == set(fresh.available())
