"""Tests for the visible child-side screen indicator and AndroidScreenProvider."""

from __future__ import annotations

import pytest

from guardianmesh.screen.indicator import (
    AdapterOnlyScreenProvider,
    AndroidScreenProvider,
    ScreenIndicator,
)
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCaptureRequest,
    ScreenCodec,
)


def _request(width: int = 1280, height: int = 720) -> ScreenCaptureRequest:
    return ScreenCaptureRequest(
        session_id="SCN-INDICATOR",
        width=width,
        height=height,
        max_fps=10,
        codec=ScreenCodec.TEST,
        pixel_format=PixelFormat.TEST,
    )


# ---------------------------------------------------------------------------
# AndroidScreenProvider boundary
# ---------------------------------------------------------------------------


def test_adapter_provider_is_available() -> None:
    """The adapter-only provider is always available for tests."""
    provider = AdapterOnlyScreenProvider()
    assert provider.is_available is True


def test_adapter_provider_is_not_real_capture() -> None:
    """The adapter-only provider must NEVER claim is_real_capture=True."""
    provider = AdapterOnlyScreenProvider()
    assert provider.is_real_capture is False


def test_adapter_provider_captures_within_bounds() -> None:
    """A request within bounds returns a captured frame with metadata."""
    provider = AdapterOnlyScreenProvider()
    result = provider.capture(_request())
    assert result.captured is True
    assert result.width == 1280
    assert result.height == 720
    assert result.codec == ScreenCodec.TEST
    assert len(result.payload) > 0
    assert "synthetic" in result.note.lower() or "NOT" in result.note


def test_adapter_provider_rejects_oversized_dimensions() -> None:
    """A request exceeding the adapter bounds returns a non-captured result."""
    provider = AdapterOnlyScreenProvider(max_width=1280, max_height=720)
    result = provider.capture(_request(width=9999, height=9999))
    assert result.captured is False
    assert result.payload == b""
    assert "exceeds" in result.note.lower()


def test_adapter_provider_rejects_excessive_fps() -> None:
    """A request with fps above the adapter cap is rejected."""
    provider = AdapterOnlyScreenProvider(max_fps=10)
    req = _request()
    req = ScreenCaptureRequest(
        session_id=req.session_id,
        width=req.width,
        height=req.height,
        max_fps=999,
        codec=req.codec,
        pixel_format=req.pixel_format,
    )
    result = provider.capture(req)
    assert result.captured is False
    assert result.payload == b""


def test_adapter_provider_is_real_capture_safety() -> None:
    """Repeated calls preserve the is_real_capture=False invariant."""
    provider = AdapterOnlyScreenProvider()
    for _ in range(5):
        provider.capture(_request())
    assert provider.is_real_capture is False


def test_adapter_provider_diagnostics_no_payload() -> None:
    """Diagnostics never include frame payload bytes."""
    provider = AdapterOnlyScreenProvider()
    diag = provider.diagnostics()
    assert diag["is_available"] is True
    assert diag["is_real_capture"] is False
    assert "payload" not in diag


def test_android_screen_provider_is_abstract() -> None:
    """AndroidScreenProvider cannot be instantiated directly."""
    with pytest.raises(TypeError):
        AndroidScreenProvider()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# ScreenIndicator
# ---------------------------------------------------------------------------


def test_indicator_inactive_by_default() -> None:
    """A fresh indicator is inactive."""
    ind = ScreenIndicator()
    assert ind.is_active is False
    assert "INACTIVE" in ind.render()


def test_indicator_activate_renders_visible_marker() -> None:
    """An active indicator MUST display SCREEN VIEW ACTIVE."""
    ind = ScreenIndicator()
    ind.activate(
        session_id="SCN-1234",
        parent_label="Zakir's Guardian",
        max_duration_seconds=300,
        started_at="2026-08-13T00:00:00+00:00",
    )
    assert ind.is_active is True
    text = ind.render()
    assert "SCREEN VIEW ACTIVE" in text
    assert "Zakir's Guardian" in text
    assert "STOP SHARING" in text


def test_indicator_deactivate_clears_state() -> None:
    """Deactivating an indicator removes the visible state."""
    ind = ScreenIndicator()
    ind.activate(
        session_id="SCN-1234",
        parent_label="Guardian",
        max_duration_seconds=300,
        started_at="2026-08-13T00:00:00+00:00",
    )
    ind.deactivate()
    assert ind.is_active is False
    assert "INACTIVE" in ind.render()


def test_indicator_update_remaining_clamps_to_zero() -> None:
    """update_remaining never produces a negative value."""
    ind = ScreenIndicator()
    ind.activate(
        session_id="SCN-1234",
        parent_label="Guardian",
        max_duration_seconds=300,
        started_at="2026-08-13T00:00:00+00:00",
    )
    ind.update_remaining(125)  # 02:05
    assert "02:05" in ind.render()
    ind.update_remaining(-1)  # Should clamp to 00:00.
    assert "00:00" in ind.render()


def test_indicator_idempotent_activation() -> None:
    """Activating twice does not corrupt state."""
    ind = ScreenIndicator()
    ind.activate(
        session_id="SCN-A",
        parent_label="First",
        max_duration_seconds=100,
        started_at="2026-08-13T00:00:00+00:00",
    )
    ind.activate(
        session_id="SCN-B",
        parent_label="Second",
        max_duration_seconds=200,
        started_at="2026-08-13T00:01:00+00:00",
    )
    assert ind.is_active is True
    assert "Second" in ind.render()
