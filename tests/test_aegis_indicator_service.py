"""Tests for the Aegis foreground service indicator model."""

from __future__ import annotations

import pytest

from guardianmesh.aegis.errors import (
    AegisForegroundServiceError,
    AegisPlatformUnavailableError,
)
from guardianmesh.aegis.indicator_service import (
    ForegroundServiceIndicator,
    default_linux_indicator,
    new_indicator_session_token,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ForegroundServiceNotification,
    ProviderCapabilities,
)


def _android_capability(supports_fg: bool = True) -> ProviderCapabilities:
    return ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=supports_fg,
        supports_media_projection=True,
    )


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------


def test_new_indicator_session_token_is_unique() -> None:
    """Each generated token is unique."""
    a = new_indicator_session_token()
    b = new_indicator_session_token()
    assert a != b
    assert len(a) == 16  # 8 bytes hex = 16 chars


# ---------------------------------------------------------------------------
# Default Linux indicator
# ---------------------------------------------------------------------------


def test_default_linux_indicator_is_inactive() -> None:
    """The default Linux indicator starts inactive."""
    ind = default_linux_indicator()
    assert ind.is_active is False


def test_default_linux_indicator_start_rejected() -> None:
    """The default Linux indicator refuses to start on a non-Android platform."""
    ind = default_linux_indicator()
    with pytest.raises(AegisPlatformUnavailableError):
        ind.start(session_id="AEG-1", parent_label="Parent")


# ---------------------------------------------------------------------------
# Android indicator
# ---------------------------------------------------------------------------


def test_indicator_starts_inactive() -> None:
    """A fresh indicator is inactive."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    assert ind.is_active is False
    assert ind.session_id is None


def test_indicator_start_activates() -> None:
    """start() activates the indicator for the given session."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.start(session_id="AEG-1", parent_label="Test Parent")
    assert ind.is_active is True
    assert ind.session_id == "AEG-1"


def test_indicator_start_twice_for_same_session_is_noop() -> None:
    """start() is idempotent for the same session."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.start(session_id="AEG-1", parent_label="Test")
    ind.start(session_id="AEG-1", parent_label="Test")
    assert ind.is_active is True
    assert ind.session_id == "AEG-1"


def test_indicator_start_for_different_session_raises() -> None:
    """start() refuses to switch to a different session while active."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.start(session_id="AEG-1", parent_label="Test")
    with pytest.raises(AegisForegroundServiceError):
        ind.start(session_id="AEG-2", parent_label="Test")


def test_indicator_stop_deactivates() -> None:
    """stop() deactivates the indicator."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.start(session_id="AEG-1", parent_label="Test")
    ind.stop()
    assert ind.is_active is False
    assert ind.session_id is None


def test_indicator_stop_when_inactive_is_idempotent() -> None:
    """stop() can be called when the indicator is already inactive."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.stop()
    ind.stop()
    assert ind.is_active is False


def test_indicator_can_be_reused_after_stop() -> None:
    """After stop(), start() works again for a new session."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.start(session_id="AEG-1", parent_label="Test")
    ind.stop()
    ind.start(session_id="AEG-2", parent_label="Test")
    assert ind.is_active is True
    assert ind.session_id == "AEG-2"


def test_indicator_diagnostics_no_payload() -> None:
    """Diagnostics never include frame content."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    ind.start(session_id="AEG-1", parent_label="Test")
    diag = ind.diagnostics()
    forbidden = {"payload", "frame", "screenshot", "image", "pixels"}
    assert forbidden.isdisjoint(set(diag.keys()))


def test_indicator_exposes_stop_action_label() -> None:
    """The diagnostics expose the STOP SHARING action label."""
    ind = ForegroundServiceIndicator(capability=_android_capability())
    diag = ind.diagnostics()
    assert "STOP" in diag["notification"]["stop_action_label"]


# ---------------------------------------------------------------------------
# Custom notification
# ---------------------------------------------------------------------------


def test_custom_notification_is_used() -> None:
    """A custom notification is exposed through diagnostics."""
    n = ForegroundServiceNotification(
        title="Custom title",
        body="Custom body",
        stop_action_label="END",
    )
    ind = ForegroundServiceIndicator(
        capability=_android_capability(),
        notification=n,
    )
    diag = ind.diagnostics()
    assert diag["notification"]["title"] == "Custom title"
    assert diag["notification"]["body"] == "Custom body"
    assert diag["notification"]["stop_action_label"] == "END"
