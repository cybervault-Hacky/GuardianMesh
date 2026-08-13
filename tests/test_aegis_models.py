"""Tests for Aegis Phase 8 data models, enums, and serialization."""

from __future__ import annotations

import datetime

import pytest

from guardianmesh.aegis.errors import AegisError
from guardianmesh.aegis.models import (
    AegisPlatform,
    AegisSessionInfo,
    AegisSessionState,
    EncoderBackend,
    ForegroundServiceNotification,
    FrameMetrics,
    ProviderCapabilities,
    SystemConsentRecord,
    SystemConsentState,
    generate_aegis_session_id,
    generate_consent_token,
)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


def test_platform_values_and_supports_real_capture() -> None:
    """AegisPlatform exposes the documented platform values."""
    assert AegisPlatform.ANDROID.value == "ANDROID"
    assert AegisPlatform.LINUX.value == "LINUX"
    assert AegisPlatform.TERMUX.value == "TERMUX"
    assert AegisPlatform.UNKNOWN.value == "UNKNOWN"
    assert AegisPlatform.ANDROID.supports_real_capture is True
    assert AegisPlatform.LINUX.supports_real_capture is False
    assert AegisPlatform.TERMUX.supports_real_capture is False
    assert AegisPlatform.UNKNOWN.supports_real_capture is False


def test_platform_from_str_case_insensitive() -> None:
    """Platform strings are parsed case-insensitively."""
    assert AegisPlatform.from_str("android") == AegisPlatform.ANDROID
    assert AegisPlatform.from_str("Linux") == AegisPlatform.LINUX


def test_platform_from_str_invalid() -> None:
    """Unknown platforms raise AegisError."""
    with pytest.raises(AegisError):
        AegisPlatform.from_str("Plan9")


def test_system_consent_state_values() -> None:
    """SystemConsentState exposes the documented values."""
    for state in (
        SystemConsentState.NOT_REQUESTED,
        SystemConsentState.REQUESTED,
        SystemConsentState.GRANTED,
        SystemConsentState.DENIED,
        SystemConsentState.REVOKED,
        SystemConsentState.EXPIRED,
    ):
        assert state.value == state.name


def test_encoder_backend_is_production_flag() -> None:
    """EncoderBackend exposes the is_production flag correctly."""
    assert EncoderBackend.MEDIA_CODEC.is_production is True
    assert EncoderBackend.TEST.is_production is False


def test_aegis_session_state_values() -> None:
    """AegisSessionState exposes the documented lifecycle values."""
    for state in (
        AegisSessionState.INITIALIZED,
        AegisSessionState.SYSTEM_CONSENT_REQUIRED,
        AegisSessionState.SYSTEM_CONSENT_DENIED,
        AegisSessionState.SYSTEM_CONSENT_GRANTED,
        AegisSessionState.CAPTURING,
        AegisSessionState.STOPPED,
        AegisSessionState.EXPIRED,
        AegisSessionState.REVOKED,
        AegisSessionState.FAILED,
    ):
        assert state.value == state.name


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------


def test_generate_aegis_session_id_unique() -> None:
    """Generated Aegis session IDs are unique and follow the format."""
    a = generate_aegis_session_id()
    b = generate_aegis_session_id()
    assert a != b
    assert a.startswith("AEG-")
    assert len(a) == 16


def test_generate_consent_token_unique() -> None:
    """Generated consent tokens are unique and follow the format."""
    a = generate_consent_token()
    b = generate_consent_token()
    assert a != b
    assert a.startswith("ACN-")


# ---------------------------------------------------------------------------
# ProviderCapabilities
# ---------------------------------------------------------------------------


def test_capabilities_rejects_zero_dimensions() -> None:
    """ProviderCapabilities refuses non-positive dimensions."""
    with pytest.raises(AegisError):
        ProviderCapabilities(
            platform=AegisPlatform.LINUX,
            backend=EncoderBackend.TEST,
            max_width=0,
            max_height=720,
            max_fps=10,
            supports_foreground_service=False,
            supports_media_projection=False,
        )


def test_capabilities_rejects_real_mediaprojection_on_non_android() -> None:
    """A non-Android platform must never claim to support real MediaProjection."""
    with pytest.raises(AegisError):
        ProviderCapabilities(
            platform=AegisPlatform.LINUX,
            backend=EncoderBackend.MEDIA_CODEC,
            max_width=1280,
            max_height=720,
            max_fps=10,
            supports_foreground_service=False,
            supports_media_projection=True,  # Forbidden.
        )


def test_capabilities_round_trip() -> None:
    """ProviderCapabilities round-trips through to_dict."""
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
        notes="production",
    )
    d = cap.to_dict()
    assert d["platform"] == "ANDROID"
    assert d["backend"] == "MEDIA_CODEC"
    assert d["max_width"] == 1280
    assert d["max_height"] == 720
    assert d["max_fps"] == 10
    assert d["supports_foreground_service"] is True
    assert d["supports_media_projection"] is True
    assert d["is_real_capture"] is True


# ---------------------------------------------------------------------------
# ForegroundServiceNotification
# ---------------------------------------------------------------------------


def test_notification_default_values_are_safe() -> None:
    """The default notification contains the documented STOP SHARING action."""
    n = ForegroundServiceNotification()
    d = n.to_dict()
    assert n.title == "GuardianMesh screen sharing is active"
    assert "STOP" in n.stop_action_label
    assert d["notification_id"] == 8421
    assert d["ongoing"] is True


def test_notification_rejects_empty_title() -> None:
    """An empty title is rejected."""
    with pytest.raises(AegisError):
        ForegroundServiceNotification(title="", stop_action_label="STOP")


def test_notification_rejects_empty_action_label() -> None:
    """An empty stop action label is rejected."""
    with pytest.raises(AegisError):
        ForegroundServiceNotification(title="t", stop_action_label="")


def test_notification_rejects_control_characters() -> None:
    """Control characters in title or body are rejected (privacy)."""
    with pytest.raises(AegisError):
        ForegroundServiceNotification(title="a\nb", stop_action_label="STOP")
    with pytest.raises(AegisError):
        ForegroundServiceNotification(title="t", body="b\nx", stop_action_label="STOP")


# ---------------------------------------------------------------------------
# FrameMetrics
# ---------------------------------------------------------------------------


def test_frame_metrics_initial_state() -> None:
    """A fresh metrics instance has zero counters."""
    m = FrameMetrics()
    s = m.snapshot().to_dict()
    assert s["frames_captured"] == 0
    assert s["frames_encoded"] == 0
    assert s["frames_dropped"] == 0
    assert s["transport_failures"] == 0


def test_frame_metrics_increments() -> None:
    """Each recorder method increments the appropriate counter."""
    m = FrameMetrics()
    m.record_capture()
    m.record_normalize()
    m.record_encode(5)
    m.record_queue()
    m.record_transmit()
    m.record_drop()
    m.record_projection_failure()
    m.record_encoder_failure()
    m.record_transport_failure()
    m.set_queue_depth(3, 30)
    m.set_last_sequence(7)
    s = m.snapshot().to_dict()
    assert s["frames_captured"] == 1
    assert s["frames_normalized"] == 1
    assert s["frames_encoded"] == 1
    assert s["frames_queued"] == 1
    assert s["frames_transmitted"] == 1
    assert s["frames_dropped"] == 1
    assert s["transport_failures"] == 1
    assert s["projection_failures"] == 1
    assert s["encoder_failures"] == 1
    assert s["queue_depth"] == 3
    assert s["queue_capacity"] == 30
    assert s["last_frame_sequence"] == 7


def test_frame_metrics_average_latency() -> None:
    """Average encode latency is computed correctly."""
    m = FrameMetrics()
    m.record_encode(10)
    m.record_encode(20)
    assert m.average_encode_latency_ms() == 15.0


def test_frame_metrics_average_latency_no_data() -> None:
    """Average encode latency is 0 when no encodes are recorded."""
    m = FrameMetrics()
    assert m.average_encode_latency_ms() == 0.0


def test_frame_metrics_snapshot_is_immutable() -> None:
    """FrameMetricsSnapshot is frozen and round-trips through to_dict."""
    m = FrameMetrics()
    m.record_capture()
    snap = m.snapshot()
    with pytest.raises((AttributeError, Exception)):  # FrozenInstanceError
        snap.frames_captured = 999  # type: ignore[misc]
    d = snap.to_dict()
    assert d["frames_captured"] == 1


def test_frame_metrics_clamps_negative_sequences() -> None:
    """Negative sequences are ignored by set_last_sequence."""
    m = FrameMetrics()
    m.set_last_sequence(-1)
    assert m.last_frame_sequence == 0


def test_frame_metrics_clamps_negative_latency() -> None:
    """Negative encode latency is clamped to zero."""
    m = FrameMetrics()
    m.record_encode(-5)
    assert m.encode_latency_total_ms == 0


# ---------------------------------------------------------------------------
# AegisSessionInfo
# ---------------------------------------------------------------------------


def _make_info(
    aegis_id: str = "AEG-12345678",
    screen_id: str = "SCN-12345678",
) -> AegisSessionInfo:
    now = datetime.datetime.now(datetime.UTC)
    return AegisSessionInfo(
        aegis_session_id=aegis_id,
        screen_session_id=screen_id,
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        consent_state=SystemConsentState.NOT_REQUESTED,
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        state=AegisSessionState.INITIALIZED.value,
        created_at=now.isoformat(),
        expires_at=(now + datetime.timedelta(seconds=300)).isoformat(),
    )


def test_session_info_validate_rejects_invalid_device() -> None:
    """AegisSessionInfo rejects malformed device IDs."""
    info = _make_info()
    info.device_id = "INVALID"
    with pytest.raises(AegisError):
        info.validate()


def test_session_info_validate_rejects_empty_ids() -> None:
    """AegisSessionInfo rejects empty session IDs."""
    info = _make_info()
    info.aegis_session_id = ""
    with pytest.raises(AegisError):
        info.validate()


def test_session_info_round_trip() -> None:
    """AegisSessionInfo round-trips through to_dict/from_dict."""
    info = _make_info()
    data = info.to_dict()
    restored = AegisSessionInfo.from_dict(data)
    assert restored.aegis_session_id == info.aegis_session_id
    assert restored.consent_state == SystemConsentState.NOT_REQUESTED
    assert restored.platform == AegisPlatform.ANDROID
    assert restored.backend == EncoderBackend.MEDIA_CODEC


# ---------------------------------------------------------------------------
# SystemConsentRecord
# ---------------------------------------------------------------------------


def test_system_consent_record_to_dict() -> None:
    """SystemConsentRecord serializes without exposing secrets."""
    record = SystemConsentRecord(
        consent_token="ACN-12345678",
        screen_session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        state=SystemConsentState.GRANTED,
        requested_at="2026-08-13T00:00:00+00:00",
        granted_at="2026-08-13T00:01:00+00:00",
        expires_at="2026-08-13T00:05:00+00:00",
    )
    d = record.to_dict()
    assert d["state"] == "GRANTED"
    assert d["consent_token"] == "ACN-12345678"
    # Verify the record contains no payload-bearing fields.
    forbidden = {"payload", "frame", "screenshot", "image", "pixels"}
    assert forbidden.isdisjoint(set(d.keys()))


def test_system_consent_state_from_str() -> None:
    """SystemConsentState parses case-insensitively."""
    assert SystemConsentState.from_str("granted") == SystemConsentState.GRANTED
    assert SystemConsentState.from_str("REVOKED") == SystemConsentState.REVOKED
    with pytest.raises(AegisError):
        SystemConsentState.from_str("invalid")
