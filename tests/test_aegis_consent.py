"""Tests for the Aegis Android system-consent gate."""

from __future__ import annotations

import datetime
from typing import Any

import pytest

from guardianmesh.aegis.consent import (
    ConsentDecision,
    SystemConsentGate,
    default_linux_capability,
)
from guardianmesh.aegis.errors import (
    AegisConsentDeniedError,
    AegisConsentRequiredError,
    AegisConsentRevokedError,
    AegisPlatformUnavailableError,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ProviderCapabilities,
    SystemConsentState,
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


def _fixed_clock() -> Any:
    state = {"now": datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)}

    def clock() -> datetime.datetime:
        return state["now"]

    def advance(seconds: int) -> None:
        state["now"] = state["now"] + datetime.timedelta(seconds=seconds)

    clock.advance = advance  # type: ignore[attr-defined]
    return clock


# ---------------------------------------------------------------------------
# Platform check
# ---------------------------------------------------------------------------


def test_linux_capability_has_no_real_capture() -> None:
    """The default Linux capability reports no real capture support."""
    cap = default_linux_capability()
    assert cap.platform == AegisPlatform.LINUX
    assert cap.supports_real_capture is False
    assert cap.supports_media_projection is False


def test_request_consent_rejected_on_linux() -> None:
    """request_consent refuses to operate on a non-Android platform."""
    gate = SystemConsentGate(capability=default_linux_capability())
    with pytest.raises(AegisPlatformUnavailableError):
        gate.request_consent(
            screen_session_id="SCN-1",
            device_id="GM-C-19A84E72",
            expires_at="2026-01-01T00:05:00+00:00",
        )


def test_evaluate_linux_always_denies() -> None:
    """On a non-Android platform the gate always denies capture."""
    gate = SystemConsentGate(capability=default_linux_capability())
    decision = gate.evaluate("SCN-1")
    assert decision.allowed is False
    assert decision.state == SystemConsentState.NOT_REQUESTED
    assert decision.capability.platform == AegisPlatform.LINUX


def test_evaluate_linux_assert_capture_raises() -> None:
    """On a non-Android platform, assert_capture_allowed always raises."""
    gate = SystemConsentGate(capability=default_linux_capability())
    with pytest.raises(AegisConsentRequiredError):
        gate.assert_capture_allowed("SCN-1")


# ---------------------------------------------------------------------------
# Android happy path
# ---------------------------------------------------------------------------


def test_request_then_grant_consent() -> None:
    """A typical request -> grant flow produces a GRANTED consent record."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    assert record.state == SystemConsentState.REQUESTED
    granted = gate.grant_consent(record.consent_token)
    assert granted.state == SystemConsentState.GRANTED
    assert granted.granted_at is not None


def test_grant_is_idempotent() -> None:
    """Re-granting an already granted consent returns the same record."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    first = gate.grant_consent(record.consent_token)
    second = gate.grant_consent(record.consent_token)
    assert first.state == SystemConsentState.GRANTED
    assert second.state == SystemConsentState.GRANTED
    assert first.granted_at == second.granted_at


def test_grant_after_denial_raises() -> None:
    """Granting a denied consent raises AegisConsentDeniedError."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.deny_consent(record.consent_token)
    with pytest.raises(AegisConsentDeniedError):
        gate.grant_consent(record.consent_token)


def test_grant_after_revocation_raises() -> None:
    """Granting a revoked consent raises AegisConsentRevokedError."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.grant_consent(record.consent_token)
    gate.revoke_consent(record.consent_token, reason="USER_REVOKED")
    with pytest.raises(AegisConsentRevokedError):
        gate.grant_consent(record.consent_token)


def test_evaluate_granted_returns_allowed() -> None:
    """A GRANTED consent returns allowed=True from evaluate()."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.grant_consent(record.consent_token)
    decision = gate.evaluate("SCN-1")
    assert decision.allowed is True
    assert decision.state == SystemConsentState.GRANTED


def test_assert_capture_allowed_when_granted() -> None:
    """assert_capture_allowed does not raise when consent is GRANTED."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.grant_consent(record.consent_token)
    decision = gate.assert_capture_allowed("SCN-1")
    assert decision.allowed is True


def test_assert_capture_allowed_when_not_requested() -> None:
    """assert_capture_allowed raises when no consent has been requested."""
    gate = SystemConsentGate(capability=_android_capability())
    with pytest.raises(AegisConsentRequiredError):
        gate.assert_capture_allowed("SCN-1")


def test_assert_capture_allowed_when_requested_but_not_granted() -> None:
    """assert_capture_allowed raises when consent is requested but not yet granted."""
    gate = SystemConsentGate(capability=_android_capability())
    gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    with pytest.raises(AegisConsentRequiredError):
        gate.assert_capture_allowed("SCN-1")


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def test_revoke_granted_consent() -> None:
    """Revoking a GRANTED consent transitions it to REVOKED."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.grant_consent(record.consent_token)
    revoked = gate.revoke_consent(record.consent_token, reason="USER_STOPPED")
    assert revoked.state == SystemConsentState.REVOKED
    decision = gate.evaluate("SCN-1")
    assert decision.allowed is False
    assert decision.state == SystemConsentState.REVOKED


def test_revoke_is_idempotent() -> None:
    """Revoking twice is a no-op."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.grant_consent(record.consent_token)
    gate.revoke_consent(record.consent_token, reason="X")
    second = gate.revoke_consent(record.consent_token, reason="Y")
    assert second.state == SystemConsentState.REVOKED
    # The second revoke should not change revoked_at or note.
    assert second.note == "X"


# ---------------------------------------------------------------------------
# Expiration
# ---------------------------------------------------------------------------


def test_expire_due_marks_expired() -> None:
    """expire_due() transitions past-expiration records to EXPIRED."""
    clock = _fixed_clock()
    gate = SystemConsentGate(capability=_android_capability(), clock=clock)
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.grant_consent(record.consent_token)
    clock.advance(360)
    expired = gate.expire_due()
    assert record.consent_token in expired
    decision = gate.evaluate("SCN-1")
    assert decision.state == SystemConsentState.EXPIRED
    assert decision.allowed is False


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def test_get_record_and_get_for_session() -> None:
    """The gate exposes consistent lookup helpers."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    assert gate.get_record(record.consent_token) is record
    assert gate.get_for_session("SCN-1") is record
    assert gate.get_record("ACN-MISSING") is None
    assert gate.get_for_session("SCN-MISSING") is None


def test_list_all_returns_all_records() -> None:
    """list_all returns every record in the gate."""
    gate = SystemConsentGate(capability=_android_capability())
    gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.request_consent(
        screen_session_id="SCN-2",
        device_id="GM-C-19A84E73",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    assert len(gate.list_all()) == 2


def test_clear_resets_state() -> None:
    """clear() removes every record from the gate."""
    gate = SystemConsentGate(capability=_android_capability())
    gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.clear()
    assert gate.list_all() == []


def test_denial_then_re_grant_does_not_auto_clear() -> None:
    """A denied consent cannot be silently re-granted without a fresh request."""
    gate = SystemConsentGate(capability=_android_capability())
    record = gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    gate.deny_consent(record.consent_token)
    with pytest.raises(AegisConsentDeniedError):
        gate.grant_consent(record.consent_token)


def test_evaluate_returns_metadata_only() -> None:
    """evaluate() returns a ConsentDecision that contains only metadata."""
    gate = SystemConsentGate(capability=_android_capability())
    gate.request_consent(
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        expires_at="2026-01-01T00:05:00+00:00",
    )
    decision = gate.evaluate("SCN-1")
    d = decision.to_dict()
    forbidden = {"payload", "frame", "screenshot", "image", "pixels"}
    assert forbidden.isdisjoint(set(d.keys()))


def test_consent_decision_to_dict_includes_capability() -> None:
    """ConsentDecision.to_dict includes the capability fields."""
    decision = ConsentDecision(
        allowed=False,
        state=SystemConsentState.NOT_REQUESTED,
        reason="no consent",
        capability=_android_capability(),
    )
    d = decision.to_dict()
    assert d["platform"] == "ANDROID"
    assert d["backend"] == "MEDIA_CODEC"
    assert d["supports_real_capture"] is True
