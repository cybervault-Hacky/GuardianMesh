"""Tests for the screen authorization state machine (Phase 7: Vista)."""

from __future__ import annotations

import datetime

import pytest

from guardianmesh.core.errors import ValidationError
from guardianmesh.screen.authorization import (
    DEFAULT_MAX_DURATION_SECONDS,
    MAX_MAX_DURATION_SECONDS,
    MIN_MAX_DURATION_SECONDS,
    ScreenAuthorizationManager,
    ScreenAuthorizationRequest,
    derive_session_state_from_decision,
)
from guardianmesh.screen.errors import (
    ScreenAuthorizationDeniedError,
    ScreenAuthorizationError,
    ScreenAuthorizationExpiredError,
    ScreenAuthorizationNotFoundError,
)
from guardianmesh.screen.models import (
    AuthorizationDecision,
    ScreenSessionState,
)


def _fixed_clock(start: datetime.datetime):
    """Return a clock function pinned to ``start`` that the caller can advance."""

    state = {"now": start}

    def clock() -> datetime.datetime:
        return state["now"]

    def advance(seconds: int) -> None:
        state["now"] = state["now"] + datetime.timedelta(seconds=seconds)

    clock.advance = advance  # type: ignore[attr-defined]
    return clock


def test_create_request_returns_pending_authorization() -> None:
    """A new request yields a PENDING authorization bound to a session."""
    mgr = ScreenAuthorizationManager()
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=120,
        label="Tablet in living room",
    )
    assert auth.decision == AuthorizationDecision.PENDING
    assert auth.session_id == "SCN-12345678"
    assert auth.device_id == "GM-C-19A84E72"
    assert auth.parent_id == "GM-P-83A1F72C"
    assert auth.max_duration_seconds == 120
    assert auth.label == "Tablet in living room"
    assert auth.metadata["nonce"]


def test_create_request_rejects_duplicate_session() -> None:
    """Only one active authorization per session is allowed."""
    mgr = ScreenAuthorizationManager()
    mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    with pytest.raises(ScreenAuthorizationError):
        mgr.create_request(
            session_id="SCN-12345678",
            device_id="GM-C-19A84E72",
            parent_id="GM-P-83A1F72C",
        )


def test_create_request_rejects_invalid_duration() -> None:
    """Duration outside the safe bounded range is rejected."""
    now = datetime.datetime.now(datetime.UTC)
    with pytest.raises(ValidationError):
        ScreenAuthorizationRequest(
            session_id="SCN-12345678",
            device_id="GM-C-19A84E72",
            parent_id="GM-P-83A1F72C",
            max_duration_seconds=MIN_MAX_DURATION_SECONDS - 1,
            requested_at=now.isoformat(),
        )
    with pytest.raises(ValidationError):
        ScreenAuthorizationRequest(
            session_id="SCN-12345678",
            device_id="GM-C-19A84E72",
            parent_id="GM-P-83A1F72C",
            max_duration_seconds=MAX_MAX_DURATION_SECONDS + 1,
            requested_at=now.isoformat(),
        )


def test_approve_transitions_to_approved() -> None:
    """Approve moves PENDING -> APPROVED and stamps approved_at."""
    mgr = ScreenAuthorizationManager()
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    updated = mgr.approve(auth.authorization_id)
    assert updated.decision == AuthorizationDecision.APPROVED
    assert updated.approved_at is not None


def test_deny_transitions_to_denied() -> None:
    """Deny moves PENDING -> DENIED and stamps denied_at."""
    mgr = ScreenAuthorizationManager()
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    updated = mgr.deny(auth.authorization_id)
    assert updated.decision == AuthorizationDecision.DENIED
    assert updated.denied_at is not None


def test_approve_after_deny_rejected() -> None:
    """Approving a denied authorization is rejected."""
    mgr = ScreenAuthorizationManager()
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    mgr.deny(auth.authorization_id)
    with pytest.raises(ScreenAuthorizationDeniedError):
        mgr.approve(auth.authorization_id)


def test_approve_unknown_authorization_raises() -> None:
    """Approving an unknown ID raises NotFound."""
    mgr = ScreenAuthorizationManager()
    with pytest.raises(ScreenAuthorizationNotFoundError):
        mgr.approve("SCA-UNKNOWN")


def test_expire_due_uses_injected_clock() -> None:
    """Authorizations are expired by the clock, not by wall time."""
    clock = _fixed_clock(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
    mgr = ScreenAuthorizationManager(clock=clock)
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=60,
    )
    clock.advance(120)
    expired_ids = mgr.expire_due()
    assert auth.authorization_id in expired_ids
    reloaded = mgr.get_by_authorization_id(auth.authorization_id)
    assert reloaded is not None
    assert reloaded.decision == AuthorizationDecision.EXPIRED


def test_approve_after_expiration_raises() -> None:
    """Approving an expired authorization is rejected."""
    clock = _fixed_clock(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
    mgr = ScreenAuthorizationManager(clock=clock)
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=60,
    )
    clock.advance(120)
    mgr.expire_due()
    with pytest.raises(ScreenAuthorizationExpiredError):
        mgr.approve(auth.authorization_id)


def test_revoke_marks_revoked() -> None:
    """Revoke is idempotent and marks the authorization as REVOKED."""
    mgr = ScreenAuthorizationManager()
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    mgr.approve(auth.authorization_id)
    revoked = mgr.revoke(auth.authorization_id, reason="TRUST_LOST")
    assert revoked.decision == AuthorizationDecision.REVOKED
    assert revoked.metadata["revoke_reason"] == "TRUST_LOST"
    # Revoking again is a no-op.
    revoked2 = mgr.revoke(auth.authorization_id)
    assert revoked2.decision == AuthorizationDecision.REVOKED


def test_revoke_denied_is_noop() -> None:
    """Revoke is a no-op when the authorization was already denied."""
    mgr = ScreenAuthorizationManager()
    auth = mgr.create_request(
        session_id="SCN-12345678",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    mgr.deny(auth.authorization_id)
    out = mgr.revoke(auth.authorization_id)
    assert out.decision == AuthorizationDecision.DENIED


def test_list_pending_returns_only_pending() -> None:
    """list_pending filters by decision."""
    mgr = ScreenAuthorizationManager()
    a = mgr.create_request(
        session_id="SCN-A", device_id="GM-C-19A84E72", parent_id="GM-P-83A1F72C"
    )
    mgr.create_request(
        session_id="SCN-B", device_id="GM-C-19A84E72", parent_id="GM-P-83A1F72C"
    )
    mgr.approve(a.authorization_id)
    pending = mgr.list_pending()
    assert len(pending) == 1
    assert pending[0].session_id == "SCN-B"


def test_default_max_duration_is_300_seconds() -> None:
    """The default authorization lifetime is 5 minutes (300s)."""
    assert DEFAULT_MAX_DURATION_SECONDS == 300


def test_derive_session_state_from_decision() -> None:
    """Decision -> session-state mapping is correct and always legal."""
    assert (
        derive_session_state_from_decision(AuthorizationDecision.PENDING)
        == ScreenSessionState.PENDING_CHILD_APPROVAL
    )
    assert (
        derive_session_state_from_decision(AuthorizationDecision.APPROVED)
        == ScreenSessionState.APPROVED
    )
    assert (
        derive_session_state_from_decision(AuthorizationDecision.DENIED)
        == ScreenSessionState.DENIED
    )
    assert (
        derive_session_state_from_decision(AuthorizationDecision.EXPIRED)
        == ScreenSessionState.EXPIRED
    )
    assert (
        derive_session_state_from_decision(AuthorizationDecision.REVOKED)
        == ScreenSessionState.REVOKED
    )
