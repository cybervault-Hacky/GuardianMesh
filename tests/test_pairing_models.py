"""Tests for pairing state machine, session data models, and trusted devices."""

from __future__ import annotations

import datetime

import pytest

from guardianmesh.core.errors import InvalidStateTransitionError
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.models import (
    PairingSession,
    PairingState,
    TrustedDevice,
    validate_state_transition,
)


def test_pairing_state_enum() -> None:
    """Test all expected Phase 2 pairing states are present."""
    assert PairingState.CREATED == "CREATED"
    assert PairingState.VERIFICATION_PENDING == "VERIFICATION_PENDING"
    assert PairingState.VERIFIED == "VERIFIED"
    assert PairingState.CHILD_AUTHORIZATION_PENDING == "CHILD_AUTHORIZATION_PENDING"
    assert PairingState.AUTHORIZED == "AUTHORIZED"
    assert PairingState.TRUST_ESTABLISHED == "TRUST_ESTABLISHED"
    assert PairingState.PAIRED == "PAIRED"
    assert PairingState.DENIED == "DENIED"
    assert PairingState.EXPIRED == "EXPIRED"
    assert PairingState.CANCELLED == "CANCELLED"
    assert PairingState.REVOKED == "REVOKED"


def test_valid_state_transitions() -> None:
    """Test standard forward lifecycle state transitions."""
    # Should not raise
    validate_state_transition(PairingState.CREATED, PairingState.VERIFICATION_PENDING)
    validate_state_transition(PairingState.VERIFICATION_PENDING, PairingState.VERIFIED)
    validate_state_transition(PairingState.VERIFIED, PairingState.CHILD_AUTHORIZATION_PENDING)
    validate_state_transition(PairingState.CHILD_AUTHORIZATION_PENDING, PairingState.AUTHORIZED)
    validate_state_transition(PairingState.CHILD_AUTHORIZATION_PENDING, PairingState.DENIED)
    validate_state_transition(PairingState.AUTHORIZED, PairingState.TRUST_ESTABLISHED)
    validate_state_transition(PairingState.TRUST_ESTABLISHED, PairingState.PAIRED)
    validate_state_transition(PairingState.PAIRED, PairingState.REVOKED)

    # Self-transition is a no-op
    validate_state_transition(PairingState.CREATED, PairingState.CREATED)


def test_invalid_state_transitions() -> None:
    """Test illegal state transitions raise InvalidStateTransitionError."""
    # Cannot jump from CREATED directly to PAIRED
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(PairingState.CREATED, PairingState.PAIRED)

    # Cannot jump from CREATED directly to AUTHORIZED without verification
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(PairingState.CREATED, PairingState.AUTHORIZED)

    # Cannot transition out of terminal states (DENIED, EXPIRED, CANCELLED, REVOKED)
    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(PairingState.DENIED, PairingState.PAIRED)

    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(PairingState.EXPIRED, PairingState.VERIFIED)

    with pytest.raises(InvalidStateTransitionError):
        validate_state_transition(PairingState.REVOKED, PairingState.PAIRED)


def test_pairing_session_serialization_and_helpers() -> None:
    """Test PairingSession model serialization, deserialization, and expiry calculations."""
    now = datetime.datetime.now(datetime.UTC)
    future = (now + datetime.timedelta(minutes=10)).isoformat()
    past = (now - datetime.timedelta(minutes=5)).isoformat()

    session = PairingSession(
        session_id="PAIR-7F2A91",
        parent_identity_id="GM-P-83A1F72C",
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        state=PairingState.CREATED,
        expires_at=future,
        otp_expires_at=future,
        auth_nonce_expires_at=future,
    )

    assert not session.is_expired()
    assert not session.is_otp_expired()
    assert not session.is_auth_nonce_expired()
    assert session.seconds_remaining() > 0

    # Transition
    session.transition_to(PairingState.VERIFICATION_PENDING)
    assert session.state == PairingState.VERIFICATION_PENDING

    # Test serialization roundtrip
    d = session.to_dict()
    assert d["session_id"] == "PAIR-7F2A91"
    assert d["state"] == "VERIFICATION_PENDING"

    restored = PairingSession.from_dict(d)
    assert restored.session_id == session.session_id
    assert restored.state == PairingState.VERIFICATION_PENDING

    # Test expired session
    session_expired = PairingSession(
        session_id="PAIR-EXPIRED",
        parent_identity_id="GM-P-83A1F72C",
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        expires_at=past,
        otp_expires_at=past,
    )
    assert session_expired.is_expired()
    assert session_expired.is_otp_expired()
    assert session_expired.seconds_remaining() == 0


def test_trusted_device_model() -> None:
    """Test TrustedDevice dataclass serialization and active check."""
    dev = TrustedDevice(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        remote_role=IdentityRole.CHILD,
        remote_public_key_fingerprint="SHA256:1i95EObyQHsID06E...",
        remote_public_key_pem="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        label="Kid's Tablet",
        status="ACTIVE",
        trust_version=1,
    )
    assert dev.is_active is True
    assert dev.remote_role == IdentityRole.CHILD

    d = dev.to_dict()
    assert d["remote_identity_id"] == "GM-C-19A84E72"
    assert d["status"] == "ACTIVE"

    restored = TrustedDevice.from_dict(d)
    assert restored.remote_identity_id == dev.remote_identity_id
    assert restored.remote_role == dev.remote_role
    assert restored.is_active is True
