"""Tests for PairingManager end-to-end workflows: OTP verification, approval, denial, and cancellation."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    ChildAuthorizationDeniedError,
    OTPAttemptLimitExceededError,
    OTPVerificationError,
    RateLimitExceededError,
    ValidationError,
)
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.authorization import LocalTestAuthorizationAdapter
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.models import PairingState
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def setup_pairing_environment(tmp_path: Path) -> tuple[PairingManager, str, str, KeyStorageManager]:
    """Helper to initialize database, identities, and PairingManager."""
    db_path = tmp_path / "pairing_mgr.db"
    keys_dir = tmp_path / "keys"

    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    config = GuardianConfig(
        home_dir=tmp_path,
        otp_expiration_seconds=300,
        session_expiration_seconds=600,
        otp_resend_cooldown_seconds=30,
        max_otp_attempts=3,
    )
    key_storage = KeyStorageManager(keys_dir)
    audit_logger = AuditLogger(db)
    identity_mgr = IdentityManager(db, key_storage, audit_logger)

    parent_ident, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="Parent Dev")
    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="Child Dev")

    trust_mgr = TrustManager(db, audit_logger)
    pairing_mgr = PairingManager(db, config, key_storage, trust_mgr, audit_logger)

    return pairing_mgr, parent_ident.id, child_ident.id, key_storage


def test_end_to_end_successful_pairing_demo(tmp_path: Path) -> None:
    """Test full successful pairing flow using Demo delivery method and child approval."""
    pairing_mgr, parent_id, child_id, key_storage = setup_pairing_environment(tmp_path)

    # 1. Parent initiates session in Demo mode
    session, demo_otp = pairing_mgr.create_session(
        parent_identity_id=parent_id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        child_identity_id=child_id,
    )
    assert session.session_id.startswith("PAIR-")
    assert session.state == PairingState.VERIFICATION_PENDING
    assert demo_otp is not None
    assert len(demo_otp) == 6

    # 2. Parent submits verification code
    verified_session = pairing_mgr.verify_otp(session.session_id, demo_otp)
    assert verified_session.state == PairingState.CHILD_AUTHORIZATION_PENDING
    assert verified_session.verified_at is not None

    # 3. Request challenge nonce for child authorization
    nonce = pairing_mgr.create_authorization_challenge(session.session_id, child_id)
    assert len(nonce) == 64

    # 4. Child signs and approves pairing decision
    adapter = LocalTestAuthorizationAdapter(key_storage, auto_approve=True)
    decision = adapter.request_authorization(
        session_id=session.session_id,
        parent_identity_id=parent_id,
        parent_public_key_fingerprint="SHA256:dummy",
        child_identity_id=child_id,
        nonce=nonce,
    )

    # 5. Submit child authorization decision -> Trust Established
    trusted_device = pairing_mgr.submit_child_authorization(
        session_id=session.session_id,
        decision=decision,
        label="Kid's Phone",
    )
    assert trusted_device.remote_identity_id == child_id
    assert trusted_device.status == "ACTIVE"
    assert trusted_device.is_active is True

    # 6. Verify session reached final terminal state PAIRED
    final_session = pairing_mgr.get_session(session.session_id)
    assert final_session is not None
    assert final_session.state == PairingState.PAIRED
    assert final_session.completed_at is not None


def test_child_denial_workflow(tmp_path: Path) -> None:
    """Test child denial transitions session to DENIED and creates zero trust records."""
    pairing_mgr, parent_id, child_id, key_storage = setup_pairing_environment(tmp_path)

    # 1. Create and verify session
    session, demo_otp = pairing_mgr.create_session(
        parent_identity_id=parent_id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        child_identity_id=child_id,
    )
    assert demo_otp is not None
    pairing_mgr.verify_otp(session.session_id, demo_otp)

    # 2. Generate challenge nonce
    nonce = pairing_mgr.create_authorization_challenge(session.session_id, child_id)

    # 3. Child explicitly DENIES authorization
    adapter = LocalTestAuthorizationAdapter(key_storage, auto_approve=False)
    denied_decision = adapter.request_authorization(
        session_id=session.session_id,
        parent_identity_id=parent_id,
        parent_public_key_fingerprint="SHA256:dummy",
        child_identity_id=child_id,
        nonce=nonce,
    )

    with pytest.raises(ChildAuthorizationDeniedError):
        pairing_mgr.submit_child_authorization(session.session_id, denied_decision)

    # Verify session state is DENIED
    session_after = pairing_mgr.get_session(session.session_id)
    assert session_after is not None
    assert session_after.state == PairingState.DENIED

    # Verify no trust record created
    assert pairing_mgr.trust_manager.is_trusted(parent_id, child_id) is False


def test_otp_attempt_limits_and_failure(tmp_path: Path) -> None:
    """Test entering incorrect OTPs up to max_attempts invalidates session."""
    pairing_mgr, parent_id, child_id, _ = setup_pairing_environment(tmp_path)

    session, _ = pairing_mgr.create_session(
        parent_identity_id=parent_id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
    )

    # Attempt 1 (wrong code)
    with pytest.raises(OTPVerificationError) as excinfo:
        pairing_mgr.verify_otp(session.session_id, "000000")
    assert "2 attempt(s) remaining" in str(excinfo.value)

    # Attempt 2 (wrong code)
    with pytest.raises(OTPVerificationError) as excinfo:
        pairing_mgr.verify_otp(session.session_id, "000000")
    assert "1 attempt(s) remaining" in str(excinfo.value)

    # Attempt 3 (wrong code -> limit exceeded)
    with pytest.raises(OTPAttemptLimitExceededError):
        pairing_mgr.verify_otp(session.session_id, "000000")

    # Session is now expired/invalidated
    session_failed = pairing_mgr.get_session(session.session_id)
    assert session_failed is not None
    assert session_failed.state == PairingState.EXPIRED


def test_otp_resend_and_cooldown(tmp_path: Path) -> None:
    """Test OTP resend cooldown enforcement."""
    pairing_mgr, parent_id, _, _ = setup_pairing_environment(tmp_path)

    session, _ = pairing_mgr.create_session(
        parent_identity_id=parent_id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
    )

    # Immediate resend should raise RateLimitExceededError (30s cooldown active)
    with pytest.raises(RateLimitExceededError) as excinfo:
        pairing_mgr.resend_otp(session.session_id)
    assert "cooldown active" in str(excinfo.value)


def test_cancel_pairing_session(tmp_path: Path) -> None:
    """Test explicit cancellation of a pending pairing session."""
    pairing_mgr, parent_id, _, _ = setup_pairing_environment(tmp_path)

    session, _ = pairing_mgr.create_session(
        parent_identity_id=parent_id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
    )

    assert pairing_mgr.cancel_session(session.session_id) is True
    cancelled = pairing_mgr.get_session(session.session_id)
    assert cancelled is not None
    assert cancelled.state == PairingState.CANCELLED


def test_invalid_initiator_role(tmp_path: Path) -> None:
    """Test child identity cannot initiate a pairing session."""
    pairing_mgr, _, child_id, _ = setup_pairing_environment(tmp_path)

    with pytest.raises(ValidationError) as excinfo:
        pairing_mgr.create_session(
            parent_identity_id=child_id,
            verification_method="DEMO",
            verification_destination="demo@guardianmesh.local",
        )
    assert "PARENT" in str(excinfo.value)
