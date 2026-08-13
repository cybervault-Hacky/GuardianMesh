"""Tests for child authorization, challenge-nonce replay protection, and signature verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.errors import InvalidNonceError, ReplayedNonceError
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.authorization import (
    ChildAuthDecision,
    FutureAndroidAuthorizationAdapter,
    LocalTestAuthorizationAdapter,
    create_signed_child_decision,
    generate_auth_nonce,
    register_nonce,
    validate_and_consume_nonce,
    verify_child_decision_signature,
)
from guardianmesh.security.crypto import generate_keypair
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_auth_nonce_generation_and_consumption(tmp_path: Path) -> None:
    """Test challenge nonce lifecycle: registration, consumption, and replay rejection."""
    db = Database(tmp_path / "nonce_test.db")
    MigrationManager().apply_migrations(db)

    session_id = "PAIR-NONCE01"
    child_id = "GM-C-19A84E72"
    nonce = generate_auth_nonce()
    assert len(nonce) == 64

    # Register nonce with 300s lifetime
    register_nonce(db, nonce, session_id, child_id, lifetime_seconds=300)

    # First consumption should succeed
    validate_and_consume_nonce(db, nonce, session_id, child_id)

    # Second consumption must raise ReplayedNonceError (replay protection)
    with pytest.raises(ReplayedNonceError):
        validate_and_consume_nonce(db, nonce, session_id, child_id)

    # Non-existent nonce raises InvalidNonceError
    with pytest.raises(InvalidNonceError):
        validate_and_consume_nonce(db, "fake_nonce_value", session_id, child_id)


def test_auth_nonce_expiration(tmp_path: Path) -> None:
    """Test expired challenge nonce is rejected."""
    db = Database(tmp_path / "nonce_exp.db")
    MigrationManager().apply_migrations(db)

    session_id = "PAIR-NONCE02"
    child_id = "GM-C-19A84E72"
    nonce = generate_auth_nonce()

    # Register with negative lifetime (already expired)
    register_nonce(db, nonce, session_id, child_id, lifetime_seconds=-10)

    with pytest.raises(InvalidNonceError) as excinfo:
        validate_and_consume_nonce(db, nonce, session_id, child_id)
    assert "has expired" in str(excinfo.value)


def test_child_decision_signing_and_verification() -> None:
    """Test cryptographic signing of child authorization decisions."""
    priv, pub = generate_keypair()
    session_id = "PAIR-AUTH01"
    parent_id = "GM-P-83A1F72C"
    child_id = "GM-C-19A84E72"
    nonce = generate_auth_nonce()

    # Approve decision
    decision_approve = create_signed_child_decision(
        private_key=priv,
        public_key=pub,
        session_id=session_id,
        parent_identity_id=parent_id,
        child_identity_id=child_id,
        nonce=nonce,
        approve=True,
    )
    assert decision_approve.is_approved is True
    assert verify_child_decision_signature(decision_approve) is True

    # Deny decision
    decision_deny = create_signed_child_decision(
        private_key=priv,
        public_key=pub,
        session_id=session_id,
        parent_identity_id=parent_id,
        child_identity_id=child_id,
        nonce=nonce,
        approve=False,
    )
    assert decision_deny.is_approved is False
    assert verify_child_decision_signature(decision_deny) is True

    # Tampered signature fails verification
    tampered_sig = bytearray.fromhex(decision_approve.signature_hex)
    tampered_sig[0] ^= 0xFF
    tampered_decision = ChildAuthDecision(
        decision=decision_approve.decision,
        session_id=decision_approve.session_id,
        parent_identity_id=decision_approve.parent_identity_id,
        child_identity_id=decision_approve.child_identity_id,
        nonce=decision_approve.nonce,
        child_public_key_pem=decision_approve.child_public_key_pem,
        signature_hex=tampered_sig.hex(),
        timestamp=decision_approve.timestamp,
    )
    assert verify_child_decision_signature(tampered_decision) is False


def test_local_test_authorization_adapter(tmp_path: Path) -> None:
    """Test LocalTestAuthorizationAdapter for automated test workflows."""
    db = Database(tmp_path / "adapter_test.db")
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="Test Child")
    parent_id = "GM-P-83A1F72C"
    session_id = "PAIR-ADAPT01"
    nonce = generate_auth_nonce()

    # Test auto-approve adapter
    adapter_approve = LocalTestAuthorizationAdapter(key_storage, auto_approve=True)
    decision = adapter_approve.request_authorization(
        session_id=session_id,
        parent_identity_id=parent_id,
        parent_public_key_fingerprint="SHA256:abcd",
        child_identity_id=child_ident.id,
        nonce=nonce,
    )
    assert decision.is_approved is True
    assert verify_child_decision_signature(decision) is True

    # Test auto-deny adapter
    adapter_deny = LocalTestAuthorizationAdapter(key_storage, auto_approve=False)
    decision_denied = adapter_deny.request_authorization(
        session_id=session_id,
        parent_identity_id=parent_id,
        parent_public_key_fingerprint="SHA256:abcd",
        child_identity_id=child_ident.id,
        nonce=nonce,
    )
    assert decision_denied.is_approved is False
    assert verify_child_decision_signature(decision_denied) is True


def test_future_android_adapter_raises() -> None:
    """Test FutureAndroidAuthorizationAdapter is clean placeholder raising NotImplementedError."""
    adapter = FutureAndroidAuthorizationAdapter()
    with pytest.raises(NotImplementedError):
        adapter.request_authorization(
            session_id="PAIR-01",
            parent_identity_id="GM-P-01",
            parent_public_key_fingerprint="SHA256:01",
            child_identity_id="GM-C-01",
            nonce="nonce",
        )
