"""Tests for TrustManager: trust establishment, listing, active verification, and revocation."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.errors import DeviceNotTrustedError, SecurityError, TrustRevokedError
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.security.fingerprints import compute_public_key_fingerprint
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_trust_manager_lifecycle(tmp_path: Path) -> None:
    """Test establishing trust, verifying active status, listing, renaming, and revocation."""
    db = Database(tmp_path / "trust_test.db")
    MigrationManager().apply_migrations(db)
    audit_logger = AuditLogger(db)
    trust_mgr = TrustManager(db, audit_logger)

    local_parent = "GM-P-83A1F72C"
    remote_child = "GM-C-19A84E72"
    _, child_pub = generate_keypair()
    child_pub_pem = public_key_to_pem(child_pub).decode("utf-8")
    expected_fp = compute_public_key_fingerprint(child_pub)

    # 1. Establish trust
    trusted_dev = trust_mgr.establish_trust(
        local_identity_id=local_parent,
        remote_identity_id=remote_child,
        remote_public_key_pem=child_pub_pem,
        pairing_session_id="PAIR-TST01",
        label="Kid's Tablet",
    )
    assert trusted_dev.remote_identity_id == remote_child
    assert trusted_dev.remote_role == IdentityRole.CHILD
    assert trusted_dev.remote_public_key_fingerprint == expected_fp
    assert trusted_dev.status == "ACTIVE"
    assert trusted_dev.is_active is True

    # 2. Check is_trusted
    assert trust_mgr.is_trusted(local_parent, remote_child) is True
    assert trust_mgr.is_trusted(local_parent, "GM-C-00000000") is False

    # 3. Verify device trust or raise
    verified = trust_mgr.verify_device_trust_or_raise(local_parent, remote_child)
    assert verified.remote_identity_id == remote_child

    # 4. List devices
    devices = trust_mgr.list_trusted_devices(local_identity_id=local_parent)
    assert len(devices) == 1
    assert devices[0].remote_identity_id == remote_child

    # 5. Rename device
    assert trust_mgr.rename_trusted_device(local_parent, remote_child, "Updated Tablet Name") is True
    updated = trust_mgr.get_trusted_device(local_parent, remote_child)
    assert updated is not None
    assert updated.label == "Updated Tablet Name"

    # 6. Revoke trust
    assert trust_mgr.revoke_trust(local_parent, remote_child, reason="User requested revocation") is True
    revoked_dev = trust_mgr.get_trusted_device(local_parent, remote_child)
    assert revoked_dev is not None
    assert revoked_dev.status == "REVOKED"
    assert revoked_dev.is_active is False

    # 7. is_trusted returns False after revocation
    assert trust_mgr.is_trusted(local_parent, remote_child) is False

    # 8. verify_device_trust_or_raise raises TrustRevokedError
    with pytest.raises(TrustRevokedError):
        trust_mgr.verify_device_trust_or_raise(local_parent, remote_child)

    # 9. Non-existent device raises DeviceNotTrustedError
    with pytest.raises(DeviceNotTrustedError):
        trust_mgr.verify_device_trust_or_raise(local_parent, "GM-C-99999999")


def test_trust_manager_invalid_identity_or_key(tmp_path: Path) -> None:
    """Test error handling on malformed identity or corrupted PEM."""
    db = Database(tmp_path / "trust_err.db")
    MigrationManager().apply_migrations(db)
    trust_mgr = TrustManager(db)

    # Invalid remote ID
    with pytest.raises(SecurityError):
        trust_mgr.establish_trust(
            local_identity_id="GM-P-83A1F72C",
            remote_identity_id="invalid-id",
            remote_public_key_pem="...",
        )

    # Corrupt PEM
    with pytest.raises(SecurityError):
        trust_mgr.establish_trust(
            local_identity_id="GM-P-83A1F72C",
            remote_identity_id="GM-C-19A84E72",
            remote_public_key_pem="NOT_VALID_PEM_DATA",
        )
