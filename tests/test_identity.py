"""Tests for GuardianMesh identity generation, validation, models, and manager."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.errors import IdentityNotFoundError, InvalidIdentityError
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import (
    IDENTITY_REGEX,
    Identity,
    IdentityRole,
    parse_identity_role,
    validate_identity_id,
)
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_identity_regex_format() -> None:
    """Test identity format regex matches valid parent and child patterns."""
    assert IDENTITY_REGEX.match("GM-P-83A1F72C")
    assert IDENTITY_REGEX.match("GM-C-19A84E72")
    assert IDENTITY_REGEX.match("GM-P-00000000")
    assert IDENTITY_REGEX.match("GM-C-FFFFFFFF")

    # Invalid formats
    assert not IDENTITY_REGEX.match("GM-P-83a1f72c")  # Lowercase
    assert not IDENTITY_REGEX.match("GM-X-83A1F72C")  # Invalid role
    assert not IDENTITY_REGEX.match("GM-P-83A1F72")  # 7 digits
    assert not IDENTITY_REGEX.match("GM-P-83A1F72CC")  # 9 digits
    assert not IDENTITY_REGEX.match("GM-P-83A1F72G")  # Non-hex G
    assert not IDENTITY_REGEX.match("83A1F72C")
    assert not IDENTITY_REGEX.match("user@example.com")
    assert not IDENTITY_REGEX.match("+15551234567")


def test_validate_identity_id() -> None:
    """Test validate_identity_id helper."""
    valid, err = validate_identity_id("GM-P-83A1F72C")
    assert valid
    assert err is None

    valid, err = validate_identity_id("GM-C-19A84E72")
    assert valid
    assert err is None

    # Invalid cases
    assert not validate_identity_id("")[0]
    assert not validate_identity_id(None)[0]  # type: ignore
    assert not validate_identity_id("GM-P-83a1f72c")[0]
    assert not validate_identity_id("GM-P-12345")[0]
    assert not validate_identity_id("GM-Z-12345678")[0]
    assert not validate_identity_id("GM-P-1234567890")[0]


def test_parse_identity_role() -> None:
    """Test extracting role from valid identity ID."""
    assert parse_identity_role("GM-P-83A1F72C") == IdentityRole.PARENT
    assert parse_identity_role("GM-C-19A84E72") == IdentityRole.CHILD

    with pytest.raises(InvalidIdentityError):
        parse_identity_role("invalid-id")


def test_identity_model_validation() -> None:
    """Test Identity dataclass validation and serialization."""
    ident = Identity(
        id="GM-P-83A1F72C",
        role=IdentityRole.PARENT,
        public_key_fingerprint="SHA256:abcd",
        public_key_pem="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
        created_at="2026-08-12T12:00:00Z",
        label="Main Parent",
    )
    assert ident.role_display == "Parent"
    assert ident.is_active is True

    d = ident.to_dict()
    assert d["id"] == "GM-P-83A1F72C"
    assert d["role"] == "PARENT"

    restored = Identity.from_dict(d)
    assert restored.id == ident.id
    assert restored.role == ident.role
    assert restored.label == ident.label

    # Mismatched role vs ID prefix
    with pytest.raises(InvalidIdentityError):
        Identity(
            id="GM-P-83A1F72C",
            role=IdentityRole.CHILD,
            public_key_fingerprint="SHA256:abcd",
            public_key_pem="...",
            created_at="2026-08-12T12:00:00Z",
        )


def test_identity_uniqueness() -> None:
    """Generate 1000 identities and verify 100% uniqueness and valid format."""
    generated = set()
    for _ in range(500):
        parent_id = IdentityManager.generate_identity_id(IdentityRole.PARENT)
        assert parent_id.startswith("GM-P-")
        assert len(parent_id) == 13
        assert parent_id not in generated
        generated.add(parent_id)

    for _ in range(500):
        child_id = IdentityManager.generate_identity_id(IdentityRole.CHILD)
        assert child_id.startswith("GM-C-")
        assert len(child_id) == 13
        assert child_id not in generated
        generated.add(child_id)

    assert len(generated) == 1000


def test_identity_manager_lifecycle(tmp_path: Path) -> None:
    """Test end-to-end creation, persistence, activation, and validation with IdentityManager."""
    db_path = tmp_path / "test.db"
    keys_dir = tmp_path / "keys"

    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(keys_dir)
    audit_logger = AuditLogger(db)
    mgr = IdentityManager(db, key_storage, audit_logger)

    # Initial state: no active identity
    assert mgr.get_active_identity() is None
    assert mgr.list_identities() == []

    # Create Parent identity
    parent_ident, priv_key_path = mgr.create_identity(
        role=IdentityRole.PARENT,
        label="Parent Device #1",
        set_active=True,
    )
    assert parent_ident.id.startswith("GM-P-")
    assert priv_key_path.is_file()
    assert parent_ident.is_active is True

    # Check active identity
    active = mgr.get_active_identity()
    assert active is not None
    assert active.id == parent_ident.id
    assert active.label == "Parent Device #1"

    # Validate integrity
    is_valid, err = mgr.validate_identity_integrity(parent_ident.id)
    assert is_valid is True
    assert err is None

    # Create Child identity
    child_ident, child_key_path = mgr.create_identity(
        role=IdentityRole.CHILD,
        label="Child Device #1",
        set_active=True,
    )
    assert child_ident.id.startswith("GM-C-")
    assert child_key_path.is_file()

    # Active identity should now be the child
    active2 = mgr.get_active_identity()
    assert active2 is not None
    assert active2.id == child_ident.id

    # List all identities
    all_idents = mgr.list_identities()
    assert len(all_idents) == 2

    # Switch active identity back to parent
    mgr.set_active_identity(parent_ident.id)
    active3 = mgr.get_active_identity()
    assert active3 is not None
    assert active3.id == parent_ident.id

    # Non-existent identity activation raises IdentityNotFoundError
    with pytest.raises(IdentityNotFoundError):
        mgr.set_active_identity("GM-P-00000000")
