"""Tests for audit errors, database integrity verification, and identity edge cases."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from guardianmesh.core.errors import (
    AuditError,
    DatabaseIntegrityError,
    IdentityError,
    InvalidIdentityError,
    StorageError,
)
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import Identity, IdentityRole
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_audit_logger_db_errors(tmp_path: Path) -> None:
    """Test AuditLogger raises AuditError when database operations fail."""
    db = Database(tmp_path / "audit_err.db")
    logger = AuditLogger(db)

    # Database not initialized (no table)
    with pytest.raises(AuditError):
        logger.record(AuditEventType.STARTUP)

    with pytest.raises(AuditError):
        logger.get_recent()


def test_audit_logger_corrupt_json_details(tmp_path: Path) -> None:
    """Test AuditLogger gracefully handles corrupted JSON strings in details column."""
    db = Database(tmp_path / "audit_corrupt.db")
    MigrationManager().apply_migrations(db)
    logger = AuditLogger(db)

    # Insert raw row with non-JSON details
    db.execute(
        """
        INSERT INTO audit_events (event_type, details, timestamp, actor_id, success)
        VALUES ('STARTUP', 'NOT_JSON_DATA', '2026-08-12T12:00:00Z', NULL, 1);
        """
    )

    events = logger.get_recent(limit=5)
    assert len(events) == 1
    assert events[0]["details"] == {}


def test_database_verify_or_raise(tmp_path: Path) -> None:
    """Test verify_or_raise raises DatabaseIntegrityError on check failure."""
    db = Database(tmp_path / "nonexistent.db")
    with pytest.raises(DatabaseIntegrityError):
        db.verify_or_raise()


def test_identity_models_edge_cases() -> None:
    """Test IdentityRole and Identity dataclass edge cases."""
    with pytest.raises(InvalidIdentityError):
        IdentityRole.from_str("UNKNOWN_ROLE")

    # Identity from dict with string JSON metadata
    data = {
        "id": "GM-P-83A1F72C",
        "role": "PARENT",
        "public_key_fingerprint": "SHA256:abcd",
        "public_key_pem": "...",
        "created_at": "2026-08-12T12:00:00Z",
        "label": "Test",
        "is_active": True,
        "metadata": '{"custom_key": 42}',
    }
    ident = Identity.from_dict(data)
    assert ident.metadata == {"custom_key": 42}

    # Corrupt string JSON metadata
    data_corrupt = dict(data)
    data_corrupt["metadata"] = "CORRUPTED_JSON_STRING"
    ident_corrupt = Identity.from_dict(data_corrupt)
    assert ident_corrupt.metadata == {}


def test_identity_manager_creation_and_validation_errors(tmp_path: Path) -> None:
    """Test IdentityManager error handling when DB or keys fail."""
    db = Database(tmp_path / "mgr_err.db")
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(tmp_path / "keys_err")
    mgr = IdentityManager(db, key_storage)

    # 1. Collision retry exhaustion
    target = "guardianmesh.identity.manager.IdentityManager.generate_identity_id"
    with patch(target, return_value="GM-P-11112222"):
        mgr.create_identity(IdentityRole.PARENT)
        with pytest.raises(IdentityError):
            mgr.create_identity(IdentityRole.PARENT)

    # 2. Database insert failure triggers cleanup
    with patch.object(db, "transaction", side_effect=Exception("DB write fail")):
        with pytest.raises(StorageError):
            mgr.create_identity(IdentityRole.CHILD)

    # 3. Cryptographic error in validate_identity_integrity
    ident, _ = mgr.create_identity(IdentityRole.PARENT)
    with patch("guardianmesh.identity.manager.public_key_from_pem", side_effect=Exception("Crypto fail")):
        valid, err = mgr.validate_identity_integrity(ident.id)
        assert valid is False
        assert "Cryptographic verification error" in str(err)
