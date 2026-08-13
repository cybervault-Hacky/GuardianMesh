"""Tests for Atlas Phase 10 integrity verification."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.atlas.integrity import (
    FORBIDDEN_TABLE_COLUMNS,
    REQUIRED_TABLES,
    AtlasIntegrityVerifier,
)
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_integrity.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_sqlite_integrity_passes_on_clean_db(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_sqlite_integrity()
    assert check.ok is True


def test_required_tables_present(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_required_tables()
    assert check.ok is True


def test_migration_state_at_v10(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_migration_state()
    assert check.ok is True


def test_foreign_keys_valid(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_foreign_keys()
    assert check.ok is True


def test_forbidden_columns_clean(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_forbidden_columns()
    assert check.ok is True


def test_audit_presence(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_audit_presence()
    assert check.ok is True


def test_audit_redaction_clean(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_audit_redaction()
    assert check.ok is True


def test_audit_redaction_detects_leak(db: Database) -> None:
    audit = AuditLogger(db)
    audit.record(
        event_type=AuditEventType.DATABASE_INITIALIZED,
        details={"frame": "secret"},
        success=True,
    )
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_audit_redaction()
    assert check.ok is False


def test_audit_redaction_handles_corrupted_json(db: Database) -> None:
    """Corrupted audit details are skipped, not crashed."""
    db.execute(
        "INSERT INTO audit_events (event_type, details, timestamp, actor_id, success) "
        "VALUES (?, ?, ?, ?, ?);",
        ("TEST", "{not valid json", "2026-08-13T00:00:00+00:00", "GM-P-00000001", 1),
    )
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_audit_redaction()
    assert check.ok is True


def test_audit_redaction_detects_password(db: Database) -> None:
    audit = AuditLogger(db)
    audit.record(
        event_type=AuditEventType.DATABASE_INITIALIZED,
        details={"password": "hunter2"},
        success=True,
    )
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_audit_redaction()
    assert check.ok is False


def test_identity_presence(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    check = verifier.check_identity_presence()
    assert check.ok is True


def test_run_all_returns_all_checks(db: Database) -> None:
    verifier = AtlasIntegrityVerifier(db)
    checks = verifier.run_all()
    assert len(checks) == 8
    assert all(c.ok for c in checks)


def test_required_tables_constant() -> None:
    for t in (
        "identities",
        "orion_events",
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
    ):
        assert t in REQUIRED_TABLES


def test_forbidden_table_columns_constant() -> None:
    assert "frame" in FORBIDDEN_TABLE_COLUMNS["orion_events"]
    assert "private_key" in FORBIDDEN_TABLE_COLUMNS["atlas_backups"]
    assert "secret" in FORBIDDEN_TABLE_COLUMNS["atlas_health"]
