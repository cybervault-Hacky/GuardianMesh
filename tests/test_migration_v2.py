"""Tests for incremental schema migration from Phase 1 Genesis (v1) to Phase 2 Link (v2)."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_incremental_migration_genesis_to_link(tmp_path: Path) -> None:
    """Test upgrading an existing Phase 1 database to Phase 2 preserves all tables and data."""
    db_path = tmp_path / "genesis_to_link.db"
    db = Database(db_path)

    # 1. Run only Migration 1 (Genesis baseline)
    genesis_mgr = MigrationManager(migrations=[MIGRATIONS[0]])
    applied_v1 = genesis_mgr.apply_migrations(db)
    assert len(applied_v1) == 1
    assert applied_v1[0] == "001_initial_schema"
    assert genesis_mgr.get_current_version(db) == 1

    # Insert test Genesis data
    db.execute(
        """
        INSERT INTO identities (
            id, role, public_key_fingerprint, public_key_pem, created_at, label, is_active
        )
        VALUES ('GM-P-83A1F72C', 'PARENT', 'SHA256:abcd', '...', '2026-08-12T12:00:00Z', 'Genesis Parent', 1);
        """
    )
    db.execute(
        """
        INSERT INTO config_entries (key, value, updated_at)
        VALUES ('test_key', 'test_val', '2026-08-12T12:00:00Z');
        """
    )
    db.execute(
        """
        INSERT INTO audit_events (event_type, details, timestamp, actor_id, success)
        VALUES ('STARTUP', '{"version": "0.1.0"}', '2026-08-12T12:00:00Z', NULL, 1);
        """
    )

    # 2. Run Migration Manager up to Link (Migration 2)
    link_mgr = MigrationManager(migrations=MIGRATIONS[:2])
    applied_v2 = link_mgr.apply_migrations(db)
    assert len(applied_v2) == 1
    assert applied_v2[0] == "002_pairing_schema"
    assert link_mgr.get_current_version(db) == 2

    # 3. Verify Genesis records were preserved untouched
    ident_row = db.fetchone("SELECT * FROM identities WHERE id = 'GM-P-83A1F72C';")
    assert ident_row is not None
    assert ident_row["label"] == "Genesis Parent"

    cfg_row = db.fetchone("SELECT * FROM config_entries WHERE key = 'test_key';")
    assert cfg_row is not None
    assert cfg_row["value"] == "test_val"

    audit_row = db.fetchone("SELECT * FROM audit_events WHERE event_type = 'STARTUP';")
    assert audit_row is not None

    # 4. Verify Phase 2 tables exist and are functional
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")]
    assert "schema_migrations" in tables
    assert "identities" in tables
    assert "config_entries" in tables
    assert "audit_events" in tables
    assert "pairing_sessions" in tables
    assert "pairing_nonces" in tables
    assert "trusted_devices" in tables

    # 5. Verify Idempotency: re-running apply_migrations applies nothing
    second_applied = link_mgr.apply_migrations(db)
    assert len(second_applied) == 0
    assert link_mgr.get_current_version(db) == 2
