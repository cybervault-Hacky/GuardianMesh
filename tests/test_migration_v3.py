"""Tests for incremental schema migration from Genesis (v1) -> Link (v2) -> Pulse (v3)."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v1_to_v2_to_v3(tmp_path: Path) -> None:
    """Test multi-version incremental schema upgrades preserve all historical data."""
    db_path = tmp_path / "v1_v2_v3.db"
    db = Database(db_path)

    # 1. Apply Migration 1
    mgr_v1 = MigrationManager(migrations=[MIGRATIONS[0]])
    mgr_v1.apply_migrations(db)
    assert mgr_v1.get_current_version(db) == 1

    db.execute(
        "INSERT INTO identities (id, role, public_key_fingerprint, public_key_pem, created_at) "
        "VALUES ('GM-P-83A1F72C', 'PARENT', 'SHA256:1', '...', '2026-08-12T12:00:00Z');"
    )

    # 2. Apply Migration 2
    mgr_v2 = MigrationManager(migrations=MIGRATIONS[:2])
    newly_v2 = mgr_v2.apply_migrations(db)
    assert len(newly_v2) == 1
    assert newly_v2[0] == "002_pairing_schema"
    assert mgr_v2.get_current_version(db) == 2

    db.execute(
        """
        INSERT INTO trusted_devices (
            local_identity_id, remote_identity_id, remote_role,
            remote_public_key_fingerprint, remote_public_key_pem, created_at, last_verified_at
        ) VALUES (
            'GM-P-83A1F72C', 'GM-C-19A84E72', 'CHILD', 'SHA256:2', '...',
            '2026-08-12T12:00:00Z', '2026-08-12T12:00:00Z'
        );
        """
    )

    # 3. Apply Migration 3 (Pulse)
    mgr_v3 = MigrationManager(migrations=MIGRATIONS[:3])
    newly_v3 = mgr_v3.apply_migrations(db)
    assert len(newly_v3) == 1
    assert newly_v3[0] == "003_telemetry_schema"
    assert mgr_v3.get_current_version(db) == 3

    # Verify Phase 1 and Phase 2 records survive intact
    ident = db.fetchone("SELECT * FROM identities WHERE id = 'GM-P-83A1F72C';")
    assert ident is not None

    trusted = db.fetchone("SELECT * FROM trusted_devices WHERE remote_identity_id = 'GM-C-19A84E72';")
    assert trusted is not None

    # Verify Phase 3 tables exist
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    assert "device_health" in tables
    assert "telemetry_events" in tables
    assert "device_sequences" in tables

    # Verify idempotency
    assert len(mgr_v3.apply_migrations(db)) == 0
    assert mgr_v3.get_current_version(db) == 3
