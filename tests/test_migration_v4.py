"""Tests for incremental schema migration from Genesis (v1) -> Link (v2) -> Pulse (v3) -> Sentinel (v4)."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v1_through_v4(tmp_path: Path) -> None:
    """Test multi-version incremental schema upgrades through Phase 4 Sentinel."""
    db_path = tmp_path / "v1_through_v4.db"
    db = Database(db_path)

    # 1. Apply Migration 1
    mgr_v1 = MigrationManager(migrations=[MIGRATIONS[0]])
    mgr_v1.apply_migrations(db)
    assert mgr_v1.get_current_version(db) == 1

    # 2. Apply Migration 2 (Link)
    mgr_v2 = MigrationManager(migrations=MIGRATIONS[:2])
    mgr_v2.apply_migrations(db)
    assert mgr_v2.get_current_version(db) == 2

    # 3. Apply Migration 3 (Pulse)
    mgr_v3 = MigrationManager(migrations=MIGRATIONS[:3])
    mgr_v3.apply_migrations(db)
    assert mgr_v3.get_current_version(db) == 3

    # Insert test data across Phase 1, 2, 3
    db.execute(
        "INSERT INTO identities (id, role, public_key_fingerprint, public_key_pem, created_at) "
        "VALUES ('GM-P-83A1F72C', 'PARENT', 'SHA256:1', '...', '2026-08-12T12:00:00Z');"
    )
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
    db.execute(
        """
        INSERT INTO device_health (
            device_id, health_state, last_heartbeat_at, connectivity, agent_version, updated_at
        ) VALUES (
            'GM-C-19A84E72', 'ONLINE', '2026-08-12T12:00:00Z', 'ONLINE', '0.3.0', '2026-08-12T12:00:00Z'
        );
        """
    )

    # 4. Apply Migration 4 (Sentinel)
    mgr_v4 = MigrationManager(migrations=MIGRATIONS[:4])
    newly_v4 = mgr_v4.apply_migrations(db)
    assert len(newly_v4) == 1
    assert newly_v4[0] == "004_sentinel_schema"
    assert mgr_v4.get_current_version(db) == 4

    # Verify existing records are preserved
    assert db.fetchone("SELECT * FROM identities WHERE id = 'GM-P-83A1F72C';") is not None
    assert (
        db.fetchone("SELECT * FROM trusted_devices WHERE remote_identity_id = 'GM-C-19A84E72';") is not None
    )
    assert db.fetchone("SELECT * FROM device_health WHERE device_id = 'GM-C-19A84E72';") is not None

    # Verify Phase 4 tables exist
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    assert "policies" in tables
    assert "policy_rules" in tables
    assert "alerts" in tables

    # Idempotency
    assert len(mgr_v4.apply_migrations(db)) == 0
    assert mgr_v4.get_current_version(db) == 4
