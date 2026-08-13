"""Tests for incremental schema migration from v1 -> v2 -> v3 -> v4 -> v6."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v1_through_v6(tmp_path: Path) -> None:
    """Test multi-version incremental schema upgrades through Phase 6 Nexus."""
    db_path = tmp_path / "v1_through_v6.db"
    db = Database(db_path)

    # 1. Apply Migration 1 (Genesis)
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

    # 4. Apply Migration 4 (Sentinel)
    mgr_v4 = MigrationManager(migrations=MIGRATIONS[:4])
    mgr_v4.apply_migrations(db)
    assert mgr_v4.get_current_version(db) == 4

    # Insert test data across Phase 1, 2, 3, 4
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
    db.execute(
        """
        INSERT INTO policies (id, device_id, name, enabled, created_at, updated_at)
        VALUES ('POL-001', 'GM-C-19A84E72', 'Default Policy', 1,
                '2026-08-12T12:00:00Z', '2026-08-12T12:00:00Z');
        """
    )

    # 5. Apply Migration 6 (Nexus)
    mgr_v6 = MigrationManager(migrations=MIGRATIONS)
    newly_v6 = mgr_v6.apply_migrations(db)
    # Migration 7 (Vista) and Migration 8 (Aegis) are also pending in
    # MIGRATIONS, so three new migrations are applied in this step.
    assert len(newly_v6) == 3
    assert "006_nexus_transport" in newly_v6
    assert "007_vista_screen_sessions" in newly_v6
    assert "008_aegis_screen_capture" in newly_v6
    assert mgr_v6.get_current_version(db) == 8

    # Verify existing records from previous phases are preserved
    assert db.fetchone("SELECT * FROM identities WHERE id = 'GM-P-83A1F72C';") is not None
    assert (
        db.fetchone("SELECT * FROM trusted_devices WHERE remote_identity_id = 'GM-C-19A84E72';") is not None
    )
    assert db.fetchone("SELECT * FROM device_health WHERE device_id = 'GM-C-19A84E72';") is not None
    assert db.fetchone("SELECT * FROM policies WHERE id = 'POL-001';") is not None

    # Verify Phase 6 tables exist
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    assert "transport_sessions" in tables
    assert "transport_peers" in tables
    assert "transport_messages" in tables
    assert "transport_sequences" in tables

    # Verify Phase 7 (Vista) screen_sessions table exists.
    assert "screen_sessions" in tables

    # Verify Phase 8 (Aegis) aegis_sessions table exists.
    assert "aegis_sessions" in tables

    # Verify Phase 6 indexes exist
    indexes = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='index';")]
    assert "idx_transport_sessions_remote" in indexes
    assert "idx_transport_sessions_state" in indexes
    assert "idx_transport_peers_state" in indexes
    assert "idx_transport_msg_device" in indexes
    assert "idx_transport_seq_device" in indexes

    # Verify Phase 7 indexes exist
    assert "idx_screen_sessions_device" in indexes
    assert "idx_screen_sessions_state" in indexes

    # Verify Phase 8 indexes exist
    assert "idx_aegis_sessions_screen" in indexes
    assert "idx_aegis_sessions_state" in indexes

    # Idempotency: applying again applies 0 new migrations and version remains 8
    assert len(mgr_v6.apply_migrations(db)) == 0
    assert mgr_v6.get_current_version(db) == 8
