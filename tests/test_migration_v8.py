"""Tests for Migration 8 (Aegis) — production Android companion."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v8_creates_aegis_sessions(tmp_path: Path) -> None:
    """Phase 8 migration creates the aegis_sessions table and indexes."""
    db_path = tmp_path / "v8.db"
    db = Database(db_path)

    # Apply migrations 1..7 in stages.
    MigrationManager(migrations=MIGRATIONS[:5]).apply_migrations(db)
    MigrationManager(migrations=[MIGRATIONS[5]]).apply_migrations(db)
    # Apply Migration 8 (Aegis).
    mgr_v8 = MigrationManager(migrations=[MIGRATIONS[6]])
    newly = mgr_v8.apply_migrations(db)
    assert newly == ["008_aegis_screen_capture"]
    assert mgr_v8.get_current_version(db) == 8

    # Verify the aegis_sessions table exists.
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    assert "aegis_sessions" in tables

    # Verify indexes exist.
    indexes = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='index';")]
    assert "idx_aegis_sessions_screen" in indexes
    assert "idx_aegis_sessions_device" in indexes
    assert "idx_aegis_sessions_state" in indexes
    assert "idx_aegis_sessions_created" in indexes

    # Verify the CHECK constraint on consent_state.
    db.execute(
        """
        INSERT INTO aegis_sessions (
            aegis_session_id, screen_session_id, device_id, parent_id,
            consent_state, platform, backend, state, created_at, expires_at
        ) VALUES (
            'AEG-TESTVALID', 'SCN-1', 'GM-C-19A84E72', 'GM-P-83A1F72C',
            'GRANTED', 'ANDROID', 'MEDIA_CODEC', 'CAPTURING',
            '2026-08-13T00:00:00+00:00', '2026-08-13T00:05:00+00:00'
        );
        """
    )
    row = db.fetchone(
        "SELECT consent_state FROM aegis_sessions WHERE aegis_session_id = 'AEG-TESTVALID';"
    )
    assert row is not None
    assert row["consent_state"] == "GRANTED"

    # Invalid consent_state should fail due to CHECK constraint.
    from guardianmesh.core.errors import StorageError

    try:
        db.execute(
            """
            INSERT INTO aegis_sessions (
                aegis_session_id, screen_session_id, device_id, parent_id,
                consent_state, platform, backend, state, created_at, expires_at
            ) VALUES (
                'AEG-TESTBAD', 'SCN-2', 'GM-C-19A84E72', 'GM-P-83A1F72C',
                'NONSENSE', 'ANDROID', 'MEDIA_CODEC', 'CAPTURING',
                '2026-08-13T00:00:00+00:00', '2026-08-13T00:05:00+00:00'
            );
            """
        )
        raise AssertionError("Expected CHECK constraint rejection")
    except StorageError:
        pass


def test_migration_v8_idempotent(tmp_path: Path) -> None:
    """Reapplying Migration 8 must be a no-op."""
    db_path = tmp_path / "v8_idempotent.db"
    db = Database(db_path)

    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    assert "008_aegis_screen_capture" in newly
    assert "009_orion_schema" in newly
    assert mgr.get_current_version(db) == 9

    # Re-apply: no new migrations should be reported.
    newly2 = mgr.apply_migrations(db)
    assert newly2 == []


def test_migration_v8_never_persists_payload(tmp_path: Path) -> None:
    """The aegis_sessions table must not contain any payload columns."""
    db_path = tmp_path / "v8_payload.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(aegis_sessions);")]
    forbidden = {
        "payload",
        "payload_hex",
        "screenshot",
        "frame_data",
        "image",
        "raw_pixels",
        "encoded_video",
    }
    assert forbidden.isdisjoint(set(cols))


def test_migration_full_chain_through_v8(tmp_path: Path) -> None:
    """A fresh install through every migration 1 -> 8 works end-to-end."""
    db_path = tmp_path / "v1_through_v8.db"
    db = Database(db_path)

    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    assert len(newly) == 8  # 1, 2, 3, 4, 6, 7, 8, 9
    assert mgr.get_current_version(db) == 9

    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    for required in (
        "identities",
        "audit_events",
        "pairing_sessions",
        "trusted_devices",
        "device_health",
        "telemetry_events",
        "device_sequences",
        "policies",
        "policy_rules",
        "alerts",
        "transport_sessions",
        "transport_peers",
        "transport_messages",
        "transport_sequences",
        "screen_sessions",
        "aegis_sessions",
        "orion_events",
        "orion_actions",
        "orion_capabilities",
        "orion_reconciliation",
    ):
        assert required in tables, f"Missing required table: {required}"


def test_migration_chain_preserves_existing_data(tmp_path: Path) -> None:
    """Applying Migration 8 preserves all prior phase data."""
    db_path = tmp_path / "v8_preserves.db"
    db = Database(db_path)

    # Apply all prior migrations.
    MigrationManager(migrations=MIGRATIONS[:5]).apply_migrations(db)
    MigrationManager(migrations=[MIGRATIONS[5]]).apply_migrations(db)

    # Insert sample data into each phase's table.
    db.execute(
        "INSERT INTO identities (id, role, public_key_fingerprint, public_key_pem, created_at) "
        "VALUES ('GM-P-83A1F72C', 'PARENT', 'SHA256:1', '...', '2026-08-13T00:00:00Z');"
    )
    db.execute(
        """
        INSERT INTO screen_sessions (
            session_id, device_id, parent_id, state, requested_at, expires_at
        ) VALUES (
            'SCN-V7', 'GM-C-19A84E72', 'GM-P-83A1F72C', 'ACTIVE',
            '2026-08-13T00:00:00+00:00', '2026-08-13T00:05:00+00:00'
        );
        """
    )

    # Apply Migration 8.
    MigrationManager(migrations=[MIGRATIONS[6]]).apply_migrations(db)

    # All prior data is preserved.
    assert db.fetchone("SELECT * FROM identities WHERE id = 'GM-P-83A1F72C';") is not None
    assert db.fetchone("SELECT * FROM screen_sessions WHERE session_id = 'SCN-V7';") is not None
