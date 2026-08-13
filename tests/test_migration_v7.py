"""Tests for Migration 7 (Vista) — consent-based view-only screen sessions."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v7_creates_screen_sessions(tmp_path: Path) -> None:
    """Phase 7 migration must create the screen_sessions table and indexes."""
    db_path = tmp_path / "v7.db"
    db = Database(db_path)

    # Apply migrations 1..4 (Genesis, Link, Pulse, Sentinel).
    mgr_pre = MigrationManager(migrations=MIGRATIONS[:4])
    mgr_pre.apply_migrations(db)
    assert mgr_pre.get_current_version(db) == 4

    # Apply Migration 6 (Nexus).
    mgr_v6 = MigrationManager(migrations=MIGRATIONS[:5])
    mgr_v6.apply_migrations(db)
    assert mgr_v6.get_current_version(db) == 6

    # Apply Migration 7 (Vista).
    mgr_v7 = MigrationManager(migrations=[MIGRATIONS[5]])
    newly = mgr_v7.apply_migrations(db)
    assert newly == ["007_vista_screen_sessions"]
    assert mgr_v7.get_current_version(db) == 7

    # Apply Migration 8 (Aegis) on top.
    mgr_v8 = MigrationManager(migrations=[MIGRATIONS[6]])
    newly8 = mgr_v8.apply_migrations(db)
    assert newly8 == ["008_aegis_screen_capture"]
    assert mgr_v8.get_current_version(db) == 8

    # Verify the table exists.
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    assert "screen_sessions" in tables

    # Verify indexes exist.
    indexes = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='index';")]
    assert "idx_screen_sessions_device" in indexes
    assert "idx_screen_sessions_parent" in indexes
    assert "idx_screen_sessions_state" in indexes
    assert "idx_screen_sessions_requested" in indexes
    assert "idx_screen_sessions_active_device" in indexes

    # Verify Migration 8 added aegis_sessions.
    assert "aegis_sessions" in tables

    # Verify CHECK constraint on state.
    db.execute(
        """
        INSERT INTO screen_sessions (
            session_id, device_id, parent_id, state, requested_at, expires_at
        ) VALUES (
            'SCN-TESTVALIDSTATE', 'GM-C-19A84E72', 'GM-P-83A1F72C',
            'ACTIVE', '2026-08-13T00:00:00+00:00',
            '2026-08-13T00:05:00+00:00'
        );
        """
    )
    row = db.fetchone(
        "SELECT state FROM screen_sessions WHERE session_id = 'SCN-TESTVALIDSTATE';"
    )
    assert row is not None
    assert row["state"] == "ACTIVE"

    # Invalid state should fail due to CHECK constraint.
    from guardianmesh.core.errors import StorageError

    try:
        db.execute(
            """
            INSERT INTO screen_sessions (
                session_id, device_id, parent_id, state, requested_at, expires_at
            ) VALUES (
                'SCN-TESTBADSTATE', 'GM-C-19A84E72', 'GM-P-83A1F72C',
                'NONSENSE', '2026-08-13T00:00:00+00:00',
                '2026-08-13T00:05:00+00:00'
            );
            """
        )
        raise AssertionError("Expected CHECK constraint rejection")
    except StorageError:
        pass


def test_migration_v7_idempotent(tmp_path: Path) -> None:
    """Reapplying Migration 7 must be a no-op."""
    db_path = tmp_path / "v7_idempotent.db"
    db = Database(db_path)

    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    assert "007_vista_screen_sessions" in newly
    assert "008_aegis_screen_capture" in newly
    assert "009_orion_schema" in newly
    assert "010_atlas" in newly
    assert mgr.get_current_version(db) == 10

    # Re-apply: no new migrations should be reported.
    newly2 = mgr.apply_migrations(db)
    assert newly2 == []
    assert mgr.get_current_version(db) == 10


def test_migration_full_chain_through_v10(tmp_path: Path) -> None:
    """Run a fresh install through every migration 1 -> 10 and ensure nothing is broken."""
    db_path = tmp_path / "v1_through_v10.db"
    db = Database(db_path)

    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    # MIGRATIONS is the documented 9-version list: 1, 2, 3, 4, 6, 7, 8, 9, 10.
    # (Version 5 is reserved / unused; this is the documented chain.)
    assert len(newly) == 9
    assert mgr.get_current_version(db) == 10

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
