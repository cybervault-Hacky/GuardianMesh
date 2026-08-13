"""Tests for Migration 10 (Atlas) — production hardening."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v10_creates_atlas_tables(tmp_path: Path) -> None:
    """Phase 10 migration creates the Atlas tables and indexes."""
    db_path = tmp_path / "v10.db"
    db = Database(db_path)

    # Apply migrations 1..9.
    for i in range(8):
        MigrationManager(migrations=[MIGRATIONS[i]]).apply_migrations(db)
    assert db.fetchone("SELECT MAX(version) AS v FROM schema_migrations;")["v"] == 9

    # Apply Migration 10.
    mgr_v10 = MigrationManager(migrations=[MIGRATIONS[8]])
    newly = mgr_v10.apply_migrations(db)
    assert newly == ["010_atlas"]
    assert mgr_v10.get_current_version(db) == 10

    # Verify all five Atlas tables exist.
    tables = [
        r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")
    ]
    for required in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        assert required in tables, f"Missing required table: {required}"


def test_migration_v10_never_persists_sensitive_data(tmp_path: Path) -> None:
    """Atlas tables must NEVER store private keys, frame bytes, or commands."""
    db_path = tmp_path / "v10_payload.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        forbidden = {
            "payload", "frame", "screenshot", "private_key", "password",
            "secret", "token", "otp", "command", "shell", "exec",
        }
        assert forbidden.isdisjoint(set(cols)), (
            f"Forbidden column in {table}: {forbidden & set(cols)}"
        )


def test_migration_v10_idempotent(tmp_path: Path) -> None:
    """Reapplying Migration 10 must be a no-op."""
    db_path = tmp_path / "v10_idempotent.db"
    db = Database(db_path)
    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    assert "010_atlas" in newly
    assert mgr.get_current_version(db) == 10

    newly2 = mgr.apply_migrations(db)
    assert newly2 == []


def test_migration_v10_insert_atlas_backup(tmp_path: Path) -> None:
    db_path = tmp_path / "v10_backup.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    db.execute(
        """
        INSERT INTO atlas_backups (
            backup_id, created_at, schema_version, orion_version,
            backup_format, device_id, integrity_digest,
            size_bytes, status, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "BAK-12345678",
            "2026-08-13T00:00:00+00:00",
            "10",
            "1.0.0",
            "atlas-1.0",
            None,
            "sha256:deadbeef",
            1024,
            "VALID",
            "",
        ),
    )
    row = db.fetchone("SELECT * FROM atlas_backups WHERE backup_id = 'BAK-12345678';")
    assert row is not None
    assert row["schema_version"] == "10"


def test_migration_v10_unique_retention_target(tmp_path: Path) -> None:
    """A UNIQUE INDEX on atlas_retention.target_table prevents duplicates."""
    db_path = tmp_path / "v10_retention.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    db.execute(
        """
        INSERT INTO atlas_retention (
            retention_id, target_table, retention_days,
            enabled, updated_at, notes
        ) VALUES (?, ?, ?, ?, ?, ?);
        """,
        (
            "RET-1",
            "audit_events",
            365,
            1,
            "2026-08-13T00:00:00+00:00",
            "",
        ),
    )
    from guardianmesh.core.errors import StorageError

    with pytest.raises(StorageError):
        db.execute(
            """
            INSERT INTO atlas_retention (
                retention_id, target_table, retention_days,
                enabled, updated_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                "RET-2",
                "audit_events",  # duplicate
                90,
                1,
                "2026-08-13T00:00:00+00:00",
                "",
            ),
        )


def test_migration_full_chain_through_v10(tmp_path: Path) -> None:
    """A fresh install through every migration 1 -> 10 works end-to-end."""
    db_path = tmp_path / "v1_through_v10.db"
    db = Database(db_path)

    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    assert len(newly) == 9  # 1, 2, 3, 4, 6, 7, 8, 9, 10
    assert mgr.get_current_version(db) == 10

    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    for required in (
        "identities",
        "audit_events",
        "pairing_sessions",
        "trusted_devices",
        "device_health",
        "telemetry_events",
        "policies",
        "alerts",
        "transport_sessions",
        "transport_peers",
        "screen_sessions",
        "screen_authorizations",
        "aegis_sessions",
        "orion_events",
        "orion_actions",
        "orion_capabilities",
        "orion_reconciliation",
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        assert required in tables, f"Missing required table: {required}"
