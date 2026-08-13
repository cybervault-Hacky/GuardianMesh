"""Tests for Migration 9 (Orion) — consent-aware orchestration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager


def test_migration_v9_creates_orion_tables(tmp_path: Path) -> None:
    """Phase 9 migration creates the Orion tables and indexes."""
    db_path = tmp_path / "v9.db"
    db = Database(db_path)

    # Apply migrations 1..8.
    for i in range(7):  # 0..6 inclusive, i.e. v1..v8
        MigrationManager(migrations=[MIGRATIONS[i]]).apply_migrations(db)
    assert db.fetchone("SELECT MAX(version) AS v FROM schema_migrations;")["v"] == 8

    # Apply Migration 9 (Orion).
    mgr_v9 = MigrationManager(migrations=[MIGRATIONS[7]])
    newly = mgr_v9.apply_migrations(db)
    assert newly == ["009_orion_schema"]
    assert mgr_v9.get_current_version(db) == 9

    # Verify all four tables exist.
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table';")]
    for required in (
        "orion_events",
        "orion_actions",
        "orion_capabilities",
        "orion_reconciliation",
    ):
        assert required in tables, f"Missing required table: {required}"

    # Verify indexes exist.
    indexes = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='index';")]
    for required in (
        "idx_orion_events_device",
        "idx_orion_events_type",
        "idx_orion_events_correlation",
        "idx_orion_actions_device",
        "idx_orion_actions_status",
        "idx_orion_actions_idempotency",
        "idx_orion_capabilities_device",
        "idx_orion_reconciliation_device",
    ):
        assert required in indexes, f"Missing required index: {required}"


def test_migration_v9_never_persists_sensitive_data(tmp_path: Path) -> None:
    """Orion tables must NEVER store private keys, frame bytes, or commands."""
    db_path = tmp_path / "v9_payload.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    for table in ("orion_events", "orion_actions", "orion_capabilities", "orion_reconciliation"):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        forbidden = {
            "payload",  # screen frame bytes
            "frame",
            "screenshot",
            "frame_data",
            "image",
            "raw_pixels",
            "private_key",
            "private_key_pem",
            "password",
            "secret",
            "token",
            "otp",
            "command",
            "shell",
            "exec",
            "execute",
        }
        assert forbidden.isdisjoint(set(cols)), (
            f"Forbidden column in {table}: {forbidden & set(cols)}"
        )


def test_migration_v9_idempotent(tmp_path: Path) -> None:
    """Reapplying Migration 9 must be a no-op."""
    db_path = tmp_path / "v9_idempotent.db"
    db = Database(db_path)
    mgr = MigrationManager(migrations=MIGRATIONS)
    newly = mgr.apply_migrations(db)
    assert "009_orion_schema" in newly
    assert mgr.get_current_version(db) == 9

    # Re-apply: no new migrations should be reported.
    newly2 = mgr.apply_migrations(db)
    assert newly2 == []


def test_migration_v9_insert_orion_event_round_trip(tmp_path: Path) -> None:
    """An Orion event can be inserted and read back as metadata only."""
    db_path = tmp_path / "v9_event.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    db.execute(
        """
        INSERT INTO orion_events (
            event_id, event_type, source, device_id, created_at,
            correlation_id, schema_version, payload_json, priority, sequence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "OEV-12345678",
            "DEVICE_CONNECTED",
            "test",
            "GM-C-19A84E72",
            "2026-08-13T00:00:00+00:00",
            "OCR-12345678",
            "1.0",
            "{}",
            "NORMAL",
            1,
        ),
    )
    row = db.fetchone("SELECT * FROM orion_events WHERE event_id = 'OEV-12345678';")
    assert row is not None
    assert row["event_type"] == "DEVICE_CONNECTED"
    assert row["device_id"] == "GM-C-19A84E72"
    assert row["payload_json"] == "{}"


def test_migration_v9_insert_orion_action_with_idempotency(tmp_path: Path) -> None:
    """An Orion action with idempotency_key is persisted and the unique
    index prevents duplicates."""
    db_path = tmp_path / "v9_action.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    db.execute(
        """
        INSERT INTO orion_actions (
            action_id, action_type, device_id, status, created_at,
            expires_at, correlation_id, requested_by, schema_version,
            parameters, idempotency_key, retry_count, max_retries,
            next_attempt_at, last_error, updated_at, result
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "OAC-12345678",
            "REFRESH_HEALTH",
            "GM-C-19A84E72",
            "PENDING",
            "2026-08-13T00:00:00+00:00",
            "2026-08-13T00:05:00+00:00",
            "OCR-12345678",
            "GM-P-83A1F72C",
            "1.0",
            json.dumps({"parameters": {}}),
            "IDEMP-KEY-1",
            0,
            3,
            None,
            None,
            None,
            json.dumps({}),
        ),
    )
    # Duplicate idempotency_key should be rejected.
    from guardianmesh.core.errors import StorageError

    with pytest.raises(StorageError):
        db.execute(
            """
            INSERT INTO orion_actions (
                action_id, action_type, device_id, status, created_at,
                expires_at, correlation_id, requested_by, schema_version,
                parameters, idempotency_key, retry_count, max_retries,
                next_attempt_at, last_error, updated_at, result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "OAC-87654321",
                "REFRESH_HEALTH",
                "GM-C-19A84E72",
                "PENDING",
                "2026-08-13T00:00:00+00:00",
                "2026-08-13T00:05:00+00:00",
                "OCR-87654321",
                "GM-P-83A1F72C",
                "1.0",
                json.dumps({"parameters": {}}),
                "IDEMP-KEY-1",  # duplicate
                0,
                3,
                None,
                None,
                None,
                json.dumps({}),
            ),
        )


def test_migration_full_chain_through_v9(tmp_path: Path) -> None:
    """A fresh install through every migration 1 -> 9 works end-to-end."""
    db_path = tmp_path / "v1_through_v9.db"
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
        "screen_authorizations",
        "aegis_sessions",
        "orion_events",
        "orion_actions",
        "orion_capabilities",
        "orion_reconciliation",
    ):
        assert required in tables, f"Missing required table: {required}"
