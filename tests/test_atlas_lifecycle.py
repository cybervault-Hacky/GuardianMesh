"""Tests for Atlas Phase 10 lifecycle validation."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from guardianmesh.atlas.lifecycle import AtlasLifecycleValidator
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_lifecycle.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_no_expired_active_identity_clean(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    check = v.check_no_expired_active_identity()
    assert check.ok is True


def test_no_expired_active_identity_detects_bad_timestamp(db: Database) -> None:
    db.execute(
        "INSERT INTO identities (id, role, public_key_fingerprint, public_key_pem, "
        "created_at, label, is_active, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "GM-P-12345678",
            "PARENT",
            "fp",
            "pem",
            "not-a-timestamp",
            None,
            1,
            "{}",
        ),
    )
    v = AtlasLifecycleValidator(db)
    check = v.check_no_expired_active_identity()
    assert check.ok is False


def test_no_revoked_device_in_active_clean(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    check = v.check_no_revoked_device_in_active()
    assert check.ok is True


def test_no_expired_transport_sessions_clean(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    check = v.check_no_expired_transport_sessions()
    assert check.ok is True


def test_no_expired_transport_sessions_detects_expired_connected(
    db: Database,
) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO transport_sessions (session_id, local_identity_id, "
        "remote_identity_id, state, transport_type, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);",
        (
            "SES-12345678",
            "GM-P-00000000",
            "GM-C-00000000",
            "CONNECTED",
            "LOCAL",
            "2026-08-13T00:00:00+00:00",
            past,
        ),
    )
    v = AtlasLifecycleValidator(db)
    check = v.check_no_expired_transport_sessions()
    assert check.ok is False


def test_no_orphaned_screen_authorizations_clean(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    check = v.check_no_orphaned_screen_authorizations()
    assert check.ok is True


def test_no_orphaned_screen_authorizations_detects_expired_active(
    db: Database,
) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO screen_authorizations (authorization_id, session_id, "
        "device_id, parent_id, decision, requested_at, expires_at, "
        "max_duration_seconds, label, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "AUT-12345678",
            "SCN-12345678",
            "GM-C-19A84E72",
            "GM-P-83A1F72C",
            "APPROVED",
            "2026-08-13T00:00:00+00:00",
            past,
            300,
            "test",
            "{}",
        ),
    )
    v = AtlasLifecycleValidator(db)
    check = v.check_no_orphaned_screen_authorizations()
    assert check.ok is False


def test_no_expired_orion_actions_clean(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    check = v.check_no_expired_orion_actions()
    assert check.ok is True


def test_no_expired_orion_actions_detects_expired_pending(
    db: Database,
) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO orion_actions (action_id, action_type, device_id, status, "
        "created_at, expires_at, correlation_id, requested_by, schema_version, "
        "parameters, idempotency_key, retry_count, max_retries, result) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "OAC-12345678",
            "REFRESH_HEALTH",
            "GM-C-19A84E72",
            "PENDING",
            "2026-08-13T00:00:00+00:00",
            past,
            "OCR-1",
            "GM-P-83A1F72C",
            "1.0",
            json.dumps({"parameters": {}}),
            None,
            0,
            3,
            json.dumps({}),
        ),
    )
    v = AtlasLifecycleValidator(db)
    check = v.check_no_expired_orion_actions()
    assert check.ok is False


def test_no_stale_sequences_clean(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    check = v.check_no_stale_sequences()
    assert check.ok is True


def test_no_stale_sequences_detects_negative(db: Database) -> None:
    db.execute(
        "INSERT INTO transport_sequences (session_id, device_id, "
        "last_inbound_sequence, last_outbound_sequence, updated_at) "
        "VALUES (?, ?, ?, ?, ?);",
        (
            "SES-12345678",
            "GM-C-19A84E72",
            -1,
            0,
            "2026-08-13T00:00:00+00:00",
        ),
    )
    v = AtlasLifecycleValidator(db)
    check = v.check_no_stale_sequences()
    assert check.ok is False


def test_run_all_returns_all_checks(db: Database) -> None:
    v = AtlasLifecycleValidator(db)
    checks = v.run_all()
    assert len(checks) == 6
