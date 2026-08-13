"""Tests for Atlas Phase 10 crash recovery."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from guardianmesh.atlas.recovery import AtlasRecoveryManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_recovery.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def test_recover_orion_actions_empty(db: Database) -> None:
    rec = AtlasRecoveryManager(db).recover_orion_actions()
    assert rec.status == "SUCCEEDED"
    assert rec.actions_taken == 0


def test_recover_orion_actions_expires_pending(db: Database) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO orion_actions (action_id, action_type, device_id, status, "
        "created_at, expires_at, correlation_id, requested_by, schema_version, "
        "parameters, idempotency_key, retry_count, max_retries, result) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "OAC-EXP-1",
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
    rec = AtlasRecoveryManager(db).recover_orion_actions()
    assert rec.actions_taken == 1
    row = db.fetchone(
        "SELECT status FROM orion_actions WHERE action_id = 'OAC-EXP-1';"
    )
    assert row["status"] == "EXPIRED"


def test_recover_screen_authorizations_empty(db: Database) -> None:
    rec = AtlasRecoveryManager(db).recover_screen_authorizations()
    assert rec.status == "SUCCEEDED"
    assert rec.actions_taken == 0


def test_recover_screen_authorizations_expires_approved(
    db: Database,
) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO screen_authorizations (authorization_id, session_id, "
        "device_id, parent_id, decision, requested_at, expires_at, "
        "max_duration_seconds, label, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "AUT-EXP-1",
            "SCN-EXP-1",
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
    rec = AtlasRecoveryManager(db).recover_screen_authorizations()
    assert rec.actions_taken == 1
    row = db.fetchone(
        "SELECT decision FROM screen_authorizations WHERE authorization_id = 'AUT-EXP-1';"
    )
    assert row["decision"] == "EXPIRED"


def test_recover_aegis_sessions_empty(db: Database) -> None:
    rec = AtlasRecoveryManager(db).recover_aegis_sessions()
    assert rec.status == "SUCCEEDED"
    assert rec.actions_taken == 0


def test_recover_aegis_sessions_expires_active(
    db: Database,
) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO aegis_sessions (aegis_session_id, screen_session_id, "
        "device_id, parent_id, consent_state, platform, backend, state, "
        "created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "AEG-EXP-1",
            "SCN-EXP-1",
            "GM-C-19A84E72",
            "GM-P-83A1F72C",
            "GRANTED",
            "ANDROID",
            "MEDIA_CODEC",
            "CAPTURING",
            "2026-08-13T00:00:00+00:00",
            past,
        ),
    )
    rec = AtlasRecoveryManager(db).recover_aegis_sessions()
    assert rec.actions_taken == 1
    row = db.fetchone(
        "SELECT state FROM aegis_sessions WHERE aegis_session_id = 'AEG-EXP-1';"
    )
    assert row["state"] == "EXPIRED"


def test_recover_all(db: Database) -> None:
    records = AtlasRecoveryManager(db).recover_all()
    assert len(records) == 3
    assert all(r.status == "SUCCEEDED" for r in records)


def test_recovery_does_not_resurrect_revoked_trust(
    db: Database,
) -> None:
    """Recovery must never re-activate a revoked device."""
    db.execute(
        "INSERT INTO trusted_devices (local_identity_id, remote_identity_id, "
        "remote_role, remote_public_key_fingerprint, remote_public_key_pem, "
        "status, created_at, trust_version, last_verified_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "GM-P-83A1F72C",
            "GM-C-19A84E72",
            "CHILD",
            "fp",
            "pem",
            "REVOKED",
            "2026-08-13T00:00:00+00:00",
            1,
            "2026-08-13T00:00:00+00:00",
        ),
    )
    AtlasRecoveryManager(db).recover_all()
    row = db.fetchone(
        "SELECT status FROM trusted_devices WHERE remote_identity_id = 'GM-C-19A84E72';"
    )
    assert row["status"] == "REVOKED"
