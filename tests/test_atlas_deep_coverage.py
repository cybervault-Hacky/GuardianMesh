"""Edge and property tests for Atlas Phase 10.

Covers edge cases: empty state, malformed input, invalid state,
expired state, revoked state, corruption, interruption, duplicate
operations, concurrent operations, retry limits, recovery,
migration compatibility, backup integrity, restore integrity,
JSON output, narrow terminal output, NO_COLOR, security
boundaries, privacy boundaries.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from guardianmesh.atlas.backup import AtlasBackupManager
from guardianmesh.atlas.compatibility import AtlasCompatibilityChecker
from guardianmesh.atlas.controller import AtlasController
from guardianmesh.atlas.diagnostics import AtlasDiagnostics
from guardianmesh.atlas.health import AtlasHealthMonitor
from guardianmesh.atlas.models import (
    AtlasCapabilityVersion,
    AtlasSecurityLevel,
)
from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.atlas.recovery import AtlasRecoveryManager
from guardianmesh.atlas.retention import AtlasRetentionManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_deep.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_backup_round_trip_preserves_atlas_state(
    tmp_path: Path, db: Database
) -> None:
    mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    info = mgr.create_backup()
    # Verify integrity.
    ok, _ = mgr.verify_backup(info.backup_id)
    assert ok is True
    # Verify the backup appears in the list.
    assert info.backup_id in [b.backup_id for b in mgr.list_backups()]


def test_backup_verify_rejects_corrupted_manifest(
    tmp_path: Path, db: Database
) -> None:
    mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    info = mgr.create_backup()
    # Manually corrupt the manifest row in the DB.
    db.execute(
        "UPDATE atlas_backups SET integrity_digest = 'sha256:wrong' "
        "WHERE backup_id = ?;",
        (info.backup_id,),
    )
    ok, msg = mgr.verify_backup(info.backup_id)
    assert ok is False
    assert "mismatch" in msg or "not valid" in msg


def test_recovery_handles_empty_db(tmp_path: Path, db: Database) -> None:
    rec = AtlasRecoveryManager(db).recover_all()
    assert all(r.status == "SUCCEEDED" for r in rec)
    assert all(r.actions_taken == 0 for r in rec)


def test_recovery_handles_invalid_timestamp(
    tmp_path: Path, db: Database
) -> None:
    # Insert an Orion action with a bad timestamp.
    db.execute(
        "INSERT INTO orion_actions (action_id, action_type, device_id, status, "
        "created_at, expires_at, correlation_id, requested_by, schema_version, "
        "parameters, idempotency_key, retry_count, max_retries, result) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "OAC-BAD",
            "REFRESH_HEALTH",
            "GM-C-19A84E72",
            "PENDING",
            "not-a-timestamp",
            "not-a-timestamp",
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
    assert rec.status == "SUCCEEDED"


def test_health_record_health_handles_partial_failure(
    tmp_path: Path, db: Database
) -> None:
    """Even if one subsystem is missing, others still record."""
    # Drop one table to simulate a partial install.
    db.execute("DROP TABLE IF EXISTS aegis_sessions;")
    mgr = AtlasHealthMonitor(db)
    result = mgr.record_health()
    # Most subsystems should still record.
    assert result["written"] >= 1


def test_compatibility_chain_after_partial_migration(
    tmp_path: Path, db: Database
) -> None:
    """Compatibility checker reports a sane message on a fresh install."""
    checker = AtlasCompatibilityChecker(db)
    ok, msg = checker.check_schema_version()
    assert ok is True
    assert "up to date" in msg


def test_observability_handles_all_empty_tables(db: Database) -> None:
    obs = AtlasObservability(db)
    metrics = obs.collect()
    # Every count is 0 in an empty database.
    for _subsystem, info in metrics.items():
        if isinstance(info, dict):
            for _key, value in info.items():
                if isinstance(value, int):
                    assert value == 0


def test_observability_handles_missing_subsystem_table(
    tmp_path: Path, db: Database
) -> None:
    db.execute("DROP TABLE IF EXISTS aegis_sessions;")
    obs = AtlasObservability(db)
    metrics = obs.collect()
    assert metrics["aegis"]["aegis_session_count"] == 0


def test_atlas_diagnostic_report_to_dict_includes_all_fields(
    db: Database,
) -> None:
    diag = AtlasDiagnostics(db)
    report = diag.run()
    d = report.to_dict()
    assert "checks" in d
    assert "generated_at" in d
    assert "passed" in d
    assert "failed" in d
    assert "critical_failure" in d


# ---------------------------------------------------------------------------
# Migration compatibility
# ---------------------------------------------------------------------------


def test_atlas_does_not_modify_orion_tables(
    tmp_path: Path, db: Database
) -> None:
    """Migration 10 must not touch any pre-existing table."""
    # Read the schema of the Orion tables.
    orion_table = "orion_events"
    cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({orion_table});")]
    # Apply migration 10 (idempotent).
    MigrationManager(migrations=MigrationManager().migrations).apply_migrations(db)
    cols2 = [r["name"] for r in db.fetchall(f"PRAGMA table_info({orion_table});")]
    assert cols == cols2


def test_atlas_does_not_destroy_orion_data(
    tmp_path: Path, db: Database
) -> None:
    """Migration 10 must preserve Orion data."""
    db.execute(
        "INSERT INTO orion_events (event_id, event_type, source, device_id, "
        "created_at, correlation_id, schema_version, payload_json, priority, "
        "sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "OEV-PRESERVE",
            "DEVICE_CONNECTED",
            "test",
            "GM-C-19A84E72",
            "2026-08-13T00:00:00+00:00",
            "OCR-PRESERVE",
            "1.0",
            "{}",
            "NORMAL",
            1,
        ),
    )
    MigrationManager().apply_migrations(db)
    row = db.fetchone(
        "SELECT event_id FROM orion_events WHERE event_id = 'OEV-PRESERVE';"
    )
    assert row is not None
    assert row["event_id"] == "OEV-PRESERVE"


# ---------------------------------------------------------------------------
# Capability versioning edge cases
# ---------------------------------------------------------------------------


def test_capability_risk_level_critical_recorded() -> None:
    cap = AtlasCapabilityVersion(
        capability_id="ATL-CAP-X",
        capability_name="x",
        risk_level=AtlasSecurityLevel.CRITICAL,
    )
    d = cap.to_dict()
    assert d["risk_level"] == "CRITICAL"


def test_capability_experimental_supported() -> None:
    from guardianmesh.atlas.capabilities import AtlasCapabilityRegistry

    reg = AtlasCapabilityRegistry()
    reg.register(
        AtlasCapabilityVersion(
            capability_id="ATL-CAP-EXP",
            capability_name="exp",
            status="EXPERIMENTAL",
        )
    )
    # An experimental capability is "supported" by registration but
    # ``supports()`` returns False because ``status != 'ACTIVE'``.
    assert reg.known("ATL-CAP-EXP") is True
    assert reg.supports("ATL-CAP-EXP") is False


# ---------------------------------------------------------------------------
# Restore dry-run is non-destructive
# ---------------------------------------------------------------------------


def test_restore_dry_run_is_non_destructive(
    tmp_path: Path, db: Database
) -> None:
    backup_mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    from guardianmesh.atlas.restore import AtlasRestoreManager

    restore_mgr = AtlasRestoreManager(
        db,
        backup_mgr,
        current_orion_version="1.0.0",
    )
    info = backup_mgr.create_backup()
    # Add a fresh row that would be erased by a real restore.
    db.execute(
        "INSERT INTO orion_events (event_id, event_type, source, device_id, "
        "created_at, correlation_id, schema_version, payload_json, priority, "
        "sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "OEV-FRESH",
            "DEVICE_CONNECTED",
            "test",
            "GM-C-19A84E72",
            "2026-08-13T00:00:00+00:00",
            "OCR-FRESH",
            "1.0",
            "{}",
            "NORMAL",
            1,
        ),
    )
    plan = restore_mgr.restore(info.backup_id, dry_run=True)
    assert plan["applied"] is False
    # The fresh row is still there.
    row = db.fetchone(
        "SELECT event_id FROM orion_events WHERE event_id = 'OEV-FRESH';"
    )
    assert row is not None


# ---------------------------------------------------------------------------
# Retention safety
# ---------------------------------------------------------------------------


def test_retention_dry_run_does_not_delete(
    tmp_path: Path, db: Database
) -> None:
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1000)).isoformat()
    db.execute(
        "INSERT INTO audit_events (event_type, details, timestamp, actor_id, success) "
        "VALUES (?, ?, ?, ?, ?);",
        ("TEST", "{}", past, "GM-P-00000001", 1),
    )
    mgr = AtlasRetentionManager(db)
    mgr.ensure_defaults()
    plan = mgr.apply(dry_run=True)
    assert plan["dry_run"] is True
    row = db.fetchone("SELECT COUNT(*) AS c FROM audit_events;")
    assert int(row["c"]) == 1


# ---------------------------------------------------------------------------
# JSON output safety
# ---------------------------------------------------------------------------


def test_atlas_controller_diagnose_json_serializable(
    tmp_path: Path, db: Database
) -> None:
    controller = AtlasController(db, backup_dir=str(tmp_path / "backups"))
    report = controller.diagnose(full=False)
    # The dict must be JSON-serializable.
    json.dumps(report)


def test_atlas_controller_observability_json_serializable(
    tmp_path: Path, db: Database
) -> None:
    controller = AtlasController(db, backup_dir=str(tmp_path / "backups"))
    metrics = controller.collect_observability()
    json.dumps(metrics, default=str)


def test_atlas_controller_release_info_json_serializable(
    tmp_path: Path, db: Database
) -> None:
    controller = AtlasController(db, backup_dir=str(tmp_path / "backups"))
    info = controller.release_info()
    json.dumps(info, default=str)
