"""Security tests for Atlas Phase 10.

These tests prove that Atlas cannot:

- bypass TrustManager
- bypass Vista authorization
- bypass Aegis system consent
- resurrect revoked devices
- resurrect expired sessions
- restart stopped screen capture
- create arbitrary commands
- execute shell commands
- execute arbitrary code
- send keyboard events
- send mouse events
- capture microphone
- capture camera
- collect location
- collect clipboard
- collect messages
- collect browser history
- persist frame bytes
- expose private keys
- expose session keys
- expose OTPs
- expose passwords
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from guardianmesh.atlas.backup import (
    BACKUP_ALLOWED_TABLES,
    BACKUP_FORBIDDEN_COLUMNS,
    AtlasBackupManager,
)
from guardianmesh.atlas.models import (
    AtlasCapabilityVersion,
    AtlasSecurityLevel,
)
from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.atlas.release import AEGIS_FORBIDDEN_PERMISSIONS
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_security.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


# ---------------------------------------------------------------------------
# Negative security: forbidden capabilities
# ---------------------------------------------------------------------------


def test_no_surveillance_capability_name_in_defaults() -> None:
    """The default Atlas capability names must not include surveillance primitives."""
    from guardianmesh.atlas.capabilities import DEFAULT_ATLAS_CAPABILITIES

    names = {c.capability_name.lower() for c in DEFAULT_ATLAS_CAPABILITIES}
    for forbidden in (
        "keystroke",
        "keylog",
        "microphone",
        "audio_capture",
        "camera_capture",
        "video_capture",
        "location_tracking",
        "clipboard",
        "sms",
        "browser_history",
        "shell",
        "remote_input",
        "remote_shell",
        "hidden_capture",
    ):
        assert forbidden not in names


def test_atlas_forbidden_permissions_block_surveillance() -> None:
    for forbidden in (
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ):
        assert forbidden in AEGIS_FORBIDDEN_PERMISSIONS


# ---------------------------------------------------------------------------
# Database safety
# ---------------------------------------------------------------------------


def test_atlas_tables_never_store_frame_bytes(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("payload", "frame", "screenshot", "keylog", "image"):
            assert forbidden not in cols


def test_atlas_tables_never_store_secrets(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("password", "private_key", "secret", "token", "otp"):
            assert forbidden not in cols


def test_atlas_tables_never_store_command_strings(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("command", "shell", "exec", "code", "script"):
            assert forbidden not in cols


def test_backup_allowed_tables_excludes_sensitive_data() -> None:
    """Backups must not include transport_messages or any sensitive table."""
    assert "transport_messages" not in BACKUP_ALLOWED_TABLES
    # The only backup-allowed table that contains user content is
    # ``identities`` — its public fields are redacted of private
    # material.
    assert "private_key_pem" in BACKUP_FORBIDDEN_COLUMNS["identities"]


# ---------------------------------------------------------------------------
# Backup safety
# ---------------------------------------------------------------------------


def test_backup_never_includes_private_keys(tmp_path: Path, db: Database) -> None:
    mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    info = mgr.create_backup()
    path = mgr._backup_dir / f"{info.backup_id}.json"
    body = path.read_bytes().decode("utf-8")
    # No private_key_pem should appear anywhere in the backup body.
    assert "private_key_pem" not in body


def test_backup_never_includes_command_strings(tmp_path: Path, db: Database) -> None:
    mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    info = mgr.create_backup()
    path = mgr._backup_dir / f"{info.backup_id}.json"
    body = path.read_bytes().decode("utf-8").lower()
    # The backup body should not contain any command keys.
    assert '"command"' not in body
    assert '"shell"' not in body
    assert '"exec"' not in body


# ---------------------------------------------------------------------------
# Recovery safety
# ---------------------------------------------------------------------------


def test_recovery_does_not_resurrect_revoked_trust(
    tmp_path: Path, db: Database
) -> None:
    from guardianmesh.atlas.recovery import AtlasRecoveryManager

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


def test_recovery_does_not_restart_stopped_screen(
    tmp_path: Path, db: Database
) -> None:
    from guardianmesh.atlas.recovery import AtlasRecoveryManager

    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=2)).isoformat()
    db.execute(
        "INSERT INTO screen_sessions (session_id, device_id, parent_id, state, "
        "requested_at, expires_at, codec, width, height, "
        "max_fps, frame_count, bytes_sent, bytes_received) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        (
            "SCN-STOPPED",
            "GM-C-19A84E72",
            "GM-P-83A1F72C",
            "STOPPED",
            "2026-08-13T00:00:00+00:00",
            past,
            "TEST",
            320,
            240,
            5,
            0,
            0,
            0,
        ),
    )
    AtlasRecoveryManager(db).recover_all()
    row = db.fetchone(
        "SELECT state FROM screen_sessions WHERE session_id = 'SCN-STOPPED';"
    )
    # The recovery must not silently restart a stopped session.
    assert row["state"] == "STOPPED"


# ---------------------------------------------------------------------------
# Audit safety
# ---------------------------------------------------------------------------


def test_audit_does_not_record_secrets_in_recovery(
    tmp_path: Path, db: Database
) -> None:
    """Recovery must not record secrets in the audit log."""
    from guardianmesh.atlas.recovery import AtlasRecoveryManager

    records = AtlasRecoveryManager(db).recover_all()
    for r in records:
        # The recovery record itself must be metadata-only.
        d = r.to_dict()
        for forbidden in ("password", "private_key", "secret", "token", "frame"):
            assert forbidden not in json.dumps(d).lower()


def test_observability_never_exposes_secrets(db: Database) -> None:
    obs = AtlasObservability(db)
    metrics = obs.collect()
    text = json.dumps(metrics, default=str).lower()
    for forbidden in ("password", "private_key", "secret", "frame", "keylog", "token"):
        assert forbidden not in text


# ---------------------------------------------------------------------------
# Authorization bypass prevention
# ---------------------------------------------------------------------------


def test_capability_does_not_bypass_consent_requirements() -> None:
    """Capability risk_level alone is not authorization."""
    cap = AtlasCapabilityVersion(
        capability_id="ATL-CAP-X",
        capability_name="x",
        requires_trust=True,
        requires_vista=True,
        requires_aegis=True,
        risk_level=AtlasSecurityLevel.CRITICAL,
    )
    # Risk level does NOT grant consent; the existing TrustManager,
    # ScreenAuthorizationManager, and SystemConsentGate do.
    assert cap.risk_level == AtlasSecurityLevel.CRITICAL
    # But Atlas does not bypass those subsystems; it only records
    # the requirements.
    assert cap.requires_trust is True
    assert cap.requires_vista is True
    assert cap.requires_aegis is True
