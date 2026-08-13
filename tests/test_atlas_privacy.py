"""Privacy tests for Atlas Phase 10.

Verifies that Atlas never persists, transmits, or audits sensitive
content: frame bytes, command strings, private messages, secrets,
passwords, OTPs, private keys, clipboard, microphone, camera,
location, browser history, contacts, photos, files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardianmesh.atlas.backup import AtlasBackupManager
from guardianmesh.atlas.metrics import AtlasMetrics
from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.atlas.recovery import AtlasRecoveryManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "atlas_privacy.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


# ---------------------------------------------------------------------------
# Database column privacy
# ---------------------------------------------------------------------------


def test_atlas_tables_never_store_audio(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("audio", "microphone", "sound"):
            assert forbidden not in cols


def test_atlas_tables_never_store_video(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("video", "frame", "frame_bytes", "screenshot", "image"):
            assert forbidden not in cols


def test_atlas_tables_never_store_location(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("location", "gps", "latitude", "longitude"):
            assert forbidden not in cols


def test_atlas_tables_never_store_clipboard(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("clipboard",):
            assert forbidden not in cols


def test_atlas_tables_never_store_messages(db: Database) -> None:
    for table in (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("message", "sms", "email", "chat", "browser_history"):
            assert forbidden not in cols


# ---------------------------------------------------------------------------
# Backup body privacy
# ---------------------------------------------------------------------------


def test_backup_body_never_contains_secrets(tmp_path: Path, db: Database) -> None:
    mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    info = mgr.create_backup()
    body = json.loads(
        (mgr._backup_dir / f"{info.backup_id}.json").read_bytes().decode("utf-8")
    )
    text = json.dumps(body).lower()
    for forbidden in (
        "private_key",
        "password",
        "secret",
        "token",
        "frame",
        "keylog",
        "microphone",
        "camera",
        "location",
        "browser_history",
    ):
        assert forbidden not in text


def test_backup_metadata_never_contains_secrets(tmp_path: Path, db: Database) -> None:
    mgr = AtlasBackupManager(
        db,
        tmp_path / "backups",
        orion_version="1.0.0",
    )
    info = mgr.create_backup()
    d = info.to_dict()
    text = json.dumps(d).lower()
    for forbidden in ("private_key", "password", "secret", "token", "frame"):
        assert forbidden not in text


# ---------------------------------------------------------------------------
# Recovery record privacy
# ---------------------------------------------------------------------------


def test_recovery_records_are_metadata_only(tmp_path: Path, db: Database) -> None:
    rec = AtlasRecoveryManager(db).recover_all()
    for r in rec:
        text = json.dumps(r.to_dict()).lower()
        for forbidden in (
            "private_key",
            "password",
            "secret",
            "frame",
            "keylog",
            "microphone",
            "location",
        ):
            assert forbidden not in text


# ---------------------------------------------------------------------------
# Observability privacy
# ---------------------------------------------------------------------------


def test_observability_never_returns_payloads(db: Database) -> None:
    obs = AtlasObservability(db)
    metrics = obs.collect()
    text = json.dumps(metrics, default=str).lower()
    for forbidden in (
        "private_key",
        "password",
        "secret",
        "frame",
        "keylog",
        "command",
    ):
        assert forbidden not in text


# ---------------------------------------------------------------------------
# Metrics privacy
# ---------------------------------------------------------------------------


def test_metrics_never_exposes_payloads(db: Database) -> None:
    metrics = AtlasMetrics(db).collect()
    text = json.dumps(metrics, default=str).lower()
    for forbidden in ("private_key", "password", "secret", "frame", "keylog"):
        assert forbidden not in text


# ---------------------------------------------------------------------------
# Diagnostic privacy
# ---------------------------------------------------------------------------


def test_diagnostics_never_expose_payloads(db: Database) -> None:
    from guardianmesh.atlas.diagnostics import AtlasDiagnostics

    report = AtlasDiagnostics(db).run()
    for check in report.checks:
        text = json.dumps(check.to_dict()).lower()
        for forbidden in ("private_key", "password", "secret", "frame", "keylog"):
            assert forbidden not in text
