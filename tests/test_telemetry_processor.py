"""Tests for TelemetryProcessor: validation, trust verification, health persistence, and retention."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    TelemetryAuthenticationError,
    TelemetryDevicePausedError,
    TelemetrySignatureError,
    TelemetryTimestampError,
)
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import DeviceHealthState, TelemetryEnvelope
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.telemetry.sequence import SequenceManager


def setup_telemetry_env(tmp_path: Path) -> tuple[TelemetryProcessor, str, str, Any]:
    """Helper setting up database, trusted device, keys, and TelemetryProcessor."""
    db = Database(tmp_path / "proc_test.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    audit_logger = AuditLogger(db)
    identity_mgr = IdentityManager(db, key_storage, audit_logger)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)

    trust_mgr = TrustManager(db, audit_logger)
    child_priv = key_storage.load_private_key(child.id)
    child_pub = key_storage.load_public_key(child.id)
    child_pub_pem = public_key_to_pem(child_pub).decode("utf-8")

    trust_mgr.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=child_pub_pem,
        label="Kid Phone",
    )

    processor = TelemetryProcessor(
        db=db,
        config=config,
        trust_manager=trust_mgr,
        sequence_manager=SequenceManager(db),
        audit_logger=audit_logger,
    )

    return processor, parent.id, child.id, child_priv


def test_telemetry_processor_success(tmp_path: Path) -> None:
    """Test successful processing of a valid signed telemetry envelope."""
    processor, parent_id, child_id, child_priv = setup_telemetry_env(tmp_path)

    now_iso = datetime.datetime.now(datetime.UTC).isoformat()
    envelope = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        payload={
            "battery_percent": 82,
            "charging": True,
            "storage_total_bytes": 64_000_000_000,
            "storage_free_bytes": 28_000_000_000,
            "uptime_seconds": 1800,
            "connectivity": "ONLINE",
            "platform": "Linux",
            "agent_version": "0.3.0",
        },
        captured_at=now_iso,
    )
    envelope.sign(child_priv)

    summary = processor.process_envelope(envelope, local_identity_id=parent_id)
    assert summary.device_id == child_id
    assert summary.health_state == DeviceHealthState.ONLINE
    assert summary.battery_percent == 82
    assert summary.is_charging is True
    assert summary.storage_free_gb == 26.1  # 28GB in GB

    # Check history
    history = processor.get_health_history(child_id, limit=5)
    assert len(history) == 1
    assert history[0]["battery_percent"] == 82


def test_telemetry_processor_untrusted_device_rejection(tmp_path: Path) -> None:
    """Test rejection when device is not in trusted registry."""
    processor, parent_id, _, _ = setup_telemetry_env(tmp_path)
    priv, _ = generate_keypair()

    envelope = TelemetryEnvelope(
        device_id="GM-C-UNKNOWN1",
        sequence=1,
        payload={"battery_percent": 50, "agent_version": "0.3.0"},
        captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
    )
    envelope.sign(priv)

    with pytest.raises(TelemetryAuthenticationError):
        processor.process_envelope(envelope, local_identity_id=parent_id)


def test_telemetry_processor_signature_rejection(tmp_path: Path) -> None:
    """Test rejection on bad signature."""
    processor, parent_id, child_id, _ = setup_telemetry_env(tmp_path)
    other_priv, _ = generate_keypair()

    envelope = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        payload={"battery_percent": 50, "agent_version": "0.3.0"},
        captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
    )
    # Signed with wrong key
    envelope.sign(other_priv)

    with pytest.raises(TelemetrySignatureError):
        processor.process_envelope(envelope, local_identity_id=parent_id)


def test_telemetry_processor_timestamp_skew_rejection(tmp_path: Path) -> None:
    """Test rejection of future timestamps exceeding tolerance."""
    processor, parent_id, child_id, child_priv = setup_telemetry_env(tmp_path)

    future_iso = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=2)).isoformat()
    envelope = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        payload={"battery_percent": 50, "agent_version": "0.3.0"},
        captured_at=future_iso,
    )
    envelope.sign(child_priv)

    with pytest.raises(TelemetryTimestampError):
        processor.process_envelope(envelope, local_identity_id=parent_id)


def test_telemetry_processor_pause_resume_and_retention(tmp_path: Path) -> None:
    """Test pause, resume, and retention cleanup."""
    processor, parent_id, child_id, child_priv = setup_telemetry_env(tmp_path)

    # Pause device
    assert processor.pause_device(child_id) is True
    assert processor.is_device_paused(child_id) is True

    # Processing while paused raises TelemetryDevicePausedError
    now_iso = datetime.datetime.now(datetime.UTC).isoformat()
    envelope = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        payload={"battery_percent": 50, "agent_version": "0.3.0"},
        captured_at=now_iso,
    )
    envelope.sign(child_priv)

    with pytest.raises(TelemetryDevicePausedError):
        processor.process_envelope(envelope, local_identity_id=parent_id)

    # Resume device
    assert processor.resume_device(child_id) is True
    assert processor.is_device_paused(child_id) is False

    # Now it processes successfully
    summary = processor.process_envelope(envelope, local_identity_id=parent_id)
    assert summary.device_id == child_id

    # Retention cleanup: insert an event older than retention window
    past_iso = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=15)).isoformat()
    processor.db.execute(
        """
        INSERT INTO telemetry_events (
            device_id, sequence, captured_at, health_state, created_at, connectivity
        ) VALUES (?, 99, ?, 'ONLINE', ?, 'ONLINE');
        """,
        (child_id, past_iso, past_iso),
    )

    deleted = processor.cleanup_retention(retention_days=7)
    assert deleted >= 1
