"""Tests for ConsoleService aggregation across trust, telemetry, policy, and audit subsystems."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.console.services import ConsoleService
from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import DeviceNotTrustedError
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import public_key_to_pem
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import TelemetryEnvelope
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.telemetry.sequence import SequenceManager


def setup_console_env(tmp_path: Path) -> tuple[ConsoleService, str, str]:
    """Helper setting up database, trusted paired device, and ConsoleService."""
    db = Database(tmp_path / "console_svc.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    audit_logger = AuditLogger(db)
    identity_mgr = IdentityManager(db, key_storage, audit_logger)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="Parent Dev", set_active=True)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="Kid Dev", set_active=False)
    child_pub = key_storage.load_public_key(child.id)

    trust_mgr = TrustManager(db, audit_logger)
    trust_mgr.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=public_key_to_pem(child_pub).decode("utf-8"),
        label="Kid Phone",
    )

    processor = TelemetryProcessor(db, config, trust_mgr, SequenceManager(db), audit_logger)

    service = ConsoleService(
        db=db,
        config=config,
        key_storage=key_storage,
        identity_manager=identity_mgr,
        trust_manager=trust_mgr,
        telemetry_processor=processor,
        audit_logger=audit_logger,
    )
    return service, parent.id, child.id


def test_console_service_dashboard_snapshot(tmp_path: Path) -> None:
    """Test get_dashboard_snapshot correctly computes device metrics and activity."""
    service, parent_id, child_id = setup_console_env(tmp_path)

    # Initial snapshot
    snap = service.get_dashboard_snapshot()
    assert snap.device_count == 1
    assert snap.unknown_count == 1
    assert snap.active_alert_count == 0
    assert "Console" in snap.subsystem_status
    assert snap.subsystem_status["Console"] == "READY"

    # Emit telemetry to mark online
    child_priv = service.key_storage.load_private_key(child_id)
    envelope = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        payload={
            "battery_percent": 82,
            "charging": True,
            "storage_total_bytes": 100_000_000_000,
            "storage_free_bytes": 45_000_000_000,
            "uptime_seconds": 3600,
            "connectivity": "ONLINE",
            "agent_version": "0.5.0",
        },
    )
    envelope.sign(child_priv)
    service.processor.process_envelope(envelope, local_identity_id=parent_id)

    # Snapshot after telemetry
    snap2 = service.get_dashboard_snapshot()
    assert snap2.device_count == 1
    assert snap2.online_count == 1
    assert snap2.summary_health["battery"] == "82%"
    assert "45.0%" in snap2.summary_health["storage"]


def test_console_service_device_detail_and_actions(tmp_path: Path) -> None:
    """Test get_device_detail, rename_device, and revoke_device."""
    service, parent_id, child_id = setup_console_env(tmp_path)

    # 1. Device detail
    detail = service.get_device_detail(child_id)
    assert detail.device_id == child_id
    assert detail.label == "Kid Phone"
    assert detail.trust_status == "ACTIVE"

    # 2. Rename device
    assert service.rename_device(child_id, "Renamed Phone") is True
    updated = service.get_device_detail(child_id)
    assert updated.label == "Renamed Phone"

    # 3. Revoke device
    assert service.revoke_device(child_id) is True
    revoked = service.get_device_detail(child_id)
    assert revoked.trust_status == "REVOKED"

    # 4. Untrusted device lookup raises DeviceNotTrustedError
    with pytest.raises(DeviceNotTrustedError):
        service.get_device_detail("GM-C-99999999")
