"""Security and privacy review tests for GuardianMesh Console (Phase 5)."""

from __future__ import annotations

import json
from pathlib import Path

from guardianmesh.console.services import ConsoleService
from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import public_key_to_pem
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_no_secrets_in_console_json_export(tmp_path: Path) -> None:
    """Verify dashboard and device JSON exports contain zero private keys, OTPs, or passwords."""
    db = Database(tmp_path / "sec_con.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(
        home_dir=tmp_path,
        smtp_password="super-secret-smtp-password-12345",
    )
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    child_pub = key_storage.load_public_key(child.id)

    trust_mgr = TrustManager(db)
    trust_mgr.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=public_key_to_pem(child_pub).decode("utf-8"),
    )

    service = ConsoleService(db, config, key_storage, identity_mgr, trust_mgr)
    snapshot = service.get_dashboard_snapshot()
    snap_json = json.dumps(snapshot.to_dict())

    # Verify no secrets
    assert "super-secret-smtp-password-12345" not in snap_json
    assert "-----BEGIN PRIVATE KEY-----" not in snap_json
    assert "PRIVATE" not in snap_json

    # Check device detail export
    detail = service.get_device_detail(child.id)
    detail_json = json.dumps(detail.to_dict())
    assert "-----BEGIN PRIVATE KEY-----" not in detail_json


def test_revoked_device_console_representation(tmp_path: Path) -> None:
    """Verify revoked devices are clearly flagged as REVOKED in console listings."""
    db = Database(tmp_path / "sec_rev.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    child_pub = key_storage.load_public_key(child.id)

    trust_mgr = TrustManager(db)
    trust_mgr.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=public_key_to_pem(child_pub).decode("utf-8"),
    )
    trust_mgr.revoke_trust(parent.id, child.id)

    service = ConsoleService(db, config, key_storage, identity_mgr, trust_mgr)
    devices = service.list_devices_summary()
    assert len(devices) == 1
    assert devices[0]["trust_status"] == "REVOKED"
