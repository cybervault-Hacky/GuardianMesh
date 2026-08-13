"""Tests for PolicyEngine: policy CRUD, rule persistence, and health summary evaluation."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.engine import PolicyEngine
from guardianmesh.policy.models import AlertSeverity, PolicyRule, RuleType
from guardianmesh.security.crypto import public_key_to_pem
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import DeviceHealthState, DeviceHealthSummary


def setup_policy_env(tmp_path: Path) -> tuple[PolicyEngine, str, str]:
    """Helper setting up database, trusted device, and PolicyEngine."""
    db = Database(tmp_path / "pol_test.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    audit_logger = AuditLogger(db)
    identity_mgr = IdentityManager(db, key_storage, audit_logger)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    child_pub = key_storage.load_public_key(child.id)

    trust_mgr = TrustManager(db, audit_logger)
    trust_mgr.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=public_key_to_pem(child_pub).decode("utf-8"),
    )

    engine = PolicyEngine(
        db=db,
        config=config,
        trust_manager=trust_mgr,
        audit_logger=audit_logger,
    )
    return engine, parent.id, child.id


def test_policy_crud(tmp_path: Path) -> None:
    """Test creating, reading, updating, enabling, disabling, and deleting policies."""
    engine, parent_id, child_id = setup_policy_env(tmp_path)

    # 1. Create policy
    policy = engine.create_policy(
        device_id=child_id,
        name="Custom Child Policy",
        rules=[
            PolicyRule(rule_type=RuleType.LOW_BATTERY, threshold=15.0, severity=AlertSeverity.WARNING),
            PolicyRule(rule_type=RuleType.OFFLINE, duration_seconds=180, severity=AlertSeverity.CRITICAL),
        ],
    )
    assert policy.id.startswith("POL-")
    assert policy.enabled is True
    assert len(policy.rules) == 2

    # 2. Get policy
    fetched = engine.get_policy(policy.id)
    assert fetched is not None
    assert fetched.name == "Custom Child Policy"
    assert len(fetched.rules) == 2

    # 3. Disable policy
    assert engine.disable_policy(policy.id) is True
    disabled = engine.get_policy(policy.id)
    assert disabled is not None
    assert disabled.enabled is False

    # 4. Enable policy
    assert engine.enable_policy(policy.id) is True
    enabled = engine.get_policy(policy.id)
    assert enabled is not None
    assert enabled.enabled is True

    # 5. List policies
    policies = engine.list_policies(device_id=child_id)
    assert len(policies) == 1

    # 6. Delete policy
    assert engine.delete_policy(policy.id) is True
    assert engine.get_policy(policy.id) is None


def test_policy_health_evaluation_flow(tmp_path: Path) -> None:
    """Test evaluating a health summary against policy generates alerts."""
    engine, parent_id, child_id = setup_policy_env(tmp_path)

    # Ensure default policy exists
    policy = engine.ensure_default_policy(child_id)
    assert policy is not None

    # Summary with low battery (14%)
    summary = DeviceHealthSummary(
        device_id=child_id,
        health_state=DeviceHealthState.ONLINE,
        battery_percent=14,
        storage_total_bytes=100_000_000_000,
        storage_free_bytes=50_000_000_000,
    )

    alerts = engine.evaluate_device_health(summary, local_identity_id=parent_id)
    assert len(alerts) == 1
    assert alerts[0].rule_type == RuleType.LOW_BATTERY
    assert "14%" in alerts[0].message

    # Now health recovers: battery 80%
    summary_recovered = DeviceHealthSummary(
        device_id=child_id,
        health_state=DeviceHealthState.ONLINE,
        battery_percent=80,
        storage_total_bytes=100_000_000_000,
        storage_free_bytes=50_000_000_000,
    )
    alerts_after = engine.evaluate_device_health(summary_recovered, local_identity_id=parent_id)
    assert len(alerts_after) == 0

    # Verify previous alert auto-resolved
    active = engine.alert_manager.get_active_alerts(device_id=child_id)
    assert len(active) == 0


def test_policy_evaluation_untrusted_device(tmp_path: Path) -> None:
    """Test policy engine skips evaluation for untrusted or revoked devices."""
    engine, parent_id, child_id = setup_policy_env(tmp_path)

    # Revoke device
    engine.trust_manager.revoke_trust(parent_id, child_id)

    summary = DeviceHealthSummary(
        device_id=child_id,
        health_state=DeviceHealthState.OFFLINE,
        battery_percent=5,
    )

    alerts = engine.evaluate_device_health(summary, local_identity_id=parent_id)
    assert len(alerts) == 0
    assert len(engine.alert_manager.get_active_alerts(device_id=child_id)) == 0
