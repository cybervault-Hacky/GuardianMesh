"""Tests for AlertManager: creation, deduplication, auto-resolution, acknowledgement, and retention."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import AlertNotFoundError
from guardianmesh.policy.alerts import AlertManager
from guardianmesh.policy.models import AlertSeverity, AlertStatus, RuleType
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_alert_lifecycle_and_deduplication(tmp_path: Path) -> None:
    """Test creating an alert, deduplication on subsequent triggers, and auto-resolution."""
    db = Database(tmp_path / "alert_test.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    audit_logger = AuditLogger(db)
    alert_mgr = AlertManager(db, config, audit_logger)

    device_id = "GM-C-19A84E72"
    policy_id = "POL-01"

    # 1. Create fresh alert
    alert1 = alert_mgr.create_or_update_alert(
        device_id=device_id,
        policy_id=policy_id,
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery is 15%",
        trigger_value="15%",
    )
    assert alert1.status == AlertStatus.ACTIVE
    assert alert1.id.startswith("ALT-")

    # 2. Deduplication: trigger again while active -> updates last_seen_at instead of duplicating
    alert2 = alert_mgr.create_or_update_alert(
        device_id=device_id,
        policy_id=policy_id,
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery is 14%",
        trigger_value="14%",
    )
    assert alert2.id == alert1.id  # Same alert ID reused
    assert alert2.trigger_value == "14%"

    # Total active alerts should remain 1
    active = alert_mgr.get_active_alerts(device_id=device_id)
    assert len(active) == 1

    # 3. Auto-resolution when condition clears
    resolved_alert = alert_mgr.auto_resolve_alert(
        device_id=device_id,
        policy_id=policy_id,
        rule_type=RuleType.LOW_BATTERY,
    )
    assert resolved_alert is not None
    assert resolved_alert.status == AlertStatus.RESOLVED
    assert resolved_alert.resolved_at is not None

    # Active alerts should now be 0
    assert len(alert_mgr.get_active_alerts(device_id=device_id)) == 0


def test_alert_acknowledgement_and_dismissal(tmp_path: Path) -> None:
    """Test manual parent acknowledgement and dismissal."""
    db = Database(tmp_path / "alert_ack.db")
    MigrationManager().apply_migrations(db)
    alert_mgr = AlertManager(db, GuardianConfig(home_dir=tmp_path))

    alert = alert_mgr.create_or_update_alert(
        device_id="GM-C-19A84E72",
        policy_id="POL-01",
        rule_type=RuleType.OFFLINE,
        severity=AlertSeverity.CRITICAL,
        message="Device offline",
    )
    assert alert.status == AlertStatus.ACTIVE

    # Acknowledge alert
    assert alert_mgr.acknowledge_alert(alert.id) is True
    acked = alert_mgr.get_alert(alert.id)
    assert acked is not None
    assert acked.status == AlertStatus.ACKNOWLEDGED
    assert acked.acknowledged_at is not None

    # Dismiss alert
    assert alert_mgr.dismiss_alert(alert.id) is True
    dismissed = alert_mgr.get_alert(alert.id)
    assert dismissed is not None
    assert dismissed.status == AlertStatus.DISMISSED

    # Non-existent alert raises AlertNotFoundError
    with pytest.raises(AlertNotFoundError):
        alert_mgr.get_alert_or_raise("ALT-NONEXIST")


def test_alert_retention_cleanup(tmp_path: Path) -> None:
    """Test retention cleanup purges resolved alerts while strictly preserving active ones."""
    db = Database(tmp_path / "alert_ret.db")
    MigrationManager().apply_migrations(db)
    alert_mgr = AlertManager(db, GuardianConfig(home_dir=tmp_path))

    # Create active alert
    alt_act = alert_mgr.create_or_update_alert(
        device_id="GM-C-19A84E72",
        policy_id="POL-01",
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery 10%",
    )

    # Insert old resolved alert directly
    past_iso = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=40)).isoformat()
    db.execute(
        """
        INSERT INTO alerts (
            id, device_id, policy_id, rule_type, severity, message,
            status, dedup_key, created_at, last_seen_at, resolved_at
        ) VALUES (
            'ALT-OLDRESOLVED', 'GM-C-19A84E72', 'POL-01', 'OFFLINE', 'CRITICAL',
            'Old offline', 'RESOLVED', 'dedup:old', ?, ?, ?
        );
        """,
        (past_iso, past_iso, past_iso),
    )

    deleted = alert_mgr.cleanup_alert_retention(retention_days=30)
    assert deleted >= 1

    # Active alert remains intact
    assert alert_mgr.get_alert(alt_act.id) is not None
    assert alert_mgr.get_alert("ALT-OLDRESOLVED") is None
