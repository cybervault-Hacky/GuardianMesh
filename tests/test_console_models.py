"""Tests for Console models, DashboardSnapshot, and DeviceView."""

from __future__ import annotations

from guardianmesh.console.models import DashboardSnapshot, DeviceView
from guardianmesh.policy.models import Alert, AlertSeverity, AlertStatus, RuleType
from guardianmesh.telemetry.models import ConnectivityState, DeviceHealthState, DeviceHealthSummary


def test_dashboard_snapshot_serialization() -> None:
    """Test DashboardSnapshot dataclass serialization and deserialization."""
    snapshot = DashboardSnapshot(
        generated_at="2026-08-13T01:54:00+00:00",
        device_count=2,
        online_count=1,
        degraded_count=0,
        offline_count=1,
        unknown_count=0,
        active_alert_count=1,
        critical_alert_count=0,
        warning_alert_count=1,
        devices=[
            {
                "device_id": "GM-C-19A84E72",
                "label": "Kid Phone",
                "role": "CHILD",
                "health_state": "ONLINE",
                "trust_status": "TRUSTED",
            }
        ],
        recent_activity=[
            {"time": "01:54", "event_type": "TELEMETRY_ACCEPTED", "description": "Device heartbeat received"}
        ],
        subsystem_status={"Identity": "READY", "Console": "READY"},
        summary_health={"battery": "78%", "storage": "42% free", "connectivity": "ONLINE"},
    )

    d = snapshot.to_dict()
    assert d["device_count"] == 2
    assert d["online_count"] == 1
    assert len(d["devices"]) == 1

    restored = DashboardSnapshot.from_dict(d)
    assert restored.device_count == 2
    assert restored.online_count == 1
    assert restored.summary_health["battery"] == "78%"


def test_device_view_serialization() -> None:
    """Test DeviceView model aggregation and dictionary export."""
    health = DeviceHealthSummary(
        device_id="GM-C-19A84E72",
        health_state=DeviceHealthState.ONLINE,
        battery_percent=85,
        is_charging=True,
        storage_free_bytes=30_000_000_000,
        uptime_seconds=3600,
        connectivity=ConnectivityState.ONLINE,
    )
    alert = Alert(
        id="ALT-01",
        device_id="GM-C-19A84E72",
        policy_id="POL-01",
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery is 15%",
        status=AlertStatus.ACTIVE,
    )

    view = DeviceView(
        device_id="GM-C-19A84E72",
        label="Kid Phone",
        role="CHILD",
        trust_status="ACTIVE",
        fingerprint="SHA256:1i95...",
        created_at="2026-08-13T01:00:00+00:00",
        health=health,
        policy=None,
        active_alerts=[alert],
    )

    d = view.to_dict()
    assert d["device_id"] == "GM-C-19A84E72"
    assert d["health"]["battery_percent"] == 85
    assert len(d["active_alerts"]) == 1
    assert d["active_alerts"][0]["id"] == "ALT-01"
