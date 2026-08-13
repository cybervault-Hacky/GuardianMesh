"""Tests for ConsoleRenderer terminal typography, JSON exports, and detail views."""

from __future__ import annotations

import json

from guardianmesh.console.formatters import TerminalFormatter
from guardianmesh.console.models import DashboardSnapshot, DeviceView
from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.policy.models import Alert, AlertSeverity, Policy, RuleType
from guardianmesh.telemetry.models import ConnectivityState, DeviceHealthState, DeviceHealthSummary


def test_render_dashboard_terminal_and_json() -> None:
    """Test render_dashboard in formatted terminal and JSON mode."""
    fmt = TerminalFormatter(color_enabled=False, explicit_width=80)
    renderer = ConsoleRenderer(fmt)

    snapshot = DashboardSnapshot(
        generated_at="2026-08-13T01:54:00+00:00",
        device_count=2,
        online_count=1,
        degraded_count=0,
        offline_count=1,
        active_alert_count=1,
        critical_alert_count=0,
        warning_alert_count=1,
        recent_activity=[{"time": "01:54", "description": "Device heartbeat received"}],
        summary_health={"battery": "78%", "storage": "42% free", "connectivity": "ONLINE"},
    )

    # Terminal render
    term_out = renderer.render_dashboard(snapshot, format_json=False)
    assert "GuardianMesh" in term_out
    assert "DEVICES" in term_out
    assert "Trusted       2" in term_out
    assert "Online        1" in term_out
    assert "Battery       78%" in term_out
    assert "Active        1" in term_out

    # JSON render
    json_out = renderer.render_dashboard(snapshot, format_json=True)
    parsed = json.loads(json_out)
    assert parsed["device_count"] == 2
    assert parsed["online_count"] == 1


def test_render_device_detail_and_health() -> None:
    """Test render_device_detail and render_device_health."""
    fmt = TerminalFormatter(color_enabled=False, explicit_width=80)
    renderer = ConsoleRenderer(fmt)

    health = DeviceHealthSummary(
        device_id="GM-C-19A84E72",
        health_state=DeviceHealthState.ONLINE,
        battery_percent=80,
        is_charging=True,
        storage_free_bytes=32_000_000_000,
        uptime_seconds=7200,
        connectivity=ConnectivityState.ONLINE,
        agent_version="0.5.0",
        last_heartbeat_at="2026-08-13T01:50:00+00:00",
    )

    alert = Alert(
        id="ALT-01",
        device_id="GM-C-19A84E72",
        policy_id="POL-01",
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery is low",
    )

    view = DeviceView(
        device_id="GM-C-19A84E72",
        label="Kid Phone",
        role="CHILD",
        trust_status="ACTIVE",
        fingerprint="SHA256:abcd",
        created_at="2026-08-13T01:00:00+00:00",
        health=health,
        policy=None,
        active_alerts=[alert],
    )

    detail_out = renderer.render_device_detail(view, format_json=False)
    assert "GM-C-19A84E72" in detail_out
    assert "Kid Phone" in detail_out
    assert "80% (Charging)" in detail_out
    assert "Active Alerts:" in detail_out

    health_out = renderer.render_device_health(health, format_json=False)
    assert "Device Health" in health_out
    assert "GM-C-19A84E72" in health_out
    assert "80% / Charging" in health_out


def test_render_policies_and_alerts() -> None:
    """Test rendering policy and alert lists."""
    renderer = ConsoleRenderer(TerminalFormatter(color_enabled=False))

    alerts = [
        Alert(
            id="ALT-01",
            device_id="GM-C-19A84E72",
            policy_id="POL-01",
            rule_type=RuleType.LOW_BATTERY,
            severity=AlertSeverity.WARNING,
            message="Battery 15%",
        )
    ]
    alt_out = renderer.render_alerts(alerts, format_json=False)
    assert "ALT-01" in alt_out
    assert "GM-C-19A84E72" in alt_out

    policies = [
        Policy(
            id="POL-01",
            device_id="GM-C-19A84E72",
            name="Default Health Policy",
            rules=[],
        )
    ]
    pol_out = renderer.render_policies(policies, format_json=False)
    assert "POL-01" in pol_out
    assert "ENABLED" in pol_out
