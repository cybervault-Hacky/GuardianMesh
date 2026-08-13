"""Tests for RuleEvaluator deterministic rule conditions."""

from __future__ import annotations

from guardianmesh.policy.evaluator import RuleEvaluator
from guardianmesh.policy.models import AlertSeverity, PolicyRule, RuleType
from guardianmesh.telemetry.models import DeviceHealthState, DeviceHealthSummary


def test_evaluator_low_battery() -> None:
    """Test LOW_BATTERY rule evaluation."""
    rule = PolicyRule(rule_type=RuleType.LOW_BATTERY, threshold=20.0, severity=AlertSeverity.WARNING)

    # Battery 15% -> Triggered
    s_low = DeviceHealthSummary(device_id="GM-C-19A84E72", battery_percent=15)
    trig, msg, sev = RuleEvaluator.evaluate_rule(rule, s_low)
    assert trig is True
    assert "15%" in str(msg)
    assert sev == AlertSeverity.WARNING

    # Battery 50% -> Not triggered
    s_ok = DeviceHealthSummary(device_id="GM-C-19A84E72", battery_percent=50)
    trig_ok, _, _ = RuleEvaluator.evaluate_rule(rule, s_ok)
    assert trig_ok is False

    # Battery None -> Not triggered (no fabrication)
    s_none = DeviceHealthSummary(device_id="GM-C-19A84E72", battery_percent=None)
    trig_none, _, _ = RuleEvaluator.evaluate_rule(rule, s_none)
    assert trig_none is False


def test_evaluator_low_storage() -> None:
    """Test LOW_STORAGE rule evaluation."""
    rule = PolicyRule(rule_type=RuleType.LOW_STORAGE, threshold=10.0, severity=AlertSeverity.WARNING)

    # 5% free (5GB / 100GB) -> Triggered
    s_low = DeviceHealthSummary(
        device_id="GM-C-19A84E72",
        storage_total_bytes=100_000_000_000,
        storage_free_bytes=5_000_000_000,
    )
    trig, msg, _ = RuleEvaluator.evaluate_rule(rule, s_low)
    assert trig is True
    assert "5.0%" in str(msg)

    # 40% free -> Not triggered
    s_ok = DeviceHealthSummary(
        device_id="GM-C-19A84E72",
        storage_total_bytes=100_000_000_000,
        storage_free_bytes=40_000_000_000,
    )
    trig_ok, _, _ = RuleEvaluator.evaluate_rule(rule, s_ok)
    assert trig_ok is False


def test_evaluator_offline_and_degraded() -> None:
    """Test OFFLINE and DEGRADED_CONNECTION rules."""
    r_off = PolicyRule(rule_type=RuleType.OFFLINE, severity=AlertSeverity.CRITICAL)
    r_deg = PolicyRule(rule_type=RuleType.DEGRADED_CONNECTION, severity=AlertSeverity.WARNING)

    s_offline = DeviceHealthSummary(device_id="GM-C-19A84E72", health_state=DeviceHealthState.OFFLINE)
    assert RuleEvaluator.evaluate_rule(r_off, s_offline)[0] is True
    assert RuleEvaluator.evaluate_rule(r_deg, s_offline)[0] is False

    s_deg = DeviceHealthSummary(device_id="GM-C-19A84E72", health_state=DeviceHealthState.DEGRADED)
    assert RuleEvaluator.evaluate_rule(r_off, s_deg)[0] is False
    assert RuleEvaluator.evaluate_rule(r_deg, s_deg)[0] is True

    s_online = DeviceHealthSummary(device_id="GM-C-19A84E72", health_state=DeviceHealthState.ONLINE)
    assert RuleEvaluator.evaluate_rule(r_off, s_online)[0] is False
    assert RuleEvaluator.evaluate_rule(r_deg, s_online)[0] is False


def test_evaluator_heartbeat_delayed_and_unknown() -> None:
    """Test HEARTBEAT_DELAYED and HEALTH_UNKNOWN rules."""
    r_delay = PolicyRule(rule_type=RuleType.HEARTBEAT_DELAYED, duration_seconds=60)
    r_unk = PolicyRule(rule_type=RuleType.HEALTH_UNKNOWN)

    s_delayed = DeviceHealthSummary(device_id="GM-C-19A84E72", last_seen_seconds_ago=95)
    assert RuleEvaluator.evaluate_rule(r_delay, s_delayed)[0] is True

    s_fresh = DeviceHealthSummary(device_id="GM-C-19A84E72", last_seen_seconds_ago=10)
    assert RuleEvaluator.evaluate_rule(r_delay, s_fresh)[0] is False

    s_unknown = DeviceHealthSummary(device_id="GM-C-19A84E72", health_state=DeviceHealthState.UNKNOWN)
    assert RuleEvaluator.evaluate_rule(r_unk, s_unknown)[0] is True
