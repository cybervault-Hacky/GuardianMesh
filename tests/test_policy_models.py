"""Tests for Policy, Rule, and Alert data models and validations."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import InvalidRuleError
from guardianmesh.policy.models import (
    Alert,
    AlertSeverity,
    AlertStatus,
    Policy,
    PolicyRule,
    RuleType,
)


def test_rule_type_and_enum_validations() -> None:
    """Test RuleType, AlertSeverity, and AlertStatus enums and conversions."""
    assert RuleType.from_str("LOW_BATTERY") == RuleType.LOW_BATTERY
    assert RuleType.from_str("low_battery") == RuleType.LOW_BATTERY
    with pytest.raises(InvalidRuleError):
        RuleType.from_str("INVALID_RULE_TYPE")

    assert AlertSeverity.from_str("CRITICAL") == AlertSeverity.CRITICAL
    assert AlertSeverity.from_str("unknown") == AlertSeverity.WARNING

    assert AlertStatus.from_str("ACTIVE") == AlertStatus.ACTIVE
    assert AlertStatus.from_str("unknown") == AlertStatus.ACTIVE


def test_policy_rule_validations() -> None:
    """Test threshold range and duration validations on PolicyRule."""
    # Valid rules
    r_bat = PolicyRule(rule_type=RuleType.LOW_BATTERY, threshold=15.0)
    assert r_bat.threshold == 15.0

    r_stor = PolicyRule(rule_type=RuleType.LOW_STORAGE, threshold=5.0)
    assert r_stor.threshold == 5.0

    r_off = PolicyRule(rule_type=RuleType.OFFLINE, duration_seconds=120)
    assert r_off.duration_seconds == 120

    # Invalid battery threshold (<1 or >99)
    with pytest.raises(InvalidRuleError):
        PolicyRule(rule_type=RuleType.LOW_BATTERY, threshold=0.0)

    with pytest.raises(InvalidRuleError):
        PolicyRule(rule_type=RuleType.LOW_BATTERY, threshold=105.0)

    # Invalid storage threshold
    with pytest.raises(InvalidRuleError):
        PolicyRule(rule_type=RuleType.LOW_STORAGE, threshold=-10.0)

    # Invalid duration (<=0)
    with pytest.raises(InvalidRuleError):
        PolicyRule(rule_type=RuleType.OFFLINE, duration_seconds=-5)


def test_policy_and_alert_serialization() -> None:
    """Test Policy and Alert serialization and deserialization roundtrip."""
    rules = [
        PolicyRule(rule_type=RuleType.LOW_BATTERY, threshold=20.0, severity=AlertSeverity.WARNING),
        PolicyRule(rule_type=RuleType.OFFLINE, duration_seconds=120, severity=AlertSeverity.CRITICAL),
    ]
    policy = Policy(
        id="POL-01",
        device_id="GM-C-19A84E72",
        name="Device Health Policy",
        enabled=True,
        rules=rules,
    )
    p_dict = policy.to_dict()
    assert p_dict["id"] == "POL-01"
    assert len(p_dict["rules"]) == 2

    restored_policy = Policy.from_dict(p_dict)
    assert restored_policy.id == policy.id
    assert len(restored_policy.rules) == 2

    # Alert model
    alert = Alert(
        id="ALT-01",
        device_id="GM-C-19A84E72",
        policy_id="POL-01",
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery is low: 15%",
        status=AlertStatus.ACTIVE,
    )
    assert alert.is_active is True
    assert alert.dedup_key == "GM-C-19A84E72:POL-01:LOW_BATTERY"

    a_dict = alert.to_dict()
    restored_alert = Alert.from_dict(a_dict)
    assert restored_alert.id == alert.id
    assert restored_alert.status == AlertStatus.ACTIVE
