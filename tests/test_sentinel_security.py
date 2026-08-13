"""Security and privacy tests for Sentinel policy & alert engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import InvalidRuleError
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.engine import PolicyEngine
from guardianmesh.policy.models import PolicyRule, RuleType
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import DeviceHealthSummary


def test_sentinel_no_behavioral_inferences(tmp_path: Path) -> None:
    """Verify Sentinel only evaluates explicit technical rules and cannot create behavioral inferences."""
    # Attempting to create a rule with arbitrary behavioral strings fails
    with pytest.raises(InvalidRuleError):
        PolicyRule(rule_type=RuleType.from_str("USER_IS_BROWSING_TOO_MUCH"))  # type: ignore

    with pytest.raises(InvalidRuleError):
        PolicyRule(rule_type=RuleType.from_str("CHILD_SLEEP_DETECTION"))  # type: ignore


def test_sentinel_revocation_halts_alerts(tmp_path: Path) -> None:
    """Verify revoking device trust immediately stops Sentinel from generating alerts for that device."""
    db = Database(tmp_path / "sent_rev.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)

    trust_mgr = TrustManager(db)
    engine = PolicyEngine(db, config, trust_mgr)

    # 1. Device is not trusted yet -> evaluation returns empty list
    s_crit = DeviceHealthSummary(device_id=child.id, battery_percent=5)
    alerts = engine.evaluate_device_health(s_crit, local_identity_id=parent.id)
    assert len(alerts) == 0
