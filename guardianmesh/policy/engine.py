"""Policy engine managing policy CRUD, default health rules, and alert evaluation."""

from __future__ import annotations

import datetime
import secrets

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import PolicyNotFoundError, ValidationError
from guardianmesh.identity.models import validate_identity_id
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.alerts import AlertManager
from guardianmesh.policy.evaluator import RuleEvaluator
from guardianmesh.policy.models import (
    Alert,
    AlertSeverity,
    Policy,
    PolicyRule,
    RuleType,
)
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.telemetry.models import DeviceHealthSummary


class PolicyEngine:
    """Orchestrates policy lifecycle management and technical health rule evaluation."""

    def __init__(
        self,
        db: Database,
        config: GuardianConfig,
        trust_manager: TrustManager,
        alert_manager: AlertManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.trust_manager = trust_manager
        self.alert_manager = alert_manager or AlertManager(db, config, audit_logger)
        self.audit_logger = audit_logger or AuditLogger(db)

    def _generate_policy_id(self) -> str:
        """Generate a unique policy identifier (e.g. POL-7A3B1C)."""
        for _ in range(10):
            token = secrets.token_hex(3).upper()
            pid = f"POL-{token}"
            existing = self.db.fetchone("SELECT id FROM policies WHERE id = ?;", (pid,))
            if not existing:
                return pid
        return f"POL-{secrets.token_hex(4).upper()}"

    def get_default_rules(self) -> list[PolicyRule]:
        """Construct the standard safe set of health monitoring rules."""
        return [
            PolicyRule(
                rule_type=RuleType.LOW_BATTERY,
                threshold=float(self.config.default_battery_threshold),
                severity=AlertSeverity.WARNING,
            ),
            PolicyRule(
                rule_type=RuleType.LOW_STORAGE,
                threshold=float(self.config.default_storage_threshold),
                severity=AlertSeverity.WARNING,
            ),
            PolicyRule(
                rule_type=RuleType.HEARTBEAT_DELAYED,
                duration_seconds=self.config.default_degraded_duration_seconds,
                severity=AlertSeverity.WARNING,
            ),
            PolicyRule(
                rule_type=RuleType.OFFLINE,
                duration_seconds=self.config.default_offline_duration_seconds,
                severity=AlertSeverity.CRITICAL,
            ),
            PolicyRule(
                rule_type=RuleType.DEGRADED_CONNECTION,
                severity=AlertSeverity.WARNING,
            ),
        ]

    def create_policy(
        self,
        device_id: str,
        name: str = "Default Health Policy",
        rules: list[PolicyRule] | None = None,
        enabled: bool = True,
    ) -> Policy:
        """Create and persist a new policy for a trusted device."""
        is_valid, err = validate_identity_id(device_id)
        if not is_valid:
            raise ValidationError(f"Invalid device ID for policy creation: {err}")

        policy_id = self._generate_policy_id()
        now = datetime.datetime.now(datetime.UTC).isoformat()
        active_rules = rules if rules is not None else self.get_default_rules()

        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO policies (id, device_id, name, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (policy_id, device_id, name.strip(), 1 if enabled else 0, now, now),
            )

            for r in active_rules:
                conn.execute(
                    """
                    INSERT INTO policy_rules (
                        policy_id, rule_type, enabled, threshold, duration_seconds, severity
                    )
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        policy_id,
                        r.rule_type.value,
                        1 if r.enabled else 0,
                        r.threshold,
                        r.duration_seconds,
                        r.severity.value,
                    ),
                )

        policy = Policy(
            id=policy_id,
            device_id=device_id,
            name=name.strip(),
            enabled=enabled,
            rules=active_rules,
            created_at=now,
            updated_at=now,
        )

        self.audit_logger.record(
            event_type=AuditEventType.POLICY_CREATED,
            details={"policy_id": policy_id, "device_id": device_id, "name": name},
            actor_id=device_id,
            success=True,
        )

        return policy

    def get_policy(self, policy_id: str) -> Policy | None:
        """Fetch policy by ID including associated rules."""
        p_row = self.db.fetchone("SELECT * FROM policies WHERE id = ?;", (policy_id,))
        if not p_row:
            return None

        rules_rows = self.db.fetchall("SELECT * FROM policy_rules WHERE policy_id = ?;", (policy_id,))
        rules = [
            PolicyRule(
                rule_type=RuleType.from_str(r["rule_type"]),
                enabled=bool(r["enabled"]),
                threshold=r["threshold"],
                duration_seconds=r["duration_seconds"],
                severity=AlertSeverity.from_str(r["severity"]),
            )
            for r in rules_rows
        ]

        return Policy(
            id=p_row["id"],
            device_id=p_row["device_id"],
            name=p_row["name"],
            enabled=bool(p_row["enabled"]),
            rules=rules,
            created_at=p_row["created_at"],
            updated_at=p_row["updated_at"],
        )

    def get_device_policy(self, device_id: str) -> Policy | None:
        """Fetch the active policy for a specific device."""
        p_row = self.db.fetchone(
            "SELECT id FROM policies WHERE device_id = ? ORDER BY created_at DESC LIMIT 1;",
            (device_id,),
        )
        if not p_row:
            return None
        return self.get_policy(p_row["id"])

    def ensure_default_policy(self, device_id: str) -> Policy:
        """Ensure a policy exists for a device, generating default if not found."""
        existing = self.get_device_policy(device_id)
        if existing:
            return existing
        return self.create_policy(device_id, name="Default Health Policy")

    def list_policies(self, device_id: str | None = None) -> list[Policy]:
        """List all policies matching filter criteria."""
        if device_id:
            rows = self.db.fetchall(
                "SELECT id FROM policies WHERE device_id = ? ORDER BY created_at DESC;",
                (device_id,),
            )
        else:
            rows = self.db.fetchall("SELECT id FROM policies ORDER BY created_at DESC;")

        policies: list[Policy] = []
        for r in rows:
            pol = self.get_policy(r["id"])
            if pol:
                policies.append(pol)
        return policies

    def enable_policy(self, policy_id: str) -> bool:
        """Enable a policy."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        affected = self.db.execute(
            "UPDATE policies SET enabled = 1, updated_at = ? WHERE id = ?;",
            (now, policy_id),
        )
        if affected == 0:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        self.audit_logger.record(
            event_type=AuditEventType.POLICY_ENABLED,
            details={"policy_id": policy_id},
            success=True,
        )
        return True

    def disable_policy(self, policy_id: str) -> bool:
        """Disable a policy."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        affected = self.db.execute(
            "UPDATE policies SET enabled = 0, updated_at = ? WHERE id = ?;",
            (now, policy_id),
        )
        if affected == 0:
            raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        self.audit_logger.record(
            event_type=AuditEventType.POLICY_DISABLED,
            details={"policy_id": policy_id},
            success=True,
        )
        return True

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy and its associated rules."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM policy_rules WHERE policy_id = ?;", (policy_id,))
            cursor = conn.execute("DELETE FROM policies WHERE id = ?;", (policy_id,))
            if cursor.rowcount == 0:
                raise PolicyNotFoundError(f"Policy '{policy_id}' not found.")

        self.audit_logger.record(
            event_type=AuditEventType.POLICY_DELETED,
            details={"policy_id": policy_id},
            success=True,
        )
        return True

    def evaluate_device_health(self, summary: DeviceHealthSummary, local_identity_id: str) -> list[Alert]:
        """Evaluate policies and manage alert lifecycle for an authenticated health update.

        Args:
            summary: Device health summary.
            local_identity_id: Local parent identity ID.

        Returns:
            List of created or updated active alerts.
        """
        device_id = summary.device_id

        # 1. Trust boundary: only evaluate active trusted devices
        if not self.trust_manager.is_trusted(local_identity_id, device_id):
            return []

        # 2. Fetch or initialize default policy
        policy = self.ensure_default_policy(device_id)
        if not policy.enabled or not self.config.policy_evaluation_enabled:
            return []

        triggered_alerts: list[Alert] = []

        # 3. Evaluate each rule deterministically
        for rule in policy.rules:
            is_triggered, msg, severity = RuleEvaluator.evaluate_rule(rule, summary)

            if is_triggered and msg and severity:
                trig_val = str(summary.battery_percent) if rule.rule_type == RuleType.LOW_BATTERY else None
                alert = self.alert_manager.create_or_update_alert(
                    device_id=device_id,
                    policy_id=policy.id,
                    rule_type=rule.rule_type,
                    severity=severity,
                    message=msg,
                    trigger_value=trig_val,
                )
                triggered_alerts.append(alert)
            else:
                # Condition is clear: auto-resolve any active alerts for this rule
                self.alert_manager.auto_resolve_alert(
                    device_id=device_id,
                    policy_id=policy.id,
                    rule_type=rule.rule_type,
                )

        return triggered_alerts
