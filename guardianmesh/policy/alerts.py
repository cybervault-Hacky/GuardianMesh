"""Alert lifecycle manager: creation, deduplication, resolution, acknowledgement, and retention."""

from __future__ import annotations

import datetime
import secrets
from typing import Any

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import AlertNotFoundError
from guardianmesh.policy.models import Alert, AlertSeverity, AlertStatus, RuleType
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


class AlertManager:
    """Manages alert creation, deduplication, auto-resolution, acknowledgements, and retention."""

    def __init__(
        self,
        db: Database,
        config: GuardianConfig,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.audit_logger = audit_logger or AuditLogger(db)

    def _generate_alert_id(self) -> str:
        """Generate a unique compact alert identifier (e.g. ALT-8B1A4F)."""
        for _ in range(10):
            token = secrets.token_hex(3).upper()
            aid = f"ALT-{token}"
            existing = self.db.fetchone("SELECT id FROM alerts WHERE id = ?;", (aid,))
            if not existing:
                return aid
        return f"ALT-{secrets.token_hex(4).upper()}"

    def create_or_update_alert(
        self,
        device_id: str,
        policy_id: str,
        rule_type: RuleType,
        severity: AlertSeverity,
        message: str,
        trigger_value: str | None = None,
    ) -> Alert:
        """Create a new alert or update existing active alert (deduplication)."""
        dedup_key = f"{device_id}:{policy_id}:{rule_type.value}"
        now = datetime.datetime.now(datetime.UTC).isoformat()

        # Check for existing active or acknowledged alert for deduplication
        row = self.db.fetchone(
            """
            SELECT * FROM alerts
            WHERE dedup_key = ? AND status IN ('ACTIVE', 'ACKNOWLEDGED')
            ORDER BY created_at DESC LIMIT 1;
            """,
            (dedup_key,),
        )

        if row:
            # Deduplication: update existing active alert's last_seen_at and current trigger value
            alert_id = row["id"]
            self.db.execute(
                """
                UPDATE alerts
                SET last_seen_at = ?, message = ?, trigger_value = ?, severity = ?
                WHERE id = ?;
                """,
                (now, message, trigger_value, severity.value, alert_id),
            )
            return self.get_alert(alert_id) or Alert(
                id=alert_id,
                device_id=device_id,
                policy_id=policy_id,
                rule_type=rule_type,
                severity=severity,
                message=message,
                status=AlertStatus.from_str(row["status"]),
                dedup_key=dedup_key,
                trigger_value=trigger_value,
                created_at=row["created_at"],
                last_seen_at=now,
            )

        # No active alert exists: create fresh alert
        new_id = self._generate_alert_id()
        self.db.execute(
            """
            INSERT INTO alerts (
                id, device_id, policy_id, rule_type, severity, message,
                status, dedup_key, trigger_value, created_at, last_seen_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?);
            """,
            (
                new_id,
                device_id,
                policy_id,
                rule_type.value,
                severity.value,
                message,
                dedup_key,
                trigger_value,
                now,
                now,
            ),
        )

        self.audit_logger.record(
            event_type=AuditEventType.ALERT_CREATED,
            details={
                "alert_id": new_id,
                "device_id": device_id,
                "rule_type": rule_type.value,
                "severity": severity.value,
            },
            actor_id=device_id,
            success=True,
        )

        return Alert(
            id=new_id,
            device_id=device_id,
            policy_id=policy_id,
            rule_type=rule_type,
            severity=severity,
            message=message,
            status=AlertStatus.ACTIVE,
            dedup_key=dedup_key,
            trigger_value=trigger_value,
            created_at=now,
            last_seen_at=now,
        )

    def auto_resolve_alert(self, device_id: str, policy_id: str, rule_type: RuleType) -> Alert | None:
        """Automatically resolve active or acknowledged alert when condition clears."""
        dedup_key = f"{device_id}:{policy_id}:{rule_type.value}"
        row = self.db.fetchone(
            """
            SELECT * FROM alerts
            WHERE dedup_key = ? AND status IN ('ACTIVE', 'ACKNOWLEDGED')
            ORDER BY created_at DESC LIMIT 1;
            """,
            (dedup_key,),
        )
        if not row:
            return None

        alert_id = row["id"]
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            UPDATE alerts
            SET status = 'RESOLVED', resolved_at = ?
            WHERE id = ?;
            """,
            (now, alert_id),
        )

        self.audit_logger.record(
            event_type=AuditEventType.ALERT_RESOLVED,
            details={"alert_id": alert_id, "device_id": device_id, "auto_resolved": True},
            actor_id=device_id,
            success=True,
        )

        return self.get_alert(alert_id)

    def acknowledge_alert(self, alert_id: str, actor_id: str | None = None) -> bool:
        """Acknowledge an active alert without resolving the condition."""
        alert = self.get_alert_or_raise(alert_id)
        if alert.status != AlertStatus.ACTIVE:
            return False

        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            "UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_at = ? WHERE id = ?;",
            (now, alert_id),
        )

        self.audit_logger.record(
            event_type=AuditEventType.ALERT_ACKNOWLEDGED,
            details={"alert_id": alert_id, "device_id": alert.device_id},
            actor_id=actor_id or alert.device_id,
            success=True,
        )
        return True

    def dismiss_alert(self, alert_id: str, actor_id: str | None = None) -> bool:
        """Dismiss an alert from the active dashboard."""
        alert = self.get_alert_or_raise(alert_id)
        if alert.status in (AlertStatus.DISMISSED, AlertStatus.RESOLVED):
            return False

        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            "UPDATE alerts SET status = 'DISMISSED', dismissed_at = ? WHERE id = ?;",
            (now, alert_id),
        )

        self.audit_logger.record(
            event_type=AuditEventType.ALERT_DISMISSED,
            details={"alert_id": alert_id, "device_id": alert.device_id},
            actor_id=actor_id or alert.device_id,
            success=True,
        )
        return True

    def resolve_alert(self, alert_id: str, actor_id: str | None = None) -> bool:
        """Manually mark an alert as resolved."""
        alert = self.get_alert_or_raise(alert_id)
        if alert.status == AlertStatus.RESOLVED:
            return False

        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            "UPDATE alerts SET status = 'RESOLVED', resolved_at = ? WHERE id = ?;",
            (now, alert_id),
        )

        self.audit_logger.record(
            event_type=AuditEventType.ALERT_RESOLVED,
            details={"alert_id": alert_id, "device_id": alert.device_id, "manual": True},
            actor_id=actor_id or alert.device_id,
            success=True,
        )
        return True

    def get_alert(self, alert_id: str) -> Alert | None:
        """Fetch alert by ID."""
        row = self.db.fetchone("SELECT * FROM alerts WHERE id = ?;", (alert_id,))
        if not row:
            return None
        return Alert.from_dict(dict(row))

    def get_alert_or_raise(self, alert_id: str) -> Alert:
        """Fetch alert or raise AlertNotFoundError."""
        alert = self.get_alert(alert_id)
        if not alert:
            raise AlertNotFoundError(f"Alert '{alert_id}' not found.")
        return alert

    def list_alerts(
        self,
        device_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        today: bool = False,
        limit: int = 50,
    ) -> list[Alert]:
        """List alerts matching search filters."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []

        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())

        if status:
            query += " AND status = ?"
            params.append(status.upper())

        if today:
            today_start = (
                datetime.datetime.now(datetime.UTC)
                .replace(hour=0, minute=0, second=0, microsecond=0)
                .isoformat()
            )
            query += " AND created_at >= ?"
            params.append(today_start)

        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [Alert.from_dict(dict(r)) for r in rows]

    def get_active_alerts(self, device_id: str | None = None, severity: str | None = None) -> list[Alert]:
        """Fetch all currently active alerts."""
        return self.list_alerts(
            device_id=device_id,
            severity=severity,
            status="ACTIVE",
            limit=100,
        )

    def cleanup_alert_retention(self, retention_days: int | None = None) -> int:
        """Delete resolved or dismissed alerts older than retention period."""
        days = retention_days or self.config.alert_retention_days
        cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).isoformat()

        with self.db.transaction() as conn:
            cursor = conn.execute(
                """
                DELETE FROM alerts
                WHERE status IN ('RESOLVED', 'DISMISSED') AND created_at < ?;
                """,
                (cutoff,),
            )
            deleted = cursor.rowcount

        self.audit_logger.record(
            event_type=AuditEventType.ALERT_CLEANUP,
            details={"retention_days": days, "alerts_purged": deleted},
            success=True,
        )
        return deleted
