"""Policy, rule, and alert models for GuardianMesh Sentinel (Phase 4)."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.core.errors import InvalidRuleError


class RuleType(str, Enum):
    """Allowed privacy-bounded technical health rule types."""

    LOW_BATTERY = "LOW_BATTERY"
    LOW_STORAGE = "LOW_STORAGE"
    OFFLINE = "OFFLINE"
    DEGRADED_CONNECTION = "DEGRADED_CONNECTION"
    HEARTBEAT_DELAYED = "HEARTBEAT_DELAYED"
    HEALTH_UNKNOWN = "HEALTH_UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> RuleType:
        norm = val.strip().upper()
        if norm in cls.__members__:
            return cls(norm)
        raise InvalidRuleError(f"Unknown rule type '{val}'. Supported types: {[r.value for r in cls]}")


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_str(cls, val: str) -> AlertSeverity:
        norm = val.strip().upper()
        if norm in cls.__members__:
            return cls(norm)
        return cls.WARNING


class AlertStatus(str, Enum):
    """Lifecycle status of an alert."""

    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"

    @classmethod
    def from_str(cls, val: str) -> AlertStatus:
        norm = val.strip().upper()
        if norm in cls.__members__:
            return cls(norm)
        return cls.ACTIVE


@dataclass
class PolicyRule:
    """A single technical condition rule within a policy."""

    rule_type: RuleType
    enabled: bool = True
    threshold: float | None = None
    duration_seconds: int | None = None
    severity: AlertSeverity = AlertSeverity.WARNING

    def __post_init__(self) -> None:
        """Validate rule parameter ranges."""
        if isinstance(self.rule_type, str):
            self.rule_type = RuleType.from_str(self.rule_type)
        if isinstance(self.severity, str):
            self.severity = AlertSeverity.from_str(self.severity)

        if self.rule_type == RuleType.LOW_BATTERY:
            if self.threshold is None:
                self.threshold = 20.0
            if not (1.0 <= self.threshold <= 99.0):
                raise InvalidRuleError(
                    f"LOW_BATTERY threshold must be between 1 and 99% (got {self.threshold})."
                )

        elif self.rule_type == RuleType.LOW_STORAGE:
            if self.threshold is None:
                self.threshold = 10.0
            if not (1.0 <= self.threshold <= 99.0):
                raise InvalidRuleError(
                    f"LOW_STORAGE threshold must be between 1 and 99% (got {self.threshold})."
                )

        elif self.rule_type in (RuleType.OFFLINE, RuleType.DEGRADED_CONNECTION, RuleType.HEARTBEAT_DELAYED):
            if self.duration_seconds is not None and self.duration_seconds <= 0:
                raise InvalidRuleError(f"{self.rule_type.value} duration_seconds must be positive.")

    def to_dict(self) -> dict[str, Any]:
        """Serialize rule to dictionary."""
        return {
            "rule_type": self.rule_type.value,
            "enabled": self.enabled,
            "threshold": self.threshold,
            "duration_seconds": self.duration_seconds,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        """Deserialize rule from dictionary."""
        dur = int(data["duration_seconds"]) if data.get("duration_seconds") is not None else None
        return cls(
            rule_type=RuleType.from_str(data["rule_type"]),
            enabled=bool(data.get("enabled", True)),
            threshold=float(data["threshold"]) if data.get("threshold") is not None else None,
            duration_seconds=dur,
            severity=AlertSeverity.from_str(data.get("severity", "WARNING")),
        )


@dataclass
class Policy:
    """A set of health surveillance rules applied to a trusted device."""

    id: str
    device_id: str
    name: str
    enabled: bool = True
    rules: list[PolicyRule] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy to dictionary."""
        return {
            "id": self.id,
            "device_id": self.device_id,
            "name": self.name,
            "enabled": self.enabled,
            "rules": [r.to_dict() for r in self.rules],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        """Deserialize policy from dictionary."""
        rules_data = data.get("rules", [])
        rules = [PolicyRule.from_dict(r) for r in rules_data]
        return cls(
            id=data["id"],
            device_id=data["device_id"],
            name=data["name"],
            enabled=bool(data.get("enabled", True)),
            rules=rules,
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class Alert:
    """A security or health alert raised when a policy rule triggers."""

    id: str
    device_id: str
    policy_id: str
    rule_type: RuleType
    severity: AlertSeverity
    message: str
    status: AlertStatus = AlertStatus.ACTIVE
    dedup_key: str = ""
    trigger_value: str | None = None
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    last_seen_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    acknowledged_at: str | None = None
    resolved_at: str | None = None
    dismissed_at: str | None = None

    def __post_init__(self) -> None:
        if not self.dedup_key:
            rule_name = self.rule_type.value if isinstance(self.rule_type, RuleType) else str(self.rule_type)
            self.dedup_key = f"{self.device_id}:{self.policy_id}:{rule_name}"

    @property
    def is_active(self) -> bool:
        return self.status == AlertStatus.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        """Serialize alert to dictionary."""
        rule_val = self.rule_type.value if isinstance(self.rule_type, RuleType) else str(self.rule_type)
        sev_val = self.severity.value if isinstance(self.severity, AlertSeverity) else str(self.severity)
        stat_val = self.status.value if isinstance(self.status, AlertStatus) else str(self.status)
        return {
            "id": self.id,
            "device_id": self.device_id,
            "policy_id": self.policy_id,
            "rule_type": rule_val,
            "severity": sev_val,
            "message": self.message,
            "status": stat_val,
            "dedup_key": self.dedup_key,
            "trigger_value": self.trigger_value,
            "created_at": self.created_at,
            "last_seen_at": self.last_seen_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "dismissed_at": self.dismissed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Deserialize alert from dictionary."""
        return cls(
            id=data["id"],
            device_id=data["device_id"],
            policy_id=data["policy_id"],
            rule_type=RuleType.from_str(data["rule_type"]),
            severity=AlertSeverity.from_str(data["severity"]),
            message=data["message"],
            status=AlertStatus.from_str(data.get("status", "ACTIVE")),
            dedup_key=data.get("dedup_key", ""),
            trigger_value=data.get("trigger_value"),
            created_at=data.get("created_at", ""),
            last_seen_at=data.get("last_seen_at", ""),
            acknowledged_at=data.get("acknowledged_at"),
            resolved_at=data.get("resolved_at"),
            dismissed_at=data.get("dismissed_at"),
        )
