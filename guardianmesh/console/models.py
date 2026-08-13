"""Data models and snapshot representations for GuardianMesh Console (Phase 5)."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from guardianmesh.policy.models import Alert, Policy
from guardianmesh.telemetry.models import DeviceHealthSummary


@dataclass
class DashboardSnapshot:
    """Consolidated read-only snapshot of the supervision ecosystem."""

    generated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    device_count: int = 0
    online_count: int = 0
    degraded_count: int = 0
    offline_count: int = 0
    unknown_count: int = 0
    active_alert_count: int = 0
    critical_alert_count: int = 0
    warning_alert_count: int = 0
    devices: list[dict[str, Any]] = field(default_factory=list)
    recent_activity: list[dict[str, Any]] = field(default_factory=list)
    subsystem_status: dict[str, str] = field(default_factory=dict)
    summary_health: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize dashboard snapshot to dictionary."""
        return {
            "generated_at": self.generated_at,
            "device_count": self.device_count,
            "online_count": self.online_count,
            "degraded_count": self.degraded_count,
            "offline_count": self.offline_count,
            "unknown_count": self.unknown_count,
            "active_alert_count": self.active_alert_count,
            "critical_alert_count": self.critical_alert_count,
            "warning_alert_count": self.warning_alert_count,
            "devices": self.devices,
            "recent_activity": self.recent_activity,
            "subsystem_status": self.subsystem_status,
            "summary_health": self.summary_health,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DashboardSnapshot:
        """Deserialize dashboard snapshot from dictionary."""
        return cls(
            generated_at=data.get("generated_at", ""),
            device_count=int(data.get("device_count", 0)),
            online_count=int(data.get("online_count", 0)),
            degraded_count=int(data.get("degraded_count", 0)),
            offline_count=int(data.get("offline_count", 0)),
            unknown_count=int(data.get("unknown_count", 0)),
            active_alert_count=int(data.get("active_alert_count", 0)),
            critical_alert_count=int(data.get("critical_alert_count", 0)),
            warning_alert_count=int(data.get("warning_alert_count", 0)),
            devices=data.get("devices", []),
            recent_activity=data.get("recent_activity", []),
            subsystem_status=data.get("subsystem_status", {}),
            summary_health=data.get("summary_health", {}),
        )


@dataclass
class DeviceView:
    """Device perspective combining identity, trust, telemetry, policy, alerts, and transport."""

    device_id: str
    label: str | None
    role: str
    trust_status: str
    fingerprint: str
    created_at: str
    health: DeviceHealthSummary | None = None
    policy: Policy | None = None
    active_alerts: list[Alert] = field(default_factory=list)
    connection_state: str = "DISCONNECTED"
    active_session_id: str | None = None
    transport_type: str = "LOCAL"
    last_sync_at: str | None = None
    last_heartbeat_at: str | None = None
    reconnect_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize device view to dictionary."""
        return {
            "device_id": self.device_id,
            "label": self.label,
            "role": self.role,
            "trust_status": self.trust_status,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "transport": {
                "connection_state": self.connection_state,
                "session_id": self.active_session_id,
                "transport_type": self.transport_type,
                "last_sync": self.last_sync_at,
                "last_heartbeat": self.last_heartbeat_at,
                "reconnect_count": self.reconnect_count,
            },
            "health": {
                "state": self.health.health_state.value,
                "battery_percent": self.health.battery_percent,
                "charging": self.health.is_charging,
                "storage_free_bytes": self.health.storage_free_bytes,
                "storage_free_gb": self.health.storage_free_gb,
                "uptime_seconds": self.health.uptime_seconds,
                "uptime_display": self.health.uptime_display,
                "connectivity": self.health.connectivity.value,
                "last_heartbeat": self.health.last_heartbeat_at,
                "last_seen_seconds_ago": self.health.last_seen_seconds_ago,
                "is_paused": self.health.is_paused,
            }
            if self.health
            else None,
            "policy": self.policy.to_dict() if self.policy else None,
            "active_alerts": [a.to_dict() for a in self.active_alerts],
        }
