"""Console service layer orchestrating domain subsystems for unified presentation."""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.console.models import DashboardSnapshot, DeviceView
from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import DeviceNotTrustedError
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.alerts import AlertManager
from guardianmesh.policy.engine import PolicyEngine
from guardianmesh.policy.models import AlertSeverity
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.telemetry.models import ConnectivityState, DeviceHealthState, DeviceHealthSummary
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.telemetry.sequence import SequenceManager
from guardianmesh.transport.registry import TransportRegistry


class ConsoleService:
    """Facade service unifying Trust, Telemetry, Policy, Alerts, and Audit subsystems."""

    def __init__(
        self,
        db: Database,
        config: GuardianConfig,
        key_storage: KeyStorageManager | None = None,
        identity_manager: IdentityManager | None = None,
        trust_manager: TrustManager | None = None,
        telemetry_processor: TelemetryProcessor | None = None,
        policy_engine: PolicyEngine | None = None,
        alert_manager: AlertManager | None = None,
        audit_logger: AuditLogger | None = None,
        transport_registry: TransportRegistry | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.key_storage = key_storage or KeyStorageManager(config.keys_dir)
        self.audit_logger = audit_logger or AuditLogger(db)
        self.identity_mgr = identity_manager or IdentityManager(db, self.key_storage, self.audit_logger)
        self.trust_mgr = trust_manager or TrustManager(db, self.audit_logger)
        self.pairing_mgr = PairingManager(db, config, self.key_storage, self.trust_mgr, self.audit_logger)

        self.seq_mgr = SequenceManager(db)
        self.processor = telemetry_processor or TelemetryProcessor(
            db, config, self.trust_mgr, self.seq_mgr, self.audit_logger
        )
        self.alert_mgr = alert_manager or AlertManager(db, config, self.audit_logger)
        self.policy_engine = policy_engine or PolicyEngine(
            db, config, self.trust_mgr, self.alert_mgr, self.audit_logger
        )
        self.transport_registry = transport_registry or TransportRegistry(db)

    def get_dashboard_snapshot(self) -> DashboardSnapshot:
        """Construct a complete, read-only snapshot of current system health and activity."""
        trusted_devs = self.trust_mgr.list_trusted_devices()
        active_trusted = [d for d in trusted_devs if d.is_active]

        online_c = 0
        degraded_c = 0
        offline_c = 0
        unknown_c = 0

        devices_summary: list[dict[str, Any]] = []
        battery_vals: list[int] = []
        free_storage_bytes = 0
        total_storage_bytes = 0
        has_online_conn = False

        for dev in active_trusted:
            health = self.processor.get_device_health(dev.remote_identity_id)
            state = health.health_state if health else DeviceHealthState.UNKNOWN

            if state == DeviceHealthState.ONLINE:
                online_c += 1
            elif state == DeviceHealthState.DEGRADED:
                degraded_c += 1
            elif state == DeviceHealthState.OFFLINE:
                offline_c += 1
            else:
                unknown_c += 1

            if health:
                if health.battery_percent is not None:
                    battery_vals.append(health.battery_percent)
                if health.storage_free_bytes is not None:
                    free_storage_bytes += health.storage_free_bytes
                if health.storage_total_bytes is not None:
                    total_storage_bytes += health.storage_total_bytes
                if health.connectivity == ConnectivityState.ONLINE:
                    has_online_conn = True

            role_str = dev.remote_role.value if hasattr(dev.remote_role, "value") else str(dev.remote_role)
            devices_summary.append(
                {
                    "device_id": dev.remote_identity_id,
                    "label": dev.label or "Child Device",
                    "role": role_str,
                    "health_state": state.value,
                    "trust_status": dev.status,
                    "last_heartbeat": health.last_heartbeat_at if health else dev.last_verified_at,
                    "last_seen_seconds_ago": health.last_seen_seconds_ago if health else None,
                }
            )

        # Alerts summary
        active_alerts = self.alert_mgr.get_active_alerts()
        crit_c = sum(1 for a in active_alerts if a.severity == AlertSeverity.CRITICAL)
        warn_c = sum(1 for a in active_alerts if a.severity == AlertSeverity.WARNING)

        # Health aggregates
        avg_battery = int(sum(battery_vals) / len(battery_vals)) if battery_vals else None
        storage_pct_free = (
            round((free_storage_bytes / total_storage_bytes) * 100, 1) if total_storage_bytes > 0 else None
        )
        overall_conn = "ONLINE" if has_online_conn else ("OFFLINE" if active_trusted else "UNKNOWN")

        # Recent activity
        activity = self.get_recent_activity(self.config.console_max_activity_entries)

        # Subsystems
        subsystems = self.get_subsystem_statuses()

        # Vista screen-view state (metadata only).
        screen_state = self.get_screen_state()

        now = datetime.datetime.now(datetime.UTC).isoformat()

        return DashboardSnapshot(
            generated_at=now,
            device_count=len(active_trusted),
            online_count=online_c,
            degraded_count=degraded_c,
            offline_count=offline_c,
            unknown_count=unknown_c,
            active_alert_count=len(active_alerts),
            critical_alert_count=crit_c,
            warning_alert_count=warn_c,
            devices=devices_summary,
            recent_activity=activity,
            subsystem_status=subsystems,
            summary_health={
                "battery": f"{avg_battery}%" if avg_battery is not None else "Unknown",
                "storage": f"{storage_pct_free}% free" if storage_pct_free is not None else "Unknown",
                "connectivity": overall_conn,
            },
            screen_active_sessions=screen_state.get("active_sessions", 0),
            screen_pending_authorizations=screen_state.get("pending_authorizations", 0),
            screen_active_devices=screen_state.get("devices", []),
        )

    def list_devices_summary(self) -> list[dict[str, Any]]:
        """List all trusted devices and their health indicators."""
        devices = self.trust_mgr.list_trusted_devices()
        results: list[dict[str, Any]] = []

        for d in devices:
            health = self.processor.get_device_health(d.remote_identity_id)
            state = health.health_state.value if health else "UNKNOWN"
            results.append(
                {
                    "device_id": d.remote_identity_id,
                    "label": d.label or "Child Device",
                    "role": d.remote_role.value if hasattr(d.remote_role, "value") else str(d.remote_role),
                    "health_state": state,
                    "trust_status": "TRUSTED" if d.is_active else "REVOKED",
                    "fingerprint": d.remote_public_key_fingerprint,
                    "last_heartbeat": health.last_heartbeat_at if health else d.last_verified_at,
                    "last_seen_seconds_ago": health.last_seen_seconds_ago if health else None,
                }
            )
        return results

    def get_device_detail(self, device_id: str) -> DeviceView:
        """Fetch full aggregated view for a single device."""
        active_parent = self.identity_mgr.get_active_identity()
        parent_id = active_parent.id if active_parent else ""

        dev = self.trust_mgr.get_trusted_device(parent_id, device_id)
        if not dev:
            # Check if any trusted device record exists for this remote ID
            all_devs = self.trust_mgr.list_trusted_devices()
            match = [d for d in all_devs if d.remote_identity_id == device_id]
            if not match:
                raise DeviceNotTrustedError(f"Device '{device_id}' not found in trusted devices.")
            dev = match[0]

        health = self.processor.get_device_health(device_id)
        policy = self.policy_engine.get_device_policy(device_id)
        alerts = self.alert_mgr.get_active_alerts(device_id=device_id)
        peer = self.transport_registry.get_peer(device_id)

        role_str = dev.remote_role.value if hasattr(dev.remote_role, "value") else str(dev.remote_role)

        return DeviceView(
            device_id=dev.remote_identity_id,
            label=dev.label,
            role=role_str,
            trust_status=dev.status,
            fingerprint=dev.remote_public_key_fingerprint,
            created_at=dev.created_at,
            health=health,
            policy=policy,
            active_alerts=alerts,
            connection_state=peer.connection_state.value if peer else "DISCONNECTED",
            active_session_id=peer.active_session_id if peer else None,
            transport_type=peer.transport_type.value if peer else "LOCAL",
            last_sync_at=peer.last_sync_at if peer else None,
            last_heartbeat_at=peer.last_heartbeat_at if peer else None,
            reconnect_count=peer.reconnect_count if peer else 0,
        )

    def get_device_health(self, device_id: str) -> DeviceHealthSummary | None:
        """Fetch health metrics for a device."""
        return self.processor.get_device_health(device_id)

    def rename_device(self, device_id: str, new_label: str) -> bool:
        """Rename a trusted device label."""
        active_parent = self.identity_mgr.get_active_identity()
        parent_id = active_parent.id if active_parent else ""

        # Find matching trusted device record
        dev = self.trust_mgr.get_trusted_device(parent_id, device_id)
        if not dev:
            all_devs = self.trust_mgr.list_trusted_devices()
            match = [d for d in all_devs if d.remote_identity_id == device_id]
            if not match:
                raise DeviceNotTrustedError(f"Device '{device_id}' not found in trusted devices.")
            parent_id = match[0].local_identity_id

        return self.trust_mgr.rename_trusted_device(parent_id, device_id, new_label)

    def revoke_device(self, device_id: str) -> bool:
        """Revoke trust for a device."""
        active_parent = self.identity_mgr.get_active_identity()
        parent_id = active_parent.id if active_parent else ""

        dev = self.trust_mgr.get_trusted_device(parent_id, device_id)
        if not dev:
            all_devs = self.trust_mgr.list_trusted_devices()
            match = [d for d in all_devs if d.remote_identity_id == device_id]
            if not match:
                err_msg = f"Cannot revoke: device '{device_id}' not found in trusted devices."
                raise DeviceNotTrustedError(err_msg)
            parent_id = match[0].local_identity_id

        return self.trust_mgr.revoke_trust(parent_id, device_id, actor_id=parent_id)

    def get_subsystem_statuses(self) -> dict[str, str]:
        """Verify operational readiness of all GuardianMesh subsystems."""
        has_id = bool(self.identity_mgr.get_active_identity())
        has_db, _ = self.db.check_integrity()
        has_keys = self.config.keys_dir.is_dir()

        return {
            "Identity": "READY" if has_id else "NOT INITIALIZED",
            "Storage": "READY" if has_db else "ERROR",
            "Security": "READY" if has_keys else "NOT INITIALIZED",
            "Pairing": "READY" if self.config.pairing_enabled else "DISABLED",
            "Telemetry": "READY" if self.config.telemetry_enabled else "DISABLED",
            "Sentinel": "READY" if self.config.policy_evaluation_enabled else "DISABLED",
            "Transport": "READY" if self.config.transport_enabled else "DISABLED",
            "Vista": "READY" if self.config.screen_view_enabled else "DISABLED",
            "Console": "READY",
        }

    def get_screen_state(self) -> dict[str, Any]:
        """Return a metadata-only screen session aggregate for the dashboard.

        This NEVER includes any frame payload. It exposes only:
        * counts of active / pending / terminal sessions
        * per-device active session ids and remaining seconds
        """
        try:
            from guardianmesh.screen.registry import ScreenSessionRegistry
        except Exception:
            return {
                "active_sessions": 0,
                "pending_authorizations": 0,
                "state": "INACTIVE",
            }

        registry = ScreenSessionRegistry(self.db)
        all_sess = registry.list_all(limit=200)
        active = [s for s in all_sess if s.state.value == "ACTIVE"]
        pending = [s for s in all_sess if s.state.value == "PENDING_CHILD_APPROVAL"]
        per_device: list[dict[str, Any]] = []
        for s in active:
            per_device.append(
                {
                    "device_id": s.device_id,
                    "session_id": s.session_id,
                    "remaining_seconds": s.remaining_seconds,
                    "resolution": f"{s.width}x{s.height}",
                    "fps": s.max_fps,
                }
            )
        return {
            "active_sessions": len(active),
            "pending_authorizations": len(pending),
            "state": "ACTIVE" if active else "INACTIVE",
            "devices": per_device,
        }

    def get_recent_activity(self, limit: int = 5) -> list[dict[str, Any]]:
        """Retrieve recent security and system activity entries without exposing sensitive payloads."""
        raw_events = self.audit_logger.get_recent(limit=limit)
        activity: list[dict[str, Any]] = []

        for ev in raw_events:
            ts = ev["captured_at"] if "captured_at" in ev else ev.get("timestamp", "")
            time_str = ts[11:16] if len(ts) >= 16 else ""

            # Format human-friendly descriptions
            e_type = ev.get("event_type", "")
            desc = self._format_event_description(e_type, ev.get("details", {}))

            activity.append(
                {
                    "time": time_str,
                    "event_type": e_type,
                    "description": desc,
                    "status": "OK" if ev.get("success", True) else "FAILED",
                }
            )
        return activity

    @staticmethod
    def _format_event_description(event_type: str, details: dict[str, Any]) -> str:
        """Translate event type to a safe, user-friendly activity description."""
        mapping = {
            "STARTUP": "System startup",
            "DATABASE_INITIALIZED": "Database initialized",
            "IDENTITY_CREATED": "Device identity created",
            "IDENTITY_ACTIVATED": "Identity activated",
            "PAIRING_CREATED": "Pairing session initiated",
            "OTP_DELIVERED": "Verification code dispatched",
            "OTP_VERIFIED": "Verification code confirmed",
            "CHILD_AUTHORIZATION_REQUESTED": "Child authorization requested",
            "CHILD_APPROVED": "Child authorized pairing",
            "CHILD_DENIED": "Child rejected pairing",
            "TRUST_ESTABLISHED": "Device paired successfully",
            "TRUST_REVOKED": "Device trust revoked",
            "TELEMETRY_ACCEPTED": "Device heartbeat received",
            "TELEMETRY_PAUSED": "Telemetry paused",
            "TELEMETRY_RESUMED": "Telemetry resumed",
            "ALERT_CREATED": "Health alert triggered",
            "ALERT_ACKNOWLEDGED": "Alert acknowledged",
            "ALERT_DISMISSED": "Alert dismissed",
            "ALERT_RESOLVED": "Health alert resolved",
            "POLICY_CREATED": "Policy created",
            "POLICY_ENABLED": "Policy enabled",
            "POLICY_DISABLED": "Policy disabled",
            "TRANSPORT_SESSION_CREATED": "Secure session established",
            "TRANSPORT_AUTHENTICATED": "Device transport authenticated",
            "TRANSPORT_CONNECTED": "Transport connected",
            "TRANSPORT_DISCONNECTED": "Transport disconnected",
            "TRANSPORT_RECONNECT": "Transport reconnect attempt",
            "TRANSPORT_MESSAGE_ACCEPTED": "Transport message accepted",
            "TRANSPORT_MESSAGE_REJECTED": "Transport message rejected",
            "TRANSPORT_REPLAY_REJECTED": "Replayed message rejected",
            "TRANSPORT_AUTH_FAILED": "Transport authentication failed",
            "TRANSPORT_SESSION_EXPIRED": "Transport session expired",
            "TRANSPORT_REVOKED": "Revoked device transport blocked",
            "TRANSPORT_ERROR": "Transport error encountered",
            "SCREEN_VIEW_REQUESTED": "Screen view requested",
            "SCREEN_VIEW_APPROVED": "Child approved screen view",
            "SCREEN_VIEW_DENIED": "Child denied screen view",
            "SCREEN_SESSION_STARTED": "Screen session started",
            "SCREEN_SESSION_STOPPED": "Screen session stopped",
            "SCREEN_SESSION_EXPIRED": "Screen session expired",
            "SCREEN_SESSION_REVOKED": "Screen session revoked",
            "SCREEN_FRAME_STREAM_STARTED": "Screen frame streaming started",
            "SCREEN_FRAME_STREAM_STOPPED": "Screen frame streaming stopped",
        }
        return mapping.get(event_type, event_type.replace("_", " ").capitalize())
