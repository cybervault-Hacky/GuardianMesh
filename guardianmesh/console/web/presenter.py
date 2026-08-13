"""Read-only, privacy-safe presentation models for the Parent Console web UI."""

from __future__ import annotations

import datetime
import platform
from dataclasses import dataclass
from typing import Any

from guardianmesh import __phase__, __version__
from guardianmesh.aegis.models import AegisPlatform, SystemConsentState
from guardianmesh.aegis.registry import AegisSessionRegistry
from guardianmesh.atlas.diagnostics import AtlasDiagnostics
from guardianmesh.atlas.health import AtlasHealthMonitor
from guardianmesh.console.services import ConsoleService
from guardianmesh.console.web.settings import ConsoleUISettings
from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import GuardianMeshError
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.models import PairingState
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.alerts import AlertManager
from guardianmesh.screen.auth_registry import ScreenAuthorizationRegistry
from guardianmesh.screen.controller import ScreenController, ScreenViewRequest
from guardianmesh.screen.models import ScreenSessionState, StopReason
from guardianmesh.screen.registry import ScreenSessionRegistry
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def parse_iso(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=datetime.UTC)
    return parsed.astimezone(datetime.UTC)


def relative_time(value: str | None) -> str:
    parsed = parse_iso(value)
    if not parsed:
        return "—"
    seconds = int((now_utc() - parsed).total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def detect_aegis_platform() -> AegisPlatform:
    system = platform.system().lower()
    if system == "android":
        return AegisPlatform.ANDROID
    if "com.termux" in str(platform.machine()).lower() or "/com.termux/" in __import__("os").environ.get(
        "PREFIX", ""
    ):
        return AegisPlatform.TERMUX
    if system == "linux":
        return AegisPlatform.LINUX
    return AegisPlatform.UNKNOWN


@dataclass(frozen=True)
class UserMessage:
    code: str
    message: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "detail": self.detail}


class ParentConsolePresenter:
    """Compose existing backend services into parent-friendly API responses.

    This class does not implement pairing, consent, authorization, transport,
    or capture. It calls existing managers/controllers and maps their metadata
    into simple UI models.
    """

    MAX_ACTIVITY = 100
    MAX_ALERTS = 100

    def __init__(self, db: Database | None, config: GuardianConfig) -> None:
        self.config = config
        self.db = db or Database(config.database_path)
        self.key_storage = KeyStorageManager(config.keys_dir)
        self.audit_logger = AuditLogger(self.db)
        self.identity_manager = IdentityManager(self.db, self.key_storage, self.audit_logger)
        self.trust_manager = TrustManager(self.db, self.audit_logger)
        self.console_service = ConsoleService(
            self.db, config, self.key_storage, self.identity_manager, self.trust_manager
        )
        self.pairing_manager = PairingManager(
            self.db, config, self.key_storage, self.trust_manager, self.audit_logger
        )
        self.alert_manager = AlertManager(self.db, config, self.audit_logger)
        self.screen_registry = ScreenSessionRegistry(self.db)
        self.screen_auth_registry = ScreenAuthorizationRegistry(self.db)
        self.screen_controller = ScreenController(self.db, config, self.trust_manager, self.audit_logger)
        self.atlas_diagnostics = AtlasDiagnostics(self.db)
        self.atlas_health = AtlasHealthMonitor(self.db)
        self.aegis_registry = AegisSessionRegistry(self.db)

    def bootstrap(self, settings: ConsoleUISettings) -> dict[str, Any]:
        active_identity = self.identity_manager.get_active_identity()
        initialized = active_identity is not None and self.config.database_path.is_file()
        return {
            "application": {
                "name": "GuardianMesh",
                "phase": __phase__,
                "version": __version__,
                "initialized": initialized,
                "offline": True,
                "localhost_only": True,
            },
            "settings": self._settings_dict(settings),
            "navigation": [
                {"id": "home", "label_key": "navigation.home"},
                {"id": "devices", "label_key": "navigation.devices"},
                {"id": "screen", "label_key": "navigation.screen"},
                {"id": "alerts", "label_key": "navigation.alerts"},
                {"id": "activity", "label_key": "navigation.activity"},
                {"id": "settings", "label_key": "navigation.settings"},
                {"id": "about", "label_key": "navigation.about"},
            ],
        }

    def home(self) -> dict[str, Any]:
        devices = self.devices()["devices"]
        online = sum(1 for device in devices if device["connection"]["is_online"])
        attention = sum(1 for device in devices if device["status"]["needs_attention"])
        active_alerts = self.alert_manager.list_alerts(status="ACTIVE", limit=self.MAX_ALERTS)
        if not devices:
            protection = {"key": "status.setup_required", "tone": "warning"}
        elif attention:
            protection = {"key": "status.attention_needed", "tone": "warning"}
        else:
            protection = {"key": "status.protected", "tone": "success"}
        return {
            "greeting_key": self._greeting_key(),
            "protection": protection,
            "metrics": [
                {"label_key": "metrics.total_devices", "value": len(devices)},
                {"label_key": "metrics.online_devices", "value": online},
                {"label_key": "metrics.devices_attention", "value": attention},
                {"label_key": "metrics.active_alerts", "value": len(active_alerts)},
            ],
            "quick_actions": [
                {"id": "devices", "label_key": "actions.view_devices"},
                {"id": "screen", "label_key": "actions.view_screen"},
                {"id": "alerts", "label_key": "actions.view_alerts"},
                {"id": "pair", "label_key": "actions.add_device"},
            ],
            "recent_activity": self.activity(limit=6)["activity"],
        }

    def devices(self) -> dict[str, Any]:
        trusted = self.trust_manager.list_trusted_devices()
        devices = [self._device_summary(device) for device in trusted]
        return {"devices": devices}

    def device_detail(self, device_id: str) -> dict[str, Any]:
        view = self.console_service.get_device_detail(device_id)
        summary = self._device_from_view(view)
        sessions = self.screen_registry.list_for_device(device_id)
        active = next((s for s in sessions if s.state == ScreenSessionState.ACTIVE), None)
        recent = [self._session_summary(s) for s in sessions[:10]]
        policy_dict = view.policy.to_dict() if view.policy else None
        if policy_dict:
            policy_dict.pop("rules", None)
        advanced = {
            "fingerprint": view.fingerprint,
            "created_at": view.created_at,
            "transport": {
                "type": view.transport_type,
                "session_id": view.active_session_id,
                "reconnect_count": view.reconnect_count,
            },
            "policy": policy_dict,
        }
        return {
            "device": summary,
            "sections": {
                "overview": summary,
                "connection": summary["connection"],
                "health": summary["health"],
                "permissions": self._screen_requirements(device_id),
                "screen_sharing": {
                    "active_session": self._session_summary(active) if active else None,
                    "recent_sessions": recent,
                    "capability": self._aegis_capability(),
                },
                "recent_activity": [
                    item for item in self.activity(limit=20)["activity"] if item.get("device_id") == device_id
                ][:10],
                "advanced": advanced,
            },
        }

    def screen_overview(self, selected_device_id: str | None = None) -> dict[str, Any]:
        devices = self.devices()["devices"]
        active = self.screen_registry.list_active()
        active_summaries = [self._session_summary(session) for session in active]
        selected = selected_device_id or (
            active[0].device_id if active else (devices[0]["id"] if devices else None)
        )
        requirements = self._screen_requirements(selected) if selected else self._empty_requirements()
        return {
            "devices": devices,
            "selected_device_id": selected,
            "active_sessions": active_summaries,
            "requirements": requirements,
            "capability": self._aegis_capability(),
            "live_view_available": bool(active) and self._aegis_capability()["real_capture_available"],
            "visible_stop_required": True,
        }

    def start_screen_request(self, device_id: str, duration_seconds: int | None = None) -> dict[str, Any]:
        parent = self.identity_manager.get_active_identity()
        if not parent:
            raise GuardianMeshError("GuardianMesh is not initialized.")
        duration = duration_seconds or self.config.screen_view_default_max_duration_seconds
        duration = max(60, min(int(duration), self.config.screen_view_max_duration_seconds))
        request = ScreenViewRequest(
            device_id=device_id,
            parent_id=parent.id,
            max_duration_seconds=duration,
            label="Parent Console request",
            width=self.config.screen_view_default_width,
            height=self.config.screen_view_default_height,
            max_fps=self.config.screen_view_default_fps,
        )
        session = self.screen_controller.request_view(request)
        self.audit_logger.record(
            AuditEventType.SCREEN_VIEW_REQUESTED,
            {"session_id": session.session_id, "device_id": device_id, "source": "parent_console"},
            actor_id=parent.id,
        )
        return {
            "session": self._session_summary(session.info),
            "requirements": self._screen_requirements(device_id),
        }

    def stop_screen_session(self, session_id: str) -> dict[str, Any]:
        session = self.screen_controller.stop_session(session_id, reason=StopReason.PARENT_STOPPED)
        return {
            "session": self._session_summary(session.info),
            "requirements": self._screen_requirements(session.info.device_id),
        }

    def alerts(self) -> dict[str, Any]:
        alerts = self.alert_manager.list_alerts(limit=self.MAX_ALERTS)
        return {"alerts": [self._alert_summary(alert) for alert in alerts]}

    def acknowledge_alert(self, alert_id: str) -> dict[str, Any]:
        actor = self._actor_id()
        self.alert_manager.acknowledge_alert(alert_id, actor_id=actor)
        return {"ok": True}

    def resolve_alert(self, alert_id: str) -> dict[str, Any]:
        actor = self._actor_id()
        self.alert_manager.resolve_alert(alert_id, actor_id=actor)
        return {"ok": True}

    def dismiss_alert(self, alert_id: str) -> dict[str, Any]:
        actor = self._actor_id()
        self.alert_manager.dismiss_alert(alert_id, actor_id=actor)
        return {"ok": True}

    def activity(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(int(limit), self.MAX_ACTIVITY))
        events = self.console_service.audit_logger.get_recent(limit=limit)
        trusted = {
            device.remote_identity_id: device.label or "Child Device"
            for device in self.trust_manager.list_trusted_devices()
        }
        items = []
        for event in events:
            details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
            device_id = details.get("device_id") or event.get("actor_id")
            items.append(
                {
                    "id": event["id"],
                    "title": self._activity_title(event["event_type"], details),
                    "description": self._activity_description(event["event_type"], details),
                    "category": self._activity_category(event["event_type"]),
                    "timestamp": event.get("timestamp", ""),
                    "relative_time": relative_time(event.get("timestamp")),
                    "device_id": device_id,
                    "device_label": trusted.get(device_id) if device_id else None,
                    "success": bool(event.get("success", True)),
                }
            )
        return {"activity": items}

    def pairing_overview(self) -> dict[str, Any]:
        parent = self.identity_manager.get_active_identity()
        sessions = self.pairing_manager.list_sessions(parent_id=parent.id) if parent else []
        trusted = self.trust_manager.list_trusted_devices()
        return {
            "parent_identity": parent.id if parent else None,
            "active_sessions": [
                {
                    "id": session.session_id,
                    "method": session.verification_method,
                    "state": session.state.value,
                    "expires_in_seconds": session.seconds_remaining(),
                    "next_step": self._pairing_next_step(session.state),
                }
                for session in sessions
                if session.state not in {PairingState.CANCELLED, PairingState.EXPIRED, PairingState.DENIED}
            ],
            "trusted_devices": len(trusted),
        }

    def start_pairing(
        self, method: str = "DEMO", destination: str = "demo@guardianmesh.local"
    ) -> dict[str, Any]:
        parent = self.identity_manager.get_active_identity()
        if not parent:
            raise GuardianMeshError("GuardianMesh is not initialized.")
        normalized_method = method.strip().upper()
        if normalized_method not in {"DEMO", "EMAIL", "SMS"}:
            raise GuardianMeshError("Unsupported verification method.")
        if normalized_method == "DEMO":
            destination = "demo@guardianmesh.local"
        if not destination:
            raise GuardianMeshError("A verification destination is required.")
        session, demo_otp = self.pairing_manager.create_session(
            parent_identity_id=parent.id,
            verification_method=normalized_method,
            verification_destination=destination,
        )
        return {
            "session": {
                "id": session.session_id,
                "state": session.state.value,
                "demo_code": demo_otp,
                "expires_in_seconds": session.seconds_remaining(),
                "next_step": self._pairing_next_step(session.state),
            }
        }

    def rename_device(self, device_id: str, label: str) -> dict[str, Any]:
        clean_label = label.strip()
        if not clean_label:
            raise GuardianMeshError("Device name cannot be empty.")
        if len(clean_label) > 80:
            raise GuardianMeshError("Device name is too long.")
        self.console_service.rename_device(device_id, clean_label)
        return {"ok": True}

    def revoke_device(self, device_id: str) -> dict[str, Any]:
        self.console_service.revoke_device(device_id)
        return {"ok": True}

    def diagnostics(self) -> dict[str, Any]:
        try:
            report = self.atlas_diagnostics.run_full()
            checks = [
                {"name": check.name, "ok": check.ok, "subsystem": check.subsystem, "reason": check.reason}
                for check in report.checks
            ]
        except Exception:
            checks = []
        try:
            health = self.atlas_health.check_all()
        except Exception:
            health = {}
        subsystem_status = self.console_service.get_subsystem_statuses()
        return {
            "checks": checks,
            "health": health,
            "subsystems": subsystem_status,
            "export_available": True,
        }

    def settings_data(self) -> dict[str, Any]:
        return {
            "retention": {
                "telemetry_days": self.config.telemetry_retention_days,
                "alerts_days": self.config.alert_retention_days,
            },
            "security": {
                "localhost_only": True,
                "screen_session_seconds": self.config.screen_view_default_max_duration_seconds,
                "session_timeout_minutes": self.config.session_expiration_seconds // 60,
                "trust_status": "READY" if self.identity_manager.get_active_identity() else "SETUP_REQUIRED",
            },
        }

    @staticmethod
    def _settings_dict(settings: ConsoleUISettings) -> dict[str, Any]:
        return {
            "language": settings.language,
            "theme": settings.theme,
            "notifications": settings.notifications,
            "open_browser": settings.open_browser,
            "startup_page": settings.startup_page,
        }

    def _greeting_key(self) -> str:
        hour = now_utc().astimezone().hour
        if hour < 12:
            return "home.good_morning"
        if hour < 18:
            return "home.good_afternoon"
        return "home.good_evening"

    def _actor_id(self) -> str | None:
        identity = self.identity_manager.get_active_identity()
        return identity.id if identity else None

    def _device_summary(self, device: Any) -> dict[str, Any]:
        health = self.console_service.get_device_health(device.remote_identity_id)
        peer = self.console_service.transport_registry.get_peer(device.remote_identity_id)
        active_alerts = self.alert_manager.get_active_alerts(device_id=device.remote_identity_id)
        is_online = bool(health and health.health_state.value == "ONLINE")
        needs_attention = (
            bool(active_alerts)
            or device.status != "ACTIVE"
            or (health and health.health_state.value != "ONLINE")
        )
        battery = health.battery_percent if health else None
        return {
            "id": device.remote_identity_id,
            "name": device.label or "Child Device",
            "role": device.remote_role.value,
            "status": {
                "key": "status.protected"
                if device.status == "ACTIVE" and is_online and not active_alerts
                else "status.attention_needed",
                "tone": "success" if not needs_attention else "warning",
                "online": is_online,
                "trusted": device.status == "ACTIVE",
                "needs_attention": needs_attention,
            },
            "connection": {
                "is_online": is_online,
                "label_key": "device.online" if is_online else "device.offline",
                "last_seen": relative_time(health.last_heartbeat_at if health else device.last_verified_at),
                "transport": peer.connection_state.value if peer else "DISCONNECTED",
            },
            "health": {
                "state": health.health_state.value if health else "UNKNOWN",
                "battery_percent": battery,
                "charging": health.is_charging if health else None,
                "storage_free_gb": round(health.storage_free_gb, 1)
                if health and health.storage_free_gb is not None
                else None,
                "connectivity": health.connectivity.value if health else "UNKNOWN",
                "uptime": health.uptime_display if health else None,
            },
            "alerts_count": len(active_alerts),
            "created_at": device.created_at,
        }

    def _device_from_view(self, view: Any) -> dict[str, Any]:
        is_online = bool(view.health and view.health.health_state.value == "ONLINE")
        active_alerts = view.active_alerts or []
        return {
            "id": view.device_id,
            "name": view.label or "Child Device",
            "role": view.role,
            "status": {
                "key": "status.protected"
                if view.trust_status == "ACTIVE" and is_online and not active_alerts
                else "status.attention_needed",
                "tone": "success"
                if view.trust_status == "ACTIVE" and is_online and not active_alerts
                else "warning",
                "online": is_online,
                "trusted": view.trust_status == "ACTIVE",
                "needs_attention": bool(active_alerts or view.trust_status != "ACTIVE" or not is_online),
            },
            "connection": {
                "is_online": is_online,
                "label_key": "device.online" if is_online else "device.offline",
                "last_seen": relative_time(view.health.last_heartbeat_at if view.health else None),
                "transport": view.connection_state,
            },
            "health": {
                "state": view.health.health_state.value if view.health else "UNKNOWN",
                "battery_percent": view.health.battery_percent if view.health else None,
                "charging": view.health.is_charging if view.health else None,
                "storage_free_gb": round(view.health.storage_free_gb, 1)
                if view.health and view.health.storage_free_gb is not None
                else None,
                "connectivity": view.health.connectivity.value if view.health else "UNKNOWN",
                "uptime": view.health.uptime_display if view.health else None,
            },
            "alerts_count": len(active_alerts),
        }

    def _alert_summary(self, alert: Any) -> dict[str, Any]:
        device = next(
            (d for d in self.trust_manager.list_trusted_devices() if d.remote_identity_id == alert.device_id),
            None,
        )
        category = {
            "CRITICAL": "security",
            "WARNING": "needs_attention",
            "INFO": "informational",
        }.get(alert.severity.value, "informational")
        if "offline" in alert.message.lower():
            category = "device_offline"
        if "auth" in alert.message.lower():
            category = "authorization_issue"
        return {
            "id": alert.id,
            "title": self._alert_title(alert.message),
            "message": alert.message,
            "category": category,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "device_id": alert.device_id,
            "device_label": device.label if device else alert.device_id,
            "created_at": alert.created_at,
            "relative_time": relative_time(alert.created_at),
        }

    @staticmethod
    def _alert_title(message: str) -> str:
        lowered = message.lower()
        if "battery" in lowered:
            return "Battery needs attention"
        if "offline" in lowered:
            return "Device is offline"
        if "storage" in lowered:
            return "Storage is low"
        return "Device needs attention"

    def _session_summary(self, info: Any) -> dict[str, Any]:
        return {
            "id": info.session_id,
            "device_id": info.device_id,
            "state": info.state.value,
            "label": info.label or "Screen sharing",
            "started_at": info.started_at,
            "requested_at": info.requested_at,
            "stopped_at": info.stopped_at,
            "expires_at": info.expires_at,
            "remaining_seconds": max(0, info.remaining_seconds) if info.expires_at else None,
            "width": info.width,
            "height": info.height,
            "fps": info.max_fps,
            "frame_count": info.frame_count,
        }

    def _screen_requirements(self, device_id: str | None) -> dict[str, Any]:
        parent = self.identity_manager.get_active_identity()
        device = None
        if device_id:
            all_devices = self.trust_manager.list_trusted_devices()
            device = next((item for item in all_devices if item.remote_identity_id == device_id), None)
        session = self._latest_session(device_id) if device_id else None
        auth = self.screen_auth_registry.get_by_session_id(session.session_id) if session else None
        aegis = self._aegis_capability()
        trust_ok = bool(device and device.status == "ACTIVE")
        parent_ok = parent is not None
        child_auth_ok = bool(auth and auth.decision.value == "APPROVED" and not auth.is_expired())
        system_consent_ok = False
        if session:
            aegis_sessions = self.aegis_registry.list_all()
            matching = next((s for s in aegis_sessions if s.screen_session_id == session.session_id), None)
            system_consent_ok = bool(matching and matching.consent_state == SystemConsentState.GRANTED)
        can_request = trust_ok and parent_ok and device_id is not None
        can_start = can_request and child_auth_ok and system_consent_ok and aegis["real_capture_available"]
        steps = [
            {"id": "parent", "label_key": "screen.parent_authorization", "ok": parent_ok},
            {"id": "trust", "label_key": "screen.trusted_device", "ok": trust_ok},
            {"id": "child", "label_key": "screen.child_approval", "ok": child_auth_ok},
            {"id": "system", "label_key": "screen.android_permission", "ok": system_consent_ok},
        ]
        explanation_key = "screen.requirements_explainer"
        if not trust_ok:
            explanation_key = "screen.trust_required"
        elif not child_auth_ok:
            explanation_key = "screen.child_approval_required"
        elif not system_consent_ok or not aegis["real_capture_available"]:
            explanation_key = "screen.android_permission_required"
        return {
            "can_request": can_request,
            "can_start": can_start,
            "session": self._session_summary(session) if session else None,
            "child_authorization": {
                "ok": child_auth_ok,
                "state": auth.decision.value if auth else "MISSING",
                "expires_at": auth.expires_at if auth else None,
            },
            "system_consent": {
                "ok": system_consent_ok,
                "state": SystemConsentState.NOT_REQUESTED.value,
            },
            "steps": steps,
            "explanation_key": explanation_key,
            "stop_always_visible": True,
        }

    def _latest_session(self, device_id: str | None) -> Any:
        if not device_id:
            return None
        sessions = self.screen_registry.list_for_device(device_id)
        return sessions[0] if sessions else None

    def _aegis_capability(self) -> dict[str, Any]:
        platform_detected = detect_aegis_platform()
        real_capture_available = platform_detected.supports_real_capture
        return {
            "platform": platform_detected.value,
            "real_capture_available": real_capture_available,
            "foreground_indicator_required": True,
            "companion_required": not real_capture_available,
            "message_key": "screen.companion_required" if not real_capture_available else "screen.ready",
        }

    @staticmethod
    def _empty_requirements() -> dict[str, Any]:
        return {
            "can_request": False,
            "can_start": False,
            "session": None,
            "steps": [],
            "explanation_key": "screen.select_device",
            "stop_always_visible": True,
        }

    @staticmethod
    def _pairing_next_step(state: PairingState) -> str:
        mapping = {
            PairingState.CREATED: "Enter the verification code on the child device.",
            PairingState.VERIFICATION_PENDING: "Enter the verification code on the child device.",
            PairingState.VERIFIED: "Wait for explicit child approval.",
            PairingState.CHILD_AUTHORIZATION_PENDING: "Child approval is required.",
            PairingState.AUTHORIZED: "Completing trusted device setup.",
            PairingState.TRUST_ESTABLISHED: "Device is trusted.",
            PairingState.PAIRED: "Device is ready.",
        }
        return mapping.get(state, "Pairing is in progress.")

    @staticmethod
    def _activity_title(event_type: str, details: dict[str, Any]) -> str:
        titles = {
            "TRUST_ESTABLISHED": "Device connected",
            "TRUST_REVOKED": "Device removed",
            "TRANSPORT_CONNECTED": "Device connected",
            "TRANSPORT_DISCONNECTED": "Device disconnected",
            "SCREEN_VIEW_REQUESTED": "Screen sharing requested",
            "SCREEN_VIEW_APPROVED": "Screen sharing approved",
            "SCREEN_SESSION_STARTED": "Screen-sharing session started",
            "SCREEN_SESSION_STOPPED": "Screen-sharing session stopped",
            "SCREEN_SESSION_EXPIRED": "Screen-sharing session expired",
            "ALERT_CREATED": "Alert received",
            "ALERT_RESOLVED": "Alert resolved",
            "CHILD_DENIED": "Authorization changed",
            "TRANSPORT_AUTH_FAILED": "Security event prevented",
            "TRANSPORT_REPLAY_REJECTED": "Security policy prevented an unauthorized action",
        }
        return titles.get(event_type, ParentConsolePresenter._humanize(event_type))

    @staticmethod
    def _activity_description(event_type: str, details: dict[str, Any]) -> str:
        descriptions = {
            "TRUST_ESTABLISHED": "A trusted device was added.",
            "TRUST_REVOKED": "A device trust relationship was removed.",
            "TRANSPORT_CONNECTED": "The device connected securely.",
            "TRANSPORT_DISCONNECTED": "The device became unavailable.",
            "SCREEN_VIEW_REQUESTED": "A parent requested view-only screen sharing.",
            "SCREEN_VIEW_APPROVED": "The child approved screen sharing.",
            "SCREEN_SESSION_STARTED": "A consent-based screen-sharing session started.",
            "SCREEN_SESSION_STOPPED": "Screen sharing was stopped.",
            "SCREEN_SESSION_EXPIRED": "Screen sharing ended because it reached its time limit.",
            "ALERT_CREATED": "A device condition needs attention.",
            "ALERT_RESOLVED": "The alert was resolved.",
            "CHILD_DENIED": "A requested authorization was not approved.",
            "TRANSPORT_AUTH_FAILED": "A connection was blocked because authorization failed.",
            "TRANSPORT_REPLAY_REJECTED": "A repeated or unauthorized message was rejected.",
        }
        return descriptions.get(event_type, "GuardianMesh recorded a safe system event.")

    @staticmethod
    def _activity_category(event_type: str) -> str:
        if event_type.startswith("SCREEN_"):
            return "screen"
        if event_type.startswith("ALERT_"):
            return "alert"
        if event_type.startswith("TRANSPORT_"):
            return "connection"
        if (
            event_type.startswith("TRUST_")
            or event_type.startswith("PAIRING_")
            or event_type.startswith("CHILD_")
        ):
            return "authorization"
        if "AUTH_FAILED" in event_type or "REJECTED" in event_type:
            return "security"
        return "system"

    @staticmethod
    def _humanize(value: str) -> str:
        return value.replace("_", " ").capitalize()
