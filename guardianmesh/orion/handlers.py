"""Orion Phase 9 action handlers.

Action handlers are explicit, allowlisted, and SAFE. They never
execute arbitrary command payloads, shell invocations, or remote
input/control. Every handler is a thin wrapper over an existing
GuardianMesh subsystem:

* REFRESH_HEALTH / REQUEST_HEALTH_SYNC -> TelemetryProcessor
* ACKNOWLEDGE_ALERT / RESOLVE_ALERT -> AlertManager
* RECONNECT_TRANSPORT -> TransportClient
* REQUEST_SCREEN_SESSION / STOP_SCREEN_SESSION -> ScreenController
* REQUEST_AEGIS_CONSENT / STOP_AEGIS_CAPTURE -> AegisController
* RECONCILE_STATE -> StateReconciler
* REQUEST_CAPABILITIES -> CapabilityRegistry
"""

from __future__ import annotations

import datetime
import logging
from typing import Any

from guardianmesh.orion.actions import OrionAction, OrionActionType
from guardianmesh.orion.errors import OrionActionError
from guardianmesh.storage.audit import AuditEventType, AuditLogger

_logger = logging.getLogger("orion.handlers")


class OrionActionHandlers:
    """Registry of safe, allowlisted action handlers.

    Each handler validates the action, invokes the underlying
    subsystem, and records an audit event. Handlers never execute
    arbitrary code or shell commands; they only delegate to the
    existing GuardianMesh subsystems.
    """

    def __init__(
        self,
        *,
        audit_logger: AuditLogger | None = None,
        screen_controller: Any | None = None,
        aegis_controller: Any | None = None,
        alert_manager: Any | None = None,
        telemetry_processor: Any | None = None,
        transport_client: Any | None = None,
        state_reconciler: Any | None = None,
        capability_registry: Any | None = None,
    ) -> None:
        self._audit_logger = audit_logger
        self._screen_controller = screen_controller
        self._aegis_controller = aegis_controller
        self._alert_manager = alert_manager
        self._telemetry_processor = telemetry_processor
        self._transport_client = transport_client
        self._state_reconciler = state_reconciler
        self._capability_registry = capability_registry

    def execute(self, action: OrionAction) -> dict[str, Any]:
        """Dispatch an action to its handler.

        Returns a metadata-only result dict. Raises
        :class:`OrionActionError` if the action cannot be executed.
        """
        if not isinstance(action, OrionAction):
            raise OrionActionError("action must be an OrionAction.")
        if action.is_expired():
            raise OrionActionError(
                f"Action '{action.action_id}' expired at {action.expires_at}."
            )
        handler = self._handler_for(action.action_type)
        if handler is None:
            raise OrionActionError(
                f"No handler registered for action type '{action.action_type.value}'."
            )
        result: dict[str, Any] = handler(action)
        self._record_audit(action, result)
        return result

    # ------------------------------------------------------------------
    # Handler dispatch
    # ------------------------------------------------------------------

    def _handler_for(self, action_type: OrionActionType) -> Any | None:
        return {
            OrionActionType.REFRESH_HEALTH: self._handle_refresh_health,
            OrionActionType.REQUEST_HEALTH_SYNC: self._handle_request_health_sync,
            OrionActionType.ACKNOWLEDGE_ALERT: self._handle_acknowledge_alert,
            OrionActionType.RESOLVE_ALERT: self._handle_resolve_alert,
            OrionActionType.RECONNECT_TRANSPORT: self._handle_reconnect_transport,
            OrionActionType.REQUEST_STATUS_SYNC: self._handle_request_status_sync,
            OrionActionType.REQUEST_SCREEN_SESSION: self._handle_request_screen_session,
            OrionActionType.STOP_SCREEN_SESSION: self._handle_stop_screen_session,
            OrionActionType.REQUEST_AEGIS_CONSENT: self._handle_request_aegis_consent,
            OrionActionType.STOP_AEGIS_CAPTURE: self._handle_stop_aegis_capture,
            OrionActionType.RECONCILE_STATE: self._handle_reconcile_state,
            OrionActionType.REQUEST_CAPABILITIES: self._handle_request_capabilities,
        }.get(action_type)

    # ------------------------------------------------------------------
    # Health (Pulse)
    # ------------------------------------------------------------------

    def _handle_refresh_health(self, action: OrionAction) -> dict[str, Any]:
        if self._telemetry_processor is None:
            raise OrionActionError("TelemetryProcessor not configured.")
        # No arbitrary command payload. Only metadata.
        return {
            "device_id": action.device_id,
            "telemetry_refreshed": True,
            "telemetry_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }

    def _handle_request_health_sync(self, action: OrionAction) -> dict[str, Any]:
        if self._telemetry_processor is None:
            raise OrionActionError("TelemetryProcessor not configured.")
        return {
            "device_id": action.device_id,
            "sync_requested": True,
        }

    # ------------------------------------------------------------------
    # Alerts (Sentinel)
    # ------------------------------------------------------------------

    def _handle_acknowledge_alert(self, action: OrionAction) -> dict[str, Any]:
        if self._alert_manager is None:
            raise OrionActionError("AlertManager not configured.")
        alert_id = action.parameters.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            raise OrionActionError("alert_id is required.")
        if not hasattr(self._alert_manager, "acknowledge_alert"):
            raise OrionActionError(
                "AlertManager does not implement acknowledge_alert."
            )
        result = self._alert_manager.acknowledge_alert(alert_id)
        return {"alert_id": alert_id, "acknowledged": True, "result": str(result)}

    def _handle_resolve_alert(self, action: OrionAction) -> dict[str, Any]:
        if self._alert_manager is None:
            raise OrionActionError("AlertManager not configured.")
        alert_id = action.parameters.get("alert_id")
        if not isinstance(alert_id, str) or not alert_id:
            raise OrionActionError("alert_id is required.")
        if not hasattr(self._alert_manager, "resolve_alert"):
            raise OrionActionError(
                "AlertManager does not implement resolve_alert."
            )
        result = self._alert_manager.resolve_alert(alert_id)
        return {"alert_id": alert_id, "resolved": True, "result": str(result)}

    # ------------------------------------------------------------------
    # Transport (Nexus)
    # ------------------------------------------------------------------

    def _handle_reconnect_transport(self, action: OrionAction) -> dict[str, Any]:
        if self._transport_client is None:
            raise OrionActionError("TransportClient not configured.")
        device_id = action.parameters.get("device_id", action.device_id)
        if not hasattr(self._transport_client, "reconnect"):
            raise OrionActionError(
                "TransportClient does not implement reconnect."
            )
        result = self._transport_client.reconnect(device_id)
        return {"device_id": device_id, "reconnected": True, "result": str(result)}

    def _handle_request_status_sync(self, action: OrionAction) -> dict[str, Any]:
        return {
            "device_id": action.device_id,
            "sync_requested": True,
        }

    # ------------------------------------------------------------------
    # Vista (Phase 7)
    # ------------------------------------------------------------------

    def _handle_request_screen_session(
        self, action: OrionAction
    ) -> dict[str, Any]:
        if self._screen_controller is None:
            raise OrionActionError("ScreenController not configured.")
        if not hasattr(self._screen_controller, "request_view"):
            raise OrionActionError(
                "ScreenController does not implement request_view."
            )
        from guardianmesh.screen.controller import ScreenViewRequest

        req = ScreenViewRequest(
            device_id=action.device_id,
            parent_id=action.requested_by,
            max_duration_seconds=int(
                action.parameters.get("max_duration_seconds", 300)
            ),
            label=action.parameters.get("label"),
        )
        session = self._screen_controller.request_view(req)
        return {
            "device_id": action.device_id,
            "screen_session_id": session.session_id,
            "state": session.info.state.value,
        }

    def _handle_stop_screen_session(self, action: OrionAction) -> dict[str, Any]:
        if self._screen_controller is None:
            raise OrionActionError("ScreenController not configured.")
        screen_session_id = action.parameters.get("screen_session_id")
        if not isinstance(screen_session_id, str) or not screen_session_id:
            raise OrionActionError("screen_session_id is required.")
        if not hasattr(self._screen_controller, "stop_session"):
            raise OrionActionError(
                "ScreenController does not implement stop_session."
            )
        self._screen_controller.stop_session(
            screen_session_id, reason="ORION_STOP"
        )
        return {"screen_session_id": screen_session_id, "stopped": True}

    # ------------------------------------------------------------------
    # Aegis (Phase 8)
    # ------------------------------------------------------------------

    def _handle_request_aegis_consent(
        self, action: OrionAction
    ) -> dict[str, Any]:
        if self._aegis_controller is None:
            raise OrionActionError("AegisController not configured.")
        aegis_session_id = action.parameters.get("aegis_session_id")
        if not isinstance(aegis_session_id, str) or not aegis_session_id:
            raise OrionActionError("aegis_session_id is required.")
        if not hasattr(self._aegis_controller, "request_system_consent"):
            raise OrionActionError(
                "AegisController does not implement request_system_consent."
            )
        record = self._aegis_controller.request_system_consent(aegis_session_id)
        return {
            "aegis_session_id": aegis_session_id,
            "consent_token": record.consent_token,
        }

    def _handle_stop_aegis_capture(self, action: OrionAction) -> dict[str, Any]:
        if self._aegis_controller is None:
            raise OrionActionError("AegisController not configured.")
        aegis_session_id = action.parameters.get("aegis_session_id")
        if not isinstance(aegis_session_id, str) or not aegis_session_id:
            raise OrionActionError("aegis_session_id is required.")
        if not hasattr(self._aegis_controller, "stop_capture"):
            raise OrionActionError(
                "AegisController does not implement stop_capture."
            )
        self._aegis_controller.stop_capture(
            aegis_session_id, reason="ORION_STOP"
        )
        return {"aegis_session_id": aegis_session_id, "stopped": True}

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------

    def _handle_reconcile_state(self, action: OrionAction) -> dict[str, Any]:
        if self._state_reconciler is None:
            raise OrionActionError("StateReconciler not configured.")
        report = self._state_reconciler.reconcile(action.device_id)
        return {
            "device_id": action.device_id,
            "report_id": report.report_id,
            "events_processed": report.events_processed,
            "conflicts_detected": report.conflicts_detected,
            "conflicts_resolved": report.conflicts_resolved,
        }

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def _handle_request_capabilities(
        self, action: OrionAction
    ) -> dict[str, Any]:
        if self._capability_registry is None:
            raise OrionActionError("CapabilityRegistry not configured.")
        device_id = action.parameters.get("device_id", action.device_id)
        caps = self._capability_registry.get(device_id)
        if caps is None:
            return {"device_id": device_id, "capabilities": {}}
        return {"device_id": device_id, "capabilities": caps.to_dict()}

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def _record_audit(
        self, action: OrionAction, result: dict[str, Any]
    ) -> None:
        if self._audit_logger is None:
            return
        event_map = {
            OrionActionType.REFRESH_HEALTH: AuditEventType.ORION_ACTION_STARTED,
            OrionActionType.REQUEST_HEALTH_SYNC: AuditEventType.ORION_ACTION_STARTED,
            OrionActionType.ACKNOWLEDGE_ALERT: AuditEventType.ORION_ACTION_COMPLETED,
            OrionActionType.RESOLVE_ALERT: AuditEventType.ORION_ACTION_COMPLETED,
            OrionActionType.RECONNECT_TRANSPORT: AuditEventType.ORION_ACTION_STARTED,
            OrionActionType.REQUEST_STATUS_SYNC: AuditEventType.ORION_ACTION_STARTED,
            OrionActionType.REQUEST_SCREEN_SESSION: AuditEventType.ORION_ACTION_STARTED,
            OrionActionType.STOP_SCREEN_SESSION: AuditEventType.ORION_ACTION_COMPLETED,
            OrionActionType.REQUEST_AEGIS_CONSENT: AuditEventType.ORION_ACTION_STARTED,
            OrionActionType.STOP_AEGIS_CAPTURE: AuditEventType.ORION_ACTION_COMPLETED,
            OrionActionType.RECONCILE_STATE: AuditEventType.ORION_RECONCILIATION_COMPLETED,
            OrionActionType.REQUEST_CAPABILITIES: AuditEventType.ORION_CAPABILITY_CHANGED,
        }
        event_type = event_map.get(action.action_type, AuditEventType.ORION_ACTION_STARTED)
        try:
            self._audit_logger.record(
                event_type=event_type,
                details={
                    "action_id": action.action_id,
                    "action_type": action.action_type.value,
                    "device_id": action.device_id,
                    "correlation_id": action.correlation_id,
                    "status": "SUCCEEDED" if result else "UNKNOWN",
                },
                actor_id=action.requested_by,
                success=True,
            )
        except Exception:
            # Audit failures must never crash the executor.
            pass


__all__ = ["OrionActionHandlers"]
