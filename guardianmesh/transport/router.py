"""Message router dispatching incoming transport messages to domain subsystems."""

from __future__ import annotations

import datetime
from collections.abc import Callable
from typing import Any

from guardianmesh.core.errors import (
    DeviceNotTrustedError,
    TransportMessageError,
    TransportRevokedError,
    TransportSessionExpiredError,
    TrustRevokedError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.telemetry.models import TelemetryEnvelope
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.transport.models import (
    ConnectionState,
    MessageType,
    TransportEnvelope,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.session import TransportSession


class MessageRouter:
    """Dispatches validated transport envelopes to Telemetry, Policy, and Alert engines."""

    def __init__(
        self,
        db: Database,
        local_identity_id: str,
        trust_manager: TrustManager,
        telemetry_processor: TelemetryProcessor | None = None,
        registry: TransportRegistry | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.local_identity_id = local_identity_id
        self.trust_manager = trust_manager
        self.telemetry_processor = telemetry_processor
        self.registry = registry or TransportRegistry(db)
        self.audit_logger = audit_logger or AuditLogger(db)
        self._custom_handlers: dict[str, Callable[[TransportEnvelope, TransportSession], Any]] = {}

    def register_handler(
        self,
        message_type: MessageType | str,
        handler: Callable[[TransportEnvelope, TransportSession], Any],
    ) -> None:
        """Register a custom callback for a message type."""
        key = message_type.value if isinstance(message_type, MessageType) else str(message_type).upper()
        self._custom_handlers[key] = handler

    def route(
        self,
        envelope: TransportEnvelope,
        session: TransportSession,
    ) -> Any:
        """Validate, authenticate, record, and route an inbound transport envelope.

        Args:
            envelope: Decrypted inbound TransportEnvelope.
            session: Active TransportSession.

        Returns:
            Result of domain handler execution.
        """
        sender_id = envelope.sender_id
        msg_type_str = envelope.message_type.value

        # 1. Verify Recipient Matching
        if envelope.recipient_id != self.local_identity_id:
            err_msg = (
                f"Recipient mismatch: envelope addressed to '{envelope.recipient_id}', "
                f"local is '{self.local_identity_id}'."
            )
            self._record_rejection(session.session_id, sender_id, msg_type_str, envelope.sequence, err_msg)
            raise TransportMessageError(err_msg)

        # 2. Check Trust and Revocation
        try:
            trusted_dev = self.trust_manager.verify_device_trust_or_raise(
                local_identity_id=self.local_identity_id,
                remote_identity_id=sender_id,
            )
            if trusted_dev.status == "REVOKED":
                raise TrustRevokedError(f"Device '{sender_id}' is revoked.")
        except (DeviceNotTrustedError, TrustRevokedError) as e:
            # Revoke active session immediately
            session.close(reason=f"Trust revoked: {e}")
            self.registry.update_session_state(session.session_id, ConnectionState.REVOKED, last_error=str(e))
            self.registry.update_peer_state(sender_id, ConnectionState.REVOKED)

            self.audit_logger.record(
                event_type=AuditEventType.TRANSPORT_REVOKED,
                details={
                    "sender_id": sender_id,
                    "session_id": session.session_id,
                    "reason": str(e),
                },
                actor_id=self.local_identity_id,
                success=False,
            )
            self._record_rejection(session.session_id, sender_id, msg_type_str, envelope.sequence, str(e))
            raise TransportRevokedError(f"Transport rejected: {e}") from e

        # 3. Check Envelope Expiration
        try:
            exp_dt = datetime.datetime.fromisoformat(envelope.expires_at)
            if datetime.datetime.now(datetime.UTC) > exp_dt:
                err_msg = f"Envelope expired at {envelope.expires_at}."
                self._record_rejection(
                    session.session_id, sender_id, msg_type_str, envelope.sequence, err_msg
                )
                raise TransportSessionExpiredError(err_msg)
        except ValueError as e:
            err_msg = f"Corrupted timestamp format: {e}"
            self._record_rejection(
                session.session_id, sender_id, msg_type_str, envelope.sequence, err_msg
            )
            raise TransportMessageError(err_msg) from e

        # 4. Record Message Acceptance
        self.registry.record_message(
            session_id=session.session_id,
            sender_id=sender_id,
            recipient_id=envelope.recipient_id,
            message_type=msg_type_str,
            sequence=envelope.sequence,
            direction="INBOUND",
            status="ACCEPTED",
            payload=envelope.payload,
            message_id=envelope.message_id,
        )
        self.registry.record_peer_heartbeat(sender_id, session.session_id)

        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_MESSAGE_ACCEPTED,
            details={
                "session_id": session.session_id,
                "sender_id": sender_id,
                "message_type": msg_type_str,
                "sequence": envelope.sequence,
            },
            actor_id=self.local_identity_id,
            success=True,
        )

        # 5. Route to Custom Handler if registered
        if msg_type_str in self._custom_handlers:
            return self._custom_handlers[msg_type_str](envelope, session)

        # 6. Route to Subsystem Default Handlers
        if envelope.message_type == MessageType.TELEMETRY:
            return self._handle_telemetry(envelope)
        elif envelope.message_type == MessageType.ALERT:
            return self._handle_alert(envelope)
        elif envelope.message_type == MessageType.HEARTBEAT:
            return self._handle_heartbeat(envelope, session)
        elif envelope.message_type == MessageType.PING:
            return self._handle_ping(envelope, session)
        elif envelope.message_type == MessageType.PONG:
            return self._handle_pong(envelope, session)
        elif envelope.message_type == MessageType.DEVICE_STATUS:
            return self._handle_device_status(envelope)
        elif envelope.message_type == MessageType.GOODBYE:
            return self._handle_goodbye(session)
        elif envelope.message_type == MessageType.ERROR:
            return self._handle_error(envelope, session)
        elif envelope.message_type == MessageType.POLICY_SYNC:
            return self._handle_policy_sync(envelope)

        return {"status": "DELIVERED", "type": msg_type_str}

    def _handle_telemetry(self, envelope: TransportEnvelope) -> Any:
        """Forward telemetry payload into TelemetryProcessor."""
        if not self.telemetry_processor:
            return {"status": "NO_PROCESSOR"}

        # Construct TelemetryEnvelope from payload
        tel_data = envelope.payload
        if not isinstance(tel_data, dict):
            raise TransportMessageError("TELEMETRY message payload must be a dictionary.")

        # Reconstruct TelemetryEnvelope if nested or direct
        if "device_id" in tel_data and "payload" in tel_data:
            tel_envelope = TelemetryEnvelope.from_dict(tel_data)
        else:
            tel_envelope = TelemetryEnvelope(
                device_id=envelope.sender_id,
                sequence=envelope.sequence,
                captured_at=envelope.created_at,
                payload=tel_data,
                signature=envelope.authentication.get("signature_hex", ""),
            )

        summary = self.telemetry_processor.process_envelope(
            envelope=tel_envelope,
            local_identity_id=self.local_identity_id,
        )
        self.registry.record_peer_sync(envelope.sender_id)
        return summary

    def _handle_alert(self, envelope: TransportEnvelope) -> Any:
        """Route alert message into Policy/Alert engine."""
        payload = envelope.payload
        policy_id = payload.get("policy_id", "REMOTE-POLICY")
        rule_type_val = payload.get("rule_type", "LOW_BATTERY")
        severity_val = payload.get("severity", "WARNING")
        message = payload.get("message", "Remote alert triggered")
        trigger_val = payload.get("trigger_value")

        from guardianmesh.policy.alerts import AlertManager
        from guardianmesh.policy.models import AlertSeverity, RuleType

        cfg = self.telemetry_processor.config if self.telemetry_processor else None
        alert_mgr = AlertManager(self.db, cfg, self.audit_logger)  # type: ignore[arg-type]
        rule_type = RuleType.from_str(rule_type_val)
        severity = AlertSeverity.from_str(severity_val)

        return alert_mgr.create_or_update_alert(
            device_id=envelope.sender_id,
            policy_id=policy_id,
            rule_type=rule_type,
            severity=severity,
            message=message,
            trigger_value=trigger_val,
        )

    def _handle_heartbeat(self, envelope: TransportEnvelope, session: TransportSession) -> dict[str, str]:
        """Process incoming heartbeat."""
        session.touch_heartbeat()
        self.registry.record_peer_heartbeat(envelope.sender_id, session.session_id)
        return {"status": "HEARTBEAT_ACK"}

    def _handle_ping(self, envelope: TransportEnvelope, session: TransportSession) -> TransportEnvelope:
        """Acknowledge ping with pong."""
        session.touch_heartbeat()
        from guardianmesh.transport.heartbeat import HeartbeatManager

        hb_mgr = HeartbeatManager()
        return hb_mgr.create_pong(
            local_id=self.local_identity_id,
            remote_id=envelope.sender_id,
            session=session,
            ping_message_id=envelope.message_id,
        )

    def _handle_pong(self, envelope: TransportEnvelope, session: TransportSession) -> dict[str, str]:
        """Process pong response."""
        session.touch_heartbeat()
        self.registry.record_peer_heartbeat(envelope.sender_id, session.session_id)
        return {"status": "PONG_RECEIVED"}

    def _handle_device_status(self, envelope: TransportEnvelope) -> dict[str, str]:
        """Update peer device status."""
        self.registry.record_peer_sync(envelope.sender_id)
        return {"status": "STATUS_RECORDED"}

    def _handle_goodbye(self, session: TransportSession) -> dict[str, str]:
        """Process graceful disconnect request."""
        session.close(reason="Received GOODBYE from peer")
        self.registry.update_session_state(session.session_id, ConnectionState.DISCONNECTED)
        self.registry.update_peer_state(session.remote_identity_id, ConnectionState.DISCONNECTED)
        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_DISCONNECTED,
            details={"session_id": session.session_id, "remote_id": session.remote_identity_id},
            actor_id=self.local_identity_id,
            success=True,
        )
        return {"status": "DISCONNECTED"}

    def _handle_error(self, envelope: TransportEnvelope, session: TransportSession) -> dict[str, str]:
        """Log incoming remote error envelope."""
        err_msg = str(envelope.payload.get("error", "Unknown remote transport error"))
        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_ERROR,
            details={
                "session_id": session.session_id,
                "sender_id": envelope.sender_id,
                "error": err_msg,
            },
            actor_id=self.local_identity_id,
            success=False,
        )
        return {"status": "ERROR_LOGGED"}

    def _handle_policy_sync(self, envelope: TransportEnvelope) -> dict[str, str]:
        """Acknowledge policy sync."""
        self.registry.record_peer_sync(envelope.sender_id)
        return {"status": "POLICY_SYNCED"}

    def _record_rejection(
        self,
        session_id: str,
        sender_id: str,
        message_type: str,
        sequence: int,
        reason: str,
    ) -> None:
        """Record rejected message in registry and audit log."""
        self.registry.record_message(
            session_id=session_id,
            sender_id=sender_id,
            recipient_id=self.local_identity_id,
            message_type=message_type,
            sequence=sequence,
            direction="INBOUND",
            status="REJECTED",
            error_reason=reason,
        )
        self.audit_logger.record(
            event_type=AuditEventType.TRANSPORT_MESSAGE_REJECTED,
            details={
                "session_id": session_id,
                "sender_id": sender_id,
                "message_type": message_type,
                "sequence": sequence,
                "reason": reason,
            },
            actor_id=self.local_identity_id,
            success=False,
        )
