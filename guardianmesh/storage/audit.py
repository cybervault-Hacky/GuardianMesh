"""Privacy-conscious audit logging with automatic sensitive data redaction."""

from __future__ import annotations

import datetime
import json
from enum import Enum
from typing import Any

from guardianmesh.core.errors import AuditError
from guardianmesh.core.logging import redact_sensitive_data
from guardianmesh.storage.database import Database

# Keys that must never be recorded in clear text in audit logs
_SENSITIVE_KEY_NAMES = {
    "password",
    "private_key",
    "private_key_pem",
    "secret",
    "token",
    "auth_token",
    "otp",
    "otp_code",
    "otp_verifier",
    "verifier",
    "salt",
    "otp_salt",
    "pin",
    "credential",
    "key_material",
    "smtp_password",
    "sms_content",
    "email_body",
    "screen_content",
    "keystroke",
    "clipboard",
    "auth_nonce",
    "nonce",
    "trust_secret",
    "messages",
    "contacts",
    "photos",
    "files",
    "browser_history",
    "keyboard_input",
    "microphone",
    "camera",
    "location",
    "screen",
    "app_usage",
    "shared_secret",
    "session_key",
    "send_key",
    "recv_key",
    "encryption_key",
    "ephemeral_key",
    "symmetric_key",
    "ciphertext",
    "nonce_hex",
}


def sanitize_audit_details(data: Any) -> Any:
    """Recursively scrub sensitive keys and secrets from audit metadata dictionaries."""
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if any(sens in key_lower for sens in _SENSITIVE_KEY_NAMES):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_details(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_audit_details(item) for item in data]
    elif isinstance(data, str):
        return redact_sensitive_data(data)
    return data


class AuditEventType(str, Enum):
    """Recognized security-relevant audit event types."""

    # Genesis (Phase 1)
    STARTUP = "STARTUP"
    DATABASE_INITIALIZED = "DATABASE_INITIALIZED"
    SCHEMA_MIGRATED = "SCHEMA_MIGRATED"
    IDENTITY_CREATED = "IDENTITY_CREATED"
    IDENTITY_ACTIVATED = "IDENTITY_ACTIVATED"
    KEYPAIR_GENERATED = "KEYPAIR_GENERATED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    SECURITY_CHECK = "SECURITY_CHECK"
    DOCTOR_RUN = "DOCTOR_RUN"

    # Link / Pairing (Phase 2)
    PAIRING_CREATED = "PAIRING_CREATED"
    OTP_GENERATED = "OTP_GENERATED"
    OTP_DELIVERY_STARTED = "OTP_DELIVERY_STARTED"
    OTP_DELIVERED = "OTP_DELIVERED"
    OTP_VERIFIED = "OTP_VERIFIED"
    OTP_REJECTED = "OTP_REJECTED"
    CHILD_AUTHORIZATION_REQUESTED = "CHILD_AUTHORIZATION_REQUESTED"
    CHILD_APPROVED = "CHILD_APPROVED"
    CHILD_DENIED = "CHILD_DENIED"
    TRUST_ESTABLISHED = "TRUST_ESTABLISHED"
    TRUST_REVOKED = "TRUST_REVOKED"
    PAIRING_EXPIRED = "PAIRING_EXPIRED"
    PAIRING_CANCELLED = "PAIRING_CANCELLED"

    # Pulse / Telemetry (Phase 3)
    TELEMETRY_ACCEPTED = "TELEMETRY_ACCEPTED"
    TELEMETRY_REJECTED = "TELEMETRY_REJECTED"
    TELEMETRY_REPLAY_REJECTED = "TELEMETRY_REPLAY_REJECTED"
    TELEMETRY_SIGNATURE_REJECTED = "TELEMETRY_SIGNATURE_REJECTED"
    DEVICE_HEALTH_CHANGED = "DEVICE_HEALTH_CHANGED"
    HEARTBEAT_RECEIVED = "HEARTBEAT_RECEIVED"
    TELEMETRY_PAUSED = "TELEMETRY_PAUSED"
    TELEMETRY_RESUMED = "TELEMETRY_RESUMED"
    TELEMETRY_CLEANUP = "TELEMETRY_CLEANUP"

    # Sentinel / Policy & Alerts (Phase 4)
    POLICY_CREATED = "POLICY_CREATED"
    POLICY_ENABLED = "POLICY_ENABLED"
    POLICY_DISABLED = "POLICY_DISABLED"
    POLICY_UPDATED = "POLICY_UPDATED"
    POLICY_DELETED = "POLICY_DELETED"
    ALERT_CREATED = "ALERT_CREATED"
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_DISMISSED = "ALERT_DISMISSED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    ALERT_CLEANUP = "ALERT_CLEANUP"

    # Nexus / Secure Transport (Phase 6)
    TRANSPORT_SESSION_CREATED = "TRANSPORT_SESSION_CREATED"
    TRANSPORT_AUTHENTICATED = "TRANSPORT_AUTHENTICATED"
    TRANSPORT_CONNECTED = "TRANSPORT_CONNECTED"
    TRANSPORT_DISCONNECTED = "TRANSPORT_DISCONNECTED"
    TRANSPORT_RECONNECT = "TRANSPORT_RECONNECT"
    TRANSPORT_MESSAGE_ACCEPTED = "TRANSPORT_MESSAGE_ACCEPTED"
    TRANSPORT_MESSAGE_REJECTED = "TRANSPORT_MESSAGE_REJECTED"
    TRANSPORT_REPLAY_REJECTED = "TRANSPORT_REPLAY_REJECTED"
    TRANSPORT_AUTH_FAILED = "TRANSPORT_AUTH_FAILED"
    TRANSPORT_SESSION_EXPIRED = "TRANSPORT_SESSION_EXPIRED"
    TRANSPORT_REVOKED = "TRANSPORT_REVOKED"
    TRANSPORT_ERROR = "TRANSPORT_ERROR"

    # Vista / Screen Sessions (Phase 7)
    SCREEN_VIEW_REQUESTED = "SCREEN_VIEW_REQUESTED"
    SCREEN_VIEW_APPROVED = "SCREEN_VIEW_APPROVED"
    SCREEN_VIEW_DENIED = "SCREEN_VIEW_DENIED"
    SCREEN_SESSION_STARTED = "SCREEN_SESSION_STARTED"
    SCREEN_SESSION_STOPPED = "SCREEN_SESSION_STOPPED"
    SCREEN_SESSION_EXPIRED = "SCREEN_SESSION_EXPIRED"
    SCREEN_SESSION_REVOKED = "SCREEN_SESSION_REVOKED"
    SCREEN_FRAME_STREAM_STARTED = "SCREEN_FRAME_STREAM_STARTED"
    SCREEN_FRAME_STREAM_STOPPED = "SCREEN_FRAME_STREAM_STOPPED"


class AuditLogger:
    """Records privacy-compliant, tamper-evident audit records in the database."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        event_type: AuditEventType | str,
        details: dict[str, Any] | None = None,
        actor_id: str | None = None,
        success: bool = True,
    ) -> int:
        """Record an audit trail event.

        Args:
            event_type: The type of security event.
            details: Optional dictionary of event context (will be sanitized).
            actor_id: Optional identity ID that triggered the event.
            success: Whether the operation succeeded.

        Returns:
            The inserted audit record ID.
        """
        e_type = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
        sanitized_details = sanitize_audit_details(details or {})
        details_json = json.dumps(sanitized_details, sort_keys=True)
        now = datetime.datetime.now(datetime.UTC).isoformat()

        try:
            with self.db.connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO audit_events (event_type, details, timestamp, actor_id, success)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (e_type, details_json, now, actor_id, 1 if success else 0),
                )
                return cursor.lastrowid or 0
        except Exception as e:
            raise AuditError(f"Failed to record audit event '{e_type}': {e}") from e

    def get_recent(
        self,
        limit: int = 50,
        event_type: AuditEventType | str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve recent audit events in reverse chronological order."""
        try:
            if event_type:
                e_type = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
                rows = self.db.fetchall(
                    """
                    SELECT id, event_type, details, timestamp, actor_id, success
                    FROM audit_events
                    WHERE event_type = ?
                    ORDER BY id DESC
                    LIMIT ?;
                    """,
                    (e_type, limit),
                )
            else:
                rows = self.db.fetchall(
                    """
                    SELECT id, event_type, details, timestamp, actor_id, success
                    FROM audit_events
                    ORDER BY id DESC
                    LIMIT ?;
                    """,
                    (limit,),
                )

            results: list[dict[str, Any]] = []
            for row in rows:
                try:
                    details = json.loads(row["details"])
                except (json.JSONDecodeError, TypeError):
                    details = {}
                results.append(
                    {
                        "id": row["id"],
                        "event_type": row["event_type"],
                        "details": details,
                        "timestamp": row["timestamp"],
                        "actor_id": row["actor_id"],
                        "success": bool(row["success"]),
                    }
                )
            return results
        except Exception as e:
            raise AuditError(f"Failed to retrieve audit events: {e}") from e
