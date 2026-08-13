"""Data models, canonical message envelopes, and protocol types for Nexus transport."""

from __future__ import annotations

import datetime
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.core.errors import (
    TransportMessageError,
    TransportOversizedMessageError,
    TransportPayloadError,
)
from guardianmesh.identity.models import validate_identity_id

PROTOCOL_VERSION = "1.0"


class MessageType(str, Enum):
    """Strict allowlist of authorized protocol message types."""

    HELLO = "HELLO"
    SESSION_INIT = "SESSION_INIT"
    SESSION_ACK = "SESSION_ACK"
    HEARTBEAT = "HEARTBEAT"
    TELEMETRY = "TELEMETRY"
    ALERT = "ALERT"
    POLICY_SYNC = "POLICY_SYNC"
    DEVICE_STATUS = "DEVICE_STATUS"
    PING = "PING"
    PONG = "PONG"
    REKEY = "REKEY"
    GOODBYE = "GOODBYE"
    ERROR = "ERROR"

    @classmethod
    def from_str(cls, val: str) -> MessageType:
        """Parse string to MessageType with case-insensitivity."""
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise TransportMessageError(f"Unsupported or unauthorized message type: '{val}'") from e


class ConnectionState(str, Enum):
    """Transport channel connection states."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    AUTHENTICATING = "AUTHENTICATING"
    CONNECTED = "CONNECTED"
    DEGRADED = "DEGRADED"
    RECONNECTING = "RECONNECTING"
    REVOKED = "REVOKED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"

    @classmethod
    def from_str(cls, val: str) -> ConnectionState:
        """Parse string to ConnectionState."""
        try:
            return cls(val.strip().upper())
        except ValueError:
            return cls.DISCONNECTED


class TransportType(str, Enum):
    """Underlying transport communication medium."""

    LOCAL = "LOCAL"
    NETWORK = "NETWORK"
    MEMORY = "MEMORY"
    RELAY = "RELAY"

    @classmethod
    def from_str(cls, val: str) -> TransportType:
        """Parse string to TransportType."""
        try:
            return cls(val.strip().upper())
        except ValueError:
            return cls.LOCAL


def generate_message_id() -> str:
    """Generate a unique message ID (e.g. MSG-8A7B6C5D4E3F)."""
    return f"MSG-{secrets.token_hex(6).upper()}"


def generate_session_id() -> str:
    """Generate a unique session ID (e.g. SES-9F8E7D6C5B4A)."""
    return f"SES-{secrets.token_hex(6).upper()}"


@dataclass
class TransportEnvelope:
    """Versioned canonical message envelope for end-to-end transport."""

    protocol_version: str = PROTOCOL_VERSION
    message_id: str = field(default_factory=generate_message_id)
    session_id: str = ""
    sender_id: str = ""
    recipient_id: str = ""
    message_type: MessageType = MessageType.HEARTBEAT
    sequence: int = 1
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    expires_at: str = field(
        default_factory=lambda: (
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)
        ).isoformat()
    )
    payload: dict[str, Any] = field(default_factory=dict)
    authentication: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize envelope to dictionary."""
        return {
            "protocol_version": self.protocol_version,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "message_type": self.message_type.value,
            "sequence": self.sequence,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "payload": self.payload,
            "authentication": self.authentication,
        }

    def header_dict(self) -> dict[str, Any]:
        """Header metadata used for associated data in AEAD encryption."""
        return {
            "protocol_version": self.protocol_version,
            "message_id": self.message_id,
            "session_id": self.session_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "message_type": self.message_type.value,
            "sequence": self.sequence,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def to_canonical_json(self) -> str:
        """Deterministic canonical JSON serialization (sorted keys, compact separators)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def to_canonical_bytes(self) -> bytes:
        """Deterministic canonical bytes representation."""
        return self.to_canonical_json().encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransportEnvelope:
        """Deserialize from dictionary."""
        if not isinstance(data, dict):
            raise TransportMessageError("Envelope data must be a JSON object dictionary.")

        required_fields = [
            "protocol_version",
            "message_id",
            "sender_id",
            "recipient_id",
            "message_type",
            "sequence",
            "created_at",
            "expires_at",
        ]
        missing = [f for f in required_fields if f not in data]
        if missing:
            raise TransportMessageError(f"Missing required envelope field(s): {missing}")

        raw_type = data["message_type"]
        m_type = MessageType.from_str(raw_type) if isinstance(raw_type, str) else raw_type

        return cls(
            protocol_version=str(data["protocol_version"]),
            message_id=str(data["message_id"]),
            session_id=str(data.get("session_id", "")),
            sender_id=str(data["sender_id"]),
            recipient_id=str(data["recipient_id"]),
            message_type=m_type,
            sequence=int(data["sequence"]),
            created_at=str(data["created_at"]),
            expires_at=str(data["expires_at"]),
            payload=data.get("payload", {}) if isinstance(data.get("payload"), dict) else {},
            authentication=data.get("authentication", {})
            if isinstance(data.get("authentication"), dict)
            else {},
        )

    @classmethod
    def from_json(cls, json_str: str) -> TransportEnvelope:
        """Deserialize from JSON string."""
        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise TransportMessageError(f"Malformed JSON envelope: {e}") from e
        return cls.from_dict(data)

    def validate(
        self,
        max_size_bytes: int = 65536,
        allowed_types: set[MessageType | str] | None = None,
    ) -> None:
        """Validate envelope constraints, formats, size, and allowlists."""
        if self.protocol_version != PROTOCOL_VERSION:
            raise TransportMessageError(
                f"Unsupported protocol version '{self.protocol_version}' (expected '{PROTOCOL_VERSION}')."
            )

        if not self.message_id or len(self.message_id) > 64:
            raise TransportMessageError(f"Invalid message ID: '{self.message_id}'.")

        # Sender ID format validation
        valid_sender, s_err = validate_identity_id(self.sender_id)
        if not valid_sender:
            raise TransportMessageError(f"Invalid sender_id: {s_err}")

        # Recipient ID format validation
        valid_recip, r_err = validate_identity_id(self.recipient_id)
        if not valid_recip:
            raise TransportMessageError(f"Invalid recipient_id: {r_err}")

        # Message type check
        if allowed_types:
            norm_allowed = {
                t.value if isinstance(t, MessageType) else str(t).upper() for t in allowed_types
            }
            if self.message_type.value not in norm_allowed:
                raise TransportMessageError(
                    f"Message type '{self.message_type.value}' is not allowed in this context."
                )

        if self.sequence < 0:
            raise TransportMessageError("Envelope sequence number cannot be negative.")

        # Timestamps validation
        try:
            c_dt = datetime.datetime.fromisoformat(self.created_at)
            e_dt = datetime.datetime.fromisoformat(self.expires_at)
            if e_dt < c_dt:
                raise TransportMessageError("expires_at cannot precede created_at.")
        except ValueError as e:
            raise TransportMessageError(f"Invalid ISO timestamp format: {e}") from e

        # Maximum payload size enforcement
        canonical_bytes = self.to_canonical_bytes()
        if len(canonical_bytes) > max_size_bytes:
            raise TransportOversizedMessageError(
                f"Envelope size ({len(canonical_bytes)} bytes) exceeds limit ({max_size_bytes} bytes)."
            )

        # Safety & privacy checks: reject arbitrary executable or forbidden structures
        self._validate_payload_safety(self.payload)

    @staticmethod
    def _validate_payload_safety(payload: dict[str, Any]) -> None:
        """Ensure payload does not contain executable code or prohibited surveillance data."""
        if not isinstance(payload, dict):
            raise TransportPayloadError("Payload must be a dictionary.")

        # Forbidden keys that must never be transmitted over transport
        forbidden = {
            "messages",
            "sms",
            "sms_messages",
            "contacts",
            "contacts_list",
            "photos",
            "files",
            "browser_history",
            "keyboard_input",
            "keystrokes",
            "clipboard",
            "clipboard_data",
            "microphone",
            "mic_stream",
            "camera",
            "camera_stream",
            "location",
            "location_history",
            "gps",
            "screen",
            "screen_stream",
            "app_usage",
            "notifications",
            "passwords",
            "command",
            "shell",
            "exec",
            "eval",
        }
        for k in payload:
            if str(k).lower() in forbidden:
                raise TransportPayloadError(
                    f"Forbidden surveillance or executable field '{k}' rejected."
                )


@dataclass
class EncryptedTransportFrame:
    """Wire format for an authenticated AES-GCM encrypted message frame."""

    protocol_version: str = PROTOCOL_VERSION
    session_id: str = ""
    sequence: int = 1
    sender_id: str = ""
    recipient_id: str = ""
    message_type: str = "ENCRYPTED"
    nonce_hex: str = ""
    ciphertext_hex: str = ""
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    expires_at: str = field(
        default_factory=lambda: (
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)
        ).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize frame to dictionary."""
        return {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "sequence": self.sequence,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "message_type": self.message_type,
            "nonce_hex": self.nonce_hex,
            "ciphertext_hex": self.ciphertext_hex,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    def to_canonical_json(self) -> str:
        """Deterministic canonical JSON serialization."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def to_canonical_bytes(self) -> bytes:
        """Deterministic canonical bytes representation."""
        return self.to_canonical_json().encode("utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedTransportFrame:
        """Deserialize frame from dictionary."""
        if not isinstance(data, dict):
            raise TransportMessageError("Encrypted frame must be a dictionary.")

        required = [
            "protocol_version",
            "session_id",
            "sequence",
            "sender_id",
            "recipient_id",
            "nonce_hex",
            "ciphertext_hex",
        ]
        missing = [f for f in required if f not in data]
        if missing:
            raise TransportMessageError(f"Missing encrypted frame field(s): {missing}")

        return cls(
            protocol_version=str(data["protocol_version"]),
            session_id=str(data["session_id"]),
            sequence=int(data["sequence"]),
            sender_id=str(data["sender_id"]),
            recipient_id=str(data["recipient_id"]),
            message_type=str(data.get("message_type", "ENCRYPTED")),
            nonce_hex=str(data["nonce_hex"]),
            ciphertext_hex=str(data["ciphertext_hex"]),
            created_at=str(data.get("created_at", "")),
            expires_at=str(data.get("expires_at", "")),
        )

    @classmethod
    def from_json(cls, json_str: str) -> EncryptedTransportFrame:
        """Deserialize from JSON string."""
        try:
            data = json.loads(json_str)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise TransportMessageError(f"Malformed JSON frame: {e}") from e
        return cls.from_dict(data)


@dataclass
class PeerInfo:
    """Registered peer connection and activity status."""

    device_id: str
    role: str
    connection_state: ConnectionState = ConnectionState.DISCONNECTED
    active_session_id: str | None = None
    last_seen_at: str | None = None
    last_sync_at: str | None = None
    last_heartbeat_at: str | None = None
    reconnect_count: int = 0
    endpoint: str | None = None
    transport_type: TransportType = TransportType.LOCAL
    metadata: dict[str, Any] = field(default_factory=dict)
    updated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Serialize peer info to dictionary."""
        return {
            "device_id": self.device_id,
            "role": self.role,
            "connection_state": self.connection_state.value,
            "active_session_id": self.active_session_id,
            "last_seen_at": self.last_seen_at,
            "last_sync_at": self.last_sync_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "reconnect_count": self.reconnect_count,
            "endpoint": self.endpoint,
            "transport_type": self.transport_type.value,
            "metadata": self.metadata,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PeerInfo:
        """Deserialize peer info from dictionary."""
        return cls(
            device_id=str(data["device_id"]),
            role=str(data.get("role", "CHILD")),
            connection_state=ConnectionState.from_str(data.get("connection_state", "DISCONNECTED")),
            active_session_id=data.get("active_session_id"),
            last_seen_at=data.get("last_seen_at"),
            last_sync_at=data.get("last_sync_at"),
            last_heartbeat_at=data.get("last_heartbeat_at"),
            reconnect_count=int(data.get("reconnect_count", 0)),
            endpoint=data.get("endpoint"),
            transport_type=TransportType.from_str(data.get("transport_type", "LOCAL")),
            metadata=data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {},
            updated_at=str(data.get("updated_at", "")),
        )


@dataclass
class SessionInfo:
    """Metadata representation of an encrypted transport session."""

    session_id: str
    local_identity_id: str
    remote_identity_id: str
    state: ConnectionState
    transport_type: TransportType
    created_at: str
    established_at: str | None = None
    expires_at: str = ""
    closed_at: str | None = None
    last_heartbeat_at: str | None = None
    reconnect_count: int = 0
    last_error: str | None = None
    inbound_sequence: int = 0
    outbound_sequence: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if session lifetime has expired."""
        if not self.expires_at:
            return False
        try:
            exp_dt = datetime.datetime.fromisoformat(self.expires_at)
            return datetime.datetime.now(datetime.UTC) > exp_dt
        except Exception:
            return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize session info to dictionary."""
        return {
            "session_id": self.session_id,
            "local_identity_id": self.local_identity_id,
            "remote_identity_id": self.remote_identity_id,
            "state": self.state.value,
            "transport_type": self.transport_type.value,
            "created_at": self.created_at,
            "established_at": self.established_at,
            "expires_at": self.expires_at,
            "closed_at": self.closed_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "reconnect_count": self.reconnect_count,
            "last_error": self.last_error,
            "inbound_sequence": self.inbound_sequence,
            "outbound_sequence": self.outbound_sequence,
            "is_expired": self.is_expired,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionInfo:
        """Deserialize session info from dictionary."""
        return cls(
            session_id=str(data["session_id"]),
            local_identity_id=str(data["local_identity_id"]),
            remote_identity_id=str(data["remote_identity_id"]),
            state=ConnectionState.from_str(data.get("state", "DISCONNECTED")),
            transport_type=TransportType.from_str(data.get("transport_type", "LOCAL")),
            created_at=str(data["created_at"]),
            established_at=data.get("established_at"),
            expires_at=str(data.get("expires_at", "")),
            closed_at=data.get("closed_at"),
            last_heartbeat_at=data.get("last_heartbeat_at"),
            reconnect_count=int(data.get("reconnect_count", 0)),
            last_error=data.get("last_error"),
            inbound_sequence=int(data.get("inbound_sequence", 0)),
            outbound_sequence=int(data.get("outbound_sequence", 0)),
            metadata=data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {},
        )
