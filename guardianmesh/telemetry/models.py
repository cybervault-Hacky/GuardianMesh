"""Data models, privacy allowlists, and envelope structures for device health telemetry."""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.core.errors import TelemetryValidationError
from guardianmesh.security.crypto import public_key_from_pem, sign_data, verify_signature

# Strict Privacy Allowlist: ONLY these technical resource fields are permitted.
ALLOWED_HEALTH_FIELDS: frozenset[str] = frozenset(
    {
        "battery_percent",
        "charging",
        "storage_total_bytes",
        "storage_free_bytes",
        "uptime_seconds",
        "connectivity",
        "platform",
        "agent_version",
    }
)

# Explicitly Prohibited Surveillance Fields (reject immediately if present)
FORBIDDEN_FIELDS: frozenset[str] = frozenset(
    {
        "messages",
        "sms",
        "contacts",
        "photos",
        "files",
        "browser_history",
        "clipboard",
        "keyboard_input",
        "keystroke",
        "microphone",
        "camera",
        "location",
        "gps",
        "screen",
        "app_usage",
        "notifications",
        "passwords",
    }
)


class ConnectivityState(str, Enum):
    """Network interface connectivity state."""

    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> ConnectivityState:
        normalized = val.strip().upper()
        if normalized in cls.__members__:
            return cls(normalized)
        return cls.UNKNOWN


class DeviceHealthState(str, Enum):
    """Aggregate health and liveness state of a paired device."""

    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> DeviceHealthState:
        normalized = val.strip().upper()
        if normalized in cls.__members__:
            return cls(normalized)
        return cls.UNKNOWN


def validate_health_payload(payload: dict[str, Any]) -> None:
    """Ensure a telemetry payload contains strictly allowlisted technical health fields.

    Raises:
        TelemetryValidationError: If any unknown or forbidden fields are detected.
    """
    if not isinstance(payload, dict):
        raise TelemetryValidationError("Telemetry payload must be a dictionary.")

    payload_keys = set(payload.keys())

    # Check for explicitly forbidden fields
    detected_forbidden = payload_keys.intersection(FORBIDDEN_FIELDS)
    if detected_forbidden:
        raise TelemetryValidationError(
            f"Privacy violation: prohibited telemetry field(s) detected: {sorted(detected_forbidden)}"
        )

    # Check for unknown / non-allowlisted fields
    unknown_keys = payload_keys.difference(ALLOWED_HEALTH_FIELDS)
    if unknown_keys:
        raise TelemetryValidationError(
            f"Telemetry payload contains non-allowlisted field(s): {sorted(unknown_keys)}"
        )

    # Type & range validations for allowlisted fields
    if "battery_percent" in payload and payload["battery_percent"] is not None:
        bp = payload["battery_percent"]
        if not isinstance(bp, int) or bp < 0 or bp > 100:
            raise TelemetryValidationError(f"Invalid battery_percent value: {bp} (must be int 0-100).")

    if "storage_free_bytes" in payload and payload["storage_free_bytes"] is not None:
        if not isinstance(payload["storage_free_bytes"], int) or payload["storage_free_bytes"] < 0:
            raise TelemetryValidationError("storage_free_bytes must be a non-negative integer.")

    if "storage_total_bytes" in payload and payload["storage_total_bytes"] is not None:
        if not isinstance(payload["storage_total_bytes"], int) or payload["storage_total_bytes"] < 0:
            raise TelemetryValidationError("storage_total_bytes must be a non-negative integer.")

    if "uptime_seconds" in payload and payload["uptime_seconds"] is not None:
        if not isinstance(payload["uptime_seconds"], int) or payload["uptime_seconds"] < 0:
            raise TelemetryValidationError("uptime_seconds must be a non-negative integer.")


@dataclass
class HealthSnapshot:
    """Raw, allowlisted technical health metrics collected on a device."""

    device_id: str
    captured_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    battery_percent: int | None = None
    charging: bool | None = None
    storage_total_bytes: int | None = None
    storage_free_bytes: int | None = None
    uptime_seconds: int | None = None
    connectivity: ConnectivityState = ConnectivityState.ONLINE
    platform: str | None = None
    agent_version: str = "0.3.0"

    def to_payload_dict(self) -> dict[str, Any]:
        """Convert metrics to a strictly allowlisted payload dictionary."""
        if isinstance(self.connectivity, ConnectivityState):
            conn_val = self.connectivity.value
        else:
            conn_val = str(self.connectivity)

        d: dict[str, Any] = {
            "battery_percent": self.battery_percent,
            "charging": self.charging,
            "storage_total_bytes": self.storage_total_bytes,
            "storage_free_bytes": self.storage_free_bytes,
            "uptime_seconds": self.uptime_seconds,
            "connectivity": conn_val,
            "platform": self.platform,
            "agent_version": self.agent_version,
        }
        validate_health_payload(d)
        return d

    @classmethod
    def from_payload_dict(
        cls, device_id: str, payload: dict[str, Any], captured_at: str | None = None
    ) -> HealthSnapshot:
        """Construct a HealthSnapshot from validated payload dictionary."""
        validate_health_payload(payload)
        now = captured_at or datetime.datetime.now(datetime.UTC).isoformat()
        conn = ConnectivityState.from_str(str(payload.get("connectivity", "UNKNOWN")))
        return cls(
            device_id=device_id,
            captured_at=now,
            battery_percent=payload.get("battery_percent"),
            charging=payload.get("charging"),
            storage_total_bytes=payload.get("storage_total_bytes"),
            storage_free_bytes=payload.get("storage_free_bytes"),
            uptime_seconds=payload.get("uptime_seconds"),
            connectivity=conn,
            platform=payload.get("platform"),
            agent_version=str(payload.get("agent_version", "0.3.0")),
        )


@dataclass
class TelemetryEnvelope:
    """Authenticated, sequenced, and timestamped telemetry envelope."""

    device_id: str
    sequence: int
    payload: dict[str, Any]
    captured_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    protocol_version: str = "1.0"
    signature: str | None = None

    def __post_init__(self) -> None:
        """Validate payload allowlist upon envelope instantiation."""
        validate_health_payload(self.payload)
        if self.sequence < 1:
            raise TelemetryValidationError(f"Sequence number must be positive (got {self.sequence}).")

    def canonical_bytes(self) -> bytes:
        """Produce deterministic, canonical byte representation for Ed25519 signing."""
        canonical_struct = {
            "captured_at": self.captured_at,
            "device_id": self.device_id,
            "payload": self.payload,
            "protocol_version": self.protocol_version,
            "sequence": self.sequence,
        }
        # Strict deterministic JSON encoding
        json_str = json.dumps(canonical_struct, sort_keys=True, separators=(",", ":"))
        return json_str.encode("utf-8")

    def sign(self, private_key: Any) -> None:
        """Sign canonical envelope representation using local Ed25519 private key."""
        sig_bytes = sign_data(private_key, self.canonical_bytes())
        self.signature = sig_bytes.hex()

    def verify_signature(self, public_key_pem: str) -> bool:
        """Verify envelope cryptographic signature using remote device public key."""
        if not self.signature:
            return False
        try:
            pub_key = public_key_from_pem(public_key_pem.encode("utf-8"))
            sig_bytes = bytes.fromhex(self.signature)
            return verify_signature(pub_key, sig_bytes, self.canonical_bytes())
        except Exception:
            return False

    def to_dict(self) -> dict[str, Any]:
        """Serialize envelope to dictionary."""
        return {
            "protocol_version": self.protocol_version,
            "device_id": self.device_id,
            "sequence": self.sequence,
            "captured_at": self.captured_at,
            "payload": self.payload,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TelemetryEnvelope:
        """Deserialize envelope from dictionary with validation."""
        payload = data.get("payload", {})
        validate_health_payload(payload)

        return cls(
            protocol_version=data.get("protocol_version", "1.0"),
            device_id=data["device_id"],
            sequence=int(data["sequence"]),
            captured_at=data.get("captured_at", ""),
            payload=payload,
            signature=data.get("signature"),
        )


@dataclass
class DeviceHealthSummary:
    """Consolidated device health record for status inspection and reporting."""

    device_id: str = ""
    health_state: DeviceHealthState = DeviceHealthState.UNKNOWN
    last_heartbeat_at: str | None = None
    battery_percent: int | None = None
    is_charging: bool | None = None
    storage_free_bytes: int | None = None
    storage_total_bytes: int | None = None
    uptime_seconds: int | None = None
    connectivity: ConnectivityState = ConnectivityState.UNKNOWN
    platform: str | None = None
    agent_version: str = "0.3.0"
    last_sequence: int = 0
    is_paused: bool = False
    last_seen_seconds_ago: int | None = None

    # Backward compatibility alias
    identity_id: str | None = None
    battery_level_pct: int | None = None
    storage_free_mb: int | None = None
    app_version: str | None = None
    last_seen_utc: str | None = None

    def __post_init__(self) -> None:
        if not self.device_id and self.identity_id:
            self.device_id = self.identity_id
        if self.battery_percent is None and self.battery_level_pct is not None:
            self.battery_percent = self.battery_level_pct
        if self.storage_free_bytes is None and self.storage_free_mb is not None:
            self.storage_free_bytes = self.storage_free_mb * 1024 * 1024
        if self.last_heartbeat_at is None and self.last_seen_utc is not None:
            self.last_heartbeat_at = self.last_seen_utc

    @property
    def storage_free_gb(self) -> float | None:
        """Convert free bytes to formatted gigabytes."""
        if self.storage_free_bytes is None:
            return None
        return round(self.storage_free_bytes / (1024**3), 1)

    @property
    def uptime_display(self) -> str:
        """Format uptime into user-friendly hours and minutes."""
        if self.uptime_seconds is None:
            return "Unknown"
        hours, rem = divmod(self.uptime_seconds, 3600)
        mins, _ = divmod(rem, 60)
        return f"{hours}h {mins}m"
