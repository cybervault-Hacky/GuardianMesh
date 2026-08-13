"""Orion Phase 9 action model.

An :class:`OrionAction` is a safe, allowlisted platform action.
Orion never accepts or executes arbitrary command payloads,
shell invocations, or remote input/control actions.

The :class:`OrionActionType` enum is the strict allowlist. Forbidden
names are rejected at construction time.

Every action carries:

* an explicit consent requirement,
* an explicit expiration,
* a deterministic id and correlation id,
* a status that flows through the persistent queue.
"""

from __future__ import annotations

import datetime
import enum
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from guardianmesh.identity.models import validate_identity_id
from guardianmesh.orion.errors import OrionActionError

SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Action type enum
# ---------------------------------------------------------------------------


class OrionActionType(str, enum.Enum):
    """Strict allowlist of safe Orion action types.

    The action allowlist is intentionally narrow. No shell
    execution, no remote input, no hidden capture, no microphone,
    no camera. Adding a forbidden name raises :class:`ValueError`
    at construction time.
    """

    # Health (Pulse / Phase 3)
    REFRESH_HEALTH = "REFRESH_HEALTH"
    REQUEST_HEALTH_SYNC = "REQUEST_HEALTH_SYNC"

    # Alerts (Sentinel / Phase 4)
    ACKNOWLEDGE_ALERT = "ACKNOWLEDGE_ALERT"
    RESOLVE_ALERT = "RESOLVE_ALERT"

    # Transport (Nexus / Phase 6)
    RECONNECT_TRANSPORT = "RECONNECT_TRANSPORT"
    REQUEST_STATUS_SYNC = "REQUEST_STATUS_SYNC"

    # Vista (Phase 7)
    REQUEST_SCREEN_SESSION = "REQUEST_SCREEN_SESSION"
    STOP_SCREEN_SESSION = "STOP_SCREEN_SESSION"

    # Aegis (Phase 8)
    REQUEST_AEGIS_CONSENT = "REQUEST_AEGIS_CONSENT"
    STOP_AEGIS_CAPTURE = "STOP_AEGIS_CAPTURE"

    # Reconciliation
    RECONCILE_STATE = "RECONCILE_STATE"

    # Capability
    REQUEST_CAPABILITIES = "REQUEST_CAPABILITIES"

    @classmethod
    def from_str(cls, val: str) -> OrionActionType:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionActionError(f"Unknown Orion action type: '{val}'") from e


# Forbidden action names. Construction with one of these names
# raises :class:`OrionActionError`.
FORBIDDEN_ACTION_NAMES = frozenset(
    {
        "EXECUTE",
        "EXEC",
        "RUN",
        "RUN_COMMAND",
        "SHELL",
        "SHELL_COMMAND",
        "OPEN_TERMINAL",
        "OPEN_REMOTE_TERMINAL",
        "REMOTE_INPUT",
        "REMOTE_TAP",
        "REMOTE_CLICK",
        "REMOTE_SWIPE",
        "REMOTE_GESTURE",
        "REMOTE_KEY",
        "REMOTE_KEY_PRESS",
        "TYPE_TEXT",
        "INPUT_TEXT",
        "INJECT_TEXT",
        "ACCESSIBILITY_ACTION",
        "READ_CLIPBOARD",
        "WRITE_CLIPBOARD",
        "ENABLE_MICROPHONE",
        "ENABLE_CAMERA",
        "ENABLE_LOCATION",
        "ENABLE_NOTIFICATIONS",
        "READ_NOTIFICATIONS",
        "READ_SMS",
        "READ_CONTACTS",
        "READ_FILES",
        "READ_BROWSER_HISTORY",
        "ENABLE_KEYLOG",
        "READ_KEYLOG",
        "HIDDEN_CAPTURE",
        "HIDDEN_SCREENSHOT",
    }
)


def assert_safe_action_type_name(name: str) -> None:
    """Raise :class:`OrionActionError` if ``name`` is forbidden."""
    if name.strip().upper() in FORBIDDEN_ACTION_NAMES:
        raise OrionActionError(
            f"Orion action type '{name}' is forbidden: surveillance or remote-control "
            f"actions are not part of the Orion safety model."
        )


# Forbidden parameter keys. Action parameters carry only metadata.
FORBIDDEN_ACTION_PARAM_KEYS = frozenset(
    {
        "command",
        "shell",
        "exec",
        "execute",
        "code",
        "script",
        "payload",  # screen frame bytes
        "frame",
        "screenshot",
        "keylog",
        "keystrokes",
        "messages",
        "clipboard",
        "microphone",
        "audio",
        "camera",
        "video",
        "location",
        "gps",
        "browser_history",
        "contacts",
        "password",
        "private_key",
        "secret",
        "token",
    }
)


def assert_safe_action_params(params: dict[str, Any]) -> None:
    """Raise :class:`OrionActionError` if ``params`` contains a forbidden key."""
    for key in params.keys():
        if str(key).lower() in FORBIDDEN_ACTION_PARAM_KEYS:
            raise OrionActionError(
                f"Orion action parameter key '{key}' is forbidden."
            )


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class OrionActionStatus(str, enum.Enum):
    """Lifecycle status of an :class:`OrionAction`."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

    @classmethod
    def from_str(cls, val: str) -> OrionActionStatus:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionActionError(f"Unknown action status: '{val}'") from e


# ---------------------------------------------------------------------------
# Consent requirements
# ---------------------------------------------------------------------------


class OrionConsentRequirement(str, enum.Enum):
    """Declares the consent requirements for an action.

    Orion never invents consent. It delegates to the existing
    subsystems (TrustManager, Vista authorization, Aegis
    SystemConsentGate) and only declares what the action needs.
    """

    NONE = "NONE"
    TRUST_REQUIRED = "TRUST_REQUIRED"
    VISTA_AUTHORIZATION_REQUIRED = "VISTA_AUTHORIZATION_REQUIRED"
    AEGIS_SYSTEM_CONSENT_REQUIRED = "AEGIS_SYSTEM_CONSENT_REQUIRED"
    CHILD_AUTHORIZATION_REQUIRED = "CHILD_AUTHORIZATION_REQUIRED"
    EXISTING_ACTIVE_SESSION = "EXISTING_ACTIVE_SESSION"

    @classmethod
    def from_str(cls, val: str) -> OrionConsentRequirement:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise OrionActionError(f"Unknown consent requirement: '{val}'") from e


# Documented per-action consent requirements. The executor consults
# this map to validate consent before running an action. The map is
# authoritative and cannot be extended at runtime.
ACTION_CONSENT_REQUIREMENTS: dict[OrionActionType, frozenset[OrionConsentRequirement]] = {
    OrionActionType.REFRESH_HEALTH: frozenset(
        {OrionConsentRequirement.TRUST_REQUIRED}
    ),
    OrionActionType.REQUEST_HEALTH_SYNC: frozenset(
        {OrionConsentRequirement.TRUST_REQUIRED}
    ),
    OrionActionType.ACKNOWLEDGE_ALERT: frozenset(),
    OrionActionType.RESOLVE_ALERT: frozenset(),
    OrionActionType.RECONNECT_TRANSPORT: frozenset(),
    OrionActionType.REQUEST_STATUS_SYNC: frozenset(
        {OrionConsentRequirement.TRUST_REQUIRED}
    ),
    OrionActionType.REQUEST_SCREEN_SESSION: frozenset(
        {
            OrionConsentRequirement.TRUST_REQUIRED,
            OrionConsentRequirement.VISTA_AUTHORIZATION_REQUIRED,
            OrionConsentRequirement.AEGIS_SYSTEM_CONSENT_REQUIRED,
            OrionConsentRequirement.CHILD_AUTHORIZATION_REQUIRED,
        }
    ),
    OrionActionType.STOP_SCREEN_SESSION: frozenset(
        {
            OrionConsentRequirement.TRUST_REQUIRED,
            OrionConsentRequirement.EXISTING_ACTIVE_SESSION,
        }
    ),
    OrionActionType.REQUEST_AEGIS_CONSENT: frozenset(
        {
            OrionConsentRequirement.TRUST_REQUIRED,
            OrionConsentRequirement.VISTA_AUTHORIZATION_REQUIRED,
            OrionConsentRequirement.AEGIS_SYSTEM_CONSENT_REQUIRED,
            OrionConsentRequirement.CHILD_AUTHORIZATION_REQUIRED,
        }
    ),
    OrionActionType.STOP_AEGIS_CAPTURE: frozenset(
        {
            OrionConsentRequirement.TRUST_REQUIRED,
            OrionConsentRequirement.EXISTING_ACTIVE_SESSION,
        }
    ),
    OrionActionType.RECONCILE_STATE: frozenset(
        {OrionConsentRequirement.TRUST_REQUIRED}
    ),
    OrionActionType.REQUEST_CAPABILITIES: frozenset(),
}


def required_consents(
    action_type: OrionActionType | str,
) -> frozenset[OrionConsentRequirement]:
    """Return the consent requirements for an action type."""
    if isinstance(action_type, str):
        action_type = OrionActionType.from_str(action_type)
    return ACTION_CONSENT_REQUIREMENTS[action_type]


# ---------------------------------------------------------------------------
# Action
# ---------------------------------------------------------------------------


def generate_action_id() -> str:
    """Generate a unique action identifier (e.g. ``OAC-...``)."""
    return f"OAC-{secrets.token_hex(6).upper()}"


@dataclass
class OrionAction:
    """A safe, allowlisted platform action queued for execution.

    Orion never invents new action types. The action's parameters
    carry only metadata — never commands, never frame bytes, never
    private user content.
    """

    action_id: str
    action_type: OrionActionType
    device_id: str
    created_at: str
    expires_at: str
    correlation_id: str
    requested_by: str
    status: OrionActionStatus
    schema_version: str = SCHEMA_VERSION
    parameters: dict[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None
    retry_count: int = 0
    max_retries: int = 3
    next_attempt_at: str | None = None
    last_error: str | None = None
    updated_at: str | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.action_id:
            raise OrionActionError("action_id is required.")
        if not isinstance(self.action_type, OrionActionType):
            raise OrionActionError("action_type must be an OrionActionType.")
        if not self.device_id:
            raise OrionActionError("device_id is required.")
        if self.device_id not in {"SYSTEM", "BUS", "ORION"}:
            ok, err = validate_identity_id(self.device_id)
            if not ok:
                raise OrionActionError(f"Invalid device_id: {err}")
        if not self.created_at or not self.expires_at:
            raise OrionActionError("created_at and expires_at are required.")
        if not self.correlation_id:
            raise OrionActionError("correlation_id is required.")
        if not self.requested_by:
            raise OrionActionError("requested_by is required.")
        if not isinstance(self.status, OrionActionStatus):
            raise OrionActionError("status must be an OrionActionStatus.")
        if self.schema_version != SCHEMA_VERSION:
            raise OrionActionError(
                f"Unsupported schema version '{self.schema_version}' "
                f"(expected '{SCHEMA_VERSION}')."
            )
        if not isinstance(self.parameters, dict):
            raise OrionActionError("parameters must be a dict.")
        assert_safe_action_params(self.parameters)
        if not isinstance(self.result, dict):
            raise OrionActionError("result must be a dict.")
        if self.retry_count < 0:
            raise OrionActionError("retry_count must be non-negative.")
        if self.max_retries < 0:
            raise OrionActionError("max_retries must be non-negative.")
        if self.retry_count > self.max_retries:
            raise OrionActionError(
                f"retry_count {self.retry_count} exceeds max_retries {self.max_retries}."
            )
        try:
            datetime.datetime.fromisoformat(self.created_at)
            datetime.datetime.fromisoformat(self.expires_at)
        except ValueError as e:
            raise OrionActionError(f"Invalid timestamp: {e}") from e
        if self.next_attempt_at is not None:
            try:
                datetime.datetime.fromisoformat(self.next_attempt_at)
            except ValueError as e:
                raise OrionActionError(f"Invalid next_attempt_at: {e}") from e

    def is_expired(self, now: datetime.datetime | None = None) -> bool:
        """Return True if the action has passed its expiration."""
        try:
            exp = datetime.datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True
        return (now or datetime.datetime.now(datetime.UTC)) > exp

    def can_retry(self) -> bool:
        """Return True if the action can be retried."""
        return self.retry_count < self.max_retries

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "device_id": self.device_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "correlation_id": self.correlation_id,
            "requested_by": self.requested_by,
            "status": self.status.value,
            "schema_version": self.schema_version,
            "parameters": self.parameters,
            "idempotency_key": self.idempotency_key,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "next_attempt_at": self.next_attempt_at,
            "last_error": self.last_error,
            "updated_at": self.updated_at,
            "result": self.result,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrionAction:
        if not isinstance(data, dict):
            raise OrionActionError("Action data must be a dict.")
        return cls(
            action_id=str(data.get("action_id", "")),
            action_type=OrionActionType.from_str(str(data.get("action_type", ""))),
            device_id=str(data.get("device_id", "")),
            created_at=str(data.get("created_at", "")),
            expires_at=str(data.get("expires_at", "")),
            correlation_id=str(data.get("correlation_id", "")),
            requested_by=str(data.get("requested_by", "")),
            status=OrionActionStatus.from_str(
                str(data.get("status", OrionActionStatus.PENDING.value))
            ),
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
            parameters=(
                data.get("parameters", {})
                if isinstance(data.get("parameters"), dict)
                else {}
            ),
            idempotency_key=data.get("idempotency_key"),
            retry_count=int(data.get("retry_count", 0)),
            max_retries=int(data.get("max_retries", 3)),
            next_attempt_at=data.get("next_attempt_at"),
            last_error=data.get("last_error"),
            updated_at=data.get("updated_at"),
            result=data.get("result", {}) if isinstance(data.get("result"), dict) else {},
        )


__all__ = [
    "ACTION_CONSENT_REQUIREMENTS",
    "FORBIDDEN_ACTION_NAMES",
    "FORBIDDEN_ACTION_PARAM_KEYS",
    "SCHEMA_VERSION",
    "OrionAction",
    "OrionActionStatus",
    "OrionActionType",
    "OrionConsentRequirement",
    "assert_safe_action_params",
    "assert_safe_action_type_name",
    "generate_action_id",
    "required_consents",
]
