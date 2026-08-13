"""Data models and state machine validation for GuardianMesh pairing sessions."""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.core.errors import InvalidStateTransitionError
from guardianmesh.identity.models import IdentityRole


class PairingState(str, Enum):
    """Lifecycle states for secure parent-child pairing sessions."""

    UNCONFIGURED = "UNCONFIGURED"
    INITIATED = "INITIATED"
    AWAITING_VERIFICATION = "AWAITING_VERIFICATION"
    CREATED = "CREATED"
    VERIFICATION_PENDING = "VERIFICATION_PENDING"
    VERIFIED = "VERIFIED"
    CHILD_AUTHORIZATION_PENDING = "CHILD_AUTHORIZATION_PENDING"
    AUTHORIZED = "AUTHORIZED"
    TRUST_ESTABLISHED = "TRUST_ESTABLISHED"
    PAIRED = "PAIRED"
    DENIED = "DENIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    REVOKED = "REVOKED"


# Allowed state transitions
VALID_TRANSITIONS: dict[PairingState, set[PairingState]] = {
    PairingState.CREATED: {
        PairingState.VERIFICATION_PENDING,
        PairingState.CANCELLED,
        PairingState.EXPIRED,
    },
    PairingState.VERIFICATION_PENDING: {
        PairingState.VERIFIED,
        PairingState.CANCELLED,
        PairingState.EXPIRED,
    },
    PairingState.VERIFIED: {
        PairingState.CHILD_AUTHORIZATION_PENDING,
        PairingState.CANCELLED,
        PairingState.EXPIRED,
    },
    PairingState.CHILD_AUTHORIZATION_PENDING: {
        PairingState.AUTHORIZED,
        PairingState.DENIED,
        PairingState.CANCELLED,
        PairingState.EXPIRED,
    },
    PairingState.AUTHORIZED: {
        PairingState.TRUST_ESTABLISHED,
        PairingState.CANCELLED,
        PairingState.EXPIRED,
    },
    PairingState.TRUST_ESTABLISHED: {
        PairingState.PAIRED,
        PairingState.REVOKED,
    },
    PairingState.PAIRED: {
        PairingState.REVOKED,
    },
    # Terminal states have no further outgoing transitions
    PairingState.DENIED: set(),
    PairingState.EXPIRED: set(),
    PairingState.CANCELLED: set(),
    PairingState.REVOKED: set(),
}


def validate_state_transition(current: PairingState, target: PairingState) -> None:
    """Validate that transition from current state to target state is permitted.

    Raises:
        InvalidStateTransitionError: If the transition is illegal.
    """
    if current == target:
        return

    allowed = VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Illegal pairing state transition from {current.value} to {target.value}."
        )


@dataclass
class PairingSession:
    """A persistent pairing session between a parent and child identity."""

    session_id: str
    parent_identity_id: str
    verification_method: str
    verification_destination: str
    state: PairingState = PairingState.CREATED
    child_identity_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    expires_at: str = ""
    verified_at: str | None = None
    authorized_at: str | None = None
    completed_at: str | None = None
    attempt_count: int = 0
    max_attempts: int = 5
    resend_count: int = 0
    last_resend_at: str | None = None
    otp_verifier: str | None = None
    otp_salt: str | None = None
    otp_expires_at: str | None = None
    auth_nonce: str | None = None
    auth_nonce_expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def transition_to(self, target_state: PairingState) -> None:
        """Safely transition this session to a new state after validation."""
        validate_state_transition(self.state, target_state)
        self.state = target_state

    def is_expired(self) -> bool:
        """Check if the overall session has expired."""
        if not self.expires_at:
            return False
        try:
            exp = datetime.datetime.fromisoformat(self.expires_at)
            now = datetime.datetime.now(datetime.UTC)
            return now >= exp
        except Exception:
            return True

    def is_otp_expired(self) -> bool:
        """Check if the issued OTP has expired."""
        if not self.otp_expires_at:
            return True
        try:
            exp = datetime.datetime.fromisoformat(self.otp_expires_at)
            now = datetime.datetime.now(datetime.UTC)
            return now >= exp
        except Exception:
            return True

    def is_auth_nonce_expired(self) -> bool:
        """Check if the authorization challenge nonce has expired."""
        if not self.auth_nonce_expires_at:
            return True
        try:
            exp = datetime.datetime.fromisoformat(self.auth_nonce_expires_at)
            now = datetime.datetime.now(datetime.UTC)
            return now >= exp
        except Exception:
            return True

    def can_resend(self, cooldown_seconds: int = 30) -> tuple[bool, int]:
        """Check if OTP resend is allowed based on cooldown."""
        if not self.last_resend_at:
            return True, 0

        try:
            last = datetime.datetime.fromisoformat(self.last_resend_at)
            now = datetime.datetime.now(datetime.UTC)
            elapsed = (now - last).total_seconds()
            if elapsed >= cooldown_seconds:
                return True, 0
            return False, int(cooldown_seconds - elapsed)
        except Exception:
            return True, 0

    def seconds_remaining(self) -> int:
        """Compute remaining seconds until session expiration."""
        if not self.expires_at:
            return 0
        try:
            exp = datetime.datetime.fromisoformat(self.expires_at)
            now = datetime.datetime.now(datetime.UTC)
            diff = int((exp - now).total_seconds())
            return max(0, diff)
        except Exception:
            return 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize session to dictionary."""
        return {
            "session_id": self.session_id,
            "parent_identity_id": self.parent_identity_id,
            "child_identity_id": self.child_identity_id,
            "verification_method": self.verification_method,
            "verification_destination": self.verification_destination,
            "state": self.state.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "verified_at": self.verified_at,
            "authorized_at": self.authorized_at,
            "completed_at": self.completed_at,
            "attempt_count": self.attempt_count,
            "max_attempts": self.max_attempts,
            "resend_count": self.resend_count,
            "last_resend_at": self.last_resend_at,
            "otp_verifier": self.otp_verifier,
            "otp_salt": self.otp_salt,
            "otp_expires_at": self.otp_expires_at,
            "auth_nonce": self.auth_nonce,
            "auth_nonce_expires_at": self.auth_nonce_expires_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PairingSession:
        """Deserialize session from dictionary."""
        raw_meta = data.get("metadata", {})
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except Exception:
                meta = {}
        else:
            meta = raw_meta or {}

        state_val = data.get("state", "CREATED")
        if state_val in PairingState.__members__.values():
            state = PairingState(state_val)
        else:
            state = PairingState.CREATED

        return cls(
            session_id=data["session_id"],
            parent_identity_id=data["parent_identity_id"],
            child_identity_id=data.get("child_identity_id"),
            verification_method=data.get("verification_method", "DEMO"),
            verification_destination=data.get("verification_destination", ""),
            state=state,
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
            verified_at=data.get("verified_at"),
            authorized_at=data.get("authorized_at"),
            completed_at=data.get("completed_at"),
            attempt_count=int(data.get("attempt_count", 0)),
            max_attempts=int(data.get("max_attempts", 5)),
            resend_count=int(data.get("resend_count", 0)),
            last_resend_at=data.get("last_resend_at"),
            otp_verifier=data.get("otp_verifier"),
            otp_salt=data.get("otp_salt"),
            otp_expires_at=data.get("otp_expires_at"),
            auth_nonce=data.get("auth_nonce"),
            auth_nonce_expires_at=data.get("auth_nonce_expires_at"),
            metadata=meta,
        )


@dataclass
class TrustedDevice:
    """A cryptographic trust relationship with a verified remote device."""

    local_identity_id: str
    remote_identity_id: str
    remote_role: IdentityRole
    remote_public_key_fingerprint: str
    remote_public_key_pem: str
    label: str | None = None
    status: str = "ACTIVE"
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    last_verified_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())
    trust_version: int = 1
    pairing_session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """Check if trust status is active."""
        return self.status == "ACTIVE"

    def to_dict(self) -> dict[str, Any]:
        """Serialize trusted device to dictionary."""
        if isinstance(self.remote_role, IdentityRole):
            role_val = self.remote_role.value
        else:
            role_val = str(self.remote_role)
        return {
            "local_identity_id": self.local_identity_id,
            "remote_identity_id": self.remote_identity_id,
            "remote_role": role_val,
            "remote_public_key_fingerprint": self.remote_public_key_fingerprint,
            "remote_public_key_pem": self.remote_public_key_pem,
            "label": self.label,
            "status": self.status,
            "created_at": self.created_at,
            "last_verified_at": self.last_verified_at,
            "trust_version": self.trust_version,
            "pairing_session_id": self.pairing_session_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustedDevice:
        """Deserialize trusted device from dictionary."""
        raw_meta = data.get("metadata", {})
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except Exception:
                meta = {}
        else:
            meta = raw_meta or {}

        role = (
            IdentityRole.from_str(data["remote_role"])
            if isinstance(data.get("remote_role"), str)
            else IdentityRole.CHILD
        )

        return cls(
            local_identity_id=data["local_identity_id"],
            remote_identity_id=data["remote_identity_id"],
            remote_role=role,
            remote_public_key_fingerprint=data["remote_public_key_fingerprint"],
            remote_public_key_pem=data["remote_public_key_pem"],
            label=data.get("label"),
            status=data.get("status", "ACTIVE"),
            created_at=data.get("created_at", ""),
            last_verified_at=data.get("last_verified_at", ""),
            trust_version=int(data.get("trust_version", 1)),
            pairing_session_id=data.get("pairing_session_id"),
            metadata=meta,
        )
