"""Child-side screen view authorization state machine.

The authorization subsystem enforces the Phase 7 invariant:

    Trust != screen-view permission.

Even when two devices are mutually trusted (Phase 2), a parent must request
explicit child consent before any screen frames can flow. The authorization
lives for a bounded duration only and is single-use.

States
------
    REQUESTED → PENDING_CHILD_APPROVAL → APPROVED → ACTIVE
                                       → DENIED
                                       → EXPIRED
                                       → REVOKED

The transition graph is enforced by :func:`assert_legal_transition` from
:mod:`guardianmesh.screen.models`.
"""

from __future__ import annotations

import datetime
import secrets
import threading
from dataclasses import dataclass
from typing import Any

from guardianmesh.core.errors import ValidationError
from guardianmesh.screen.errors import (
    ScreenAuthorizationDeniedError,
    ScreenAuthorizationError,
    ScreenAuthorizationExpiredError,
    ScreenAuthorizationNotFoundError,
)
from guardianmesh.screen.models import (
    AuthorizationDecision,
    ScreenAuthorization,
    ScreenSessionState,
    generate_authorization_id,
)

# Default and hard cap bounds for authorization durations.
DEFAULT_MAX_DURATION_SECONDS = 300  # 5 minutes
MIN_MAX_DURATION_SECONDS = 30
MAX_MAX_DURATION_SECONDS = 3600    # 1 hour absolute cap
AUTH_NONCE_BYTES = 16


@dataclass
class ScreenAuthorizationRequest:
    """Immutable description of a parent's view request."""

    session_id: str
    device_id: str   # child identity ID
    parent_id: str   # parent identity ID
    requested_at: str
    max_duration_seconds: int = DEFAULT_MAX_DURATION_SECONDS
    label: str | None = None
    nonce: str = ""

    def __post_init__(self) -> None:
        if not self.nonce:
            self.nonce = secrets.token_hex(AUTH_NONCE_BYTES)
        if self.max_duration_seconds < MIN_MAX_DURATION_SECONDS:
            raise ValidationError(
                f"max_duration_seconds must be at least {MIN_MAX_DURATION_SECONDS}."
            )
        if self.max_duration_seconds > MAX_MAX_DURATION_SECONDS:
            raise ValidationError(
                f"max_duration_seconds cannot exceed {MAX_MAX_DURATION_SECONDS}."
            )


class ScreenAuthorizationManager:
    """Thread-safe in-memory state machine for child-side screen authorization.

    The manager is the single source of truth for whether a child has
    approved a screen view request. It never persists the rendered
    authorization nonce, secret, or frame content — only the decision
    metadata.
    """

    def __init__(
        self,
        clock: Any | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._authorizations: dict[str, ScreenAuthorization] = {}
        self._by_session: dict[str, str] = {}
        # Optional injected clock for deterministic testing. When None, the
        # manager uses ``datetime.datetime.now(datetime.UTC)``.
        self._clock = clock

    # ------------------------------------------------------------------
    # Factory + lifecycle
    # ------------------------------------------------------------------

    def create_request(
        self,
        session_id: str,
        device_id: str,
        parent_id: str,
        max_duration_seconds: int = DEFAULT_MAX_DURATION_SECONDS,
        label: str | None = None,
    ) -> ScreenAuthorization:
        """Create a new pending authorization for the given session.

        Args:
            session_id: ID of the screen session requesting authorization.
            device_id: Child identity ID.
            parent_id: Parent identity ID.
            max_duration_seconds: Bounded max duration (default 300s / 5min).
            label: Optional human-readable description shown to the child.

        Returns:
            The newly created :class:`ScreenAuthorization` in PENDING state.

        Raises:
            ScreenAuthorizationError: If the parameters are invalid.
        """
        with self._lock:
            if not session_id:
                raise ScreenAuthorizationError("session_id is required.")
            if session_id in self._by_session:
                raise ScreenAuthorizationError(
                    f"An authorization already exists for session '{session_id}'."
                )

            req = ScreenAuthorizationRequest(
                session_id=session_id,
                device_id=device_id,
                parent_id=parent_id,
                max_duration_seconds=max_duration_seconds,
                label=label,
                requested_at=self._now_iso(),
            )

            now_dt = self._now()
            expires = now_dt + datetime.timedelta(seconds=max_duration_seconds)
            auth = ScreenAuthorization(
                authorization_id=generate_authorization_id(),
                session_id=session_id,
                device_id=device_id,
                parent_id=parent_id,
                decision=AuthorizationDecision.PENDING,
                requested_at=req.requested_at,
                expires_at=expires.isoformat(),
                max_duration_seconds=max_duration_seconds,
                label=label,
                metadata={"nonce": req.nonce},
            )
            auth.validate()
            self._authorizations[auth.authorization_id] = auth
            self._by_session[session_id] = auth.authorization_id
            return auth

    def get_for_session(self, session_id: str) -> ScreenAuthorization | None:
        """Return the authorization attached to a session, if any."""
        with self._lock:
            auth_id = self._by_session.get(session_id)
            if auth_id is None:
                return None
            return self._authorizations.get(auth_id)

    def get_by_authorization_id(
        self, authorization_id: str
    ) -> ScreenAuthorization | None:
        """Return an authorization by its primary key."""
        with self._lock:
            return self._authorizations.get(authorization_id)

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def approve(
        self,
        authorization_id: str,
        approved_at: str | None = None,
    ) -> ScreenAuthorization:
        """Mark an authorization as APPROVED.

        Raises:
            ScreenAuthorizationNotFoundError: If the authorization does not exist.
            ScreenAuthorizationError: If the transition is illegal.
        """
        with self._lock:
            auth = self._require(authorization_id)
            self._assert_state_for_decision(
                auth, allowed=(AuthorizationDecision.PENDING,)
            )
            auth.decision = AuthorizationDecision.APPROVED
            auth.approved_at = approved_at or self._now_iso()
            return auth

    def deny(
        self,
        authorization_id: str,
        denied_at: str | None = None,
    ) -> ScreenAuthorization:
        """Mark an authorization as DENIED."""
        with self._lock:
            auth = self._require(authorization_id)
            self._assert_state_for_decision(
                auth, allowed=(AuthorizationDecision.PENDING,)
            )
            auth.decision = AuthorizationDecision.DENIED
            auth.denied_at = denied_at or self._now_iso()
            return auth

    def revoke(
        self,
        authorization_id: str,
        reason: str = "REVOKED",
    ) -> ScreenAuthorization:
        """Mark an authorization as REVOKED (e.g. trust revoked)."""
        with self._lock:
            auth = self._require(authorization_id)
            if auth.decision in (
                AuthorizationDecision.DENIED,
                AuthorizationDecision.EXPIRED,
            ):
                return auth
            auth.decision = AuthorizationDecision.REVOKED
            auth.metadata["revoke_reason"] = reason
            return auth

    def expire_due(self) -> list[str]:
        """Expire any authorizations whose lifetime has elapsed.

        Returns:
            List of authorization IDs that were expired.
        """
        expired: list[str] = []
        with self._lock:
            for auth_id, auth in list(self._authorizations.items()):
                if auth.is_expired(self._now()) and auth.decision in (
                    AuthorizationDecision.PENDING,
                    AuthorizationDecision.APPROVED,
                ):
                    auth.decision = AuthorizationDecision.EXPIRED
                    expired.append(auth_id)
        return expired

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def list_pending(self) -> list[ScreenAuthorization]:
        """Return all currently PENDING authorizations."""
        with self._lock:
            return [
                a
                for a in self._authorizations.values()
                if a.decision == AuthorizationDecision.PENDING
            ]

    def list_all(self) -> list[ScreenAuthorization]:
        with self._lock:
            return list(self._authorizations.values())

    def clear(self) -> None:
        with self._lock:
            self._authorizations.clear()
            self._by_session.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require(self, authorization_id: str) -> ScreenAuthorization:
        auth = self._authorizations.get(authorization_id)
        if auth is None:
            raise ScreenAuthorizationNotFoundError(
                f"Screen authorization '{authorization_id}' not found."
            )
        return auth

    def _assert_state_for_decision(
        self,
        auth: ScreenAuthorization,
        allowed: tuple[AuthorizationDecision, ...],
    ) -> None:
        if auth.is_expired(self._now()):
            auth.decision = AuthorizationDecision.EXPIRED
            raise ScreenAuthorizationExpiredError(
                f"Authorization '{auth.authorization_id}' expired at {auth.expires_at}."
            )
        if auth.decision not in allowed:
            if auth.decision == AuthorizationDecision.DENIED:
                raise ScreenAuthorizationDeniedError(
                    f"Authorization '{auth.authorization_id}' was previously denied."
                )
            raise ScreenAuthorizationError(
                f"Authorization '{auth.authorization_id}' is in state "
                f"{auth.decision.value}; expected one of {[d.value for d in allowed]}."
            )

    def _now(self) -> datetime.datetime:
        if self._clock is not None:
            result = self._clock()
            if isinstance(result, datetime.datetime):
                return result
            return datetime.datetime.now(datetime.UTC)
        return datetime.datetime.now(datetime.UTC)

    def _now_iso(self) -> str:
        return self._now().isoformat()


def derive_session_state_from_decision(
    decision: AuthorizationDecision,
) -> ScreenSessionState:
    """Map an authorization decision onto the corresponding session state.

    The function performs a deterministic, table-based mapping. It does NOT
    itself validate the resulting state transition graph — that is the
    responsibility of the session lifecycle (see :class:`ScreenSession`).
    """
    mapping = {
        AuthorizationDecision.PENDING: ScreenSessionState.PENDING_CHILD_APPROVAL,
        AuthorizationDecision.APPROVED: ScreenSessionState.APPROVED,
        AuthorizationDecision.DENIED: ScreenSessionState.DENIED,
        AuthorizationDecision.EXPIRED: ScreenSessionState.EXPIRED,
        AuthorizationDecision.REVOKED: ScreenSessionState.REVOKED,
    }
    return mapping.get(decision, ScreenSessionState.REQUESTED)


__all__ = [
    "DEFAULT_MAX_DURATION_SECONDS",
    "MAX_MAX_DURATION_SECONDS",
    "MIN_MAX_DURATION_SECONDS",
    "ScreenAuthorizationManager",
    "ScreenAuthorizationRequest",
    "derive_session_state_from_decision",
]
