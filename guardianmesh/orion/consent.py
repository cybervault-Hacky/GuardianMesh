"""Orion Phase 9 consent validator.

Orion never invents consent. It delegates to the existing
subsystems:

* :class:`guardianmesh.pairing.trust.TrustManager` (Phase 2)
* :class:`guardianmesh.screen.authorization.ScreenAuthorizationManager`
  (Phase 7)
* :class:`guardianmesh.aegis.consent.SystemConsentGate` (Phase 8)

The :class:`OrionConsentValidator` consults these subsystems and
raises :class:`OrionConsentViolationError` if any required consent
is missing or expired.
"""

from __future__ import annotations

from guardianmesh.aegis.consent import SystemConsentGate
from guardianmesh.orion.actions import (
    OrionAction,
    OrionConsentRequirement,
    required_consents,
)
from guardianmesh.orion.errors import OrionConsentViolationError
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.screen.authorization import ScreenAuthorizationManager


class OrionConsentValidator:
    """Validates the consent requirements for an Orion action.

    The validator is the only place where Orion makes consent
    decisions. It never short-circuits or weakens consent; it only
    delegates to the existing subsystems and surfaces their verdicts.
    """

    def __init__(
        self,
        trust_manager: TrustManager | None = None,
        screen_authorization_manager: ScreenAuthorizationManager | None = None,
        aegis_consent_gate: SystemConsentGate | None = None,
    ) -> None:
        self._trust_manager = trust_manager
        self._screen_authorization_manager = screen_authorization_manager
        self._aegis_consent_gate = aegis_consent_gate

    def validate(
        self,
        action: OrionAction,
        *,
        active_session_id: str | None = None,
        active_aegis_session_id: str | None = None,
    ) -> None:
        """Validate the consent requirements for ``action``.

        Raises :class:`OrionConsentViolationError` if any required
        consent is missing, revoked, or expired.
        """
        if not isinstance(action, OrionAction):
            raise OrionConsentViolationError("action must be an OrionAction.")
        requirements = required_consents(action.action_type)
        self._enforce_trust(action, requirements)
        self._enforce_vista_authorization(
            action, requirements, screen_session_id=active_session_id
        )
        self._enforce_aegis_consent(
            action, requirements, aegis_session_id=active_aegis_session_id
        )
        self._enforce_existing_active_session(
            action, requirements, active_session_id=active_session_id
        )
        # Child authorization: the Vista authorization manager records
        # the child's decision; we already enforced it above.

    # ------------------------------------------------------------------
    # Consent gates
    # ------------------------------------------------------------------

    def _enforce_trust(
        self,
        action: OrionAction,
        requirements: frozenset[OrionConsentRequirement],
    ) -> None:
        if OrionConsentRequirement.TRUST_REQUIRED not in requirements:
            return
        if self._trust_manager is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires trust verification, "
                f"but no TrustManager is configured."
            )
        # We need a parent identity to verify trust against. The
        # controller passes this in via the ``requested_by`` field
        # when the action is created. If the device is not yet
        # trusted, the TrustManager raises the appropriate error.
        try:
            self._trust_manager.verify_device_trust_or_raise(
                local_identity_id=action.requested_by,
                remote_identity_id=action.device_id,
            )
        except Exception as e:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires trust, "
                f"but trust verification failed: {e}"
            ) from e

    def _enforce_vista_authorization(
        self,
        action: OrionAction,
        requirements: frozenset[OrionConsentRequirement],
        *,
        screen_session_id: str | None,
    ) -> None:
        if (
            OrionConsentRequirement.VISTA_AUTHORIZATION_REQUIRED
            not in requirements
        ):
            return
        if self._screen_authorization_manager is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires a Vista authorization, "
                f"but no ScreenAuthorizationManager is configured."
            )
        if screen_session_id is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires a Vista screen session, "
                f"but no active session id was provided."
            )
        auth = self._screen_authorization_manager.get_for_session(
            screen_session_id
        )
        if auth is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires a Vista authorization, "
                f"but no authorization exists for session '{screen_session_id}'."
            )
        if auth.decision.value != "APPROVED":
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires a Vista authorization, "
                f"but the current decision is '{auth.decision.value}'."
            )

    def _enforce_aegis_consent(
        self,
        action: OrionAction,
        requirements: frozenset[OrionConsentRequirement],
        *,
        aegis_session_id: str | None,
    ) -> None:
        if OrionConsentRequirement.AEGIS_SYSTEM_CONSENT_REQUIRED not in requirements:
            return
        if self._aegis_consent_gate is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires Aegis system consent, "
                f"but no SystemConsentGate is configured."
            )
        if aegis_session_id is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires Aegis system consent, "
                f"but no active Aegis session id was provided."
            )
        # We use the screen_session_id field to look up consent, which
        # is the canonical mapping in Aegis.
        try:
            self._aegis_consent_gate.assert_capture_allowed(aegis_session_id)
        except Exception as e:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires Aegis system consent, "
                f"but consent verification failed: {e}"
            ) from e

    def _enforce_existing_active_session(
        self,
        action: OrionAction,
        requirements: frozenset[OrionConsentRequirement],
        *,
        active_session_id: str | None,
    ) -> None:
        if OrionConsentRequirement.EXISTING_ACTIVE_SESSION not in requirements:
            return
        if active_session_id is None:
            raise OrionConsentViolationError(
                f"Action '{action.action_type.value}' requires an existing active "
                f"screen session, but none is active."
            )


__all__ = ["OrionConsentValidator"]
