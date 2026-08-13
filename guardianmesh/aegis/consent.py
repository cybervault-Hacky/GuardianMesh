"""Android ``MediaProjection`` system-consent gate.

The consent gate enforces the privacy contract of Aegis:

* Capture is forbidden until the Android system capture-consent dialog
  has been presented to the child and the child has tapped **Allow**.
* The system consent is single-use: once revoked or expired, a new
  capture session requires a fresh dialog presentation.
* The gate is intentionally separate from the Vista authorization
  state machine. A Vista authorization is granted by the child *inside
  GuardianMesh*; the system consent is granted by the child *via the
  Android system dialog*. Both must be present and unexpired before
  capture is allowed.

The gate is the enforcement point of the *trust != authorization != system
consent* invariant. All three checks are required:

1. Trust (``trusted_devices.status == ACTIVE``) - Phase 2.
2. Authorization (``screen_authorizations.decision == APPROVED``) - Phase 7.
3. System consent (``SystemConsentState == GRANTED``) - Phase 8.

The gate is platform-aware: on a non-Android platform the gate is
permanently in the ``NOT_REQUESTED`` state and capture is impossible.
This is by design; the gate must never be bypassed.
"""

from __future__ import annotations

import datetime
import threading
from dataclasses import dataclass
from typing import Any

from guardianmesh.aegis.errors import (
    AegisConsentDeniedError,
    AegisConsentRequiredError,
    AegisConsentRevokedError,
    AegisError,
    AegisPlatformUnavailableError,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    ProviderCapabilities,
    SystemConsentRecord,
    SystemConsentState,
    generate_consent_token,
)


@dataclass
class ConsentDecision:
    """Result of a consent evaluation.

    The decision is metadata only. It contains a single boolean,
    a state, and a human-readable reason. It never contains frame
    bytes or any captured screen content.
    """

    allowed: bool
    state: SystemConsentState
    reason: str
    capability: ProviderCapabilities

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "state": self.state.value,
            "reason": self.reason,
            "platform": self.capability.platform.value,
            "backend": self.capability.backend.value,
            "supports_real_capture": self.capability.platform.supports_real_capture,
        }


class SystemConsentGate:
    """In-memory state machine for the Android system consent dialog.

    The gate is thread-safe. Every transition is recorded with an ISO
    timestamp. The gate refuses any transition that would enable
    capture on a platform that does not support real MediaProjection.
    """

    def __init__(
        self,
        capability: ProviderCapabilities,
        clock: Any | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._capability = capability
        self._clock = clock
        self._records: dict[str, SystemConsentRecord] = {}
        self._by_session: dict[str, str] = {}

    @property
    def capability(self) -> ProviderCapabilities:
        return self._capability

    def _now(self) -> datetime.datetime:
        if self._clock is not None:
            result = self._clock()
            if isinstance(result, datetime.datetime):
                return result
            return datetime.datetime.now(datetime.UTC)
        return datetime.datetime.now(datetime.UTC)

    def _now_iso(self) -> str:
        return self._now().isoformat()

    # ------------------------------------------------------------------
    # Platform check
    # ------------------------------------------------------------------

    def _assert_android_platform(self) -> None:
        """Refuse to operate when the platform is not real Android."""
        if not self._capability.platform.supports_real_capture:
            raise AegisPlatformUnavailableError(
                f"Platform {self._capability.platform.value} cannot perform real "
                f"MediaProjection. Use an Android companion (APK)."
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def request_consent(
        self,
        screen_session_id: str,
        device_id: str,
        expires_at: str,
    ) -> SystemConsentRecord:
        """Present (record the presentation of) the system consent dialog.

        The actual presentation is performed by the Android companion at
        runtime. From the control plane's perspective, this method
        records the *intent* to present the dialog. If the platform is
        not real Android, the call is rejected with
        :class:`AegisPlatformUnavailableError`.
        """
        self._assert_android_platform()
        with self._lock:
            if screen_session_id in self._by_session:
                # A consent request is already in flight for this session.
                existing = self._records[self._by_session[screen_session_id]]
                if existing.state == SystemConsentState.REQUESTED:
                    return existing
            token = generate_consent_token()
            record = SystemConsentRecord(
                consent_token=token,
                screen_session_id=screen_session_id,
                device_id=device_id,
                state=SystemConsentState.REQUESTED,
                requested_at=self._now_iso(),
                expires_at=expires_at,
            )
            self._records[token] = record
            self._by_session[screen_session_id] = token
            return record

    def grant_consent(
        self,
        consent_token: str,
    ) -> SystemConsentRecord:
        """Mark the system consent as granted.

        This is called by the Android companion after the child taps
        "Allow" in the system dialog. After this call the gate allows
        capture to begin for the associated screen session.
        """
        self._assert_android_platform()
        with self._lock:
            record = self._require(consent_token)
            if record.state == SystemConsentState.GRANTED:
                return record
            if record.state == SystemConsentState.DENIED:
                raise AegisConsentDeniedError(
                    f"System consent '{consent_token}' was denied by the user."
                )
            if record.state == SystemConsentState.REVOKED:
                raise AegisConsentRevokedError(
                    f"System consent '{consent_token}' was revoked."
                )
            record.state = SystemConsentState.GRANTED
            record.granted_at = self._now_iso()
            return record

    def deny_consent(
        self,
        consent_token: str,
        note: str = "",
    ) -> SystemConsentRecord:
        """Mark the system consent as denied by the user."""
        self._assert_android_platform()
        with self._lock:
            record = self._require(consent_token)
            if record.state == SystemConsentState.DENIED:
                return record
            record.state = SystemConsentState.DENIED
            record.denied_at = self._now_iso()
            record.note = note
            return record

    def revoke_consent(
        self,
        consent_token: str,
        reason: str = "REVOKED",
    ) -> SystemConsentRecord:
        """Revoke a previously granted system consent (mid-session or not)."""
        self._assert_android_platform()
        with self._lock:
            record = self._require(consent_token)
            if record.state in (
                SystemConsentState.REVOKED,
                SystemConsentState.EXPIRED,
            ):
                return record
            record.state = SystemConsentState.REVOKED
            record.revoked_at = self._now_iso()
            record.note = reason
            return record

    def expire_due(self) -> list[str]:
        """Expire any consent record whose lifetime has elapsed."""
        expired: list[str] = []
        with self._lock:
            for token, record in list(self._records.items()):
                if not record.expires_at:
                    continue
                try:
                    exp_dt = datetime.datetime.fromisoformat(record.expires_at)
                except ValueError:
                    continue
                if self._now() <= exp_dt:
                    continue
                if record.state in (
                    SystemConsentState.GRANTED,
                    SystemConsentState.REQUESTED,
                ):
                    record.state = SystemConsentState.EXPIRED
                    expired.append(token)
        return expired

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        screen_session_id: str,
    ) -> ConsentDecision:
        """Return a :class:`ConsentDecision` for the given screen session.

        The decision is deterministic and stateless beyond the gate's
        internal record map.
        """
        with self._lock:
            # On non-Android, capture is never allowed.
            if not self._capability.platform.supports_real_capture:
                return ConsentDecision(
                    allowed=False,
                    state=SystemConsentState.NOT_REQUESTED,
                    reason=(
                        f"Platform {self._capability.platform.value} does not "
                        f"support real MediaProjection. Use an Android companion."
                    ),
                    capability=self._capability,
                )
            token = self._by_session.get(screen_session_id)
            if token is None:
                return ConsentDecision(
                    allowed=False,
                    state=SystemConsentState.NOT_REQUESTED,
                    reason="System consent has not been requested for this session.",
                    capability=self._capability,
                )
            record = self._records[token]
            if record.state == SystemConsentState.GRANTED:
                return ConsentDecision(
                    allowed=True,
                    state=SystemConsentState.GRANTED,
                    reason="System consent is granted.",
                    capability=self._capability,
                )
            if record.state == SystemConsentState.DENIED:
                return ConsentDecision(
                    allowed=False,
                    state=SystemConsentState.DENIED,
                    reason="System consent was denied by the user.",
                    capability=self._capability,
                )
            if record.state == SystemConsentState.REVOKED:
                return ConsentDecision(
                    allowed=False,
                    state=SystemConsentState.REVOKED,
                    reason="System consent was revoked.",
                    capability=self._capability,
                )
            if record.state == SystemConsentState.EXPIRED:
                return ConsentDecision(
                    allowed=False,
                    state=SystemConsentState.EXPIRED,
                    reason="System consent expired.",
                    capability=self._capability,
                )
            return ConsentDecision(
                allowed=False,
                state=SystemConsentState.REQUESTED,
                reason="System consent has been requested but not yet granted.",
                capability=self._capability,
            )

    def assert_capture_allowed(
        self,
        screen_session_id: str,
    ) -> ConsentDecision:
        """Raise if capture is not allowed for the given screen session.

        This is the enforcement point used by the AegisController and
        the Android companion. A refusal is signalled through a typed
        exception (never by returning a permissive result).
        """
        decision = self.evaluate(screen_session_id)
        if decision.allowed:
            return decision
        if decision.state == SystemConsentState.NOT_REQUESTED:
            raise AegisConsentRequiredError(decision.reason)
        if decision.state == SystemConsentState.DENIED:
            raise AegisConsentDeniedError(decision.reason)
        if decision.state == SystemConsentState.REVOKED:
            raise AegisConsentRevokedError(decision.reason)
        if decision.state == SystemConsentState.EXPIRED:
            raise AegisConsentRequiredError(decision.reason)
        raise AegisConsentRequiredError(decision.reason)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_record(self, consent_token: str) -> SystemConsentRecord | None:
        with self._lock:
            return self._records.get(consent_token)

    def get_for_session(self, screen_session_id: str) -> SystemConsentRecord | None:
        with self._lock:
            token = self._by_session.get(screen_session_id)
            if token is None:
                return None
            return self._records.get(token)

    def list_all(self) -> list[SystemConsentRecord]:
        with self._lock:
            return list(self._records.values())

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._by_session.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require(self, consent_token: str) -> SystemConsentRecord:
        record = self._records.get(consent_token)
        if record is None:
            raise AegisError(f"System consent '{consent_token}' not found.")
        return record


def default_linux_capability() -> ProviderCapabilities:
    """Return the default capabilities for a Linux/Termux development host.

    The returned capabilities report ``supports_real_capture = False``
    and the gate refuses capture on this platform.
    """
    return ProviderCapabilities(
        platform=AegisPlatform.LINUX,
        backend=__import__(
            "guardianmesh.aegis.models", fromlist=["EncoderBackend"]
        ).EncoderBackend.TEST,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=False,
        supports_media_projection=False,
        notes="Linux development host. Real Android capture is not available.",
    )


__all__ = [
    "ConsentDecision",
    "SystemConsentGate",
    "default_linux_capability",
]
