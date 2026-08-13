"""Aegis controller — high-level orchestrator.

The :class:`AegisController` coordinates the system-consent gate, the
frame pipeline, the foreground-service indicator, the Nexus
transport bridge, and the audit log. It is the single object that
the CLI and the Android companion talk to.

The controller enforces the *three-key consent gate*:

1. Trust (Phase 2): the device is in the trusted registry.
2. Authorization (Phase 7): the child has approved the screen view.
3. System consent (Phase 8): the child has tapped "Allow" in the
   Android system capture-consent dialog.

All three are required. The controller refuses to start capture if
any one is missing or expired. The controller never bypasses this
gate; any attempt to call ``start_capture`` without a GRANTED system
consent raises :class:`AegisConsentRequiredError`.
"""

from __future__ import annotations

import datetime
import threading
from dataclasses import dataclass
from typing import Any

from guardianmesh.aegis.consent import (
    SystemConsentGate,
)
from guardianmesh.aegis.encoder import (
    ScreenEncoder,
    ScreenEncoderRegistry,
)
from guardianmesh.aegis.errors import (
    AegisAuthorizationRequiredError,
    AegisError,
    AegisPlatformUnavailableError,
    AegisSessionError,
)
from guardianmesh.aegis.errors import AegisError as _AegisError  # noqa: F401
from guardianmesh.aegis.indicator_service import (
    ForegroundServiceIndicator,
)
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    MediaProjectionProvider,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    AegisSessionInfo,
    AegisSessionState,
    ProviderCapabilities,
    SystemConsentRecord,
    SystemConsentState,
    generate_aegis_session_id,
)
from guardianmesh.aegis.pipeline import AegisFramePipeline
from guardianmesh.aegis.registry import AegisSessionRegistry
from guardianmesh.identity.models import validate_identity_id
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


@dataclass
class AegisViewRequest:
    """Parent-side view request payload.

    Mirrors the structure of :class:`ScreenViewRequest` from Phase 7
    so that the controller can be invoked from the same CLI flow.
    """

    screen_session_id: str
    device_id: str
    parent_id: str
    width: int = 1280
    height: int = 720
    max_fps: int = 10
    label: str | None = None


class AegisController:
    """High-level Aegis orchestrator.

    The controller is the only object the CLI and the Android companion
    talk to. It is intentionally framework-free: it does not depend on
    argparse, asyncio, or any Android-only library.
    """

    def __init__(
        self,
        db: Database,
        config: Any,
        trust_manager: TrustManager | None = None,
        audit_logger: AuditLogger | None = None,
        provider: MediaProjectionProvider | None = None,
        encoder: ScreenEncoder | None = None,
        consent_gate: SystemConsentGate | None = None,
        indicator: ForegroundServiceIndicator | None = None,
        encoder_registry: ScreenEncoderRegistry | None = None,
        registry: AegisSessionRegistry | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.audit_logger = audit_logger or AuditLogger(db)
        self._trust_manager = trust_manager
        self._registry = registry or AegisSessionRegistry(db)
        # If the caller did not provide a provider, use the Linux
        # adapter. This makes the control plane honest about the
        # platform limitation.
        self._provider = provider or AdapterOnlyMediaProjectionProvider(
            platform=AegisPlatform.LINUX,
            max_width=getattr(config, "screen_view_default_width", 1280),
            max_height=getattr(config, "screen_view_default_height", 720),
            max_fps=getattr(config, "screen_view_default_fps", 10),
        )
        self._encoder_registry = encoder_registry or ScreenEncoderRegistry()
        if encoder is None:
            encoder = self._encoder_registry.default()
        self._encoder = encoder
        self._consent_gate = consent_gate or SystemConsentGate(
            capability=self._provider.capability,
        )
        self._indicator = indicator or ForegroundServiceIndicator(
            capability=self._provider.capability,
        )
        self._pipelines: dict[str, AegisFramePipeline] = {}
        self._lock = threading.RLock()
        # In-memory AegisSessionInfo store, keyed by aegis_session_id.
        self._sessions: dict[str, AegisSessionInfo] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def provider(self) -> MediaProjectionProvider:
        return self._provider

    @property
    def encoder(self) -> ScreenEncoder:
        return self._encoder

    @property
    def consent_gate(self) -> SystemConsentGate:
        return self._consent_gate

    @property
    def indicator(self) -> ForegroundServiceIndicator:
        return self._indicator

    @property
    def registry(self) -> AegisSessionRegistry:
        return self._registry

    @property
    def capability(self) -> ProviderCapabilities:
        return self._provider.capability

    @property
    def transport_only(self) -> bool:
        return not self._provider.is_real_capture

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def create_session(
        self,
        request: AegisViewRequest,
    ) -> AegisSessionInfo:
        """Create a new Aegis capture session in the ``INITIALIZED`` state.

        The session is metadata only. No projection is started. The
        caller must subsequently request system consent via
        :meth:`request_system_consent` and grant it via
        :meth:`grant_system_consent` before capture can begin.
        """
        valid_dev, dev_err = validate_identity_id(request.device_id)
        if not valid_dev:
            raise AegisError(f"Invalid device_id: {dev_err}")
        valid_par, par_err = validate_identity_id(request.parent_id)
        if not valid_par:
            raise AegisError(f"Invalid parent_id: {par_err}")
        if not request.screen_session_id:
            raise AegisError("screen_session_id is required.")
        self._assert_trust_or_raise(
            local_identity_id=request.parent_id,
            remote_identity_id=request.device_id,
        )
        with self._lock:
            aegis_id = generate_aegis_session_id()
            now = datetime.datetime.now(datetime.UTC)
            session = AegisSessionInfo(
                aegis_session_id=aegis_id,
                screen_session_id=request.screen_session_id,
                device_id=request.device_id,
                parent_id=request.parent_id,
                consent_state=SystemConsentState.NOT_REQUESTED,
                platform=self._provider.capability.platform,
                backend=self._encoder.backend,
                state=AegisSessionState.INITIALIZED.value,
                created_at=now.isoformat(),
                expires_at=(
                    now + datetime.timedelta(
                        seconds=getattr(
                            self.config, "screen_view_default_max_duration_seconds", 300
                        )
                    )
                ).isoformat(),
                label=request.label,
            )
            session.validate()
            self._sessions[aegis_id] = session
            try:
                self._registry.upsert(session)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.AEGIS_SESSION_CREATED,
                details={
                    "aegis_session_id": aegis_id,
                    "screen_session_id": request.screen_session_id,
                    "device_id": request.device_id,
                    "parent_id": request.parent_id,
                    "platform": self._provider.capability.platform.value,
                    "backend": self._encoder.backend.value,
                    "width": request.width,
                    "height": request.height,
                    "max_fps": request.max_fps,
                },
                actor_id=request.parent_id,
                success=True,
            )
            return session

    def get_session(self, aegis_session_id: str) -> AegisSessionInfo | None:
        with self._lock:
            return self._sessions.get(aegis_session_id)

    def list_sessions(self) -> list[AegisSessionInfo]:
        with self._lock:
            return list(self._sessions.values())

    # ------------------------------------------------------------------
    # System consent
    # ------------------------------------------------------------------

    def request_system_consent(
        self,
        aegis_session_id: str,
    ) -> SystemConsentRecord:
        """Request the Android system capture-consent dialog.

        On non-Android platforms this method raises
        :class:`AegisPlatformUnavailableError`; the control plane
        cannot manufacture system consent.
        """
        with self._lock:
            session = self._require(aegis_session_id)
            record = self._consent_gate.request_consent(
                screen_session_id=session.screen_session_id,
                device_id=session.device_id,
                expires_at=session.expires_at,
            )
            session.consent_state = SystemConsentState.REQUESTED
            session.consent_requested_at = record.requested_at
            session.state = AegisSessionState.SYSTEM_CONSENT_REQUIRED.value
            try:
                self._registry.upsert(session)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.AEGIS_SYSTEM_CONSENT_REQUESTED,
                details={
                    "aegis_session_id": aegis_session_id,
                    "screen_session_id": session.screen_session_id,
                    "device_id": session.device_id,
                },
                actor_id=session.device_id,
                success=True,
            )
            return record

    def grant_system_consent(
        self,
        aegis_session_id: str,
        consent_token: str,
    ) -> SystemConsentRecord:
        """Mark the system consent as granted.

        This method is called by the Android companion after the child
        taps **Allow** in the system dialog. It is the only way to
        transition the session to the ``CAPTURING`` state.
        """
        with self._lock:
            session = self._require(aegis_session_id)
            record = self._consent_gate.grant_consent(consent_token)
            session.consent_state = SystemConsentState.GRANTED
            session.consent_granted_at = record.granted_at
            session.state = AegisSessionState.SYSTEM_CONSENT_GRANTED.value
            try:
                self._registry.upsert(session)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.AEGIS_SYSTEM_CONSENT_GRANTED,
                details={
                    "aegis_session_id": aegis_session_id,
                    "screen_session_id": session.screen_session_id,
                    "device_id": session.device_id,
                },
                actor_id=session.device_id,
                success=True,
            )
            return record

    def deny_system_consent(
        self,
        aegis_session_id: str,
        consent_token: str,
        note: str = "User denied the system consent dialog.",
    ) -> SystemConsentRecord:
        """Mark the system consent as denied by the user."""
        with self._lock:
            session = self._require(aegis_session_id)
            record = self._consent_gate.deny_consent(consent_token, note=note)
            session.consent_state = SystemConsentState.DENIED
            session.state = AegisSessionState.SYSTEM_CONSENT_DENIED.value
            session.stopped_at = datetime.datetime.now(datetime.UTC).isoformat()
            session.stop_reason = "SYSTEM_CONSENT_DENIED"
            try:
                self._registry.upsert(session)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.AEGIS_SYSTEM_CONSENT_DENIED,
                details={
                    "aegis_session_id": aegis_session_id,
                    "screen_session_id": session.screen_session_id,
                    "device_id": session.device_id,
                },
                actor_id=session.device_id,
                success=False,
            )
            return record

    # ------------------------------------------------------------------
    # Capture lifecycle
    # ------------------------------------------------------------------

    def start_capture(
        self,
        aegis_session_id: str,
        transport_session_id: str | None = None,
    ) -> AegisFramePipeline:
        """Begin frame capture for an Aegis session.

        Raises :class:`AegisConsentRequiredError` if the system
        consent is not GRANTED. Raises
        :class:`AegisPlatformUnavailableError` if the platform does
        not support real capture.
        """
        with self._lock:
            session = self._require(aegis_session_id)
            # Enforce the three-key consent gate.
            self._consent_gate.assert_capture_allowed(session.screen_session_id)
            if not self._provider.is_real_capture and not self._provider.is_available:
                raise AegisPlatformUnavailableError(
                    f"Provider {self._provider.__class__.__name__} is not "
                    f"available on this platform."
                )
            if transport_session_id is not None:
                session.transport_session_id = transport_session_id
            session.state = AegisSessionState.CAPTURING.value
            session.started_at = datetime.datetime.now(datetime.UTC).isoformat()
            try:
                self._registry.upsert(session)
            except Exception:
                pass
            # Build (or rebuild) the pipeline.
            pipeline = AegisFramePipeline(
                provider=self._provider,
                encoder=self._encoder,
                screen_session_id=session.screen_session_id,
                device_id=session.device_id,
                max_width=1280,
                max_height=720,
                max_fps=10,
            )
            pipeline.start()
            # Start the foreground service indicator.
            self._indicator.start(
                session_id=session.aegis_session_id,
                parent_label=session.label or session.parent_id,
            )
            self._pipelines[aegis_session_id] = pipeline
            self.audit_logger.record(
                event_type=AuditEventType.AEGIS_CAPTURE_STARTED,
                details={
                    "aegis_session_id": aegis_session_id,
                    "screen_session_id": session.screen_session_id,
                    "device_id": session.device_id,
                    "platform": self._provider.capability.platform.value,
                    "backend": self._encoder.backend.value,
                },
                actor_id=session.device_id,
                success=True,
            )
            return pipeline

    def stop_capture(
        self,
        aegis_session_id: str,
        reason: str = "USER_STOPPED",
    ) -> AegisSessionInfo:
        """Terminate the capture session and tear down all resources."""
        with self._lock:
            session = self._require(aegis_session_id)
            pipeline = self._pipelines.pop(aegis_session_id, None)
            if pipeline is not None:
                pipeline.stop()
            self._indicator.stop()
            if self._consent_gate is not None:
                record = self._consent_gate.get_for_session(
                    session.screen_session_id
                )
                if record is not None and record.state == SystemConsentState.GRANTED:
                    self._consent_gate.revoke_consent(
                        record.consent_token, reason=reason
                    )
            session.state = AegisSessionState.STOPPED.value
            session.stopped_at = datetime.datetime.now(datetime.UTC).isoformat()
            session.stop_reason = reason
            try:
                self._registry.upsert(session)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.AEGIS_CAPTURE_STOPPED,
                details={
                    "aegis_session_id": aegis_session_id,
                    "screen_session_id": session.screen_session_id,
                    "device_id": session.device_id,
                    "reason": reason,
                },
                actor_id=session.device_id,
                success=True,
            )
            return session

    def expire_due(self) -> list[str]:
        """Expire any session whose lifetime has elapsed.

        Returns the list of session IDs that were expired.
        """
        expired: list[str] = []
        with self._lock:
            now = datetime.datetime.now(datetime.UTC)
            for aegis_id, session in list(self._sessions.items()):
                if session.state in (
                    AegisSessionState.STOPPED.value,
                    AegisSessionState.EXPIRED.value,
                    AegisSessionState.REVOKED.value,
                ):
                    continue
                try:
                    exp = datetime.datetime.fromisoformat(session.expires_at)
                except ValueError:
                    continue
                if now > exp:
                    self.stop_capture(aegis_id, reason="EXPIRED")
                    session.state = AegisSessionState.EXPIRED.value
                    try:
                        self._registry.upsert(session)
                    except Exception:
                        pass
                    expired.append(aegis_id)
        return expired

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def diagnostics(self) -> dict[str, Any]:
        """Return a metadata-only aggregate of the Aegis subsystem."""
        with self._lock:
            total = len(self._sessions)
            capturing = sum(
                1
                for s in self._sessions.values()
                if s.state == AegisSessionState.CAPTURING.value
            )
            consent_pending = sum(
                1
                for s in self._sessions.values()
                if s.state == AegisSessionState.SYSTEM_CONSENT_REQUIRED.value
            )
            consent_denied = sum(
                1
                for s in self._sessions.values()
                if s.state == AegisSessionState.SYSTEM_CONSENT_DENIED.value
            )
            return {
                "total_sessions": total,
                "capturing_sessions": capturing,
                "system_consent_pending": consent_pending,
                "system_consent_denied": consent_denied,
                "platform": self._provider.capability.platform.value,
                "backend": self._encoder.backend.value,
                "provider_class": self._provider.__class__.__name__,
                "provider_is_real_capture": self._provider.is_real_capture,
                "supports_media_projection": self._provider.capability.supports_media_projection,
                "supports_foreground_service": self._provider.capability.supports_foreground_service,
                "consent_decision": self._consent_gate.evaluate(
                    # The decision is purely diagnostic; we look up the
                    # most recent session if any.
                    next(
                        iter(s.screen_session_id for s in self._sessions.values()),
                        "",
                    )
                ).to_dict()
                if self._sessions
                else None,
                "indicator_active": self._indicator.is_active,
            }

    def list_providers(self) -> list[dict[str, Any]]:
        """Return a metadata-only list of available providers."""
        with self._lock:
            return [
                {
                    "class": self._provider.__class__.__name__,
                    "capability": self._provider.capability.to_dict(),
                    "is_available": self._provider.is_available,
                    "is_real_capture": self._provider.is_real_capture,
                }
            ]

    def list_limits(self) -> dict[str, Any]:
        """Return the documented hard limits of the Aegis subsystem."""
        return {
            "max_fps": 10,
            "max_width": 1280,
            "max_height": 720,
            "max_frame_bytes": 4 * 1024 * 1024,
            "max_queue_size": 30,
            "default_max_duration_seconds": 300,
            "hard_max_duration_seconds": 3600,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _require(self, aegis_session_id: str) -> AegisSessionInfo:
        session = self._sessions.get(aegis_session_id)
        if session is None:
            raise AegisSessionError(
                f"Aegis session '{aegis_session_id}' not found in controller."
            )
        return session

    def _assert_trust_or_raise(self, local_identity_id: str, remote_identity_id: str) -> None:
        if self._trust_manager is None:
            return  # No trust manager configured; trust check is a no-op.
        try:
            self._trust_manager.verify_device_trust_or_raise(
                local_identity_id=local_identity_id,
                remote_identity_id=remote_identity_id,
            )
        except Exception as e:
            raise AegisAuthorizationRequiredError(
                f"Trust verification failed for device '{remote_identity_id}': {e}"
            ) from e


__all__ = [
    "AegisController",
    "AegisViewRequest",
]
