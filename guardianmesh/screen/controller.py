"""Screen session controller for Vista Phase 7.

The :class:`ScreenController` is the high-level orchestrator that ties
together authorization, session lifecycle, frame ingestion, and audit
logging. It is the *only* object that the CLI/parent viewer code is
expected to interact with.

The controller exposes:

* :meth:`request_view` — parent requests a screen view from a child.
* :meth:`approve` / :meth:`deny` — child-side decisions.
* :meth:`start_session` — actually begin streaming.
* :meth:`stop_session` — terminate (parent- or child-initiated).
* :meth:`revoke_session` — terminate immediately due to trust revocation.
* :meth:`ingest_frame` — child-side frame ingestion.
* :meth:`drain_frames` — parent-side frame drain.

The controller never logs frame payloads. It only logs metadata
(session_id, device_id, parent_id, frame size, codec, resolution, etc.).
"""

from __future__ import annotations

import datetime
import threading
from dataclasses import dataclass
from typing import Any

from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.models import validate_identity_id
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.screen.auth_registry import ScreenAuthorizationRegistry
from guardianmesh.screen.authorization import (
    DEFAULT_MAX_DURATION_SECONDS,
    ScreenAuthorizationManager,
)
from guardianmesh.screen.errors import (
    ScreenAuthorizationError,
    ScreenSessionError,
)
from guardianmesh.screen.indicator import AdapterOnlyScreenProvider, AndroidScreenProvider
from guardianmesh.screen.models import (
    ScreenFrame,
    ScreenSessionState,
    StopReason,
)
from guardianmesh.screen.session import (
    ScreenSession,
    ScreenSessionConfig,
    ScreenSessionManager,
)
from guardianmesh.screen.transport import ScreenMessageType
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


@dataclass
class ScreenViewRequest:
    """Parent-side view request payload."""

    device_id: str
    parent_id: str
    max_duration_seconds: int = DEFAULT_MAX_DURATION_SECONDS
    label: str | None = None
    width: int = 1280
    height: int = 720
    max_fps: int = 10


@dataclass
class ScreenControllerDiagnostics:
    """Aggregate, metadata-only diagnostics snapshot."""

    total_sessions: int
    active_sessions: int
    pending_authorizations: int
    denied_sessions: int
    expired_sessions: int
    revoked_sessions: int
    indicator_provider_class: str
    provider_is_real_capture: bool
    transport_only: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_sessions": self.total_sessions,
            "active_sessions": self.active_sessions,
            "pending_authorizations": self.pending_authorizations,
            "denied_sessions": self.denied_sessions,
            "expired_sessions": self.expired_sessions,
            "revoked_sessions": self.revoked_sessions,
            "indicator_provider_class": self.indicator_provider_class,
            "provider_is_real_capture": self.provider_is_real_capture,
            "transport_only": self.transport_only,
        }


class ScreenController:
    """High-level Vista controller orchestrating authorization, sessions, and audit."""

    def __init__(
        self,
        db: Database,
        config: GuardianConfig,
        trust_manager: TrustManager | None = None,
        audit_logger: AuditLogger | None = None,
        screen_provider: AndroidScreenProvider | None = None,
        session_manager: ScreenSessionManager | None = None,
        auth_manager: ScreenAuthorizationManager | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self._trust_manager = trust_manager
        self.audit_logger = audit_logger or AuditLogger(db)
        self._screen_provider = screen_provider or AdapterOnlyScreenProvider()
        # Defer imports to avoid circular dependency at module import time.
        from guardianmesh.screen.registry import ScreenSessionRegistry

        self._registry = ScreenSessionRegistry(db)
        self._auth_registry = ScreenAuthorizationRegistry(db)
        self._auth_manager = auth_manager or ScreenAuthorizationManager()
        self._session_manager = session_manager or ScreenSessionManager(
            registry=self._registry,
            auth_manager=self._auth_manager,
        )
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_manager(self) -> ScreenSessionManager:
        return self._session_manager

    @property
    def auth_manager(self) -> ScreenAuthorizationManager:
        return self._auth_manager

    @property
    def registry(self):  # type: ignore[no-untyped-def]
        return self._registry

    @property
    def screen_provider(self) -> AndroidScreenProvider:
        return self._screen_provider

    @property
    def transport_only(self) -> bool:
        """True if the transport-only path is in effect (no real Android capture)."""
        return not self._screen_provider.is_real_capture

    # ------------------------------------------------------------------
    # Parent-side API
    # ------------------------------------------------------------------

    def request_view(self, request: ScreenViewRequest) -> ScreenSession:
        """Parent requests a screen view from a child device.

        The child device must already be in the trusted devices registry.
        Trust is necessary but not sufficient; this method also creates
        a fresh PENDING authorization that the child must approve.
        """
        valid_dev, dev_err = validate_identity_id(request.device_id)
        if not valid_dev:
            raise ScreenAuthorizationError(f"Invalid child device_id: {dev_err}")
        valid_par, par_err = validate_identity_id(request.parent_id)
        if not valid_par:
            raise ScreenAuthorizationError(f"Invalid parent_id: {par_err}")

        self._assert_trust_or_raise(request.parent_id, request.device_id)

        with self._lock:
            config = ScreenSessionConfig(
                max_duration_seconds=request.max_duration_seconds,
                width=request.width,
                height=request.height,
                max_fps=request.max_fps,
                label=request.label,
            )
            session = self._session_manager.create_session(
                device_id=request.device_id,
                parent_id=request.parent_id,
                config=config,
            )
            session.request(
                device_id=request.device_id,
                parent_id=request.parent_id,
                max_duration_seconds=request.max_duration_seconds,
            )
            # Create matching authorization.
            auth = self._auth_manager.create_request(
                session_id=session.session_id,
                device_id=request.device_id,
                parent_id=request.parent_id,
                max_duration_seconds=request.max_duration_seconds,
                label=request.label,
            )
            session.info.authorization_id = auth.authorization_id
            # Persist the authorization record so cross-CLI flows survive a restart.
            try:
                self._auth_registry.upsert(auth)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.SCREEN_VIEW_REQUESTED,
                details={
                    "session_id": session.session_id,
                    "device_id": request.device_id,
                    "parent_id": request.parent_id,
                    "max_duration_seconds": request.max_duration_seconds,
                    "width": request.width,
                    "height": request.height,
                    "max_fps": request.max_fps,
                },
                actor_id=request.parent_id,
                success=True,
            )
            return session

    def approve(self, session_id: str) -> ScreenSession:
        """Child-side approval. Transitions session to APPROVED state."""
        with self._lock:
            session = self._session_manager.require(session_id)
            # Prefer the in-memory authorization, but fall back to the DB one
            # so a child CLI started in a different process can still approve.
            auth = self._auth_manager.get_for_session(session_id)
            if auth is None:
                auth = self._auth_registry.get_by_session_id(session_id)
                if auth is not None:
                    # Hydrate the in-memory manager so subsequent operations
                    # (e.g. start_session) work in the same process.
                    self._auth_manager._authorizations[auth.authorization_id] = auth
                    self._auth_manager._by_session[session_id] = auth.authorization_id
            if auth is None:
                raise ScreenAuthorizationError(
                    f"No authorization exists for session '{session_id}'."
                )
            if auth.decision.value != "PENDING":
                raise ScreenAuthorizationError(
                    f"Authorization for session '{session_id}' is in state "
                    f"{auth.decision.value}, not PENDING."
                )
            session.approve(auth.authorization_id)
            try:
                self._auth_registry.upsert(auth)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.SCREEN_VIEW_APPROVED,
                details={
                    "session_id": session_id,
                    "device_id": session.info.device_id,
                    "parent_id": session.info.parent_id,
                    "authorization_id": auth.authorization_id,
                },
                actor_id=session.info.device_id,
                success=True,
            )
            return session

    def deny(self, session_id: str) -> ScreenSession:
        """Child-side denial. Transitions session to DENIED state."""
        with self._lock:
            session = self._session_manager.require(session_id)
            auth = self._auth_manager.get_for_session(session_id)
            if auth is None:
                auth = self._auth_registry.get_by_session_id(session_id)
                if auth is not None:
                    self._auth_manager._authorizations[auth.authorization_id] = auth
                    self._auth_manager._by_session[session_id] = auth.authorization_id
            if auth is None:
                raise ScreenAuthorizationError(
                    f"No authorization exists for session '{session_id}'."
                )
            session.deny(auth.authorization_id)
            try:
                self._auth_registry.upsert(auth)
            except Exception:
                pass
            self.audit_logger.record(
                event_type=AuditEventType.SCREEN_VIEW_DENIED,
                details={
                    "session_id": session_id,
                    "device_id": session.info.device_id,
                    "parent_id": session.info.parent_id,
                    "authorization_id": auth.authorization_id,
                },
                actor_id=session.info.device_id,
                success=True,
            )
            return session

    def start_session(self, session_id: str) -> ScreenSession:
        """Begin streaming frames for an APPROVED session."""
        with self._lock:
            session = self._session_manager.require(session_id)
            if session.info.state != ScreenSessionState.APPROVED:
                raise ScreenSessionError(
                    f"Cannot start session in state {session.info.state.value}."
                )
            session.start()
            self.audit_logger.record(
                event_type=AuditEventType.SCREEN_SESSION_STARTED,
                details={
                    "session_id": session_id,
                    "device_id": session.info.device_id,
                    "parent_id": session.info.parent_id,
                    "width": session.info.width,
                    "height": session.info.height,
                    "codec": session.info.codec.value,
                },
                actor_id=session.info.device_id,
                success=True,
            )
            return session

    def stop_session(
        self, session_id: str, reason: StopReason = StopReason.PARENT_STOPPED
    ) -> ScreenSession:
        """Terminate the session from the parent or child side."""
        with self._lock:
            session = self._session_manager.require(session_id)
            if session.info.state in (
                ScreenSessionState.STOPPED,
                ScreenSessionState.DENIED,
                ScreenSessionState.EXPIRED,
                ScreenSessionState.REVOKED,
            ):
                return session
            session.stop(reason=reason)
            event = (
                AuditEventType.SCREEN_SESSION_STOPPED
                if reason != StopReason.EXPIRED
                else AuditEventType.SCREEN_SESSION_EXPIRED
            )
            self.audit_logger.record(
                event_type=event,
                details={
                    "session_id": session_id,
                    "device_id": session.info.device_id,
                    "parent_id": session.info.parent_id,
                    "stop_reason": reason.value,
                },
                actor_id=(
                    session.info.parent_id
                    if reason == StopReason.PARENT_STOPPED
                    else session.info.device_id
                ),
                success=True,
            )
            return session

    def revoke_session(
        self, session_id: str, reason: str = "TRUST_REVOKED"
    ) -> ScreenSession:
        """Terminate the session because trust was revoked."""
        with self._lock:
            session = self._session_manager.require(session_id)
            if session.info.state in (
                ScreenSessionState.STOPPED,
                ScreenSessionState.DENIED,
                ScreenSessionState.EXPIRED,
                ScreenSessionState.REVOKED,
            ):
                return session
            session.revoke_due_to_trust()
            self.audit_logger.record(
                event_type=AuditEventType.SCREEN_SESSION_REVOKED,
                details={
                    "session_id": session_id,
                    "device_id": session.info.device_id,
                    "parent_id": session.info.parent_id,
                    "reason": reason,
                },
                actor_id=session.info.device_id,
                success=False,
            )
            return session

    # ------------------------------------------------------------------
    # Frame ingestion
    # ------------------------------------------------------------------

    def ingest_frame(self, session_id: str, frame: ScreenFrame) -> bool:
        """Validate, sequence-check, and enqueue an inbound frame.

        Returns:
            True if the frame was buffered, False if it was dropped.
        """
        with self._lock:
            session = self._session_manager.require(session_id)
            return session.ingest_frame(frame)

    def drain_frames(self, session_id: str) -> list[ScreenFrame]:
        """Atomically remove and return all queued frames for a session."""
        with self._lock:
            session = self._session_manager.require(session_id)
            return session.buffer.drain()

    # ------------------------------------------------------------------
    # Status & diagnostics
    # ------------------------------------------------------------------

    def status(self, session_id: str) -> dict[str, Any]:
        """Return a metadata-only status snapshot of a session."""
        with self._lock:
            session = self._session_manager.require(session_id)
            return session.summary()

    def rehydrate_session(self, session_id: str) -> ScreenSession:
        """Reconstruct an in-memory :class:`ScreenSession` from the database.

        CLI subprocess invocations create a new controller each time, so the
        in-memory session map starts empty. This method looks up a previously
        persisted session and rehydrates the session wrapper around the
        database record. The active authorization is also rehydrated so that
        subsequent child-side decisions (approve, deny) can be processed
        without re-requesting.
        """
        from guardianmesh.screen.models import (
            ScreenSessionState,
        )

        with self._lock:
            info = self._registry.get(session_id)
            if info is None:
                raise ScreenSessionError(
                    f"Screen session '{session_id}' not found in database."
                )
            # If the session is already in memory, return it.
            existing = self._session_manager.get(session_id)
            if existing is not None:
                return existing

            # Rehydrate the authorization record from the database so that
            # cross-CLI approval flows (parent requests, child approves in
            # another process) work end-to-end.
            db_auth = self._auth_registry.get_by_session_id(session_id)
            if db_auth is not None and self._auth_manager.get_by_authorization_id(
                db_auth.authorization_id
            ) is None:
                self._auth_manager._authorizations[db_auth.authorization_id] = db_auth
                self._auth_manager._by_session[session_id] = db_auth.authorization_id

            # Build a new ScreenSession wrapping the existing info.
            config = ScreenSessionConfig(
                max_duration_seconds=self.config.screen_view_default_max_duration_seconds,
                width=info.width or self.config.screen_view_default_width,
                height=info.height or self.config.screen_view_default_height,
                max_fps=info.max_fps or self.config.screen_view_default_fps,
            )
            # The session may already be in a terminal state; if so, we still
            # wrap it but transitions are no-ops.
            new_session = ScreenSession(
                info=info,
                config=config,
                registry=self._registry,
                auth_manager=self._auth_manager,
            )
            # If the persisted session is ACTIVE, the indicator must also
            # be reactivated so the child-side UI continues to show the
            # active-screen-share banner.
            if info.state == ScreenSessionState.ACTIVE:
                new_session.indicator.activate(
                    session_id=info.session_id,
                    parent_label=info.label or info.parent_id,
                    max_duration_seconds=config.max_duration_seconds,
                    started_at=info.started_at or info.requested_at,
                )
                new_session.indicator.update_remaining(info.remaining_seconds)
            # Stash in the in-memory manager.
            self._session_manager._sessions[session_id] = new_session
            return new_session

    def diagnostics(self) -> ScreenControllerDiagnostics:
        """Return a metadata-only aggregate of the screen subsystem."""
        with self._lock:
            sessions = self._session_manager.list_all()
            total = len(sessions)
            active = sum(1 for s in sessions if s.is_active)
            denied = sum(1 for s in sessions if s.info.state == ScreenSessionState.DENIED)
            expired = sum(1 for s in sessions if s.info.state == ScreenSessionState.EXPIRED)
            revoked = sum(1 for s in sessions if s.info.state == ScreenSessionState.REVOKED)
            pending_auths = len(self._auth_manager.list_pending())
            return ScreenControllerDiagnostics(
                total_sessions=total,
                active_sessions=active,
                pending_authorizations=pending_auths,
                denied_sessions=denied,
                expired_sessions=expired,
                revoked_sessions=revoked,
                indicator_provider_class=self._screen_provider.__class__.__name__,
                provider_is_real_capture=self._screen_provider.is_real_capture,
                transport_only=True,
            )

    # ------------------------------------------------------------------
    # Frame provider integration
    # ------------------------------------------------------------------

    def capture_frame(self, session_id: str) -> ScreenFrame:
        """Capture a single frame from the screen provider and convert it.

        The provider may refuse to capture (e.g. dimensions out of bounds).
        In that case, ``ScreenFrame`` is constructed with an empty payload
        and ``payload_size == 0``. The caller is expected to validate.
        """
        from guardianmesh.screen.models import (
            ScreenCaptureRequest,
            ScreenFrame,
            generate_frame_id,
        )

        with self._lock:
            session = self._session_manager.require(session_id)
            now = datetime.datetime.now(datetime.UTC)
            request = ScreenCaptureRequest(
                session_id=session.session_id,
                width=session.info.width,
                height=session.info.height,
                max_fps=session.info.max_fps,
                codec=session.info.codec,
                pixel_format=session.buffer.summary().get("max_fps") and  # type: ignore[arg-type]
                    __import__(
                        "guardianmesh.screen.models", fromlist=["PixelFormat"]
                    ).PixelFormat.TEST,
            )
            result = self._screen_provider.capture(request)
            frame = ScreenFrame(
                protocol_version="1.0",
                session_id=session.session_id,
                device_id=session.info.device_id,
                frame_id=generate_frame_id(),
                sequence=session.buffer.last_sequence + 1,
                captured_at=now.isoformat(),
                width=result.width,
                height=result.height,
                pixel_format=result.pixel_format,
                codec=result.codec,
                payload_size=len(result.payload),
                payload=result.payload,
            )
            return frame

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_trust_or_raise(self, parent_id: str, device_id: str) -> None:
        if self._trust_manager is None:
            return  # No trust manager configured; trust check is a no-op.
        try:
            self._trust_manager.verify_device_trust_or_raise(
                local_identity_id=parent_id,
                remote_identity_id=device_id,
            )
        except Exception as e:
            raise ScreenAuthorizationError(
                f"Trust verification failed for device '{device_id}': {e}"
            ) from e


# Re-export for callers that need the message-type allowlist at top level.
_ = ScreenMessageType


__all__ = [
    "ScreenController",
    "ScreenControllerDiagnostics",
    "ScreenViewRequest",
]
