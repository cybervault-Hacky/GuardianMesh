"""Screen session lifecycle management for Vista Phase 7.

A :class:`ScreenSession` ties together the authorization state machine, the
in-memory frame buffer, the database record, the visible indicator state, and
the backpressure behavior. The session enforces:

* Strict state transitions (REQUESTED → PENDING → APPROVED → ACTIVE → terminal)
* Frame ingestion ONLY in the ACTIVE state
* Session expiration based on ``max_duration_seconds`` and inactivity timeout
* Immediate stop when the child revokes, the trust is revoked, or the
  transport disconnects

The session class NEVER persists frame bytes. The database record holds
metadata only.
"""

from __future__ import annotations

import datetime
import threading
import uuid
from dataclasses import dataclass
from typing import Any

from guardianmesh.screen.authorization import (
    DEFAULT_MAX_DURATION_SECONDS,
    ScreenAuthorizationManager,
)
from guardianmesh.screen.errors import (
    ScreenFrameError,
    ScreenFrameValidationError,
    ScreenSessionError,
    ScreenSessionExpiredError,
    ScreenSessionRevokedError,
    ScreenSessionStateError,
)
from guardianmesh.screen.frames import FrameStreamBuffer, FrameValidator
from guardianmesh.screen.indicator import ScreenIndicator
from guardianmesh.screen.models import (
    BackpressureStrategy,
    PixelFormat,
    ScreenCodec,
    ScreenFrame,
    ScreenSessionInfo,
    ScreenSessionState,
    StopReason,
    assert_legal_transition,
    generate_screen_session_id,
)
from guardianmesh.screen.registry import ScreenSessionRegistry


@dataclass
class ScreenSessionConfig:
    """Configuration for a single :class:`ScreenSession`."""

    max_duration_seconds: int = DEFAULT_MAX_DURATION_SECONDS
    inactivity_timeout_seconds: int = 60
    width: int = 1280
    height: int = 720
    max_fps: int = 10
    codec: ScreenCodec = ScreenCodec.TEST
    pixel_format: PixelFormat = PixelFormat.TEST
    max_queue_size: int = 30
    backpressure: BackpressureStrategy = BackpressureStrategy.DROP_OLDEST
    max_frame_bytes: int = 4 * 1024 * 1024
    label: str | None = None

    def __post_init__(self) -> None:
        if self.max_duration_seconds <= 0:
            raise ScreenSessionError("max_duration_seconds must be positive.")
        if self.width <= 0 or self.height <= 0:
            raise ScreenSessionError("width and height must be positive.")
        if self.max_fps <= 0:
            raise ScreenSessionError("max_fps must be positive.")
        if self.max_queue_size <= 0:
            raise ScreenSessionError("max_queue_size must be positive.")
        if self.max_frame_bytes <= 0:
            raise ScreenSessionError("max_frame_bytes must be positive.")


class ScreenSession:
    """One in-flight screen view session, with bounded resources.

    The session owns a :class:`FrameStreamBuffer` for in-memory frame
    delivery and an in-memory :class:`ScreenIndicator` for the child-side
    UI. The persistent record is mirrored in the SQLite database via a
    :class:`ScreenSessionRegistry`.
    """

    def __init__(
        self,
        info: ScreenSessionInfo,
        config: ScreenSessionConfig,
        registry: ScreenSessionRegistry | None = None,
        auth_manager: ScreenAuthorizationManager | None = None,
        indicator: ScreenIndicator | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._info = info
        self._config = config
        self._registry = registry
        self._auth_manager = auth_manager
        self._indicator = indicator or ScreenIndicator()
        self._buffer = FrameStreamBuffer(
            session_id=info.session_id,
            max_queue_size=config.max_queue_size,
            backpressure=config.backpressure,
            validator=FrameValidator(
                max_width=config.width,
                max_height=config.height,
                max_payload_bytes=config.max_frame_bytes,
                max_fps=config.max_fps,
            ),
        )
        self._last_activity_at: datetime.datetime = datetime.datetime.now(datetime.UTC)
        self._closed = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._info.session_id

    @property
    def info(self) -> ScreenSessionInfo:
        return self._info

    @property
    def state(self) -> ScreenSessionState:
        with self._lock:
            return self._info.state

    @property
    def indicator(self) -> ScreenIndicator:
        return self._indicator

    @property
    def buffer(self) -> FrameStreamBuffer:
        return self._buffer

    @property
    def is_active(self) -> bool:
        return self.state == ScreenSessionState.ACTIVE

    @property
    def is_terminal(self) -> bool:
        return self._info.is_terminal

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def transition_to(self, target: ScreenSessionState) -> None:
        """Move the session to ``target`` with a legal-transition check."""
        with self._lock:
            assert_legal_transition(self._info.state, target)
            self._info.state = target
            self._persist()
            self._update_indicator()

    def request(
        self, device_id: str, parent_id: str, max_duration_seconds: int | None = None
    ) -> None:
        """Begin a new request: state goes REQUESTED -> PENDING_CHILD_APPROVAL."""
        with self._lock:
            if self._info.state != ScreenSessionState.REQUESTED:
                raise ScreenSessionStateError(
                    f"Session is in state {self._info.state.value}; cannot request."
                )
            self._info.device_id = device_id
            self._info.parent_id = parent_id
            if max_duration_seconds is not None and max_duration_seconds > 0:
                self._info.expires_at = (
                    datetime.datetime.now(datetime.UTC)
                    + datetime.timedelta(seconds=max_duration_seconds)
                ).isoformat()
            assert_legal_transition(
                self._info.state, ScreenSessionState.PENDING_CHILD_APPROVAL
            )
            self._info.state = ScreenSessionState.PENDING_CHILD_APPROVAL
            self._persist()

    def approve(self, authorization_id: str) -> None:
        """Apply child-side APPROVAL to the session."""
        with self._lock:
            if not self._auth_manager:
                raise ScreenSessionError("Authorization manager not configured.")
            self._auth_manager.approve(authorization_id)
            self._info.authorization_id = authorization_id
            now = datetime.datetime.now(datetime.UTC).isoformat()
            self._info.approved_at = now
            self.transition_to(ScreenSessionState.APPROVED)

    def deny(self, authorization_id: str) -> None:
        """Apply child-side DENIAL to the session."""
        with self._lock:
            if not self._auth_manager:
                raise ScreenSessionError("Authorization manager not configured.")
            self._auth_manager.deny(authorization_id)
            self._info.authorization_id = authorization_id
            assert_legal_transition(
                self._info.state, ScreenSessionState.DENIED
            )
            self._info.state = ScreenSessionState.DENIED
            self._info.stopped_at = datetime.datetime.now(datetime.UTC).isoformat()
            self._info.stop_reason = StopReason.CHILD_STOPPED
            self._indicator.deactivate()
            self._closed = True
            self._persist()

    def start(self) -> None:
        """Move APPROVED -> ACTIVE. No-op if not in APPROVED."""
        with self._lock:
            if self._info.state != ScreenSessionState.APPROVED:
                raise ScreenSessionStateError(
                    f"Cannot start session in state {self._info.state.value}."
                )
            now = datetime.datetime.now(datetime.UTC)
            self._info.started_at = now.isoformat()
            self._last_activity_at = now
            self.transition_to(ScreenSessionState.ACTIVE)
            self._indicator.activate(
                session_id=self._info.session_id,
                parent_label=self._info.label or self._info.parent_id,
                max_duration_seconds=self._config.max_duration_seconds,
                started_at=self._info.started_at or now.isoformat(),
            )

    def stop(
        self,
        reason: StopReason = StopReason.PARENT_STOPPED,
    ) -> None:
        """Terminate the session and deactivate the child-side indicator."""
        with self._lock:
            if self._info.state in (
                ScreenSessionState.STOPPED,
                ScreenSessionState.DENIED,
                ScreenSessionState.EXPIRED,
                ScreenSessionState.REVOKED,
            ):
                return  # Already terminal.
            assert_legal_transition(self._info.state, ScreenSessionState.STOPPED)
            self._info.state = ScreenSessionState.STOPPED
            self._info.stopped_at = datetime.datetime.now(datetime.UTC).isoformat()
            self._info.stop_reason = reason
            self._indicator.deactivate()
            self._buffer.clear()
            self._closed = True
            self._persist()

    def expire(self) -> None:
        """Mark the session as expired and tear it down."""
        with self._lock:
            if self._info.state in (
                ScreenSessionState.STOPPED,
                ScreenSessionState.DENIED,
                ScreenSessionState.EXPIRED,
                ScreenSessionState.REVOKED,
            ):
                return
            assert_legal_transition(self._info.state, ScreenSessionState.EXPIRED)
            self._info.state = ScreenSessionState.EXPIRED
            self._info.stopped_at = datetime.datetime.now(datetime.UTC).isoformat()
            self._info.stop_reason = StopReason.EXPIRED
            self._indicator.deactivate()
            self._buffer.clear()
            self._closed = True
            self._persist()

    def revoke_due_to_trust(self) -> None:
        """Terminate immediately because trust was revoked."""
        with self._lock:
            if self._info.state in (
                ScreenSessionState.STOPPED,
                ScreenSessionState.DENIED,
                ScreenSessionState.EXPIRED,
                ScreenSessionState.REVOKED,
            ):
                return
            assert_legal_transition(self._info.state, ScreenSessionState.REVOKED)
            self._info.state = ScreenSessionState.REVOKED
            self._info.stopped_at = datetime.datetime.now(datetime.UTC).isoformat()
            self._info.stop_reason = StopReason.TRUST_REVOKED
            self._indicator.deactivate()
            self._buffer.clear()
            self._closed = True
            self._persist()

    # ------------------------------------------------------------------
    # Frame ingestion
    # ------------------------------------------------------------------

    def ingest_frame(self, frame: ScreenFrame) -> bool:
        """Validate and enqueue a frame. Only valid in ACTIVE state."""
        with self._lock:
            if self._closed:
                raise ScreenFrameError("Session is closed; cannot ingest frames.")
            if self._info.state != ScreenSessionState.ACTIVE:
                raise ScreenFrameError(
                    f"Cannot ingest frames in state {self._info.state.value}."
                )
            accepted = self._buffer.ingest(frame)
            now = datetime.datetime.now(datetime.UTC)
            self._last_activity_at = now
            if accepted:
                self._info.frame_count += 1
                self._info.bytes_sent += len(frame.payload)
                self._info.last_frame_at = now.isoformat()
                self._indicator.update_remaining(self._info.remaining_seconds)
                self._persist()
            return accepted

    # ------------------------------------------------------------------
    # Health & lifecycle helpers
    # ------------------------------------------------------------------

    def check_lifecycle(self) -> bool:
        """Check expiration and inactivity. Returns True if the session was torn down."""
        with self._lock:
            if self._info.is_terminal:
                return True
            now = datetime.datetime.now(datetime.UTC)
            if self._info.is_expired:
                self.expire()
                return True
            if (
                self._info.state == ScreenSessionState.ACTIVE
                and (now - self._last_activity_at).total_seconds()
                >= self._config.inactivity_timeout_seconds
            ):
                self._info.stop_reason = StopReason.INACTIVITY
                self.stop(StopReason.INACTIVITY)
                return True
            return False

    # ------------------------------------------------------------------
    # Snapshot / diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "session": self._info.to_dict(),
                "buffer": self._buffer.summary(),
                "indicator_active": self._indicator.is_active,
                "indicator": self._indicator.render(),
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _persist(self) -> None:
        if self._registry is not None:
            try:
                self._registry.upsert(self._info)
            except Exception:
                # Persistence failure is non-fatal for in-memory operations;
                # callers may still operate on the in-memory state.
                pass

    def _update_indicator(self) -> None:
        if self._info.state in (
            ScreenSessionState.STOPPED,
            ScreenSessionState.DENIED,
            ScreenSessionState.EXPIRED,
            ScreenSessionState.REVOKED,
        ):
            self._indicator.deactivate()
        elif self._info.state == ScreenSessionState.ACTIVE:
            self._indicator.activate(
                session_id=self._info.session_id,
                parent_label=self._info.label or self._info.parent_id,
                max_duration_seconds=self._config.max_duration_seconds,
                started_at=self._info.started_at
                or self._info.requested_at
                or datetime.datetime.now(datetime.UTC).isoformat(),
            )
            self._indicator.update_remaining(self._info.remaining_seconds)


class ScreenSessionManager:
    """In-memory registry of :class:`ScreenSession` instances keyed by session_id.

    The manager is the *control plane* for active screen sessions. It
    delegates persistence to :class:`ScreenSessionRegistry` but never
    persists frame content.
    """

    def __init__(
        self,
        registry: ScreenSessionRegistry,
        auth_manager: ScreenAuthorizationManager | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, ScreenSession] = {}
        self._registry = registry
        self._auth_manager = auth_manager or ScreenAuthorizationManager()

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    def create_session(
        self,
        device_id: str,
        parent_id: str,
        config: ScreenSessionConfig | None = None,
        transport_session_id: str | None = None,
    ) -> ScreenSession:
        """Create a new :class:`ScreenSession` in REQUESTED state."""
        cfg = config or ScreenSessionConfig()
        now = datetime.datetime.now(datetime.UTC)
        info = ScreenSessionInfo(
            session_id=generate_screen_session_id(),
            device_id=device_id,
            parent_id=parent_id,
            state=ScreenSessionState.REQUESTED,
            transport_session_id=transport_session_id,
            requested_at=now.isoformat(),
            expires_at=(
                now + datetime.timedelta(seconds=cfg.max_duration_seconds)
            ).isoformat(),
            width=cfg.width,
            height=cfg.height,
            codec=cfg.codec,
            max_fps=cfg.max_fps,
            label=cfg.label,
        )
        session = ScreenSession(
            info=info,
            config=cfg,
            registry=self._registry,
            auth_manager=self._auth_manager,
        )
        with self._lock:
            self._sessions[session.session_id] = session
        return session

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, session_id: str) -> ScreenSession | None:
        with self._lock:
            return self._sessions.get(session_id)

    def require(self, session_id: str) -> ScreenSession:
        sess = self.get(session_id)
        if sess is None:
            raise ScreenSessionError(
                f"Screen session '{session_id}' not found in manager."
            )
        return sess

    def list_all(self) -> list[ScreenSession]:
        with self._lock:
            return list(self._sessions.values())

    def list_active(self) -> list[ScreenSession]:
        with self._lock:
            return [s for s in self._sessions.values() if s.is_active]

    def list_for_device(self, device_id: str) -> list[ScreenSession]:
        with self._lock:
            return [s for s in self._sessions.values() if s.info.device_id == device_id]

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def sweep_lifecycle(self) -> list[str]:
        """Tear down expired/inactive sessions. Returns IDs that were terminated."""
        terminated: list[str] = []
        with self._lock:
            sessions = list(self._sessions.values())
        for s in sessions:
            if s.check_lifecycle():
                terminated.append(s.session_id)
        return terminated

    @property
    def auth_manager(self) -> ScreenAuthorizationManager:
        return self._auth_manager


__all__ = [
    "ScreenSession",
    "ScreenSessionConfig",
    "ScreenSessionManager",
]


# A small re-export to keep imports working in test code that may reach into
# this module for the exception hierarchy. The classes live in ``screen.errors``.
_ = (
    ScreenFrameValidationError,
    ScreenSessionExpiredError,
    ScreenSessionRevokedError,
    ScreenSessionStateError,
    uuid,
)
