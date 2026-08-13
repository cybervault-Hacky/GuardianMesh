"""Tests for screen session lifecycle management (Phase 7: Vista)."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.screen.authorization import ScreenAuthorizationManager
from guardianmesh.screen.errors import (
    ScreenFrameError,
    ScreenSessionError,
    ScreenSessionStateError,
)
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCodec,
    ScreenFrame,
    ScreenSessionInfo,
    ScreenSessionState,
    StopReason,
)
from guardianmesh.screen.registry import ScreenSessionRegistry
from guardianmesh.screen.session import (
    ScreenSession,
    ScreenSessionConfig,
    ScreenSessionManager,
)
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "session.db"


@pytest.fixture
def db(db_path: Path) -> Database:
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


@pytest.fixture
def registry(db: Database) -> ScreenSessionRegistry:
    return ScreenSessionRegistry(db)


def _frame(sequence: int, payload_size: int = 8) -> ScreenFrame:
    return ScreenFrame(
        session_id="SCN-LIFECYCLE",
        device_id="GM-C-19A84E72",
        sequence=sequence,
        width=320,
        height=240,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload_size=payload_size,
        payload=b"x" * payload_size,
    )


# ---------------------------------------------------------------------------
# ScreenSessionConfig
# ---------------------------------------------------------------------------


def test_config_rejects_zero_duration() -> None:
    """A non-positive max_duration_seconds is rejected."""
    with pytest.raises(ScreenSessionError):
        ScreenSessionConfig(max_duration_seconds=0)


def test_config_rejects_zero_dimensions() -> None:
    """Non-positive dimensions are rejected."""
    with pytest.raises(ScreenSessionError):
        ScreenSessionConfig(width=0, height=720)
    with pytest.raises(ScreenSessionError):
        ScreenSessionConfig(width=1280, height=0)


def test_config_rejects_zero_fps() -> None:
    """Non-positive max_fps is rejected."""
    with pytest.raises(ScreenSessionError):
        ScreenSessionConfig(max_fps=0)


def test_config_rejects_zero_queue_size() -> None:
    """Non-positive max_queue_size is rejected."""
    with pytest.raises(ScreenSessionError):
        ScreenSessionConfig(max_queue_size=0)


def test_config_rejects_zero_frame_bytes() -> None:
    """Non-positive max_frame_bytes is rejected."""
    with pytest.raises(ScreenSessionError):
        ScreenSessionConfig(max_frame_bytes=0)


# ---------------------------------------------------------------------------
# ScreenSession
# ---------------------------------------------------------------------------


def test_session_indicator_activates_on_start(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """The child-side indicator activates when the session starts."""
    auth_mgr = ScreenAuthorizationManager()
    info = _make_session_info("SCN-INDSTART")
    sess = ScreenSession(
        info=info,
        config=ScreenSessionConfig(max_duration_seconds=60),
        registry=registry,
        auth_manager=auth_mgr,
    )
    sess.request(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=60,
    )
    auth = auth_mgr.create_request(
        session_id="SCN-INDSTART",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=60,
    )
    sess.approve(auth.authorization_id)
    sess.start()
    assert sess.indicator.is_active is True
    assert "SCREEN VIEW ACTIVE" in sess.indicator.render()


def test_session_indicator_deactivates_on_stop(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """The child-side indicator deactivates when the session stops."""
    sess = _build_active_session(registry)
    sess.stop()
    assert sess.indicator.is_active is False
    assert "INACTIVE" in sess.indicator.render()


def test_session_frame_ingestion_only_when_active(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """Frame ingestion is rejected unless the session is ACTIVE."""
    sess = _build_active_session(registry)
    sess.stop()
    with pytest.raises(ScreenFrameError):
        sess.ingest_frame(_frame(1))


def test_session_state_transitions(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """A full REQUESTED -> PENDING -> APPROVED -> ACTIVE -> STOPPED path works."""
    sess = _build_active_session(registry)
    assert sess.info.state == ScreenSessionState.ACTIVE
    sess.stop()
    assert sess.info.state == ScreenSessionState.STOPPED
    assert sess.info.is_terminal is True


def test_session_stop_reason_recorded(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """The stop reason is recorded in the session info."""
    sess = _build_active_session(registry)
    sess.stop(reason=StopReason.CHILD_STOPPED)
    assert sess.info.stop_reason == StopReason.CHILD_STOPPED


def test_session_revoke_due_to_trust(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """Revocation transitions the session to REVOKED and tears down the indicator."""
    sess = _build_active_session(registry)
    assert sess.indicator.is_active is True
    sess.revoke_due_to_trust()
    assert sess.info.state == ScreenSessionState.REVOKED
    assert sess.info.stop_reason == StopReason.TRUST_REVOKED
    assert sess.indicator.is_active is False


def test_session_terminate_is_idempotent(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """Calling stop / expire / revoke multiple times is safe."""
    sess = _build_active_session(registry)
    sess.stop()
    sess.stop()  # no-op
    sess.expire()  # no-op
    sess.revoke_due_to_trust()  # no-op
    assert sess.info.state == ScreenSessionState.STOPPED


def test_session_expiration_transitions_to_expired(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """When expires_at has passed, the session transitions to EXPIRED."""
    sess = _build_active_session(registry)
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=10)).isoformat()
    sess.info.expires_at = past
    terminated = sess.check_lifecycle()
    assert terminated is True
    assert sess.info.state == ScreenSessionState.EXPIRED
    assert sess.info.stop_reason == StopReason.EXPIRED


def test_session_inactivity_transitions_to_stopped(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """Excessive inactivity tears the session down."""
    auth_mgr = ScreenAuthorizationManager()
    info = _make_session_info("SCN-INACTIVE")
    sess = ScreenSession(
        info=info,
        config=ScreenSessionConfig(max_duration_seconds=300, inactivity_timeout_seconds=10),
        registry=registry,
        auth_manager=auth_mgr,
    )
    sess.request(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=300,
    )
    auth = auth_mgr.create_request(
        session_id="SCN-INACTIVE",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=300,
    )
    sess.approve(auth.authorization_id)
    sess.start()
    sess._last_activity_at = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
        seconds=120
    )
    terminated = sess.check_lifecycle()
    assert terminated is True
    assert sess.info.state == ScreenSessionState.STOPPED
    assert sess.info.stop_reason == StopReason.INACTIVITY


def test_session_buffer_tracks_frame_count(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """Each accepted frame increments the frame count and bytes sent."""
    sess = _build_active_session(registry)
    for i in range(1, 5):
        sess.ingest_frame(_frame(i))
    assert sess.info.frame_count == 4
    assert sess.info.bytes_sent == 4 * 8
    assert sess.info.last_frame_at is not None


def test_session_summary_contains_no_payload(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """The session summary never includes frame payloads."""
    sess = _build_active_session(registry)
    sess.ingest_frame(_frame(1))
    summary = sess.summary()
    serialized = str(summary)
    # The payload bytes are 8 'x' characters; ensure they are not leaked.
    assert "xxxxxxxx" not in serialized
    assert "buffer" in summary
    assert "indicator" in summary


# ---------------------------------------------------------------------------
# ScreenSessionManager
# ---------------------------------------------------------------------------


def test_manager_create_and_lookup(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """The manager creates and looks up sessions by ID."""
    mgr = ScreenSessionManager(registry=registry)
    sess = mgr.create_session(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    assert sess.info.state == ScreenSessionState.REQUESTED
    found = mgr.get(sess.session_id)
    assert found is not None
    assert found.session_id == sess.session_id


def test_manager_require_raises_for_unknown(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """require() raises if the session is unknown."""
    mgr = ScreenSessionManager(registry=registry)
    with pytest.raises(ScreenSessionError):
        mgr.require("SCN-UNKNOWN")


def test_manager_list_active(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """list_active returns only sessions in the ACTIVE state."""
    mgr = ScreenSessionManager(registry=registry)
    s1 = mgr.create_session(device_id="GM-C-A", parent_id="GM-P-A")
    s2 = mgr.create_session(device_id="GM-C-B", parent_id="GM-P-B")
    s1.request(device_id="GM-C-A", parent_id="GM-P-A", max_duration_seconds=30)
    s1.transition_to(ScreenSessionState.APPROVED)
    s1.start()
    s2.request(device_id="GM-C-B", parent_id="GM-P-B", max_duration_seconds=30)
    s2.transition_to(ScreenSessionState.APPROVED)
    active = mgr.list_active()
    assert len(active) == 1
    assert active[0].session_id == s1.session_id


def test_manager_sweep_lifecycle_terminates_expired(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """sweep_lifecycle terminates sessions that have expired."""
    mgr = ScreenSessionManager(registry=registry)
    sess = mgr.create_session(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    sess.request(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=30,
    )
    sess.transition_to(ScreenSessionState.APPROVED)
    sess.start()
    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)).isoformat()
    sess.info.expires_at = past
    terminated = mgr.sweep_lifecycle()
    assert sess.session_id in terminated
    assert sess.info.state == ScreenSessionState.EXPIRED


def test_manager_remove(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """remove() drops a session from the in-memory map."""
    mgr = ScreenSessionManager(registry=registry)
    sess = mgr.create_session(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
    )
    mgr.remove(sess.session_id)
    assert mgr.get(sess.session_id) is None


def test_illegal_state_transition_rejected(
    db: Database, registry: ScreenSessionRegistry
) -> None:
    """transition_to() refuses illegal target states."""
    sess = _build_active_session(registry)
    sess.stop()
    # Cannot go from STOPPED back to ACTIVE.
    with pytest.raises(ScreenSessionStateError):
        sess.transition_to(ScreenSessionState.ACTIVE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session_info(session_id: str) -> ScreenSessionInfo:
    now = datetime.datetime.now(datetime.UTC)
    return ScreenSessionInfo(
        session_id=session_id,
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        state=ScreenSessionState.REQUESTED,
        requested_at=now.isoformat(),
        expires_at=(now + datetime.timedelta(seconds=300)).isoformat(),
        width=320,
        height=240,
        codec=ScreenCodec.TEST,
        max_fps=10,
    )


def _build_active_session(
    registry: ScreenSessionRegistry,
) -> ScreenSession:
    auth_mgr = ScreenAuthorizationManager()
    info = _make_session_info("SCN-LIFECYCLE")
    sess = ScreenSession(
        info=info,
        config=ScreenSessionConfig(max_duration_seconds=300),
        registry=registry,
        auth_manager=auth_mgr,
    )
    sess.request(
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=300,
    )
    auth = auth_mgr.create_request(
        session_id="SCN-LIFECYCLE",
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        max_duration_seconds=300,
    )
    sess.approve(auth.authorization_id)
    sess.start()
    return sess
