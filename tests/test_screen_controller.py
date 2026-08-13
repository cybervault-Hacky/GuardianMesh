"""Tests for the high-level ScreenController (Phase 7: Vista)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.screen.controller import ScreenController, ScreenViewRequest
from guardianmesh.screen.errors import (
    ScreenAuthorizationError,
    ScreenFrameError,
    ScreenSessionError,
)
from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCodec,
    ScreenFrame,
    ScreenSessionState,
    StopReason,
)
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def workspace(tmp_path: Path):
    """Create a fully initialized parent + child identity + trust fixture."""
    db_path = tmp_path / "controller.db"
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()

    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit_logger = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="Test Parent")
    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="Test Child")
    trust_mgr = TrustManager(db, audit_logger)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
        pairing_session_id="TEST-PAIR-001",
        label="Test Child",
    )
    controller = ScreenController(
        db=db,
        config=config,
        trust_manager=trust_mgr,
        audit_logger=audit_logger,
    )
    return {
        "config": config,
        "db": db,
        "parent_id": parent_ident.id,
        "child_id": child_ident.id,
        "controller": controller,
        "audit_logger": audit_logger,
    }


def _frame(
    session_id: str,
    device_id: str,
    sequence: int,
    payload_size: int = 8,
) -> ScreenFrame:
    return ScreenFrame(
        session_id=session_id,
        device_id=device_id,
        sequence=sequence,
        width=320,
        height=240,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload_size=payload_size,
        payload=b"x" * payload_size,
    )


# ---------------------------------------------------------------------------
# Trust != authorization
# ---------------------------------------------------------------------------


def test_trusted_device_still_requires_authorization(workspace) -> None:
    """Trust alone is insufficient to start streaming — authorization is required."""
    controller: ScreenController = workspace["controller"]
    child_id: str = workspace["child_id"]
    parent_id: str = workspace["parent_id"]

    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_id,
            parent_id=parent_id,
            max_duration_seconds=120,
        )
    )
    assert session.info.state == ScreenSessionState.PENDING_CHILD_APPROVAL
    # Session is NOT active even though the devices are trusted.
    assert session.is_active is False


def test_untrusted_device_cannot_request_view(workspace) -> None:
    """A device that is not trusted cannot be a target of a view request."""
    controller: ScreenController = workspace["controller"]
    parent_id: str = workspace["parent_id"]

    with pytest.raises(ScreenAuthorizationError):
        controller.request_view(
            ScreenViewRequest(
                device_id="GM-C-UNTRUSTED",
                parent_id=parent_id,
                max_duration_seconds=120,
            )
        )


# ---------------------------------------------------------------------------
# Full lifecycle
# ---------------------------------------------------------------------------


def test_full_authorization_to_active_lifecycle(workspace) -> None:
    """request -> approve -> start -> ingest -> drain -> stop is fully supported."""
    controller: ScreenController = workspace["controller"]
    child_id: str = workspace["child_id"]
    parent_id: str = workspace["parent_id"]

    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_id,
            parent_id=parent_id,
            max_duration_seconds=120,
        )
    )
    controller.approve(session.session_id)
    assert session.info.state == ScreenSessionState.APPROVED

    controller.start_session(session.session_id)
    assert session.info.state == ScreenSessionState.ACTIVE
    assert session.indicator.is_active is True

    # Ingest three frames.
    for i in range(1, 4):
        accepted = controller.ingest_frame(
            session.session_id,
            _frame(session.session_id, child_id, sequence=i),
        )
        assert accepted is True

    frames = controller.drain_frames(session.session_id)
    assert len(frames) == 3

    controller.stop_session(session.session_id, reason=StopReason.PARENT_STOPPED)
    assert session.info.state == ScreenSessionState.STOPPED


# ---------------------------------------------------------------------------
# Child stop control
# ---------------------------------------------------------------------------


def test_child_can_deny_request(workspace) -> None:
    """A child can explicitly deny a screen view request."""
    controller: ScreenController = workspace["controller"]
    child_id: str = workspace["child_id"]
    parent_id: str = workspace["parent_id"]

    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_id,
            parent_id=parent_id,
            max_duration_seconds=120,
        )
    )
    controller.deny(session.session_id)
    assert session.info.state == ScreenSessionState.DENIED


# ---------------------------------------------------------------------------
# Transport disconnect
# ---------------------------------------------------------------------------


def test_terminate_when_session_missing_raises(workspace) -> None:
    """stop_session on an unknown session raises ScreenSessionError."""
    controller: ScreenController = workspace["controller"]
    with pytest.raises(ScreenSessionError):
        controller.stop_session("SCN-NOT-EXIST")


# ---------------------------------------------------------------------------
# Frame ingestion guards
# ---------------------------------------------------------------------------


def test_ingest_rejects_inactive_state(workspace) -> None:
    """Frame ingestion is rejected unless the session is ACTIVE."""
    controller: ScreenController = workspace["controller"]
    child_id: str = workspace["child_id"]
    parent_id: str = workspace["parent_id"]

    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_id,
            parent_id=parent_id,
            max_duration_seconds=120,
        )
    )
    with pytest.raises(ScreenFrameError):
        controller.ingest_frame(
            session.session_id,
            _frame(session.session_id, child_id, sequence=1),
        )


# ---------------------------------------------------------------------------
# Trust revocation
# ---------------------------------------------------------------------------


def test_revoke_session_records_audit(workspace) -> None:
    """Revoking a session records a SCREEN_SESSION_REVOKED audit event."""
    controller: ScreenController = workspace["controller"]
    audit: AuditLogger = workspace["audit_logger"]
    child_id: str = workspace["child_id"]
    parent_id: str = workspace["parent_id"]

    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_id,
            parent_id=parent_id,
            max_duration_seconds=120,
        )
    )
    controller.approve(session.session_id)
    controller.start_session(session.session_id)
    controller.revoke_session(session.session_id, reason="TRUST_LOST")
    assert session.info.state == ScreenSessionState.REVOKED

    events = audit.get_recent(limit=20, event_type=AuditEventType.SCREEN_SESSION_REVOKED)
    assert any(e["details"].get("session_id") == session.session_id for e in events)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def test_diagnostics_exposes_metadata_only(workspace) -> None:
    """Diagnostics are metadata-only and do not leak frame payloads."""
    controller: ScreenController = workspace["controller"]
    diag = controller.diagnostics()
    d = diag.to_dict()
    assert "payload" not in d
    assert "screenshot" not in d
    assert "frame_data" not in d
    assert d["provider_is_real_capture"] is False
    assert d["transport_only"] is True


def test_status_returns_session_summary(workspace) -> None:
    """status() returns the session summary (metadata only)."""
    controller: ScreenController = workspace["controller"]
    child_id: str = workspace["child_id"]
    parent_id: str = workspace["parent_id"]
    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_id,
            parent_id=parent_id,
            max_duration_seconds=120,
        )
    )
    s = controller.status(session.session_id)
    assert s["session"]["session_id"] == session.session_id
    # The summary must not include any frame payload.
    blob = json.dumps(s)
    assert "payload_hex" not in blob
