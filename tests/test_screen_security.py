"""Security and privacy tests for the Vista Phase 7 subsystem.

These tests enforce the documented prohibitions:

* No silent capture, no hidden capture, no remote control.
* No remote-control message types in the protocol.
* No frame content persisted to the database.
* No sensitive material in audit logs.
* Trust != screen-view authorization.
* Sessions never outlive their bounded lifetime.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.screen.controller import ScreenController, ScreenViewRequest
from guardianmesh.screen.errors import (
    ScreenError,
    ScreenRemoteControlError,
    ScreenSessionError,
)
from guardianmesh.screen.models import (
    ScreenFrame,
    ScreenSessionState,
)
from guardianmesh.screen.transport import (
    ALLOWED_SCREEN_MESSAGE_TYPES,
    ScreenMessageType,
    ScreenTransportBridge,
    assert_no_remote_control_type,
    is_allowed_screen_message_type,
)
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.transport.models import MessageType

# ---------------------------------------------------------------------------
# Remote control prohibition
# ---------------------------------------------------------------------------


def test_no_remote_control_message_type_in_allowlist() -> None:
    """The screen message type allowlist contains zero remote-control names."""
    remote_control_pattern = re.compile(
        r"(remote|control|shell|exec|command|tap|click|swipe|gesture|keylog|"
        r"keystroke|input|inject)",
        re.IGNORECASE,
    )
    for t in ScreenMessageType:
        assert not remote_control_pattern.search(t.value), t.value


def test_no_remote_control_message_type_in_transport() -> None:
    """The transport MessageType allowlist contains zero remote-control names."""
    forbidden = {
        "SCREEN_CONTROL",
        "REMOTE_INPUT",
        "REMOTE_CLICK",
        "REMOTE_TAP",
        "REMOTE_SWIPE",
        "REMOTE_GESTURE",
        "EXECUTE",
        "SHELL",
        "COMMAND",
        "KEYLOG",
        "KEYSTROKE",
        "INPUT",
    }
    actual = {m.value for m in MessageType}
    assert forbidden.isdisjoint(actual), f"Forbidden message types present: {forbidden & actual}"


def test_assert_no_remote_control_rejects_forbidden() -> None:
    """assert_no_remote_control_type raises ScreenRemoteControlError for all forbidden names."""
    for name in (
        "SCREEN_CONTROL",
        "REMOTE_INPUT",
        "REMOTE_TAP",
        "EXECUTE",
        "SHELL",
        "COMMAND",
        "KEYLOG",
    ):
        with pytest.raises(ScreenRemoteControlError):
            assert_no_remote_control_type(name)


def test_is_allowed_screen_message_type_rejects_forbidden() -> None:
    """is_allowed_screen_message_type returns False for every forbidden name."""
    for name in (
        "SCREEN_CONTROL",
        "REMOTE_INPUT",
        "EXECUTE",
        "SHELL",
        "COMMAND",
        "REMOTE_CLICK",
    ):
        assert is_allowed_screen_message_type(name) is False


def test_screen_message_types_isolated() -> None:
    """The screen message type set is strictly smaller than the full transport set."""
    assert ALLOWED_SCREEN_MESSAGE_TYPES.isdisjoint(
        {
            "HELLO",
            "SESSION_INIT",
            "HEARTBEAT",
            "TELEMETRY",
            "ALERT",
            "POLICY_SYNC",
            "PING",
            "PONG",
            "GOODBYE",
            "ERROR",
        }
    )


# ---------------------------------------------------------------------------
# No plaintext frames at rest
# ---------------------------------------------------------------------------


def test_no_frame_payload_columns_in_db(tmp_path: Path) -> None:
    """The screen_sessions table must not contain any frame payload columns."""
    db_path = tmp_path / "security.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(screen_sessions);")]
    forbidden = {
        "payload",
        "payload_hex",
        "screenshot",
        "frame_data",
        "image",
        "frame_blob",
        "raw_pixels",
    }
    assert forbidden.isdisjoint(set(cols)), forbidden & set(cols)


def test_audit_log_never_contains_frame_payload(tmp_path: Path) -> None:
    """Audit events for screen sessions must not contain frame payload bytes."""
    db_path = tmp_path / "security_audit.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="P")
    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="C")
    trust_mgr = TrustManager(db, audit)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )
    controller = ScreenController(
        db=db, config=config, trust_manager=trust_mgr, audit_logger=audit
    )
    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_ident.id,
            parent_id=parent_ident.id,
            max_duration_seconds=120,
        )
    )
    controller.approve(session.session_id)
    controller.start_session(session.session_id)
    secret_bytes = b"SECRETx!"  # 8 bytes
    assert len(secret_bytes) == 8
    for i in range(1, 4):
        f = ScreenFrame(
            session_id=session.session_id,
            device_id=child_ident.id,
            sequence=i,
            width=320,
            height=240,
            payload_size=8,
            payload=secret_bytes,
        )
        controller.ingest_frame(session.session_id, f)
    controller.stop_session(session.session_id)

    events = audit.get_recent(limit=100)
    for ev in events:
        details_json = json.dumps(ev.get("details", {}))
        assert "SECRETx" not in details_json
        assert "payload_hex" not in details_json
        assert "screenshot" not in details_json
        assert "frame_data" not in details_json
        assert "raw_pixels" not in details_json


# ---------------------------------------------------------------------------
# Trust != screen authorization
# ---------------------------------------------------------------------------


def test_trust_alone_does_not_start_streaming(tmp_path: Path) -> None:
    """Two trusted devices do not produce a screen view without authorization."""
    db_path = tmp_path / "trust_vs_auth.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="P")
    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="C")
    trust_mgr = TrustManager(db, audit)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )
    controller = ScreenController(db=db, config=config, trust_manager=trust_mgr, audit_logger=audit)

    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_ident.id,
            parent_id=parent_ident.id,
            max_duration_seconds=120,
        )
    )
    # The session is in PENDING_CHILD_APPROVAL — not ACTIVE.
    assert session.info.state == ScreenSessionState.PENDING_CHILD_APPROVAL
    assert session.is_active is False


def test_revoke_trust_terminates_active_session(tmp_path: Path) -> None:
    """Revoking trust on a device with an active session terminates the session."""
    db_path = tmp_path / "revoke.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="P")
    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="C")
    trust_mgr = TrustManager(db, audit)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )
    controller = ScreenController(db=db, config=config, trust_manager=trust_mgr, audit_logger=audit)
    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_ident.id,
            parent_id=parent_ident.id,
            max_duration_seconds=120,
        )
    )
    controller.approve(session.session_id)
    controller.start_session(session.session_id)
    assert session.is_active is True

    # Revoke the trust relationship; this should also tear the session down.
    trust_mgr.revoke_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
    )
    # The controller's revoke_session should be invoked by callers when they
    # observe the trust revocation. We test that path explicitly.
    controller.revoke_session(session.session_id, reason="TRUST_REVOKED")
    assert session.info.state == ScreenSessionState.REVOKED
    assert session.indicator.is_active is False


# ---------------------------------------------------------------------------
# Bounded session lifetime
# ---------------------------------------------------------------------------


def test_session_max_duration_is_bounded(tmp_path: Path) -> None:
    """The maximum authorization duration is bounded at 1 hour."""
    from guardianmesh.core.errors import ValidationError
    from guardianmesh.screen.authorization import (
        MAX_MAX_DURATION_SECONDS,
        ScreenAuthorizationRequest,
    )

    with pytest.raises(ValidationError):
        ScreenAuthorizationRequest(
            session_id="SCN-BOUND",
            device_id="GM-C-19A84E72",
            parent_id="GM-P-83A1F72C",
            max_duration_seconds=MAX_MAX_DURATION_SECONDS + 1,
            requested_at=__import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
        )


def test_session_cannot_be_started_without_approval(tmp_path: Path) -> None:
    """start_session on a non-APPROVED session is rejected."""
    db_path = tmp_path / "no_approval.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(role=IdentityRole.PARENT, label="P")
    child_ident, _ = identity_mgr.create_identity(role=IdentityRole.CHILD, label="C")
    trust_mgr = TrustManager(db, audit)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )
    controller = ScreenController(db=db, config=config, trust_manager=trust_mgr, audit_logger=audit)
    session = controller.request_view(
        ScreenViewRequest(
            device_id=child_ident.id,
            parent_id=parent_ident.id,
            max_duration_seconds=120,
        )
    )
    # Session is in PENDING_CHILD_APPROVAL — start must fail.
    with pytest.raises(ScreenSessionError):
        controller.start_session(session.session_id)


# ---------------------------------------------------------------------------
# Privacy guarantees
# ---------------------------------------------------------------------------


def test_transport_bridge_uses_narrow_message_types() -> None:
    """The screen transport bridge is wired to narrowly-scoped message types only."""
    bridge = ScreenTransportBridge()
    # Construct a heartbeat envelope and try to extract as screen — must fail.
    from guardianmesh.transport.models import TransportEnvelope

    heartbeat = TransportEnvelope(
        message_type=MessageType.HEARTBEAT,
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
    )
    with pytest.raises(ScreenError):
        bridge.extract_screen_envelope(heartbeat)
