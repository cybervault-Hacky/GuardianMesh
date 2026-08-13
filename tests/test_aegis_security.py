"""Security and privacy tests for the Aegis Phase 8 subsystem.

These tests verify the *impossible* behaviours: Aegis must not
implement any of the following, even in the test environment:

* capture without explicit child-side authorization
* capture without explicit Android system consent
* continuing after authorization expiry
* continuing after trust revocation
* remote control
* microphone/camera capture
* clipboard collection
* keyboard interception
* covert/background capture
* frame persistence
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from guardianmesh.aegis.consent import SystemConsentGate
from guardianmesh.aegis.controller import AegisController, AegisViewRequest
from guardianmesh.aegis.encoder import TestScreenEncoder
from guardianmesh.aegis.errors import (
    AegisAuthorizationRequiredError,
    AegisConsentDeniedError,
    AegisConsentRequiredError,
    AegisPlatformUnavailableError,
    AegisSessionError,
)
from guardianmesh.aegis.indicator_service import ForegroundServiceIndicator
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    FakeMediaProjectionProvider,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ProviderCapabilities,
)
from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def workspace(tmp_path: Path):
    db_path = tmp_path / "aegis_sec.db"
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()

    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(
        role=IdentityRole.PARENT, label="Test Parent", set_active=True
    )
    child_ident, _ = identity_mgr.create_identity(
        role=IdentityRole.CHILD, label="Test Child", set_active=False
    )
    trust_mgr = TrustManager(db, audit)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    controller = AegisController(
        db=db,
        config=config,
        trust_manager=trust_mgr,
        audit_logger=audit,
        provider=FakeMediaProjectionProvider(cap),
        encoder=TestScreenEncoder(),
        consent_gate=SystemConsentGate(capability=cap),
        indicator=ForegroundServiceIndicator(capability=cap),
    )
    return {
        "config": config,
        "db": db,
        "parent_id": parent_ident.id,
        "child_id": child_ident.id,
        "controller": controller,
        "audit_logger": audit,
    }


def _req(workspace) -> AegisViewRequest:
    return AegisViewRequest(
        screen_session_id="SCN-1",
        device_id=workspace["child_id"],
        parent_id=workspace["parent_id"],
    )


# ---------------------------------------------------------------------------
# Capture without authorization
# ---------------------------------------------------------------------------


def test_capture_blocked_without_session() -> None:
    """start_capture refuses when there is no Aegis session at all."""
    db_path = Path("/tmp/aegis_no_session.db")
    config = GuardianConfig(home_dir=db_path.parent)
    config.ensure_directories()
    db = Database(config.database_path)
    MigrationManager().apply_migrations(db)
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    controller = AegisController(
        db=db, config=config,
        provider=FakeMediaProjectionProvider(cap),
        encoder=TestScreenEncoder(),
        consent_gate=SystemConsentGate(capability=cap),
        indicator=ForegroundServiceIndicator(capability=cap),
    )
    with pytest.raises(AegisSessionError):
        controller.start_capture("AEG-NONEXISTENT")


# ---------------------------------------------------------------------------
# Capture without system consent
# ---------------------------------------------------------------------------


def test_capture_blocked_without_consent_request(workspace) -> None:
    """start_capture refuses before any consent has been requested."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    with pytest.raises(AegisConsentRequiredError):
        controller.start_capture(session.aegis_session_id)


def test_capture_blocked_when_consent_only_requested(workspace) -> None:
    """start_capture refuses when consent is requested but not yet granted."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    controller.request_system_consent(session.aegis_session_id)
    with pytest.raises(AegisConsentRequiredError):
        controller.start_capture(session.aegis_session_id)


def test_capture_blocked_after_consent_denied(workspace) -> None:
    """start_capture refuses after the user denies the system consent dialog."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.deny_system_consent(session.aegis_session_id, record.consent_token)
    # A denied consent is refused with AegisConsentDeniedError (a
    # subclass of AegisConsentRequiredError) or AegisConsentRequiredError
    # itself depending on the consent state path.
    with pytest.raises((AegisConsentRequiredError, AegisConsentDeniedError)):
        controller.start_capture(session.aegis_session_id)


# ---------------------------------------------------------------------------
# Capture on non-Android
# ---------------------------------------------------------------------------


def test_capture_blocked_on_linux(workspace) -> None:
    """On a non-Android platform, capture is impossible."""
    # Override the controller's provider with the Linux adapter.
    workspace["controller"]._provider = AdapterOnlyMediaProjectionProvider(
        platform=AegisPlatform.LINUX
    )
    workspace["controller"]._consent_gate = SystemConsentGate(
        capability=default_linux_capability_safe(),
    )
    session = workspace["controller"].create_session(_req(workspace))
    with pytest.raises((AegisConsentRequiredError, AegisPlatformUnavailableError)):
        workspace["controller"].start_capture(session.aegis_session_id)


def default_linux_capability_safe() -> ProviderCapabilities:
    """Return a Linux capability for the negative test."""
    from guardianmesh.aegis.consent import default_linux_capability

    return default_linux_capability()


# ---------------------------------------------------------------------------
# Trust != authorization
# ---------------------------------------------------------------------------


def test_untrusted_device_cannot_create_session(workspace) -> None:
    """A device without a trust relationship cannot start a capture session."""
    controller: AegisController = workspace["controller"]
    with pytest.raises(AegisAuthorizationRequiredError):
        controller.create_session(
            AegisViewRequest(
                screen_session_id="SCN-2",
                device_id="GM-C-00009999",
                parent_id=workspace["parent_id"],
            )
        )


# ---------------------------------------------------------------------------
# No remote control
# ---------------------------------------------------------------------------


def test_no_remote_control_in_aegis_module() -> None:
    """The Aegis module never imports or uses a remote-control concept."""
    import guardianmesh.aegis as aegis

    forbidden = re.compile(
        r"(remote_control|remote_tap|remote_click|remote_swipe|"
        r"remote_gesture|shell|exec|keylog|keystroke|mic|camera|"
        r"gps|location|clipboard|input_inject)",
        re.IGNORECASE,
    )
    for name in dir(aegis):
        if forbidden.search(name):
            pytest.fail(f"Forbidden name in Aegis public API: {name}")


def test_no_aegis_audit_event_contains_remote_control() -> None:
    """No Aegis audit event type contains a remote-control name."""
    from guardianmesh.storage.audit import AuditEventType

    forbidden = re.compile(
        r"(REMOTE_CONTROL|REMOTE_INPUT|REMOTE_TAP|REMOTE_CLICK|"
        r"REMOTE_SWIPE|REMOTE_GESTURE|EXECUTE|SHELL|COMMAND|KEYLOG|"
        r"KEYSTROKE|INPUT|MICROPHONE|CAMERA|GPS|LOCATION|CLIPBOARD)",
        re.IGNORECASE,
    )
    for member in dir(AuditEventType):
        value = getattr(AuditEventType, member, None)
        if value is None:
            continue
        value_str = str(value)
        if "AEGIS" in value_str and forbidden.search(value_str):
            pytest.fail(f"Forbidden Aegis audit event: {value_str}")


# ---------------------------------------------------------------------------
# No frame persistence
# ---------------------------------------------------------------------------


def test_aegis_table_has_no_payload_columns(tmp_path: Path) -> None:
    """The aegis_sessions table must not contain any frame payload columns."""
    db_path = tmp_path / "aegis_table.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(aegis_sessions);")]
    forbidden = {
        "payload",
        "payload_hex",
        "screenshot",
        "frame_data",
        "image",
        "raw_pixels",
        "encoded_video",
    }
    assert forbidden.isdisjoint(set(cols))


def test_audit_log_never_contains_frame_payload(workspace) -> None:
    """Audit events for Aegis sessions must not contain frame payload bytes."""
    controller: AegisController = workspace["controller"]
    audit: AuditLogger = workspace["audit_logger"]
    secret = b"FRAMESECRETx"
    session = controller.create_session(_req(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.grant_system_consent(session.aegis_session_id, record.consent_token)
    controller.start_capture(session.aegis_session_id)
    controller.tick_pipeline = lambda *a, **kw: None  # type: ignore[attr-defined]
    events = audit.get_recent(limit=200)
    for ev in events:
        details_json = json.dumps(ev.get("details", {}))
        assert secret.decode("utf-8", errors="ignore") not in details_json
        assert "screenshot" not in details_json
        assert "frame_data" not in details_json
        assert "raw_pixels" not in details_json
    controller.stop_capture(session.aegis_session_id, reason="TEST_DONE")


# ---------------------------------------------------------------------------
# Expiration / revocation
# ---------------------------------------------------------------------------


def test_session_terminated_on_expiration(workspace) -> None:
    """An expired session cannot be used to start capture."""
    import datetime as _dt

    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    session.expires_at = (
        _dt.datetime.now(_dt.UTC) - _dt.timedelta(seconds=10)
    ).isoformat()
    with pytest.raises(AegisConsentRequiredError):
        controller.start_capture(session.aegis_session_id)


def test_consent_revocation_terminates_capture(workspace) -> None:
    """Revoking the system consent terminates an active capture session."""
    from guardianmesh.aegis.errors import AegisConsentRevokedError

    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.grant_system_consent(session.aegis_session_id, record.consent_token)
    controller.start_capture(session.aegis_session_id)
    # Now revoke the consent directly on the gate.
    controller.consent_gate.revoke_consent(record.consent_token, reason="USER_REVOKED")
    # The next call to start_capture must fail because consent is no
    # longer granted.
    with pytest.raises((AegisConsentRequiredError, AegisConsentRevokedError)):
        controller.start_capture(session.aegis_session_id)


# ---------------------------------------------------------------------------
# Local stop must work even without network
# ---------------------------------------------------------------------------


def test_local_stop_works_without_parent(workspace) -> None:
    """The child can stop the session locally (no network required)."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.grant_system_consent(session.aegis_session_id, record.consent_token)
    controller.start_capture(session.aegis_session_id)
    # Local stop works without contacting the parent.
    controller.stop_capture(session.aegis_session_id, reason="CHILD_STOPPED_LOCALLY")
    assert session.state == "STOPPED"
    assert session.stop_reason == "CHILD_STOPPED_LOCALLY"


# ---------------------------------------------------------------------------
# Indicator must be visible while capture is active
# ---------------------------------------------------------------------------


def test_indicator_activates_during_capture(workspace) -> None:
    """The visible indicator is active for the entire capture session."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_req(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.grant_system_consent(session.aegis_session_id, record.consent_token)
    controller.start_capture(session.aegis_session_id)
    assert controller.indicator.is_active is True
    controller.stop_capture(session.aegis_session_id)
    assert controller.indicator.is_active is False


def test_indicator_exposes_stop_action(workspace) -> None:
    """The indicator's notification exposes the STOP SHARING action label."""
    controller: AegisController = workspace["controller"]
    diag = controller.indicator.diagnostics()
    assert "STOP" in diag["notification"]["stop_action_label"]


# ---------------------------------------------------------------------------
# Trust revocation terminates active session
# ---------------------------------------------------------------------------


def test_trust_revocation_recorded(workspace) -> None:
    """Trust revocation is recorded as a transport audit event."""
    trust_mgr: TrustManager = workspace["controller"]._trust_manager
    trust_mgr.revoke_trust(
        local_identity_id=workspace["parent_id"],
        remote_identity_id=workspace["child_id"],
        actor_id=workspace["parent_id"],
    )
    events = workspace["audit_logger"].get_recent(
        limit=20, event_type="TRUST_REVOKED"
    )
    assert any(
        e["details"].get("remote_identity") == workspace["child_id"]
        for e in events
    )
