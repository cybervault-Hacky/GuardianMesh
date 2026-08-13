"""Tests for the Aegis high-level controller."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from guardianmesh.aegis.consent import SystemConsentGate
from guardianmesh.aegis.controller import AegisController, AegisViewRequest
from guardianmesh.aegis.encoder import TestScreenEncoder
from guardianmesh.aegis.errors import (
    AegisAuthorizationRequiredError,
    AegisConsentRequiredError,
)
from guardianmesh.aegis.indicator_service import ForegroundServiceIndicator
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    FakeMediaProjectionProvider,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    AegisSessionState,
    EncoderBackend,
    ProviderCapabilities,
    SystemConsentState,
)
from guardianmesh.core.config import GuardianConfig
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def workspace(tmp_path: Path):
    """Create a fully initialized parent + child identity + trust fixture."""
    db_path = tmp_path / "aegis_controller.db"
    keys_dir = tmp_path / "keys"
    config = GuardianConfig(home_dir=tmp_path, keys_dir=keys_dir, log_dir=tmp_path / "logs")
    config.ensure_directories()

    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit_logger = AuditLogger(db)
    parent_ident, _ = identity_mgr.create_identity(
        role=IdentityRole.PARENT, label="Test Parent", set_active=True
    )
    child_ident, _ = identity_mgr.create_identity(
        role=IdentityRole.CHILD, label="Test Child", set_active=False
    )
    trust_mgr = TrustManager(db, audit_logger)
    trust_mgr.establish_trust(
        local_identity_id=parent_ident.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )
    controller = AegisController(
        db=db,
        config=config,
        trust_manager=trust_mgr,
        audit_logger=audit_logger,
        provider=AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX),
        encoder=TestScreenEncoder(),
    )
    return {
        "config": config,
        "db": db,
        "parent_id": parent_ident.id,
        "child_id": child_ident.id,
        "controller": controller,
        "audit_logger": audit_logger,
    }


def _request(workspace, screen_id: str = "SCN-1") -> AegisViewRequest:
    return AegisViewRequest(
        screen_session_id=screen_id,
        device_id=workspace["child_id"],
        parent_id=workspace["parent_id"],
        width=1280,
        height=720,
        max_fps=10,
    )


# ---------------------------------------------------------------------------
# Trust != authorization != system consent
# ---------------------------------------------------------------------------


def test_untrusted_device_cannot_create_session(workspace) -> None:
    """A device that is not trusted cannot be a target of a capture session."""
    controller: AegisController = workspace["controller"]
    parent_id: str = workspace["parent_id"]
    with pytest.raises(AegisAuthorizationRequiredError):
        controller.create_session(
            AegisViewRequest(
                screen_session_id="SCN-1",
                device_id="GM-C-00009999",
                parent_id=parent_id,
            )
        )


def test_trusted_device_can_create_but_not_capture(workspace) -> None:
    """A trusted device can create a session but cannot start capture without consent."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_request(workspace))
    assert session.state == AegisSessionState.INITIALIZED.value
    assert controller.consent_gate.evaluate(session.screen_session_id).allowed is False


def test_capture_blocked_without_system_consent(workspace) -> None:
    """start_capture refuses when the system consent is not granted."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_request(workspace))
    with pytest.raises(AegisConsentRequiredError):
        controller.start_capture(session.aegis_session_id)


# ---------------------------------------------------------------------------
# Full happy path
# ---------------------------------------------------------------------------


def test_full_consent_to_capture_lifecycle(workspace) -> None:
    """request -> consent -> grant -> capture works end-to-end on Android.

    This test uses a fake Android provider to simulate the real Android
    consent flow without requiring a physical device.
    """
    # Replace the provider with a fake Android one for this test.
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    fake_provider = FakeMediaProjectionProvider(cap)
    gate = SystemConsentGate(capability=cap)
    indicator = ForegroundServiceIndicator(capability=cap)
    controller = AegisController(
        db=workspace["db"],
        config=workspace["config"],
        trust_manager=workspace["controller"]._trust_manager,
        audit_logger=workspace["audit_logger"],
        provider=fake_provider,
        encoder=TestScreenEncoder(),
        consent_gate=gate,
        indicator=indicator,
    )

    # 1. Create session.
    session = controller.create_session(_request(workspace))
    assert session.state == AegisSessionState.INITIALIZED.value

    # 2. Request system consent.
    record = controller.request_system_consent(session.aegis_session_id)
    assert session.state == AegisSessionState.SYSTEM_CONSENT_REQUIRED.value

    # 3. Grant system consent.
    granted = controller.grant_system_consent(session.aegis_session_id, record.consent_token)
    assert granted.state == SystemConsentState.GRANTED
    assert session.state == AegisSessionState.SYSTEM_CONSENT_GRANTED.value

    # 4. Start capture.
    pipeline = controller.start_capture(session.aegis_session_id)
    assert session.state == AegisSessionState.CAPTURING.value
    assert pipeline.is_running
    assert indicator.is_active

    # 5. Stop capture.
    controller.stop_capture(session.aegis_session_id, reason="USER_STOPPED")
    assert session.state == AegisSessionState.STOPPED.value
    assert not indicator.is_active


def test_denial_terminates_session(workspace) -> None:
    """A denied system consent marks the session as denied."""
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    gate = SystemConsentGate(capability=cap)
    controller = AegisController(
        db=workspace["db"],
        config=workspace["config"],
        trust_manager=workspace["controller"]._trust_manager,
        audit_logger=workspace["audit_logger"],
        provider=AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX),
        encoder=TestScreenEncoder(),
        consent_gate=gate,
    )
    session = controller.create_session(_request(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.deny_system_consent(session.aegis_session_id, record.consent_token)
    assert session.state == AegisSessionState.SYSTEM_CONSENT_DENIED.value


# ---------------------------------------------------------------------------
# Linux behavior
# ---------------------------------------------------------------------------


def test_linux_capture_is_always_refused(workspace) -> None:
    """On Linux, the controller refuses to start capture."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_request(workspace))
    with pytest.raises(AegisConsentRequiredError):
        controller.start_capture(session.aegis_session_id)


def test_linux_diagnostics_reports_linux(workspace) -> None:
    """Diagnostics on Linux report the Linux platform."""
    controller: AegisController = workspace["controller"]
    diag = controller.diagnostics()
    assert diag["platform"] == "LINUX"
    assert diag["provider_is_real_capture"] is False


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def test_diagnostics_exposes_metadata_only(workspace) -> None:
    """Diagnostics never include frame content."""
    controller: AegisController = workspace["controller"]
    diag = controller.diagnostics()
    forbidden = {"payload", "frame", "screenshot", "image", "pixels"}
    assert forbidden.isdisjoint(set(diag.keys()))


def test_list_providers_includes_active_provider(workspace) -> None:
    """list_providers includes the active provider."""
    controller: AegisController = workspace["controller"]
    providers = controller.list_providers()
    assert len(providers) == 1
    assert providers[0]["class"] == "AdapterOnlyMediaProjectionProvider"
    assert providers[0]["is_real_capture"] is False


def test_list_limits_returns_documented_bounds(workspace) -> None:
    """list_limits returns the documented Aegis hard limits."""
    controller: AegisController = workspace["controller"]
    limits = controller.list_limits()
    assert limits["max_fps"] == 10
    assert limits["max_width"] == 1280
    assert limits["max_height"] == 720
    assert limits["max_frame_bytes"] == 4 * 1024 * 1024
    assert limits["max_queue_size"] == 30


# ---------------------------------------------------------------------------
# Session lookup
# ---------------------------------------------------------------------------


def test_get_session_returns_created_session(workspace) -> None:
    """get_session returns the created session by ID."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_request(workspace))
    fetched = controller.get_session(session.aegis_session_id)
    assert fetched is not None
    assert fetched.aegis_session_id == session.aegis_session_id


def test_get_session_returns_none_for_unknown(workspace) -> None:
    """get_session returns None for an unknown session ID."""
    controller: AegisController = workspace["controller"]
    assert controller.get_session("AEG-MISSING") is None


def test_list_sessions_returns_created_sessions(workspace) -> None:
    """list_sessions returns all created sessions."""
    controller: AegisController = workspace["controller"]
    controller.create_session(_request(workspace, screen_id="SCN-A"))
    controller.create_session(_request(workspace, screen_id="SCN-B"))
    sessions = controller.list_sessions()
    assert len(sessions) == 2


# ---------------------------------------------------------------------------
# Expiration
# ---------------------------------------------------------------------------


def test_expire_due_marks_expired_sessions(workspace) -> None:
    """expire_due terminates sessions whose lifetime has elapsed."""
    controller: AegisController = workspace["controller"]
    session = controller.create_session(_request(workspace))
    # Manually set the session's expires_at to the past.
    session.expires_at = (
        datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=10)
    ).isoformat()
    expired = controller.expire_due()
    assert session.aegis_session_id in expired
    assert session.state == AegisSessionState.EXPIRED.value


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_session_creation_records_audit_event(workspace) -> None:
    """Creating a session records an AEGIS_SESSION_CREATED audit event."""
    controller: AegisController = workspace["controller"]
    audit: AuditLogger = workspace["audit_logger"]
    session = controller.create_session(_request(workspace))
    events = audit.get_recent(limit=20, event_type=AuditEventType.AEGIS_SESSION_CREATED)
    assert any(e["details"].get("aegis_session_id") == session.aegis_session_id for e in events)


def test_consent_request_records_audit_event(workspace) -> None:
    """Requesting system consent records the audit event."""
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    gate = SystemConsentGate(capability=cap)
    controller = AegisController(
        db=workspace["db"],
        config=workspace["config"],
        trust_manager=workspace["controller"]._trust_manager,
        audit_logger=workspace["audit_logger"],
        provider=AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX),
        encoder=TestScreenEncoder(),
        consent_gate=gate,
    )
    session = controller.create_session(_request(workspace))
    controller.request_system_consent(session.aegis_session_id)
    events = workspace["audit_logger"].get_recent(
        limit=20, event_type=AuditEventType.AEGIS_SYSTEM_CONSENT_REQUESTED
    )
    assert any(e["details"].get("aegis_session_id") == session.aegis_session_id for e in events)


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------


def test_audit_log_never_contains_frame_payload(workspace) -> None:
    """Audit events for Aegis sessions must not contain frame payload bytes."""
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    gate = SystemConsentGate(capability=cap)
    indicator = ForegroundServiceIndicator(capability=cap)
    fake_provider = FakeMediaProjectionProvider(cap)
    controller = AegisController(
        db=workspace["db"],
        config=workspace["config"],
        trust_manager=workspace["controller"]._trust_manager,
        audit_logger=workspace["audit_logger"],
        provider=fake_provider,
        encoder=TestScreenEncoder(),
        consent_gate=gate,
        indicator=indicator,
    )
    secret = b"FRAMESECRETx"
    session = controller.create_session(_request(workspace))
    record = controller.request_system_consent(session.aegis_session_id)
    controller.grant_system_consent(session.aegis_session_id, record.consent_token)
    controller.start_capture(session.aegis_session_id)
    # The audit log is metadata only. The secret bytes never appear.
    events = workspace["audit_logger"].get_recent(limit=200)
    for ev in events:
        details_json = json.dumps(ev.get("details", {}))
        assert secret.decode("utf-8", errors="ignore") not in details_json
        assert "screenshot" not in details_json
        assert "frame_data" not in details_json
        assert "raw_pixels" not in details_json
    controller.stop_capture(session.aegis_session_id, reason="TEST_DONE")
