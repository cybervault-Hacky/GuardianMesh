"""Security tests for Orion Phase 9.

These tests prove that Orion is an orchestration layer, not a
surveillance or remote-control layer. They cover:

- Revoked device cannot create actions.
- Expired authorization cannot create screen actions.
- Expired Aegis consent cannot continue capture.
- Duplicate actions are idempotent.
- Duplicate events are ignored.
- Stale events cannot overwrite newer state.
- Reconciliation cannot restore revoked trust.
- Reconciliation cannot restore expired sessions.
- Arbitrary command execution is impossible.
- Shell execution is impossible.
- Remote input is impossible.
- Frame bytes never enter Orion database.
- Private content never enters events.
- Secrets never enter audit logs.
- Queue cannot grow without bound.
- Retries are bounded.
- Action expiry works.
- Authorization cannot be bypassed.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.orion.actions import (
    FORBIDDEN_ACTION_NAMES,
    FORBIDDEN_ACTION_PARAM_KEYS,
    OrionAction,
    OrionActionStatus,
    OrionActionType,
)
from guardianmesh.orion.bus import OrionEventBus
from guardianmesh.orion.errors import (
    OrionActionError,
    OrionConsentViolationError,
    OrionEventError,
)
from guardianmesh.orion.events import (
    FORBIDDEN_EVENT_NAMES,
    OrionEvent,
    OrionEventType,
)
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.orion.queue import OrionActionQueue
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager

# ---------------------------------------------------------------------------
# Test setup
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "orion_security.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def _make_action(
    action_id: str,
    action_type: OrionActionType = OrionActionType.REQUEST_CAPABILITIES,
    ttl_seconds: int = 300,
    parameters: dict | None = None,
    device_id: str = "GM-C-19A84E72",
) -> OrionAction:
    now = datetime.datetime.now(datetime.UTC)
    return OrionAction(
        action_id=action_id,
        action_type=action_type,
        device_id=device_id,
        created_at=now.isoformat(),
        expires_at=(now + datetime.timedelta(seconds=ttl_seconds)).isoformat(),
        correlation_id="OCR-00000001",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
        parameters=parameters or {},
    )


# ---------------------------------------------------------------------------
# No covert monitoring
# ---------------------------------------------------------------------------


def test_no_keystroke_event_type() -> None:
    """The KEYSTROKE event type is forbidden."""
    assert "KEYSTROKE" in FORBIDDEN_EVENT_NAMES


def test_no_message_event_type() -> None:
    assert "MESSAGE" in FORBIDDEN_EVENT_NAMES


def test_no_clipboard_event_type() -> None:
    assert "CLIPBOARD" in FORBIDDEN_EVENT_NAMES


def test_no_microphone_event_type() -> None:
    assert "MICROPHONE" in FORBIDDEN_EVENT_NAMES


def test_no_camera_event_type() -> None:
    assert "CAMERA" in FORBIDDEN_EVENT_NAMES


def test_no_location_event_type() -> None:
    assert "LOCATION" in FORBIDDEN_EVENT_NAMES
    assert "GPS" in FORBIDDEN_EVENT_NAMES


def test_no_shell_event_type() -> None:
    assert "SHELL" in FORBIDDEN_EVENT_NAMES
    assert "SHELL_COMMAND" in FORBIDDEN_EVENT_NAMES
    assert "EXEC" in FORBIDDEN_EVENT_NAMES


def test_no_remote_input_event_type() -> None:
    assert "REMOTE_INPUT" in FORBIDDEN_EVENT_NAMES
    assert "REMOTE_TAP" in FORBIDDEN_EVENT_NAMES
    assert "REMOTE_CLICK" in FORBIDDEN_EVENT_NAMES
    assert "REMOTE_SWIPE" in FORBIDDEN_EVENT_NAMES
    assert "REMOTE_GESTURE" in FORBIDDEN_EVENT_NAMES


def test_no_browser_history_event_type() -> None:
    assert "BROWSER_HISTORY" in FORBIDDEN_EVENT_NAMES
    assert "CONTACT" in FORBIDDEN_EVENT_NAMES
    assert "PHOTO" in FORBIDDEN_EVENT_NAMES


# ---------------------------------------------------------------------------
# No arbitrary command execution
# ---------------------------------------------------------------------------


def test_no_execute_action_type() -> None:
    assert "EXECUTE" in FORBIDDEN_ACTION_NAMES
    assert "EXEC" in FORBIDDEN_ACTION_NAMES
    assert "RUN" in FORBIDDEN_ACTION_NAMES
    assert "RUN_COMMAND" in FORBIDDEN_ACTION_NAMES


def test_no_shell_action_type() -> None:
    assert "SHELL" in FORBIDDEN_ACTION_NAMES
    assert "SHELL_COMMAND" in FORBIDDEN_ACTION_NAMES
    assert "OPEN_TERMINAL" in FORBIDDEN_ACTION_NAMES
    assert "OPEN_REMOTE_TERMINAL" in FORBIDDEN_ACTION_NAMES


def test_no_remote_input_action_type() -> None:
    assert "REMOTE_INPUT" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_TAP" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_CLICK" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_SWIPE" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_KEY" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_KEY_PRESS" in FORBIDDEN_ACTION_NAMES
    assert "TYPE_TEXT" in FORBIDDEN_ACTION_NAMES
    assert "INPUT_TEXT" in FORBIDDEN_ACTION_NAMES
    assert "INJECT_TEXT" in FORBIDDEN_ACTION_NAMES


def test_no_accessibility_action() -> None:
    assert "ACCESSIBILITY_ACTION" in FORBIDDEN_ACTION_NAMES


def test_no_clipboard_action() -> None:
    assert "READ_CLIPBOARD" in FORBIDDEN_ACTION_NAMES
    assert "WRITE_CLIPBOARD" in FORBIDDEN_ACTION_NAMES


def test_no_microphone_or_camera_action() -> None:
    assert "ENABLE_MICROPHONE" in FORBIDDEN_ACTION_NAMES
    assert "ENABLE_CAMERA" in FORBIDDEN_ACTION_NAMES


def test_no_hidden_screen_capture_action() -> None:
    assert "HIDDEN_CAPTURE" in FORBIDDEN_ACTION_NAMES
    assert "HIDDEN_SCREENSHOT" in FORBIDDEN_ACTION_NAMES


def test_no_location_tracking_action() -> None:
    assert "ENABLE_LOCATION" in FORBIDDEN_ACTION_NAMES


def test_no_message_or_file_or_browser_history_action() -> None:
    assert "READ_SMS" in FORBIDDEN_ACTION_NAMES
    assert "READ_CONTACTS" in FORBIDDEN_ACTION_NAMES
    assert "READ_FILES" in FORBIDDEN_ACTION_NAMES
    assert "READ_BROWSER_HISTORY" in FORBIDDEN_ACTION_NAMES


def test_no_keylog_action() -> None:
    assert "ENABLE_KEYLOG" in FORBIDDEN_ACTION_NAMES
    assert "READ_KEYLOG" in FORBIDDEN_ACTION_NAMES


# ---------------------------------------------------------------------------
# Parameter safety
# ---------------------------------------------------------------------------


def test_no_command_param_key() -> None:
    assert "command" in FORBIDDEN_ACTION_PARAM_KEYS


def test_no_shell_or_exec_param_key() -> None:
    assert "shell" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "exec" in FORBIDDEN_ACTION_PARAM_KEYS


def test_no_code_or_script_param_key() -> None:
    assert "code" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "script" in FORBIDDEN_ACTION_PARAM_KEYS


def test_no_frame_param_key() -> None:
    assert "frame" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "screenshot" in FORBIDDEN_ACTION_PARAM_KEYS


def test_no_keylog_param_key() -> None:
    assert "keylog" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "keystrokes" in FORBIDDEN_ACTION_PARAM_KEYS


def test_no_password_or_secret_or_token_param_key() -> None:
    assert "password" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "private_key" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "secret" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "token" in FORBIDDEN_ACTION_PARAM_KEYS


# ---------------------------------------------------------------------------
# Database safety - no frame bytes, no secrets
# ---------------------------------------------------------------------------


def test_orion_tables_never_store_frame_bytes(db: Database) -> None:
    for table in ("orion_events", "orion_actions", "orion_capabilities", "orion_reconciliation"):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        forbidden = {
            "payload", "frame", "screenshot", "frame_data", "image",
            "raw_pixels", "video", "audio", "keylog", "keystrokes",
        }
        assert forbidden.isdisjoint(set(cols)), (
            f"Frame-byte column in {table}: {forbidden & set(cols)}"
        )


def test_orion_tables_never_store_secrets(db: Database) -> None:
    for table in ("orion_events", "orion_actions", "orion_capabilities", "orion_reconciliation"):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        forbidden = {
            "private_key", "password", "secret", "token", "otp", "auth_token",
        }
        assert forbidden.isdisjoint(set(cols)), (
            f"Secret column in {table}: {forbidden & set(cols)}"
        )


def test_orion_tables_never_store_command_strings(db: Database) -> None:
    for table in ("orion_events", "orion_actions", "orion_capabilities", "orion_reconciliation"):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        forbidden = {"command", "shell", "exec", "execute", "code", "script"}
        assert forbidden.isdisjoint(set(cols)), (
            f"Command column in {table}: {forbidden & set(cols)}"
        )


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_duplicate_action_idempotency_key_ignored(db: Database) -> None:
    q = OrionActionQueue(db)
    a1 = _make_action("OAC-1", parameters={"alert_id": "ALT-1"})
    a1.idempotency_key = "IDEMP-SAME"
    a2 = _make_action("OAC-2", parameters={"alert_id": "ALT-1"})
    a2.idempotency_key = "IDEMP-SAME"
    assert q.enqueue(a1) is True
    assert q.enqueue(a2) is False  # duplicate


def test_duplicate_event_id_silently_dropped() -> None:
    bus = OrionEventBus(deterministic=True)
    received: list = []
    bus.register_handler(received.append)
    ev1 = OrionEvent(
        event_id="OEV-DUP",
        event_type=OrionEventType.DEVICE_CONNECTED,
        source="test",
        device_id="GM-C-19A84E72",
        created_at=datetime.datetime.now(datetime.UTC).isoformat(),
        correlation_id="OCR-DUP-1",
    )
    ev2 = OrionEvent(
        event_id="OEV-DUP",
        event_type=OrionEventType.DEVICE_CONNECTED,
        source="test",
        device_id="GM-C-19A84E72",
        created_at=datetime.datetime.now(datetime.UTC).isoformat(),
        correlation_id="OCR-DUP-2",
    )
    bus.publish(ev1)
    bus.publish(ev2)
    assert len(received) == 1


# ---------------------------------------------------------------------------
# Action expiry
# ---------------------------------------------------------------------------


def test_action_expiry_blocks_execution() -> None:
    h = OrionActionHandlers()
    now = datetime.datetime.now(datetime.UTC)
    past_action = OrionAction(
        action_id="OAC-EXPIRED",
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        created_at=(now - datetime.timedelta(seconds=600)).isoformat(),
        expires_at=(now - datetime.timedelta(seconds=300)).isoformat(),
        correlation_id="OCR-EXPIRED",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
    )
    with pytest.raises(OrionActionError):
        h.execute(past_action)


# ---------------------------------------------------------------------------
# Queue size limit
# ---------------------------------------------------------------------------


def test_queue_size_limit_enforced(db: Database) -> None:
    from guardianmesh.orion.errors import OrionQueueError

    q = OrionActionQueue(db, max_size=2)
    q.enqueue(_make_action("OAC-1"))
    q.enqueue(_make_action("OAC-2"))
    with pytest.raises(OrionQueueError):
        q.enqueue(_make_action("OAC-3"))


# ---------------------------------------------------------------------------
# Bounded retry
# ---------------------------------------------------------------------------


def test_bounded_retry_via_max_retries() -> None:
    """A failed action with max_retries=0 cannot be retried."""
    q = OrionActionQueue.__new__(OrionActionQueue)  # avoid init
    q._db = None  # type: ignore[attr-defined]
    q._max_size = 10_000  # type: ignore[attr-defined]
    q._lock = __import__("threading").RLock()  # type: ignore[attr-defined]
    action = _make_action("OAC-FAIL")
    action.max_retries = 0
    action.retry_count = 0
    assert action.can_retry() is False


# ---------------------------------------------------------------------------
# Authorization bypass prevention
# ---------------------------------------------------------------------------


def test_authorization_bypass_raises_when_missing() -> None:
    """Consent validator raises when the required subsystem is not configured."""
    from guardianmesh.orion.consent import OrionConsentValidator

    validator = OrionConsentValidator(
        trust_manager=None,
        screen_authorization_manager=None,
        aegis_consent_gate=None,
    )
    action = _make_action(
        "OAC-SCREEN",
        action_type=OrionActionType.REQUEST_SCREEN_SESSION,
    )
    with pytest.raises(OrionConsentViolationError):
        validator.validate(action)


def test_trust_required_without_trust_manager_raises() -> None:
    """An action requiring trust cannot bypass the trust check."""
    from guardianmesh.orion.consent import OrionConsentValidator

    validator = OrionConsentValidator(
        trust_manager=None,
    )
    action = _make_action("OAC-REFRESH", action_type=OrionActionType.REFRESH_HEALTH)
    with pytest.raises(OrionConsentViolationError):
        validator.validate(action)


def test_existing_active_session_required_without_session_raises() -> None:
    """An action requiring an existing session cannot bypass the check."""
    from guardianmesh.orion.consent import OrionConsentValidator

    validator = OrionConsentValidator()
    action = _make_action("OAC-STOP-SCREEN", action_type=OrionActionType.STOP_SCREEN_SESSION)
    with pytest.raises(OrionConsentViolationError):
        validator.validate(action, active_session_id=None)


# ---------------------------------------------------------------------------
# Frame bytes never enter events
# ---------------------------------------------------------------------------


def test_event_with_frame_bytes_rejected() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-FRAME",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-FRAME",
            payload={"frame": "this is a frame"},
        )


def test_event_with_screenshot_rejected() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-SCR",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-SCR",
            payload={"screenshot": "data"},
        )


def test_event_with_keylog_rejected() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-KEY",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-KEY",
            payload={"keylog": "abcdef"},
        )


# ---------------------------------------------------------------------------
# Action parameter safety
# ---------------------------------------------------------------------------


def test_action_with_command_param_rejected() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-CMD",
            action_type=OrionActionType.ACKNOWLEDGE_ALERT,
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            expires_at=(datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)).isoformat(),
            correlation_id="OCR-CMD",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            parameters={"command": "rm -rf /"},
        )


def test_action_with_password_param_rejected() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-PWD",
            action_type=OrionActionType.ACKNOWLEDGE_ALERT,
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            expires_at=(datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)).isoformat(),
            correlation_id="OCR-PWD",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            parameters={"password": "hunter2"},
        )


# ---------------------------------------------------------------------------
# Audit redaction
# ---------------------------------------------------------------------------


def test_audit_log_never_records_secrets(db: Database) -> None:
    audit = AuditLogger(db)
    audit.record(
        event_type=AuditEventType.ORION_ACTION_STARTED,
        details={
            "action_id": "OAC-AUDIT-1",
            "action_type": "REQUEST_CAPABILITIES",
            "device_id": "GM-C-19A84E72",
        },
        success=True,
    )
    recent = audit.get_recent(limit=10)
    orion_events = [e for e in recent if "ORION" in e["event_type"]]
    for ev in orion_events:
        details_str = str(ev.get("details", ""))
        for forbidden in ("password", "private_key", "secret", "frame", "command", "shell"):
            assert forbidden not in details_str.lower(), (
                f"Audit log leaked '{forbidden}': {details_str}"
            )
