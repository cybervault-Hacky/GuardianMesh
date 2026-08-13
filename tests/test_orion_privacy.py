"""Privacy tests for Orion Phase 9.

Verifies that Orion never persists, transmits, or audits sensitive
content: frame bytes, command strings, private messages, secrets,
passwords, OTPs, private keys, clipboard, microphone, camera,
location, browser history, contacts, photos, files.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

from guardianmesh.orion.actions import OrionAction, OrionActionStatus, OrionActionType
from guardianmesh.orion.errors import OrionEventError
from guardianmesh.orion.events import OrionEvent, OrionEventType
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "orion_privacy.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


# ---------------------------------------------------------------------------
# Event payload privacy
# ---------------------------------------------------------------------------


def test_event_payload_rejects_frame_bytes() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-1",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-1",
            payload={"frame": "abcdef"},
        )


def test_event_payload_rejects_screenshot() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-2",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-2",
            payload={"screenshot": "abc"},
        )


def test_event_payload_rejects_image_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-3",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-3",
            payload={"image": "data"},
        )


def test_event_payload_rejects_video_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-4",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-4",
            payload={"video": "data"},
        )


def test_event_payload_rejects_audio_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-5",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-5",
            payload={"audio": "data"},
        )


def test_event_payload_rejects_microphone_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-6",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-6",
            payload={"microphone": "data"},
        )


def test_event_payload_rejects_camera_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-7",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-7",
            payload={"camera": "data"},
        )


def test_event_payload_rejects_location_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-8",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-8",
            payload={"location": "data"},
        )


def test_event_payload_rejects_gps_data() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-9",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-9",
            payload={"gps": "data"},
        )


def test_event_payload_rejects_keylog() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-10",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-10",
            payload={"keylog": "data"},
        )


def test_event_payload_rejects_keystrokes() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-11",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-11",
            payload={"keystrokes": "data"},
        )


def test_event_payload_rejects_messages() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-12",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-12",
            payload={"messages": "data"},
        )


def test_event_payload_rejects_clipboard() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-13",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-13",
            payload={"clipboard": "data"},
        )


def test_event_payload_rejects_browser_history() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-14",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-14",
            payload={"browser_history": "data"},
        )


def test_event_payload_rejects_contacts() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-15",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-15",
            payload={"contacts": "data"},
        )


def test_event_payload_rejects_photos() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-16",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-16",
            payload={"photos": "data"},
        )


def test_event_payload_rejects_files() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-17",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-17",
            payload={"files": "data"},
        )


def test_event_payload_rejects_command() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-18",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-18",
            payload={"command": "rm -rf /"},
        )


def test_event_payload_rejects_shell() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-19",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-19",
            payload={"shell": "bash"},
        )


def test_event_payload_rejects_password() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-20",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-20",
            payload={"password": "secret"},
        )


def test_event_payload_rejects_secret() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-21",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-21",
            payload={"secret": "value"},
        )


def test_event_payload_rejects_token() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-22",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="x",
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            correlation_id="OCR-22",
            payload={"token": "abc"},
        )


# ---------------------------------------------------------------------------
# Database persistence privacy
# ---------------------------------------------------------------------------


def test_orion_events_table_never_stores_frame_bytes(db: Database) -> None:
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(orion_events);")]
    for forbidden in ("payload", "frame", "screenshot", "image", "video", "audio", "keylog"):
        assert forbidden not in cols


def test_orion_actions_table_never_stores_frame_bytes(db: Database) -> None:
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(orion_actions);")]
    for forbidden in ("payload", "frame", "screenshot", "image", "video", "audio", "keylog"):
        assert forbidden not in cols


def test_orion_actions_table_never_stores_command_strings(db: Database) -> None:
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(orion_actions);")]
    for forbidden in ("command", "shell", "exec", "code", "script"):
        assert forbidden not in cols


def test_orion_events_table_never_stores_command_strings(db: Database) -> None:
    cols = [r["name"] for r in db.fetchall("PRAGMA table_info(orion_events);")]
    for forbidden in ("command", "shell", "exec", "code", "script"):
        assert forbidden not in cols


def test_orion_tables_never_store_secrets(db: Database) -> None:
    for table in ("orion_events", "orion_actions", "orion_capabilities", "orion_reconciliation"):
        cols = [r["name"] for r in db.fetchall(f"PRAGMA table_info({table});")]
        for forbidden in ("password", "private_key", "secret", "token", "otp", "auth_token"):
            assert forbidden not in cols, f"{forbidden} found in {table}"


# ---------------------------------------------------------------------------
# Action parameter privacy
# ---------------------------------------------------------------------------


def test_action_parameters_reject_command() -> None:
    from guardianmesh.orion.errors import OrionActionError

    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-1",
            action_type=OrionActionType.ACKNOWLEDGE_ALERT,
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            expires_at=(datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)).isoformat(),
            correlation_id="OCR-1",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            parameters={"command": "echo pwned"},
        )


def test_action_parameters_reject_password() -> None:
    from guardianmesh.orion.errors import OrionActionError

    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-2",
            action_type=OrionActionType.ACKNOWLEDGE_ALERT,
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            expires_at=(datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)).isoformat(),
            correlation_id="OCR-2",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            parameters={"password": "abc123"},
        )


def test_action_parameters_reject_frame() -> None:
    from guardianmesh.orion.errors import OrionActionError

    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-3",
            action_type=OrionActionType.ACKNOWLEDGE_ALERT,
            device_id="GM-C-19A84E72",
            created_at=datetime.datetime.now(datetime.UTC).isoformat(),
            expires_at=(datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=300)).isoformat(),
            correlation_id="OCR-3",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            parameters={"frame": "binary data"},
        )


# ---------------------------------------------------------------------------
# Audit log privacy
# ---------------------------------------------------------------------------


def test_audit_does_not_record_secrets_in_action_details(db: Database) -> None:
    audit = AuditLogger(db)
    audit.record(
        event_type=AuditEventType.ORION_ACTION_STARTED,
        details={
            "action_id": "OAC-A",
            "action_type": "REQUEST_CAPABILITIES",
            "device_id": "GM-C-19A84E72",
            "alert_id": "ALT-001",
        },
        success=True,
    )
    recent = audit.get_recent(limit=10)
    for ev in recent:
        if "ORION" in ev["event_type"]:
            details_str = json.dumps(ev["details"]).lower()
            for forbidden in ("password", "private_key", "secret", "frame", "command", "shell", "keylog"):
                assert forbidden not in details_str


def test_audit_records_metadata_only(db: Database) -> None:
    audit = AuditLogger(db)
    audit.record(
        event_type=AuditEventType.ORION_EVENT_ACCEPTED,
        details={"event_id": "OEV-A", "event_type": "DEVICE_CONNECTED"},
        success=True,
    )
    recent = audit.get_recent(limit=10)
    orion = [e for e in recent if e["event_type"] == "ORION_EVENT_ACCEPTED"]
    assert len(orion) == 1
    details = orion[0]["details"]
    # Only metadata keys, no payload-bearing keys.
    assert "event_id" in details
    assert "event_type" in details
    # Verify no payload-bearing keys were recorded.
    assert "frame" not in details
    assert "payload" not in details
    assert "command" not in details
