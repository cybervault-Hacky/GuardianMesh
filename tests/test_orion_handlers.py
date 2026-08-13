"""Tests for Orion Phase 9 action handlers.

Covers action dispatch to existing subsystems, audit recording,
and the safety guarantees (no shell, no remote input, no hidden
capture).
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.orion.actions import (
    OrionAction,
    OrionActionStatus,
    OrionActionType,
)
from guardianmesh.orion.errors import OrionActionError
from guardianmesh.orion.handlers import OrionActionHandlers
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_path = tmp_path / "orion_handlers.db"
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


@pytest.fixture
def audit(db: Database) -> AuditLogger:
    return AuditLogger(db)


def _make_action(
    action_id: str = "OAC-00000001",
    action_type: OrionActionType = OrionActionType.REQUEST_CAPABILITIES,
    device_id: str = "GM-C-19A84E72",
    parameters: dict | None = None,
    ttl_seconds: int = 300,
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
# Construction
# ---------------------------------------------------------------------------


def test_handlers_construct_with_no_subsystems() -> None:
    """Handlers can be constructed without subsystem dependencies."""
    h = OrionActionHandlers()
    assert h is not None


# ---------------------------------------------------------------------------
# Dispatch - health
# ---------------------------------------------------------------------------


def test_refresh_health_requires_telemetry_processor() -> None:
    h = OrionActionHandlers()
    action = _make_action(action_type=OrionActionType.REFRESH_HEALTH)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_refresh_health_returns_metadata() -> None:
    h = OrionActionHandlers(telemetry_processor=object())
    action = _make_action(action_type=OrionActionType.REFRESH_HEALTH)
    result = h.execute(action)
    assert result["device_id"] == "GM-C-19A84E72"
    assert result["telemetry_refreshed"] is True


def test_request_health_sync_requires_telemetry_processor() -> None:
    h = OrionActionHandlers()
    action = _make_action(action_type=OrionActionType.REQUEST_HEALTH_SYNC)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_request_health_sync_returns_metadata() -> None:
    h = OrionActionHandlers(telemetry_processor=object())
    action = _make_action(action_type=OrionActionType.REQUEST_HEALTH_SYNC)
    result = h.execute(action)
    assert result["sync_requested"] is True


# ---------------------------------------------------------------------------
# Dispatch - alerts
# ---------------------------------------------------------------------------


def test_acknowledge_alert_requires_alert_manager() -> None:
    h = OrionActionHandlers()
    action = _make_action(
        action_type=OrionActionType.ACKNOWLEDGE_ALERT,
        parameters={"alert_id": "ALT-001"},
    )
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_acknowledge_alert_requires_alert_id() -> None:
    h = OrionActionHandlers(alert_manager=object())
    action = _make_action(action_type=OrionActionType.ACKNOWLEDGE_ALERT)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_acknowledge_alert_requires_method() -> None:
    class _FakeAlertManager:
        pass

    h = OrionActionHandlers(alert_manager=_FakeAlertManager())
    action = _make_action(
        action_type=OrionActionType.ACKNOWLEDGE_ALERT,
        parameters={"alert_id": "ALT-001"},
    )
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_acknowledge_alert_succeeds() -> None:
    class _FakeAlertManager:
        def acknowledge_alert(self, alert_id: str) -> str:
            return "OK"

    h = OrionActionHandlers(alert_manager=_FakeAlertManager())
    action = _make_action(
        action_type=OrionActionType.ACKNOWLEDGE_ALERT,
        parameters={"alert_id": "ALT-001"},
    )
    result = h.execute(action)
    assert result["acknowledged"] is True
    assert result["alert_id"] == "ALT-001"


def test_resolve_alert_succeeds() -> None:
    class _FakeAlertManager:
        def resolve_alert(self, alert_id: str) -> str:
            return "OK"

    h = OrionActionHandlers(alert_manager=_FakeAlertManager())
    action = _make_action(
        action_type=OrionActionType.RESOLVE_ALERT,
        parameters={"alert_id": "ALT-002"},
    )
    result = h.execute(action)
    assert result["resolved"] is True


# ---------------------------------------------------------------------------
# Dispatch - transport
# ---------------------------------------------------------------------------


def test_reconnect_transport_succeeds() -> None:
    class _FakeTransportClient:
        def reconnect(self, device_id: str) -> str:
            return f"reconnected:{device_id}"

    h = OrionActionHandlers(transport_client=_FakeTransportClient())
    action = _make_action(action_type=OrionActionType.RECONNECT_TRANSPORT)
    result = h.execute(action)
    assert result["reconnected"] is True
    assert "reconnected" in result["result"]


def test_reconnect_transport_requires_client() -> None:
    h = OrionActionHandlers()
    action = _make_action(action_type=OrionActionType.RECONNECT_TRANSPORT)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_reconnect_transport_requires_method() -> None:
    class _FakeTransportClient:
        pass

    h = OrionActionHandlers(transport_client=_FakeTransportClient())
    action = _make_action(action_type=OrionActionType.RECONNECT_TRANSPORT)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_request_status_sync() -> None:
    h = OrionActionHandlers()
    action = _make_action(action_type=OrionActionType.REQUEST_STATUS_SYNC)
    result = h.execute(action)
    assert result["sync_requested"] is True


# ---------------------------------------------------------------------------
# Dispatch - screen (Vista)
# ---------------------------------------------------------------------------


def test_request_screen_session_requires_controller() -> None:
    h = OrionActionHandlers()
    action = _make_action(action_type=OrionActionType.REQUEST_SCREEN_SESSION)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_request_screen_session_uses_view_request() -> None:
    captured: dict = {}

    class _FakeScreenController:
        def request_view(self, request):
            captured["req"] = request
            info = type("Info", (), {})()
            info.session_id = "SCN-FAKE"
            info.state = type("S", (), {"value": "REQUESTED"})()
            session = type("Sess", (), {"session_id": "SCN-FAKE", "info": info})()
            return session

    h = OrionActionHandlers(screen_controller=_FakeScreenController())
    action = _make_action(
        action_type=OrionActionType.REQUEST_SCREEN_SESSION,
        parameters={"max_duration_seconds": 120, "label": "Test"},
    )
    result = h.execute(action)
    assert result["screen_session_id"] == "SCN-FAKE"
    assert captured["req"].max_duration_seconds == 120
    assert captured["req"].label == "Test"


def test_stop_screen_session_requires_session_id() -> None:
    h = OrionActionHandlers(screen_controller=object())
    action = _make_action(action_type=OrionActionType.STOP_SCREEN_SESSION)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_stop_screen_session_succeeds() -> None:
    stopped: list = []

    class _FakeScreenController:
        def stop_session(self, sid: str, reason: str) -> None:
            stopped.append((sid, reason))

    h = OrionActionHandlers(screen_controller=_FakeScreenController())
    action = _make_action(
        action_type=OrionActionType.STOP_SCREEN_SESSION,
        parameters={"screen_session_id": "SCN-12345678"},
    )
    result = h.execute(action)
    assert result["stopped"] is True
    assert stopped == [("SCN-12345678", "ORION_STOP")]


# ---------------------------------------------------------------------------
# Dispatch - Aegis
# ---------------------------------------------------------------------------


def test_request_aegis_consent_requires_session_id() -> None:
    h = OrionActionHandlers(aegis_controller=object())
    action = _make_action(action_type=OrionActionType.REQUEST_AEGIS_CONSENT)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_request_aegis_consent_succeeds() -> None:
    class _Record:
        consent_token = "CT-FAKE"

    class _FakeAegisController:
        def request_system_consent(self, aegis_session_id: str):
            return _Record()

    h = OrionActionHandlers(aegis_controller=_FakeAegisController())
    action = _make_action(
        action_type=OrionActionType.REQUEST_AEGIS_CONSENT,
        parameters={"aegis_session_id": "AEG-12345678"},
    )
    result = h.execute(action)
    assert result["consent_token"] == "CT-FAKE"


def test_stop_aegis_capture_requires_session_id() -> None:
    h = OrionActionHandlers(aegis_controller=object())
    action = _make_action(action_type=OrionActionType.STOP_AEGIS_CAPTURE)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_stop_aegis_capture_succeeds() -> None:
    stopped: list = []

    class _FakeAegisController:
        def stop_capture(self, sid: str, reason: str) -> None:
            stopped.append((sid, reason))

    h = OrionActionHandlers(aegis_controller=_FakeAegisController())
    action = _make_action(
        action_type=OrionActionType.STOP_AEGIS_CAPTURE,
        parameters={"aegis_session_id": "AEG-12345678"},
    )
    h.execute(action)
    assert stopped == [("AEG-12345678", "ORION_STOP")]


# ---------------------------------------------------------------------------
# Dispatch - reconciliation & capabilities
# ---------------------------------------------------------------------------


def test_reconcile_state_requires_reconciler() -> None:
    h = OrionActionHandlers()
    action = _make_action(action_type=OrionActionType.RECONCILE_STATE)
    with pytest.raises(OrionActionError):
        h.execute(action)


def test_reconcile_state_succeeds() -> None:
    class _Report:
        report_id = "ORC-FAKE"
        events_processed = 5
        conflicts_detected = 1
        conflicts_resolved = 1

    class _FakeReconciler:
        def reconcile(self, device_id):
            return _Report()

    h = OrionActionHandlers(state_reconciler=_FakeReconciler())
    action = _make_action(action_type=OrionActionType.RECONCILE_STATE)
    result = h.execute(action)
    assert result["report_id"] == "ORC-FAKE"
    assert result["events_processed"] == 5


def test_request_capabilities_no_record() -> None:
    class _FakeRegistry:
        def get(self, device_id):
            return None

    h = OrionActionHandlers(capability_registry=_FakeRegistry())
    action = _make_action(action_type=OrionActionType.REQUEST_CAPABILITIES)
    result = h.execute(action)
    assert result["capabilities"] == {}


def test_request_capabilities_returns_record() -> None:
    class _Caps:
        def to_dict(self):
            return {"HEALTH_TELEMETRY": True}

    class _FakeRegistry:
        def get(self, device_id):
            return _Caps()

    h = OrionActionHandlers(capability_registry=_FakeRegistry())
    action = _make_action(action_type=OrionActionType.REQUEST_CAPABILITIES)
    result = h.execute(action)
    assert result["capabilities"]["HEALTH_TELEMETRY"] is True


# ---------------------------------------------------------------------------
# Expiry / unknown actions
# ---------------------------------------------------------------------------


def test_execute_rejects_expired_action() -> None:
    h = OrionActionHandlers()
    now = datetime.datetime.now(datetime.UTC)
    action = OrionAction(
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
        h.execute(action)


def test_execute_rejects_non_action() -> None:
    h = OrionActionHandlers()
    with pytest.raises(OrionActionError):
        h.execute("not an action")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Audit recording
# ---------------------------------------------------------------------------


def test_execute_records_audit_event(audit: AuditLogger) -> None:
    class _Caps:
        def to_dict(self):
            return {"capabilities": {}}

    class _FakeRegistry:
        def get(self, device_id):
            return _Caps()

    h = OrionActionHandlers(audit_logger=audit, capability_registry=_FakeRegistry())
    action = _make_action(action_type=OrionActionType.REQUEST_CAPABILITIES)
    h.execute(action)
    recent = audit.get_recent(limit=10)
    # The most recent audit event should be an ORION event.
    assert len(recent) >= 1
    types = [e["event_type"] for e in recent]
    assert any("ORION" in t for t in types)


def test_audit_records_action_metadata(audit: AuditLogger) -> None:
    class _Caps:
        def to_dict(self):
            return {"capabilities": {}}

    class _FakeRegistry:
        def get(self, device_id):
            return _Caps()

    h = OrionActionHandlers(audit_logger=audit, capability_registry=_FakeRegistry())
    action = _make_action(
        action_id="OAC-AUDIT-1",
        action_type=OrionActionType.REQUEST_CAPABILITIES,
    )
    h.execute(action)
    recent = audit.get_recent(limit=10)
    orion_events = [e for e in recent if "ORION" in e["event_type"]]
    assert len(orion_events) >= 1
    details = orion_events[0]["details"]
    assert details["action_id"] == "OAC-AUDIT-1"


def test_audit_does_not_record_secrets(audit: AuditLogger) -> None:
    """Audit records must not contain command strings, frame bytes, or secrets."""
    class _Caps:
        def to_dict(self):
            return {"capabilities": {}}

    class _FakeRegistry:
        def get(self, device_id):
            return _Caps()

    h = OrionActionHandlers(audit_logger=audit, capability_registry=_FakeRegistry())
    action = _make_action(action_type=OrionActionType.REQUEST_CAPABILITIES)
    h.execute(action)
    recent = audit.get_recent(limit=10)
    orion_events = [e for e in recent if "ORION" in e["event_type"]]
    for ev in orion_events:
        details = ev["details"]
        for forbidden in ("password", "token", "private_key", "frame", "command", "shell"):
            assert forbidden not in str(details).lower()
