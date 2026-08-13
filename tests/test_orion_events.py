"""Tests for Orion Phase 9 event model.

Covers the :class:`OrionEvent` lifecycle, the strict type allowlist,
the forbidden event names, the forbidden payload keys, the factory
method, and deterministic serialization.
"""

from __future__ import annotations

import datetime
import json

import pytest

from guardianmesh.orion.errors import OrionEventError
from guardianmesh.orion.events import (
    FORBIDDEN_EVENT_NAMES,
    FORBIDDEN_PAYLOAD_KEYS,
    SCHEMA_VERSION,
    OrionEvent,
    OrionEventPriority,
    OrionEventType,
    assert_safe_event_type_name,
    assert_safe_payload,
    generate_correlation_id,
    generate_event_id,
)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


def test_event_type_values_documented() -> None:
    """OrionEventType exposes the documented event types."""
    for value in (
        "DEVICE_CONNECTED",
        "DEVICE_DISCONNECTED",
        "HEALTH_UPDATED",
        "HEALTH_DEGRADED",
        "HEALTH_RECOVERED",
        "ALERT_CREATED",
        "ALERT_RESOLVED",
        "ALERT_ACKNOWLEDGED",
        "POLICY_CHANGED",
        "TRUST_ESTABLISHED",
        "TRUST_REVOKED",
        "TRANSPORT_CONNECTED",
        "TRANSPORT_DISCONNECTED",
        "TRANSPORT_RECONNECTED",
        "TRANSPORT_RECONCILED",
        "TRANSPORT_REVOKED",
        "SCREEN_AUTHORIZED",
        "SCREEN_STARTED",
        "SCREEN_STOPPED",
        "SCREEN_EXPIRED",
        "SCREEN_DENIED",
        "AEGIS_SESSION_CREATED",
        "AEGIS_CONSENT_GRANTED",
        "AEGIS_CONSENT_DENIED",
        "AEGIS_CONSENT_EXPIRED",
        "AEGIS_CAPTURE_STARTED",
        "AEGIS_STOPPED",
        "CAPABILITY_CHANGED",
        "RECONCILIATION_STARTED",
        "RECONCILIATION_COMPLETED",
        "CONFLICT_RESOLVED",
    ):
        assert OrionEventType(value).value == value


def test_event_type_from_str_case_insensitive() -> None:
    assert OrionEventType.from_str("device_connected") == OrionEventType.DEVICE_CONNECTED
    assert OrionEventType.from_str("Health_Updated") == OrionEventType.HEALTH_UPDATED


def test_event_type_from_str_invalid_raises() -> None:
    with pytest.raises(OrionEventError):
        OrionEventType.from_str("UNKNOWN_EVENT_TYPE")


def test_event_priority_values() -> None:
    for v in ("LOW", "NORMAL", "HIGH", "CRITICAL"):
        assert OrionEventPriority(v).value == v


def test_event_priority_from_str_case_insensitive() -> None:
    assert OrionEventPriority.from_str("high") == OrionEventPriority.HIGH
    with pytest.raises(OrionEventError):
        OrionEventPriority.from_str("URGENT")


# ---------------------------------------------------------------------------
# Forbidden names and keys
# ---------------------------------------------------------------------------


def test_forbidden_event_names_is_frozenset() -> None:
    assert isinstance(FORBIDDEN_EVENT_NAMES, frozenset)
    assert "KEYSTROKE" in FORBIDDEN_EVENT_NAMES
    assert "SHELL_COMMAND" in FORBIDDEN_EVENT_NAMES
    assert "REMOTE_INPUT" in FORBIDDEN_EVENT_NAMES
    assert "MICROPHONE" in FORBIDDEN_EVENT_NAMES
    assert "CAMERA" in FORBIDDEN_EVENT_NAMES
    assert "LOCATION" in FORBIDDEN_EVENT_NAMES
    assert "BROWSER_HISTORY" in FORBIDDEN_EVENT_NAMES


def test_assert_safe_event_type_name_rejects_forbidden() -> None:
    for forbidden in ("KEYSTROKE", "MESSAGE", "SHELL_COMMAND", "REMOTE_INPUT", "CLIPBOARD"):
        with pytest.raises(OrionEventError):
            assert_safe_event_type_name(forbidden)


def test_assert_safe_event_type_name_accepts_safe() -> None:
    # Should not raise.
    assert_safe_event_type_name("DEVICE_CONNECTED")
    assert_safe_event_type_name("TRUST_REVOKED")


def test_forbidden_payload_keys_includes_sensitive() -> None:
    assert isinstance(FORBIDDEN_PAYLOAD_KEYS, frozenset)
    assert "payload" in FORBIDDEN_PAYLOAD_KEYS
    assert "frame" in FORBIDDEN_PAYLOAD_KEYS
    assert "screenshot" in FORBIDDEN_PAYLOAD_KEYS
    assert "keylog" in FORBIDDEN_PAYLOAD_KEYS
    assert "password" in FORBIDDEN_PAYLOAD_KEYS
    assert "command" in FORBIDDEN_PAYLOAD_KEYS
    assert "shell" in FORBIDDEN_PAYLOAD_KEYS
    assert "exec" in FORBIDDEN_PAYLOAD_KEYS
    assert "location" in FORBIDDEN_PAYLOAD_KEYS


def test_assert_safe_payload_rejects_forbidden_keys() -> None:
    for forbidden in (
        "payload",
        "frame",
        "screenshot",
        "keystrokes",
        "password",
        "private_key",
        "command",
        "shell",
        "exec",
        "microphone",
        "location",
        "gps",
    ):
        with pytest.raises(OrionEventError):
            assert_safe_payload({forbidden: "value"})


def test_assert_safe_payload_accepts_safe_keys() -> None:
    # Should not raise.
    assert_safe_payload({"health_state": "OK", "battery_percent": 75, "tier": "INFO"})


def test_assert_safe_payload_accepts_empty() -> None:
    assert_safe_payload({})


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------


def test_generate_event_id_format_and_uniqueness() -> None:
    a = generate_event_id()
    b = generate_event_id()
    assert a != b
    assert a.startswith("OEV-")
    assert b.startswith("OEV-")


def test_generate_correlation_id_format() -> None:
    cid = generate_correlation_id()
    assert cid.startswith("OCR-")
    assert cid != generate_correlation_id()


# ---------------------------------------------------------------------------
# OrionEvent construction
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def test_orion_event_minimal_valid() -> None:
    ev = OrionEvent(
        event_id="OEV-00000001",
        event_type=OrionEventType.DEVICE_CONNECTED,
        source="test",
        device_id="GM-C-19A84E72",
        created_at=_now_iso(),
        correlation_id="OCR-00000001",
    )
    assert ev.payload == {}
    assert ev.priority == OrionEventPriority.NORMAL
    assert ev.sequence == 0


def test_orion_event_with_safe_payload() -> None:
    ev = OrionEvent(
        event_id="OEV-00000002",
        event_type=OrionEventType.HEALTH_UPDATED,
        source="pulse",
        device_id="GM-C-19A84E72",
        created_at=_now_iso(),
        correlation_id="OCR-00000002",
        payload={"health_state": "OK", "battery_percent": 80},
    )
    assert ev.payload["health_state"] == "OK"
    assert ev.payload["battery_percent"] == 80


def test_orion_event_rejects_forbidden_payload_key() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000003",
            event_type=OrionEventType.HEALTH_UPDATED,
            source="pulse",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="OCR-00000003",
            payload={"frame": "data"},
        )


def test_orion_event_rejects_empty_event_id() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="OCR-00000004",
        )


def test_orion_event_rejects_empty_source() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000005",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="OCR-00000005",
        )


def test_orion_event_rejects_empty_device_id() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000006",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="",
            created_at=_now_iso(),
            correlation_id="OCR-00000006",
        )


def test_orion_event_rejects_empty_correlation_id() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000007",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="",
        )


def test_orion_event_accepts_sentinel_device_ids() -> None:
    for sentinel in ("SYSTEM", "BUS", "ORION"):
        ev = OrionEvent(
            event_id=f"OEV-{sentinel}",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id=sentinel,
            created_at=_now_iso(),
            correlation_id="OCR-00000007",
        )
        assert ev.device_id == sentinel


def test_orion_event_rejects_invalid_device_id_format() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000008",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="INVALID-DEVICE-ID",
            created_at=_now_iso(),
            correlation_id="OCR-00000008",
        )


def test_orion_event_rejects_invalid_timestamp() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000009",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at="not-a-timestamp",
            correlation_id="OCR-00000009",
        )


def test_orion_event_rejects_bad_schema_version() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000010",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="OCR-00000010",
            schema_version="0.1",
        )


def test_orion_event_rejects_non_dict_payload() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000011",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="OCR-00000011",
            payload=["list", "not", "dict"],  # type: ignore[arg-type]
        )


def test_orion_event_rejects_negative_sequence() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent(
            event_id="OEV-00000012",
            event_type=OrionEventType.DEVICE_CONNECTED,
            source="test",
            device_id="GM-C-19A84E72",
            created_at=_now_iso(),
            correlation_id="OCR-00000012",
            sequence=-1,
        )


# ---------------------------------------------------------------------------
# Factory method
# ---------------------------------------------------------------------------


def test_orion_event_create_factory_basic() -> None:
    ev = OrionEvent.create(
        event_type="DEVICE_CONNECTED",
        source="test",
        device_id="GM-C-19A84E72",
    )
    assert ev.event_id.startswith("OEV-")
    assert ev.correlation_id.startswith("OCR-")
    assert ev.event_type == OrionEventType.DEVICE_CONNECTED


def test_orion_event_create_factory_with_payload() -> None:
    ev = OrionEvent.create(
        event_type=OrionEventType.HEALTH_UPDATED,
        source="pulse",
        device_id="GM-C-19A84E72",
        payload={"health_state": "DEGRADED"},
    )
    assert ev.payload == {"health_state": "DEGRADED"}


def test_orion_event_create_factory_rejects_forbidden_type() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent.create(
            event_type="KEYSTROKE",
            source="test",
            device_id="GM-C-19A84E72",
        )


def test_orion_event_create_factory_rejects_forbidden_payload() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent.create(
            event_type=OrionEventType.HEALTH_UPDATED,
            source="test",
            device_id="GM-C-19A84E72",
            payload={"frame": "sensitive"},
        )


def test_orion_event_create_factory_preserves_overrides() -> None:
    ev = OrionEvent.create(
        event_type=OrionEventType.TRUST_REVOKED,
        source="test",
        device_id="GM-C-19A84E72",
        priority="CRITICAL",
        event_id="OEV-CUSTOMID",
        correlation_id="OCR-CUSTOM",
    )
    assert ev.event_id == "OEV-CUSTOMID"
    assert ev.correlation_id == "OCR-CUSTOM"
    assert ev.priority == OrionEventPriority.CRITICAL


def test_orion_event_create_factory_rejects_invalid_priority() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent.create(
            event_type=OrionEventType.HEALTH_UPDATED,
            source="test",
            device_id="GM-C-19A84E72",
            priority="URGENT",
        )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_orion_event_to_dict_round_trip() -> None:
    ev = OrionEvent(
        event_id="OEV-00000020",
        event_type=OrionEventType.HEALTH_UPDATED,
        source="pulse",
        device_id="GM-C-19A84E72",
        created_at="2026-08-13T00:00:00+00:00",
        correlation_id="OCR-00000020",
        payload={"health_state": "OK"},
        priority=OrionEventPriority.HIGH,
        sequence=5,
    )
    data = ev.to_dict()
    assert data["event_id"] == "OEV-00000020"
    assert data["event_type"] == "HEALTH_UPDATED"
    assert data["priority"] == "HIGH"
    assert data["sequence"] == 5
    assert data["schema_version"] == SCHEMA_VERSION
    restored = OrionEvent.from_dict(data)
    assert restored.event_id == ev.event_id
    assert restored.event_type == ev.event_type
    assert restored.payload == ev.payload
    assert restored.sequence == ev.sequence


def test_orion_event_canonical_json_is_deterministic() -> None:
    ev = OrionEvent(
        event_id="OEV-00000030",
        event_type=OrionEventType.POLICY_CHANGED,
        source="sentinel",
        device_id="GM-C-19A84E72",
        created_at="2026-08-13T00:00:00+00:00",
        correlation_id="OCR-00000030",
        payload={"k": "v"},
    )
    a = ev.to_canonical_json()
    b = ev.to_canonical_json()
    assert a == b
    # JSON is parseable and contains the expected key.
    parsed = json.loads(a)
    assert parsed["event_type"] == "POLICY_CHANGED"


def test_orion_event_canonical_json_sorted_keys() -> None:
    ev = OrionEvent(
        event_id="OEV-00000040",
        event_type=OrionEventType.HEALTH_UPDATED,
        source="pulse",
        device_id="GM-C-19A84E72",
        created_at="2026-08-13T00:00:00+00:00",
        correlation_id="OCR-00000040",
    )
    # Sorted keys are a defensive invariant for any signed/digested event.
    a = ev.to_canonical_json()
    assert a == json.dumps(ev.to_dict(), sort_keys=True, separators=(",", ":"))


def test_orion_event_from_dict_rejects_non_dict() -> None:
    with pytest.raises(OrionEventError):
        OrionEvent.from_dict(["not", "a", "dict"])  # type: ignore[arg-type]
