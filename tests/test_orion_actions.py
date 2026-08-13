"""Tests for Orion Phase 9 action model.

Covers the :class:`OrionAction` allowlist, consent requirements,
status transitions, serialization, and rejection of forbidden
action types and parameters.
"""

from __future__ import annotations

import datetime

import pytest

from guardianmesh.orion.actions import (
    ACTION_CONSENT_REQUIREMENTS,
    FORBIDDEN_ACTION_NAMES,
    FORBIDDEN_ACTION_PARAM_KEYS,
    SCHEMA_VERSION,
    OrionAction,
    OrionActionStatus,
    OrionActionType,
    OrionConsentRequirement,
    assert_safe_action_params,
    assert_safe_action_type_name,
    generate_action_id,
    required_consents,
)
from guardianmesh.orion.errors import OrionActionError

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


def test_action_type_values_documented() -> None:
    for v in (
        "REFRESH_HEALTH",
        "REQUEST_HEALTH_SYNC",
        "ACKNOWLEDGE_ALERT",
        "RESOLVE_ALERT",
        "RECONNECT_TRANSPORT",
        "REQUEST_STATUS_SYNC",
        "REQUEST_SCREEN_SESSION",
        "STOP_SCREEN_SESSION",
        "REQUEST_AEGIS_CONSENT",
        "STOP_AEGIS_CAPTURE",
        "RECONCILE_STATE",
        "REQUEST_CAPABILITIES",
    ):
        assert OrionActionType(v).value == v


def test_action_type_from_str_case_insensitive() -> None:
    assert OrionActionType.from_str("refresh_health") == OrionActionType.REFRESH_HEALTH
    with pytest.raises(OrionActionError):
        OrionActionType.from_str("UNKNOWN_ACTION")


def test_action_status_values() -> None:
    for v in (
        "PENDING",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
        "EXPIRED",
        "CANCELLED",
    ):
        assert OrionActionStatus(v).value == v


def test_action_status_from_str_case_insensitive() -> None:
    assert OrionActionStatus.from_str("pending") == OrionActionStatus.PENDING
    with pytest.raises(OrionActionError):
        OrionActionStatus.from_str("UNKNOWN_STATUS")


def test_consent_requirement_values() -> None:
    for v in (
        "NONE",
        "TRUST_REQUIRED",
        "VISTA_AUTHORIZATION_REQUIRED",
        "AEGIS_SYSTEM_CONSENT_REQUIRED",
        "CHILD_AUTHORIZATION_REQUIRED",
        "EXISTING_ACTIVE_SESSION",
    ):
        assert OrionConsentRequirement(v).value == v


def test_consent_requirement_from_str_invalid() -> None:
    with pytest.raises(OrionActionError):
        OrionConsentRequirement.from_str("UNKNOWN")


# ---------------------------------------------------------------------------
# Forbidden names and keys
# ---------------------------------------------------------------------------


def test_forbidden_action_names_includes_surveillance() -> None:
    assert "EXECUTE" in FORBIDDEN_ACTION_NAMES
    assert "EXEC" in FORBIDDEN_ACTION_NAMES
    assert "SHELL" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_INPUT" in FORBIDDEN_ACTION_NAMES
    assert "REMOTE_CLICK" in FORBIDDEN_ACTION_NAMES
    assert "TYPE_TEXT" in FORBIDDEN_ACTION_NAMES
    assert "ENABLE_MICROPHONE" in FORBIDDEN_ACTION_NAMES
    assert "ENABLE_CAMERA" in FORBIDDEN_ACTION_NAMES
    assert "ENABLE_LOCATION" in FORBIDDEN_ACTION_NAMES
    assert "READ_SMS" in FORBIDDEN_ACTION_NAMES
    assert "READ_CONTACTS" in FORBIDDEN_ACTION_NAMES
    assert "READ_FILES" in FORBIDDEN_ACTION_NAMES
    assert "READ_BROWSER_HISTORY" in FORBIDDEN_ACTION_NAMES
    assert "ENABLE_KEYLOG" in FORBIDDEN_ACTION_NAMES
    assert "HIDDEN_SCREENSHOT" in FORBIDDEN_ACTION_NAMES


def test_assert_safe_action_type_name_rejects_forbidden() -> None:
    for forbidden in (
        "EXECUTE",
        "SHELL",
        "REMOTE_INPUT",
        "REMOTE_CLICK",
        "ENABLE_MICROPHONE",
        "ENABLE_CAMERA",
        "READ_SMS",
        "READ_FILES",
    ):
        with pytest.raises(OrionActionError):
            assert_safe_action_type_name(forbidden)


def test_assert_safe_action_type_name_accepts_safe() -> None:
    assert_safe_action_type_name("REFRESH_HEALTH")
    assert_safe_action_type_name("REQUEST_SCREEN_SESSION")
    assert_safe_action_type_name("STOP_SCREEN_SESSION")


def test_forbidden_action_param_keys_includes_sensitive() -> None:
    assert "command" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "shell" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "exec" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "code" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "script" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "frame" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "screenshot" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "keylog" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "password" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "private_key" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "secret" in FORBIDDEN_ACTION_PARAM_KEYS
    assert "token" in FORBIDDEN_ACTION_PARAM_KEYS


def test_assert_safe_action_params_rejects_forbidden() -> None:
    for forbidden in (
        "command",
        "shell",
        "exec",
        "code",
        "script",
        "frame",
        "screenshot",
        "keylog",
        "keystrokes",
        "messages",
        "clipboard",
        "password",
        "private_key",
        "secret",
        "token",
    ):
        with pytest.raises(OrionActionError):
            assert_safe_action_params({forbidden: "value"})


def test_assert_safe_action_params_accepts_safe() -> None:
    assert_safe_action_params({"alert_id": "ALT-001"})
    assert_safe_action_params({"max_duration_seconds": 300, "label": "Test"})
    assert_safe_action_params({})


# ---------------------------------------------------------------------------
# Consent requirements map
# ---------------------------------------------------------------------------


def test_consent_requirements_map_is_authoritative() -> None:
    """Every action type has an entry in the consent map."""
    for at in OrionActionType:
        assert at in ACTION_CONSENT_REQUIREMENTS


def test_screen_session_requires_full_consent_chain() -> None:
    reqs = required_consents(OrionActionType.REQUEST_SCREEN_SESSION)
    assert OrionConsentRequirement.TRUST_REQUIRED in reqs
    assert OrionConsentRequirement.VISTA_AUTHORIZATION_REQUIRED in reqs
    assert OrionConsentRequirement.AEGIS_SYSTEM_CONSENT_REQUIRED in reqs
    assert OrionConsentRequirement.CHILD_AUTHORIZATION_REQUIRED in reqs


def test_stop_screen_session_requires_active_session() -> None:
    reqs = required_consents(OrionActionType.STOP_SCREEN_SESSION)
    assert OrionConsentRequirement.TRUST_REQUIRED in reqs
    assert OrionConsentRequirement.EXISTING_ACTIVE_SESSION in reqs


def test_refresh_health_requires_trust_only() -> None:
    reqs = required_consents(OrionActionType.REFRESH_HEALTH)
    assert reqs == frozenset({OrionConsentRequirement.TRUST_REQUIRED})


def test_acknowledge_alert_has_no_consent_requirements() -> None:
    reqs = required_consents(OrionActionType.ACKNOWLEDGE_ALERT)
    assert reqs == frozenset()


def test_resolve_alert_has_no_consent_requirements() -> None:
    reqs = required_consents(OrionActionType.RESOLVE_ALERT)
    assert reqs == frozenset()


def test_aegis_consent_requires_full_chain() -> None:
    reqs = required_consents(OrionActionType.REQUEST_AEGIS_CONSENT)
    assert OrionConsentRequirement.TRUST_REQUIRED in reqs
    assert OrionConsentRequirement.VISTA_AUTHORIZATION_REQUIRED in reqs
    assert OrionConsentRequirement.AEGIS_SYSTEM_CONSENT_REQUIRED in reqs
    assert OrionConsentRequirement.CHILD_AUTHORIZATION_REQUIRED in reqs


def test_stop_aegis_capture_requires_active_session() -> None:
    reqs = required_consents(OrionActionType.STOP_AEGIS_CAPTURE)
    assert OrionConsentRequirement.TRUST_REQUIRED in reqs
    assert OrionConsentRequirement.EXISTING_ACTIVE_SESSION in reqs


def test_required_consents_accepts_string() -> None:
    reqs = required_consents("REFRESH_HEALTH")
    assert reqs == frozenset({OrionConsentRequirement.TRUST_REQUIRED})


def test_required_consents_invalid_string_raises() -> None:
    with pytest.raises(OrionActionError):
        required_consents("NOT_AN_ACTION")


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------


def test_generate_action_id_format() -> None:
    a = generate_action_id()
    b = generate_action_id()
    assert a != b
    assert a.startswith("OAC-")


# ---------------------------------------------------------------------------
# OrionAction construction
# ---------------------------------------------------------------------------


def _ts(seconds: int = 0) -> str:
    return (
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=seconds)
    ).isoformat()


def test_orion_action_minimal_valid() -> None:
    action = OrionAction(
        action_id="OAC-00000001",
        action_type=OrionActionType.REFRESH_HEALTH,
        device_id="GM-C-19A84E72",
        created_at=_ts(0),
        expires_at=_ts(300),
        correlation_id="OCR-00000001",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
    )
    assert action.parameters == {}
    assert action.idempotency_key is None
    assert action.retry_count == 0
    assert action.max_retries == 3


def test_orion_action_with_parameters() -> None:
    action = OrionAction(
        action_id="OAC-00000002",
        action_type=OrionActionType.ACKNOWLEDGE_ALERT,
        device_id="GM-C-19A84E72",
        created_at=_ts(0),
        expires_at=_ts(300),
        correlation_id="OCR-00000002",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
        parameters={"alert_id": "ALT-001"},
    )
    assert action.parameters["alert_id"] == "ALT-001"


def test_orion_action_with_idempotency_key() -> None:
    action = OrionAction(
        action_id="OAC-00000003",
        action_type=OrionActionType.REQUEST_SCREEN_SESSION,
        device_id="GM-C-19A84E72",
        created_at=_ts(0),
        expires_at=_ts(300),
        correlation_id="OCR-00000003",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
        idempotency_key="IDEMP-KEY-XYZ",
    )
    assert action.idempotency_key == "IDEMP-KEY-XYZ"


def test_orion_action_rejects_forbidden_param() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000004",
            action_type=OrionActionType.ACKNOWLEDGE_ALERT,
            device_id="GM-C-19A84E72",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="OCR-00000004",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            parameters={"command": "rm -rf /"},
        )


def test_orion_action_rejects_empty_action_id() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="GM-C-19A84E72",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="OCR-00000005",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
        )


def test_orion_action_rejects_empty_device_id() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000006",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="OCR-00000006",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
        )


def test_orion_action_rejects_empty_correlation_id() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000007",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="GM-C-19A84E72",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
        )


def test_orion_action_rejects_empty_requested_by() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000008",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="GM-C-19A84E72",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="OCR-00000008",
            requested_by="",
            status=OrionActionStatus.PENDING,
        )


def test_orion_action_rejects_invalid_timestamps() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000009",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="GM-C-19A84E72",
            created_at="not-a-timestamp",
            expires_at=_ts(300),
            correlation_id="OCR-00000009",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
        )


def test_orion_action_rejects_negative_retry() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000010",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="GM-C-19A84E72",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="OCR-00000010",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            retry_count=-1,
        )


def test_orion_action_rejects_retry_exceeding_max() -> None:
    with pytest.raises(OrionActionError):
        OrionAction(
            action_id="OAC-00000011",
            action_type=OrionActionType.REFRESH_HEALTH,
            device_id="GM-C-19A84E72",
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id="OCR-00000011",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
            retry_count=5,
            max_retries=3,
        )


def test_orion_action_accepts_sentinel_device_ids() -> None:
    for sentinel in ("SYSTEM", "BUS", "ORION"):
        action = OrionAction(
            action_id=f"OAC-{sentinel}",
            action_type=OrionActionType.REQUEST_CAPABILITIES,
            device_id=sentinel,
            created_at=_ts(0),
            expires_at=_ts(300),
            correlation_id=f"OCR-{sentinel}",
            requested_by="GM-P-83A1F72C",
            status=OrionActionStatus.PENDING,
        )
        assert action.device_id == sentinel


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------


def test_orion_action_is_expired() -> None:
    past_action = OrionAction(
        action_id="OAC-EXP",
        action_type=OrionActionType.REFRESH_HEALTH,
        device_id="GM-C-19A84E72",
        created_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-01-01T00:01:00+00:00",
        correlation_id="OCR-EXP",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
    )
    assert past_action.is_expired() is True

    future_action = OrionAction(
        action_id="OAC-FUT",
        action_type=OrionActionType.REFRESH_HEALTH,
        device_id="GM-C-19A84E72",
        created_at=_ts(0),
        expires_at=_ts(3600),
        correlation_id="OCR-FUT",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
    )
    assert future_action.is_expired() is False


def test_orion_action_can_retry() -> None:
    action = OrionAction(
        action_id="OAC-RET",
        action_type=OrionActionType.REFRESH_HEALTH,
        device_id="GM-C-19A84E72",
        created_at=_ts(0),
        expires_at=_ts(300),
        correlation_id="OCR-RET",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
        retry_count=1,
        max_retries=3,
    )
    assert action.can_retry() is True

    action.retry_count = 3
    assert action.can_retry() is False


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_orion_action_to_dict_round_trip() -> None:
    action = OrionAction(
        action_id="OAC-00000020",
        action_type=OrionActionType.RESOLVE_ALERT,
        device_id="GM-C-19A84E72",
        created_at="2026-08-13T00:00:00+00:00",
        expires_at="2026-08-13T00:05:00+00:00",
        correlation_id="OCR-00000020",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
        parameters={"alert_id": "ALT-002"},
        idempotency_key="IDEMP-1",
        retry_count=1,
        max_retries=3,
    )
    data = action.to_dict()
    assert data["action_id"] == "OAC-00000020"
    assert data["action_type"] == "RESOLVE_ALERT"
    assert data["idempotency_key"] == "IDEMP-1"
    assert data["schema_version"] == SCHEMA_VERSION
    restored = OrionAction.from_dict(data)
    assert restored.action_id == action.action_id
    assert restored.action_type == action.action_type
    assert restored.parameters == action.parameters
    assert restored.idempotency_key == action.idempotency_key


def test_orion_action_to_canonical_json_deterministic() -> None:
    action = OrionAction(
        action_id="OAC-00000030",
        action_type=OrionActionType.REQUEST_CAPABILITIES,
        device_id="GM-C-19A84E72",
        created_at="2026-08-13T00:00:00+00:00",
        expires_at="2026-08-13T00:05:00+00:00",
        correlation_id="OCR-00000030",
        requested_by="GM-P-83A1F72C",
        status=OrionActionStatus.PENDING,
    )
    assert action.to_canonical_json() == action.to_canonical_json()


def test_orion_action_from_dict_rejects_non_dict() -> None:
    with pytest.raises(OrionActionError):
        OrionAction.from_dict("not a dict")  # type: ignore[arg-type]
