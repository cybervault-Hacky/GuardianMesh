"""Tests for Orion Phase 9 models, capabilities, and reconciliation reports."""

from __future__ import annotations

import pytest

from guardianmesh.orion.errors import OrionCapabilityError
from guardianmesh.orion.models import (
    DEFAULT_CONTROL_PLANE_CAPABILITIES,
    SCHEMA_VERSION,
    OrionCapability,
    OrionDeviceCapabilities,
    OrionReconciliationReport,
    generate_capability_id,
)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


def test_orion_capability_values() -> None:
    """The capability enum exposes the documented values."""
    for value in (
        "HEALTH_TELEMETRY",
        "POLICIES",
        "ALERTS",
        "SECURE_TRANSPORT",
        "SCREEN_SESSION",
        "SYSTEM_CONSENT",
        "ORCHESTRATION",
        "AUDIO_CAPTURE",
        "CAMERA_CAPTURE",
        "REMOTE_INPUT",
        "REMOTE_SHELL",
        "KEYLOGGING",
        "LOCATION_TRACKING",
        "CLIPBOARD_ACCESS",
        "MESSAGE_COLLECTION",
        "BROWSER_HISTORY",
        "HIDDEN_SCREEN_CAPTURE",
    ):
        assert OrionCapability(value).value == value


def test_negative_default_capabilities_are_identified() -> None:
    """Each negative-default capability reports is_negative_default=True."""
    for cap in (
        OrionCapability.AUDIO_CAPTURE,
        OrionCapability.CAMERA_CAPTURE,
        OrionCapability.REMOTE_INPUT,
        OrionCapability.REMOTE_SHELL,
        OrionCapability.KEYLOGGING,
        OrionCapability.LOCATION_TRACKING,
        OrionCapability.CLIPBOARD_ACCESS,
        OrionCapability.MESSAGE_COLLECTION,
        OrionCapability.BROWSER_HISTORY,
        OrionCapability.HIDDEN_SCREEN_CAPTURE,
    ):
        assert cap.is_negative_default is True


def test_positive_capabilities_are_not_negative_default() -> None:
    """Each positive capability reports is_negative_default=False."""
    for cap in (
        OrionCapability.HEALTH_TELEMETRY,
        OrionCapability.POLICIES,
        OrionCapability.ALERTS,
        OrionCapability.SECURE_TRANSPORT,
        OrionCapability.SCREEN_SESSION,
        OrionCapability.SYSTEM_CONSENT,
        OrionCapability.ORCHESTRATION,
    ):
        assert cap.is_negative_default is False


def test_orion_capability_from_str_case_insensitive() -> None:
    assert OrionCapability.from_str("health_telemetry") == OrionCapability.HEALTH_TELEMETRY


def test_orion_capability_from_str_invalid() -> None:
    with pytest.raises(OrionCapabilityError):
        OrionCapability.from_str("UNKNOWN_CAPABILITY")


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------


def test_generate_capability_id_format() -> None:
    a = generate_capability_id()
    b = generate_capability_id()
    assert a != b
    assert a.startswith("OCP-")


# ---------------------------------------------------------------------------
# OrionDeviceCapabilities
# ---------------------------------------------------------------------------


def test_capabilities_rejects_empty_device_id() -> None:
    with pytest.raises(OrionCapabilityError):
        OrionDeviceCapabilities(device_id="")


def test_capabilities_rejects_negative_default_true() -> None:
    """A negative-default capability cannot be set to True."""
    with pytest.raises(OrionCapabilityError):
        OrionDeviceCapabilities(
            device_id="GM-C-19A84E72",
            capabilities={OrionCapability.AUDIO_CAPTURE: True},
        )


def test_capabilities_negative_default_can_be_explicit_false() -> None:
    """A negative-default capability can be explicitly recorded as False."""
    caps = OrionDeviceCapabilities(
        device_id="GM-C-19A84E72",
        capabilities={OrionCapability.AUDIO_CAPTURE: False},
    )
    assert caps.supports(OrionCapability.AUDIO_CAPTURE) is False


def test_capabilities_supports_method() -> None:
    """supports() returns True only for explicitly enabled capabilities."""
    caps = OrionDeviceCapabilities.discover(
        "GM-C-19A84E72", health_telemetry=True, policies=True
    )
    assert caps.supports(OrionCapability.HEALTH_TELEMETRY) is True
    assert caps.supports(OrionCapability.POLICIES) is True
    assert caps.supports(OrionCapability.SCREEN_SESSION) is False
    assert caps.supports(OrionCapability.AUDIO_CAPTURE) is False


def test_capabilities_enable_disable() -> None:
    """enable() and disable() update the capabilities record."""
    caps = OrionDeviceCapabilities.discover("GM-C-19A84E72")
    caps.enable(OrionCapability.HEALTH_TELEMETRY)
    assert caps.supports(OrionCapability.HEALTH_TELEMETRY) is True
    caps.disable(OrionCapability.HEALTH_TELEMETRY)
    assert caps.supports(OrionCapability.HEALTH_TELEMETRY) is False


def test_capabilities_enable_rejects_negative_default() -> None:
    """enable() on a negative-default capability raises OrionCapabilityError."""
    caps = OrionDeviceCapabilities.discover("GM-C-19A84E72")
    with pytest.raises(OrionCapabilityError):
        caps.enable(OrionCapability.REMOTE_INPUT)


def test_capabilities_round_trip() -> None:
    """OrionDeviceCapabilities round-trips through to_dict/from_dict."""
    caps = OrionDeviceCapabilities.discover(
        "GM-C-19A84E72",
        health_telemetry=True,
        alerts=True,
        secure_transport=True,
    )
    data = caps.to_dict()
    restored = OrionDeviceCapabilities.from_dict(data)
    assert restored.device_id == caps.device_id
    assert restored.supports(OrionCapability.HEALTH_TELEMETRY) is True
    assert restored.supports(OrionCapability.ALERTS) is True
    assert restored.supports(OrionCapability.SCREEN_SESSION) is False


def test_capabilities_positive_capabilities_returns_only_enabled() -> None:
    """positive_capabilities() returns only the enabled positive capabilities."""
    caps = OrionDeviceCapabilities.discover(
        "GM-C-19A84E72", health_telemetry=True, policies=True
    )
    positives = caps.positive_capabilities()
    assert OrionCapability.HEALTH_TELEMETRY in positives
    assert OrionCapability.POLICIES in positives
    assert OrionCapability.SCREEN_SESSION not in positives


def test_capabilities_negative_capabilities_returns_all() -> None:
    """negative_capabilities() returns all negative defaults."""
    caps = OrionDeviceCapabilities.discover("GM-C-19A84E72")
    negs = caps.negative_capabilities()
    assert OrionCapability.AUDIO_CAPTURE in negs
    assert OrionCapability.REMOTE_SHELL in negs
    assert OrionCapability.HIDDEN_SCREEN_CAPTURE in negs


def test_capabilities_canonical_json_deterministic() -> None:
    """to_canonical_json() is deterministic for the same input."""
    caps = OrionDeviceCapabilities.discover(
        "GM-C-19A84E72", health_telemetry=True
    )
    a = caps.to_canonical_json()
    b = caps.to_canonical_json()
    assert a == b


def test_capabilities_rejects_invalid_device_id_format() -> None:
    """An invalid device_id format is rejected at construction."""
    with pytest.raises(OrionCapabilityError):
        OrionDeviceCapabilities(device_id="INVALID")


def test_capabilities_accepts_orion_sentinel() -> None:
    """The 'ORION' sentinel device_id is accepted."""
    caps = OrionDeviceCapabilities.discover("ORION")
    assert caps.device_id == "ORION"


def test_default_control_plane_profile() -> None:
    """The default control-plane profile has the documented capabilities."""
    caps = OrionDeviceCapabilities(
        device_id="ORION",
        capabilities=DEFAULT_CONTROL_PLANE_CAPABILITIES.copy(),
    )
    assert caps.supports(OrionCapability.HEALTH_TELEMETRY) is True
    assert caps.supports(OrionCapability.ORCHESTRATION) is True
    assert caps.supports(OrionCapability.SCREEN_SESSION) is False
    assert caps.supports(OrionCapability.AUDIO_CAPTURE) is False


# ---------------------------------------------------------------------------
# OrionReconciliationReport
# ---------------------------------------------------------------------------


def test_report_rejects_empty_report_id() -> None:
    from guardianmesh.orion.errors import OrionError

    with pytest.raises(OrionError):
        OrionReconciliationReport(
            report_id="",
            device_id="GM-C-19A84E72",
            started_at="2026-08-13T00:00:00+00:00",
            completed_at=None,
        )


def test_report_rejects_empty_device_id() -> None:
    from guardianmesh.orion.errors import OrionError

    with pytest.raises(OrionError):
        OrionReconciliationReport(
            report_id="ORC-12345678",
            device_id="",
            started_at="2026-08-13T00:00:00+00:00",
            completed_at=None,
        )


def test_report_rejects_empty_started_at() -> None:
    from guardianmesh.orion.errors import OrionError

    with pytest.raises(OrionError):
        OrionReconciliationReport(
            report_id="ORC-12345678",
            device_id="GM-C-19A84E72",
            started_at="",
            completed_at=None,
        )


def test_report_round_trip() -> None:
    report = OrionReconciliationReport(
        report_id="ORC-12345678",
        device_id="GM-C-19A84E72",
        started_at="2026-08-13T00:00:00+00:00",
        completed_at="2026-08-13T00:01:00+00:00",
        events_processed=42,
        conflicts_detected=3,
        conflicts_resolved=3,
        stale_events=2,
        failed_actions=0,
    )
    data = report.to_dict()
    restored = OrionReconciliationReport.from_dict(data)
    assert restored.report_id == report.report_id
    assert restored.events_processed == 42
    assert restored.conflicts_detected == 3


def test_report_default_final_state() -> None:
    report = OrionReconciliationReport(
        report_id="ORC-12345678",
        device_id="GM-C-19A84E72",
        started_at="2026-08-13T00:00:00+00:00",
        completed_at=None,
    )
    assert report.final_state == "SYNCED"


def test_report_no_sensitive_payload() -> None:
    """The report never contains sensitive fields."""
    report = OrionReconciliationReport(
        report_id="ORC-12345678",
        device_id="GM-C-19A84E72",
        started_at="2026-08-13T00:00:00+00:00",
        completed_at=None,
    )
    data = report.to_dict()
    forbidden = {"payload", "frame", "screenshot", "password", "secret", "command"}
    assert forbidden.isdisjoint(set(data.keys()))


def test_schema_version_constant() -> None:
    """The schema version is documented and stable."""
    assert SCHEMA_VERSION == "1.0"
    assert OrionDeviceCapabilities(device_id="GM-C-19A84E72").schema_version == "1.0"
