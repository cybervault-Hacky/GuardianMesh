"""Tests for Orion Phase 9 in-memory capability registry."""

from __future__ import annotations

import pytest

from guardianmesh.orion.capabilities import OrionCapabilityRegistry
from guardianmesh.orion.errors import OrionCapabilityError
from guardianmesh.orion.models import OrionCapability


def test_registry_pre_populated_with_control_plane() -> None:
    reg = OrionCapabilityRegistry()
    assert "ORION" in reg.device_ids()
    caps = reg.require("ORION")
    assert caps.supports(OrionCapability.HEALTH_TELEMETRY) is True


def test_registry_register_and_get() -> None:
    reg = OrionCapabilityRegistry()
    from guardianmesh.orion.models import OrionDeviceCapabilities

    record = OrionDeviceCapabilities.discover(
        "GM-C-19A84E72", health_telemetry=True, alerts=True
    )
    reg.register(record)
    fetched = reg.get("GM-C-19A84E72")
    assert fetched is record


def test_registry_register_validates_type() -> None:
    reg = OrionCapabilityRegistry()
    with pytest.raises(OrionCapabilityError):
        reg.register("not a capabilities record")  # type: ignore[arg-type]


def test_registry_require_raises_for_unknown() -> None:
    reg = OrionCapabilityRegistry()
    with pytest.raises(OrionCapabilityError):
        reg.require("DOES-NOT-EXIST")


def test_registry_all_returns_records() -> None:
    reg = OrionCapabilityRegistry()
    all_records = reg.all()
    assert len(all_records) >= 1  # at least ORION


def test_registry_supports_unknown_device() -> None:
    reg = OrionCapabilityRegistry()
    assert reg.supports("MISSING", OrionCapability.HEALTH_TELEMETRY) is False


def test_registry_set_capability_enables() -> None:
    reg = OrionCapabilityRegistry()
    reg.set_capability("GM-C-19A84E72", OrionCapability.HEALTH_TELEMETRY, True)
    assert reg.supports("GM-C-19A84E72", OrionCapability.HEALTH_TELEMETRY) is True


def test_registry_set_capability_disables() -> None:
    reg = OrionCapabilityRegistry()
    reg.set_capability("GM-C-19A84E72", OrionCapability.HEALTH_TELEMETRY, True)
    reg.set_capability("GM-C-19A84E72", OrionCapability.HEALTH_TELEMETRY, False)
    assert reg.supports("GM-C-19A84E72", OrionCapability.HEALTH_TELEMETRY) is False


def test_registry_set_capability_rejects_negative_default() -> None:
    reg = OrionCapabilityRegistry()
    with pytest.raises(OrionCapabilityError):
        reg.set_capability("GM-C-19A84E72", OrionCapability.AUDIO_CAPTURE, True)


def test_registry_clear_repopulates_control_plane() -> None:
    reg = OrionCapabilityRegistry()
    reg.set_capability("GM-C-19A84E72", OrionCapability.HEALTH_TELEMETRY, True)
    reg.clear()
    assert "ORION" in reg.device_ids()
    assert reg.get("GM-C-19A84E72") is None


def test_registry_metrics() -> None:
    reg = OrionCapabilityRegistry()
    m = reg.metrics()
    assert "device_count" in m
    assert "positive_capability_count" in m
    assert "negative_capability_count" in m
    assert m["device_count"] >= 1
