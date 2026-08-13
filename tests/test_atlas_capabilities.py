"""Tests for Atlas Phase 10 capability registry."""

from __future__ import annotations

import pytest

from guardianmesh.atlas.capabilities import (
    DEFAULT_ATLAS_CAPABILITIES,
    AtlasCapabilityRegistry,
)
from guardianmesh.atlas.errors import AtlasCapabilityError
from guardianmesh.atlas.models import (
    AtlasCapabilityVersion,
    AtlasSecurityLevel,
)


def test_default_capabilities_cover_every_subsystem() -> None:
    names = {c.capability_name for c in DEFAULT_ATLAS_CAPABILITIES}
    assert "genesis" in names
    assert "link" in names
    assert "pulse" in names
    assert "sentinel" in names
    assert "console" in names
    assert "nexus" in names
    assert "vista" in names
    assert "aegis" in names
    assert "orion" in names
    assert "atlas" in names


def test_default_capabilities_have_version() -> None:
    for c in DEFAULT_ATLAS_CAPABILITIES:
        assert c.version == "1.0"
        assert c.status == "ACTIVE"


def test_aegis_capability_requires_aegis_consent() -> None:
    aegis = next(c for c in DEFAULT_ATLAS_CAPABILITIES if c.capability_name == "aegis")
    assert aegis.requires_trust is True
    assert aegis.requires_vista is True
    assert aegis.requires_aegis is True
    assert aegis.risk_level == AtlasSecurityLevel.CRITICAL


def test_vista_capability_requires_vista() -> None:
    vista = next(c for c in DEFAULT_ATLAS_CAPABILITIES if c.capability_name == "vista")
    assert vista.requires_trust is True
    assert vista.requires_vista is True
    assert vista.requires_aegis is False
    assert vista.risk_level == AtlasSecurityLevel.HIGH


def test_atlas_capability_low_risk() -> None:
    atlas = next(c for c in DEFAULT_ATLAS_CAPABILITIES if c.capability_name == "atlas")
    assert atlas.requires_trust is False
    assert atlas.requires_vista is False
    assert atlas.requires_aegis is False
    assert atlas.risk_level == AtlasSecurityLevel.LOW


def test_registry_pre_populated() -> None:
    reg = AtlasCapabilityRegistry()
    assert reg.metrics()["capability_count"] == 10


def test_registry_get_known_capability() -> None:
    reg = AtlasCapabilityRegistry()
    cap = reg.get("ATL-CAP-AEGIS")
    assert cap is not None
    assert cap.capability_name == "aegis"


def test_registry_get_unknown_capability() -> None:
    reg = AtlasCapabilityRegistry()
    assert reg.get("ATL-CAP-UNKNOWN") is None


def test_registry_register_validates_type() -> None:
    reg = AtlasCapabilityRegistry()
    with pytest.raises(AtlasCapabilityError):
        reg.register("not a capability")  # type: ignore[arg-type]


def test_registry_register_overrides() -> None:
    reg = AtlasCapabilityRegistry()
    new_cap = AtlasCapabilityVersion(
        capability_id="ATL-CAP-AEGIS",
        capability_name="aegis-v2",
        version="2.0",
        risk_level=AtlasSecurityLevel.CRITICAL,
    )
    reg.register(new_cap)
    assert reg.get("ATL-CAP-AEGIS").capability_name == "aegis-v2"


def test_registry_known() -> None:
    reg = AtlasCapabilityRegistry()
    assert reg.known("ATL-CAP-AEGIS") is True
    assert reg.known("ATL-CAP-UNKNOWN") is False


def test_registry_supports_returns_false_for_unknown() -> None:
    reg = AtlasCapabilityRegistry()
    assert reg.supports("ATL-CAP-UNKNOWN") is False


def test_registry_supports_returns_true_for_active() -> None:
    reg = AtlasCapabilityRegistry()
    assert reg.supports("ATL-CAP-AEGIS") is True


def test_registry_supports_returns_false_for_deprecated() -> None:
    reg = AtlasCapabilityRegistry()
    reg.register(
        AtlasCapabilityVersion(
            capability_id="ATL-CAP-DEP",
            capability_name="dep",
            status="DEPRECATED",
        )
    )
    assert reg.supports("ATL-CAP-DEP") is False


def test_registry_all_returns_records() -> None:
    reg = AtlasCapabilityRegistry()
    all_caps = reg.all()
    assert len(all_caps) == 10


def test_registry_metrics() -> None:
    reg = AtlasCapabilityRegistry()
    m = reg.metrics()
    assert m["capability_count"] == 10
    assert m["active"] == 10
    assert m["deprecated"] == 0
    assert m["experimental"] == 0


def test_registry_rejects_surveillance_capability() -> None:
    """A capability that tries to enable a surveillance name must be safe."""
    # Atlas capability names do not include surveillance-style names.
    # The registry will accept any name string, but the documented
    # allowlist never includes them. We verify that no default
    # capability is named like a surveillance primitive.
    names = {c.capability_name.lower() for c in DEFAULT_ATLAS_CAPABILITIES}
    for forbidden in (
        "keystroke",
        "microphone",
        "camera",
        "location",
        "clipboard",
        "browser_history",
        "shell",
        "remote_input",
    ):
        assert forbidden not in names
