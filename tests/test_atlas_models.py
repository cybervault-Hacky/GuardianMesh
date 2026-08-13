"""Tests for Atlas Phase 10 data models, enums, and serialization."""

from __future__ import annotations

import pytest

from guardianmesh.atlas.errors import (
    AtlasCapabilityError,
    AtlasError,
    AtlasHealthError,
)
from guardianmesh.atlas.models import (
    DEFAULT_ATLAS_HEALTH_PROFILES,
    SCHEMA_VERSION,
    AtlasBackupFormat,
    AtlasBackupInfo,
    AtlasCapabilityVersion,
    AtlasDiagnosticCheck,
    AtlasDiagnosticReport,
    AtlasHealthStatus,
    AtlasRecoveryRecord,
    AtlasRetentionPolicy,
    AtlasSecurityLevel,
    AtlasSubsystem,
    generate_atlas_id,
)

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


def test_atlas_subsystem_values() -> None:
    for v in (
        "GENESIS",
        "LINK",
        "PULSE",
        "SENTINEL",
        "CONSOLE",
        "NEXUS",
        "VISTA",
        "AEGIS",
        "ORION",
        "ATLAS",
    ):
        assert AtlasSubsystem(v).value == v


def test_atlas_subsystem_from_str_case_insensitive() -> None:
    assert AtlasSubsystem.from_str("genesis") == AtlasSubsystem.GENESIS
    with pytest.raises(AtlasError):
        AtlasSubsystem.from_str("UNKNOWN")


def test_atlas_health_status_values() -> None:
    for v in ("OK", "DEGRADED", "WARNING", "FAILED", "UNAVAILABLE"):
        assert AtlasHealthStatus(v).value == v


def test_atlas_health_status_from_str_invalid() -> None:
    with pytest.raises(AtlasHealthError):
        AtlasHealthStatus.from_str("UNKNOWN")


def test_atlas_security_level_values() -> None:
    for v in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        assert AtlasSecurityLevel(v).value == v


def test_atlas_security_level_from_str_invalid() -> None:
    with pytest.raises(AtlasCapabilityError):
        AtlasSecurityLevel.from_str("UNKNOWN")


def test_atlas_backup_format_values() -> None:
    assert AtlasBackupFormat.ATLAS_V1.value == "atlas-1.0"


def test_atlas_backup_format_from_str() -> None:
    assert AtlasBackupFormat.from_str("atlas-1.0") == AtlasBackupFormat.ATLAS_V1
    with pytest.raises(AtlasError):
        AtlasBackupFormat.from_str("atlas-99.0")


# ---------------------------------------------------------------------------
# Identifier generation
# ---------------------------------------------------------------------------


def test_generate_atlas_id_format() -> None:
    a = generate_atlas_id()
    b = generate_atlas_id()
    assert a != b
    assert a.startswith("ATL-")


def test_generate_atlas_id_custom_prefix() -> None:
    aid = generate_atlas_id("CUSTOM")
    assert aid.startswith("CUSTOM-")


# ---------------------------------------------------------------------------
# AtlasCapabilityVersion
# ---------------------------------------------------------------------------


def test_capability_version_minimal_valid() -> None:
    cap = AtlasCapabilityVersion(
        capability_id="ATL-CAP-X",
        capability_name="x",
    )
    assert cap.status == "ACTIVE"
    assert cap.risk_level == AtlasSecurityLevel.LOW
    assert cap.requires_trust is False


def test_capability_version_rejects_empty_id() -> None:
    with pytest.raises(AtlasCapabilityError):
        AtlasCapabilityVersion(capability_id="", capability_name="x")


def test_capability_version_rejects_empty_name() -> None:
    with pytest.raises(AtlasCapabilityError):
        AtlasCapabilityVersion(capability_id="ATL-CAP-X", capability_name="")


def test_capability_version_rejects_invalid_status() -> None:
    with pytest.raises(AtlasCapabilityError):
        AtlasCapabilityVersion(
            capability_id="ATL-CAP-X",
            capability_name="x",
            status="BAD_STATUS",
        )


def test_capability_version_string_risk_level() -> None:
    cap = AtlasCapabilityVersion(
        capability_id="ATL-CAP-X",
        capability_name="x",
        risk_level="CRITICAL",
    )
    assert cap.risk_level == AtlasSecurityLevel.CRITICAL


def test_capability_version_to_dict() -> None:
    cap = AtlasCapabilityVersion(
        capability_id="ATL-CAP-X",
        capability_name="x",
        requires_trust=True,
        requires_vista=True,
        risk_level=AtlasSecurityLevel.HIGH,
    )
    d = cap.to_dict()
    assert d["capability_id"] == "ATL-CAP-X"
    assert d["requires_trust"] is True
    assert d["risk_level"] == "HIGH"


# ---------------------------------------------------------------------------
# AtlasBackupInfo
# ---------------------------------------------------------------------------


def _make_backup() -> AtlasBackupInfo:
    return AtlasBackupInfo(
        backup_id="BAK-00000001",
        created_at="2026-08-13T00:00:00+00:00",
        schema_version="10",
        orion_version="1.0.0",
        integrity_digest="sha256:abc",
        size_bytes=2048,
    )


def test_backup_info_minimal_valid() -> None:
    info = _make_backup()
    assert info.status == "VALID"


def test_backup_info_rejects_empty_id() -> None:
    with pytest.raises(AtlasError):
        AtlasBackupInfo(
            backup_id="",
            created_at="2026-08-13T00:00:00+00:00",
            schema_version="10",
            orion_version="1.0.0",
        )


def test_backup_info_rejects_empty_timestamps() -> None:
    with pytest.raises(AtlasError):
        AtlasBackupInfo(
            backup_id="BAK-1",
            created_at="",
            schema_version="10",
            orion_version="1.0.0",
        )


def test_backup_info_rejects_negative_size() -> None:
    from guardianmesh.core.errors import ValidationError

    with pytest.raises(ValidationError):
        AtlasBackupInfo(
            backup_id="BAK-1",
            created_at="2026-08-13T00:00:00+00:00",
            schema_version="10",
            orion_version="1.0.0",
            size_bytes=-1,
        )


def test_backup_info_to_dict() -> None:
    info = _make_backup()
    d = info.to_dict()
    assert d["backup_id"] == "BAK-00000001"
    assert d["orion_version"] == "1.0.0"


# ---------------------------------------------------------------------------
# AtlasRecoveryRecord
# ---------------------------------------------------------------------------


def test_recovery_record_minimal_valid() -> None:
    rec = AtlasRecoveryRecord(
        recovery_id="REC-00000001",
        operation="recover_orion_actions",
        started_at="2026-08-13T00:00:00+00:00",
    )
    assert rec.status == "PENDING"
    assert rec.actions_taken == 0


def test_recovery_record_rejects_invalid_status() -> None:
    with pytest.raises(AtlasError):
        AtlasRecoveryRecord(
            recovery_id="REC-1",
            operation="x",
            started_at="2026-08-13T00:00:00+00:00",
            status="BAD_STATUS",
        )


def test_recovery_record_rejects_negative_actions() -> None:
    from guardianmesh.core.errors import ValidationError

    with pytest.raises(ValidationError):
        AtlasRecoveryRecord(
            recovery_id="REC-1",
            operation="x",
            started_at="2026-08-13T00:00:00+00:00",
            actions_taken=-1,
        )


# ---------------------------------------------------------------------------
# AtlasRetentionPolicy
# ---------------------------------------------------------------------------


def test_retention_policy_minimal_valid() -> None:
    policy = AtlasRetentionPolicy(
        retention_id="RET-00000001",
        target_table="audit_events",
        retention_days=365,
    )
    assert policy.enabled is True


def test_retention_policy_rejects_zero_days() -> None:
    from guardianmesh.core.errors import ValidationError

    with pytest.raises(ValidationError):
        AtlasRetentionPolicy(
            retention_id="RET-1",
            target_table="audit_events",
            retention_days=0,
        )


# ---------------------------------------------------------------------------
# AtlasDiagnosticCheck / Report
# ---------------------------------------------------------------------------


def test_diagnostic_check_to_dict() -> None:
    check = AtlasDiagnosticCheck(name="x", ok=True, subsystem="ATLAS", reason="r")
    d = check.to_dict()
    assert d["name"] == "x"
    assert d["ok"] is True


def test_diagnostic_report_counts() -> None:
    report = AtlasDiagnosticReport(
        checks=[
            AtlasDiagnosticCheck(name="a", ok=True, subsystem="ATLAS"),
            AtlasDiagnosticCheck(name="b", ok=False, subsystem="ATLAS"),
        ]
    )
    assert report.passed == 1
    assert report.failed == 1
    assert report.critical_failure is True


def test_diagnostic_report_to_dict() -> None:
    report = AtlasDiagnosticReport(
        checks=[AtlasDiagnosticCheck(name="a", ok=True, subsystem="ATLAS")],
    )
    d = report.to_dict()
    assert d["passed"] == 1
    assert d["failed"] == 0
    assert d["critical_failure"] is False


# ---------------------------------------------------------------------------
# Default health profiles
# ---------------------------------------------------------------------------


def test_default_health_profiles_covers_every_subsystem() -> None:
    for sub in AtlasSubsystem:
        assert sub in DEFAULT_ATLAS_HEALTH_PROFILES
        assert DEFAULT_ATLAS_HEALTH_PROFILES[sub] == AtlasHealthStatus.OK


def test_schema_version_constant() -> None:
    assert SCHEMA_VERSION == "1.0"
