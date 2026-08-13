"""GuardianMesh Atlas Phase 10 data models.

This module defines the strongly-typed, deterministic data models
used by the Atlas production-hardening layer. Every model carries
only metadata — never frame bytes, command strings, secrets, or
private user content.
"""

from __future__ import annotations

import datetime
import enum
import secrets
from dataclasses import dataclass, field
from typing import Any

from guardianmesh.atlas.errors import (
    AtlasCapabilityError,
    AtlasError,
    AtlasHealthError,
)
from guardianmesh.core.errors import ValidationError

SCHEMA_VERSION = "1.0"


def generate_atlas_id(prefix: str = "ATL") -> str:
    """Generate a unique Atlas identifier (e.g. ``ATL-...``)."""
    return f"{prefix}-{secrets.token_hex(6).upper()}"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AtlasSubsystem(str, enum.Enum):
    """Subsystems covered by Atlas health and diagnostics."""

    GENESIS = "GENESIS"
    LINK = "LINK"
    PULSE = "PULSE"
    SENTINEL = "SENTINEL"
    CONSOLE = "CONSOLE"
    NEXUS = "NEXUS"
    VISTA = "VISTA"
    AEGIS = "AEGIS"
    ORION = "ORION"
    ATLAS = "ATLAS"

    @classmethod
    def from_str(cls, val: str) -> AtlasSubsystem:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AtlasError(f"Unknown Atlas subsystem: '{val}'") from e


class AtlasHealthStatus(str, enum.Enum):
    """Health status of a GuardianMesh subsystem."""

    OK = "OK"
    DEGRADED = "DEGRADED"
    WARNING = "WARNING"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"

    @classmethod
    def from_str(cls, val: str) -> AtlasHealthStatus:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AtlasHealthError(f"Unknown health status: '{val}'") from e


class AtlasSecurityLevel(str, enum.Enum):
    """Security classification for a capability."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_str(cls, val: str) -> AtlasSecurityLevel:
        normalized = val.strip().upper()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AtlasCapabilityError(f"Unknown security level: '{val}'") from e


class AtlasBackupFormat(str, enum.Enum):
    """Supported backup formats."""

    ATLAS_V1 = "atlas-1.0"

    @classmethod
    def from_str(cls, val: str) -> AtlasBackupFormat:
        normalized = val.strip().lower()
        try:
            return cls(normalized)
        except ValueError as e:
            raise AtlasError(f"Unknown backup format: '{val}'") from e


# ---------------------------------------------------------------------------
# Capability version
# ---------------------------------------------------------------------------


@dataclass
class AtlasCapabilityVersion:
    """Versioned capability descriptor.

    Capabilities describe what a subsystem can do. They are
    informational — they are never inferred from the platform.
    """

    capability_id: str
    capability_name: str
    version: str = SCHEMA_VERSION
    status: str = "ACTIVE"
    requires_trust: bool = False
    requires_vista: bool = False
    requires_aegis: bool = False
    risk_level: AtlasSecurityLevel = AtlasSecurityLevel.LOW
    schema_version: str = SCHEMA_VERSION
    updated_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.capability_id:
            raise AtlasCapabilityError("capability_id is required.")
        if not self.capability_name:
            raise AtlasCapabilityError("capability_name is required.")
        if not self.version:
            raise AtlasCapabilityError("version is required.")
        if self.status not in ("ACTIVE", "DEPRECATED", "DISABLED", "EXPERIMENTAL"):
            raise AtlasCapabilityError(
                f"Unknown capability status: '{self.status}'"
            )
        if isinstance(self.risk_level, str):
            self.risk_level = AtlasSecurityLevel.from_str(self.risk_level)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "capability_name": self.capability_name,
            "version": self.version,
            "status": self.status,
            "requires_trust": self.requires_trust,
            "requires_vista": self.requires_vista,
            "requires_aegis": self.requires_aegis,
            "risk_level": self.risk_level.value
            if isinstance(self.risk_level, AtlasSecurityLevel)
            else str(self.risk_level),
            "schema_version": self.schema_version,
            "updated_at": self.updated_at,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Backup info
# ---------------------------------------------------------------------------


@dataclass
class AtlasBackupInfo:
    """Metadata-only backup descriptor.

    A backup is identified by its manifest. The manifest is
    integrity-protected by a digest. The backup never contains
    frame bytes, secrets, or private user content.
    """

    backup_id: str
    created_at: str
    schema_version: str
    orion_version: str
    backup_format: AtlasBackupFormat = AtlasBackupFormat.ATLAS_V1
    device_id: str | None = None
    integrity_digest: str = ""
    size_bytes: int = 0
    status: str = "VALID"
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.backup_id:
            raise AtlasError("backup_id is required.")
        if not self.created_at:
            raise AtlasError("created_at is required.")
        if not self.schema_version:
            raise AtlasError("schema_version is required.")
        if not self.orion_version:
            raise AtlasError("orion_version is required.")
        if self.size_bytes < 0:
            raise ValidationError("size_bytes must be non-negative.")
        if isinstance(self.backup_format, str):
            self.backup_format = AtlasBackupFormat.from_str(self.backup_format)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "schema_version": self.schema_version,
            "orion_version": self.orion_version,
            "backup_format": self.backup_format.value
            if isinstance(self.backup_format, AtlasBackupFormat)
            else str(self.backup_format),
            "device_id": self.device_id,
            "integrity_digest": self.integrity_digest,
            "size_bytes": self.size_bytes,
            "status": self.status,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Recovery record
# ---------------------------------------------------------------------------


@dataclass
class AtlasRecoveryRecord:
    """Metadata-only record of a crash-recovery operation."""

    recovery_id: str
    operation: str
    started_at: str
    completed_at: str | None = None
    device_id: str | None = None
    status: str = "PENDING"
    actions_taken: int = 0
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.recovery_id:
            raise AtlasError("recovery_id is required.")
        if not self.operation:
            raise AtlasError("operation is required.")
        if not self.started_at:
            raise AtlasError("started_at is required.")
        if self.status not in ("PENDING", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED"):
            raise AtlasError(f"Unknown recovery status: '{self.status}'")
        if self.actions_taken < 0:
            raise ValidationError("actions_taken must be non-negative.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "recovery_id": self.recovery_id,
            "operation": self.operation,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "device_id": self.device_id,
            "status": self.status,
            "actions_taken": self.actions_taken,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Retention policy
# ---------------------------------------------------------------------------


@dataclass
class AtlasRetentionPolicy:
    """Bounded retention policy for a metadata table.

    Atlas retention is metadata-only. It never collects new
    categories of personal data. It only bounds the growth of
    tables that already exist.
    """

    retention_id: str
    target_table: str
    retention_days: int
    enabled: bool = True
    updated_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.retention_id:
            raise AtlasError("retention_id is required.")
        if not self.target_table:
            raise AtlasError("target_table is required.")
        if self.retention_days <= 0:
            raise ValidationError("retention_days must be positive.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "retention_id": self.retention_id,
            "target_table": self.target_table,
            "retention_days": self.retention_days,
            "enabled": self.enabled,
            "updated_at": self.updated_at,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Diagnostic report
# ---------------------------------------------------------------------------


@dataclass
class AtlasDiagnosticCheck:
    """A single diagnostic check result."""

    name: str
    ok: bool
    subsystem: str = "ATLAS"
    reason: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "subsystem": self.subsystem,
            "reason": self.reason,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AtlasDiagnosticReport:
    """A collection of diagnostic check results."""

    checks: list[AtlasDiagnosticCheck] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat()
    )

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.ok)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if not c.ok)

    @property
    def critical_failure(self) -> bool:
        return any(not c.ok for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checks": [c.to_dict() for c in self.checks],
            "generated_at": self.generated_at,
            "passed": self.passed,
            "failed": self.failed,
            "critical_failure": self.critical_failure,
        }


# ---------------------------------------------------------------------------
# Default health profiles
# ---------------------------------------------------------------------------


DEFAULT_ATLAS_HEALTH_PROFILES: dict[AtlasSubsystem, AtlasHealthStatus] = {
    AtlasSubsystem.GENESIS: AtlasHealthStatus.OK,
    AtlasSubsystem.LINK: AtlasHealthStatus.OK,
    AtlasSubsystem.PULSE: AtlasHealthStatus.OK,
    AtlasSubsystem.SENTINEL: AtlasHealthStatus.OK,
    AtlasSubsystem.CONSOLE: AtlasHealthStatus.OK,
    AtlasSubsystem.NEXUS: AtlasHealthStatus.OK,
    AtlasSubsystem.VISTA: AtlasHealthStatus.OK,
    AtlasSubsystem.AEGIS: AtlasHealthStatus.OK,
    AtlasSubsystem.ORION: AtlasHealthStatus.OK,
    AtlasSubsystem.ATLAS: AtlasHealthStatus.OK,
}


__all__ = [
    "DEFAULT_ATLAS_HEALTH_PROFILES",
    "AtlasBackupFormat",
    "AtlasBackupInfo",
    "AtlasCapabilityVersion",
    "AtlasDiagnosticCheck",
    "AtlasDiagnosticReport",
    "AtlasHealthStatus",
    "AtlasRecoveryRecord",
    "AtlasRetentionPolicy",
    "AtlasSecurityLevel",
    "AtlasSubsystem",
    "generate_atlas_id",
]
