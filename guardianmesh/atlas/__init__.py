"""GuardianMesh Atlas Phase 10 (v1.0.0).

Production Hardening, Reliability & Release Platform.

Atlas is the final production layer in the GuardianMesh 10-phase
roadmap. It does not introduce any new surveillance capability. It
hardens the existing system by adding:

* Integrity verification for the database, identity, trust, and
  audit subsystems.
* Lifecycle validation for keys, sessions, sequences, and stale
  state.
* Health and observability metrics for every GuardianMesh
  subsystem.
* Bounded backup and restore of metadata-only state.
* Crash recovery for interrupted operations.
* Capability versioning with explicit risk classification.
* Retention policies for bounded metadata growth.
* Release validation that does not claim readiness when checks
  fail.
* Diagnostics that report honestly on Linux/Termux without faking
  Android validation.

Atlas never bypasses Trust, Vista authorization, or Aegis system
consent. It never stores frame bytes, command strings, secrets, or
private user content.
"""

from __future__ import annotations

from guardianmesh.atlas.backup import AtlasBackupManager
from guardianmesh.atlas.capabilities import AtlasCapabilityRegistry
from guardianmesh.atlas.compatibility import AtlasCompatibilityChecker
from guardianmesh.atlas.controller import AtlasController
from guardianmesh.atlas.diagnostics import AtlasDiagnostics
from guardianmesh.atlas.errors import (
    AtlasBackupError,
    AtlasCapabilityError,
    AtlasCompatibilityError,
    AtlasConcurrencyError,
    AtlasConfigurationError,
    AtlasDiagnosticsError,
    AtlasError,
    AtlasHealthError,
    AtlasIntegrityError,
    AtlasLifecycleError,
    AtlasObservabilityError,
    AtlasRecoveryError,
    AtlasReleaseError,
    AtlasRetentionError,
    AtlasSecurityError,
)
from guardianmesh.atlas.health import AtlasHealthMonitor
from guardianmesh.atlas.integrity import AtlasIntegrityVerifier
from guardianmesh.atlas.lifecycle import AtlasLifecycleValidator
from guardianmesh.atlas.metrics import AtlasMetrics
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
from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.atlas.recovery import AtlasRecoveryManager
from guardianmesh.atlas.release import AtlasReleaseValidator
from guardianmesh.atlas.restore import AtlasRestoreManager
from guardianmesh.atlas.retention import AtlasRetentionManager

__all__ = [
    "DEFAULT_ATLAS_HEALTH_PROFILES",
    "SCHEMA_VERSION",
    "AtlasBackupError",
    "AtlasBackupFormat",
    "AtlasBackupInfo",
    "AtlasBackupManager",
    "AtlasCapabilityError",
    "AtlasCapabilityRegistry",
    "AtlasCapabilityVersion",
    "AtlasCompatibilityChecker",
    "AtlasCompatibilityError",
    "AtlasConcurrencyError",
    "AtlasConfigurationError",
    "AtlasController",
    "AtlasDiagnosticCheck",
    "AtlasDiagnosticReport",
    "AtlasDiagnostics",
    "AtlasDiagnosticsError",
    "AtlasError",
    "AtlasHealthError",
    "AtlasHealthMonitor",
    "AtlasHealthStatus",
    "AtlasIntegrityError",
    "AtlasIntegrityVerifier",
    "AtlasLifecycleError",
    "AtlasLifecycleValidator",
    "AtlasMetrics",
    "AtlasObservability",
    "AtlasObservabilityError",
    "AtlasRecoveryError",
    "AtlasRecoveryManager",
    "AtlasRecoveryRecord",
    "AtlasReleaseError",
    "AtlasReleaseValidator",
    "AtlasRestoreManager",
    "AtlasRetentionError",
    "AtlasRetentionManager",
    "AtlasRetentionPolicy",
    "AtlasSecurityError",
    "AtlasSecurityLevel",
    "AtlasSubsystem",
    "generate_atlas_id",
]
