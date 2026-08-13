"""GuardianMesh Atlas Phase 10 exception hierarchy.

All Atlas errors derive from :class:`AtlasError`, which itself
derives from :class:`guardianmesh.core.errors.GuardianMeshError`.
"""

from __future__ import annotations

from guardianmesh.core.errors import GuardianMeshError


class AtlasError(GuardianMeshError):
    """Base exception for the Atlas production-hardening subsystem."""


class AtlasIntegrityError(AtlasError):
    """Raised when an integrity check fails (DB, identity, audit, etc.)."""


class AtlasLifecycleError(AtlasError):
    """Raised when a key or session lifecycle validation fails."""


class AtlasHealthError(AtlasError):
    """Raised when a subsystem health check cannot be evaluated."""


class AtlasDiagnosticsError(AtlasError):
    """Raised when a diagnostic check cannot be evaluated."""


class AtlasBackupError(AtlasError):
    """Raised when a backup operation fails."""


class AtlasRecoveryError(AtlasError):
    """Raised when a crash-recovery operation fails."""


class AtlasCompatibilityError(AtlasError):
    """Raised when a backup, schema, or capability is incompatible."""


class AtlasCapabilityError(AtlasError):
    """Raised when a capability is unknown, unsafe, or unsupported."""


class AtlasObservabilityError(AtlasError):
    """Raised when an observability metric cannot be collected."""


class AtlasRetentionError(AtlasError):
    """Raised when a retention operation fails."""


class AtlasSecurityError(AtlasError):
    """Raised when a security hardening check fails."""


class AtlasReleaseError(AtlasError):
    """Raised when a release validation check fails."""


class AtlasConfigurationError(AtlasError):
    """Raised when a configuration is invalid or unsafe."""


class AtlasConcurrencyError(AtlasError):
    """Raised when a concurrency invariant is violated."""


__all__ = [
    "AtlasBackupError",
    "AtlasCapabilityError",
    "AtlasCompatibilityError",
    "AtlasConcurrencyError",
    "AtlasConfigurationError",
    "AtlasDiagnosticsError",
    "AtlasError",
    "AtlasHealthError",
    "AtlasIntegrityError",
    "AtlasLifecycleError",
    "AtlasObservabilityError",
    "AtlasRecoveryError",
    "AtlasReleaseError",
    "AtlasRetentionError",
    "AtlasSecurityError",
]
