"""GuardianMesh Atlas Phase 10 high-level controller.

The :class:`AtlasController` is the high-level entry point for
the Atlas subsystem. It composes the integrity verifier,
lifecycle validator, health monitor, diagnostics, backup,
restore, recovery, compatibility, capability registry,
observability, metrics, retention, and release validator into
a single coordinator.
"""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.atlas.backup import AtlasBackupManager
from guardianmesh.atlas.capabilities import AtlasCapabilityRegistry
from guardianmesh.atlas.compatibility import AtlasCompatibilityChecker
from guardianmesh.atlas.diagnostics import AtlasDiagnostics
from guardianmesh.atlas.health import AtlasHealthMonitor
from guardianmesh.atlas.integrity import AtlasIntegrityVerifier
from guardianmesh.atlas.lifecycle import AtlasLifecycleValidator
from guardianmesh.atlas.metrics import AtlasMetrics
from guardianmesh.atlas.models import (
    DEFAULT_ATLAS_HEALTH_PROFILES,
    AtlasHealthStatus,
    AtlasSubsystem,
)
from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.atlas.recovery import AtlasRecoveryManager
from guardianmesh.atlas.release import AtlasReleaseValidator
from guardianmesh.atlas.restore import AtlasRestoreManager
from guardianmesh.atlas.retention import AtlasRetentionManager
from guardianmesh.storage.database import Database


class AtlasController:
    """High-level Atlas controller.

    The controller wires together every Atlas component. Callers
    can either use the high-level methods (``diagnose``,
    ``backup``, ``restore``, ``recover``, ``metrics``) or reach
    into the individual components.
    """

    def __init__(
        self,
        db: Database,
        *,
        orion_version: str = "1.0.0",
        schema_version: str = "10",
        backup_dir: str | None = None,
    ) -> None:
        self._db = db
        self._orion_version = orion_version
        self._schema_version = schema_version
        self._backup_dir = backup_dir

        self.integrity = AtlasIntegrityVerifier(db)
        self.lifecycle = AtlasLifecycleValidator(db)
        self.health = AtlasHealthMonitor(db)
        self.diagnostics = AtlasDiagnostics(db)
        self.compatibility = AtlasCompatibilityChecker(db)
        self.capabilities = AtlasCapabilityRegistry()
        self.observability = AtlasObservability(db)
        self.metrics = AtlasMetrics(db)
        self.recovery = AtlasRecoveryManager(db)
        self.retention = AtlasRetentionManager(db)
        self.release = AtlasReleaseValidator(db)
        self.backup_manager = (
            AtlasBackupManager(
                db,
                _resolve_backup_dir(backup_dir),
                orion_version=orion_version,
                schema_version=schema_version,
            )
            if backup_dir is not None
            else None
        )
        self.restore_manager = (
            AtlasRestoreManager(
                db,
                self.backup_manager,
                current_orion_version=orion_version,
                current_schema_version=schema_version,
            )
            if self.backup_manager is not None
            else None
        )

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def diagnose(self, full: bool = False) -> dict[str, Any]:
        report = self.diagnostics.run_full() if full else self.diagnostics.run()
        return report.to_dict()

    def backup(self, device_id: str | None = None) -> dict[str, Any]:
        if self.backup_manager is None:
            raise RuntimeError("AtlasController has no backup_dir configured.")
        info = self.backup_manager.create_backup(device_id=device_id)
        return info.to_dict()

    def list_backups(self) -> list[dict[str, Any]]:
        if self.backup_manager is None:
            return []
        return [b.to_dict() for b in self.backup_manager.list_backups()]

    def verify_backup(self, backup_id: str) -> tuple[bool, str]:
        if self.backup_manager is None:
            return False, "AtlasController has no backup_dir configured."
        return self.backup_manager.verify_backup(backup_id)

    def restore(
        self, backup_id: str, *, dry_run: bool = True
    ) -> dict[str, Any]:
        if self.restore_manager is None:
            raise RuntimeError("AtlasController has no backup_dir configured.")
        return self.restore_manager.restore(backup_id, dry_run=dry_run)

    def recover(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.recovery.recover_all()]

    def run_retention(self, *, dry_run: bool = True) -> dict[str, Any]:
        return self.retention.apply(dry_run=dry_run)

    def health_snapshot(self) -> dict[str, Any]:
        return self.health.record_health()

    def collect_observability(self) -> dict[str, Any]:
        return self.observability.collect()

    def release_info(self) -> dict[str, Any]:
        return {
            "orion_version": self._orion_version,
            "schema_version": self._schema_version,
            "subsystems": [s.value for s in AtlasSubsystem],
            "default_health": {
                k.value if isinstance(k, AtlasSubsystem) else str(k): (
                    v.value if isinstance(v, AtlasHealthStatus) else str(v)
                )
                for k, v in DEFAULT_ATLAS_HEALTH_PROFILES.items()
            },
            "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }


def _resolve_backup_dir(backup_dir: str | None) -> Any:
    """Resolve the backup directory. Lazy import to avoid hard dependency."""
    from pathlib import Path

    if backup_dir is None:
        return Path("atlas_backups")
    return Path(backup_dir)


__all__ = ["AtlasController"]
