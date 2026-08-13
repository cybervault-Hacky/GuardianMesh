"""GuardianMesh Atlas Phase 10 metrics.

The :class:`AtlasMetrics` is a thin wrapper that exposes
bounded, machine-readable metrics for the Atlas subsystem. The
metrics never include secrets, frame bytes, or private payloads.
"""

from __future__ import annotations

from typing import Any

from guardianmesh.atlas.health import AtlasHealthMonitor
from guardianmesh.atlas.models import (
    AtlasHealthStatus,
)
from guardianmesh.atlas.observability import AtlasObservability
from guardianmesh.storage.database import Database


class AtlasMetrics:
    """Read-only Atlas metrics aggregator."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self._observability = AtlasObservability(db)
        self._health = AtlasHealthMonitor(db)

    def collect(self) -> dict[str, Any]:
        health = self._health.check_all()
        observability = self._observability.collect()
        # Count failures.
        failed = [
            name
            for name, info in health.items()
            if info["status"] in (AtlasHealthStatus.FAILED.value, "FAILED")
        ]
        degraded = [
            name
            for name, info in health.items()
            if info["status"] in (
                AtlasHealthStatus.DEGRADED.value,
                AtlasHealthStatus.WARNING.value,
                "DEGRADED",
                "WARNING",
            )
        ]
        return {
            "health": health,
            "observability": observability,
            "summary": {
                "failed_subsystems": failed,
                "degraded_subsystems": degraded,
                "total_subsystems": len(health),
            },
        }


__all__ = ["AtlasMetrics"]
