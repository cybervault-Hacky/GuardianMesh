"""GuardianMesh Atlas Phase 10 health monitoring.

The :class:`AtlasHealthMonitor` aggregates per-subsystem health
status into a unified health model. The monitor is read-only and
does not expose secrets.
"""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.atlas.models import (
    DEFAULT_ATLAS_HEALTH_PROFILES,
    AtlasHealthStatus,
    AtlasSubsystem,
    generate_atlas_id,
)
from guardianmesh.storage.database import Database

# Tables that the health monitor references for each subsystem.
SUBSYSTEM_TABLES: dict[AtlasSubsystem, tuple[str, ...]] = {
    AtlasSubsystem.GENESIS: ("identities", "config_entries", "audit_events"),
    AtlasSubsystem.LINK: ("pairing_sessions", "trusted_devices"),
    AtlasSubsystem.PULSE: ("device_health", "telemetry_events"),
    AtlasSubsystem.SENTINEL: ("policies", "alerts"),
    AtlasSubsystem.CONSOLE: ("config_entries",),
    AtlasSubsystem.NEXUS: (
        "transport_sessions",
        "transport_peers",
        "transport_messages",
    ),
    AtlasSubsystem.VISTA: ("screen_sessions", "screen_authorizations"),
    AtlasSubsystem.AEGIS: ("aegis_sessions",),
    AtlasSubsystem.ORION: (
        "orion_events",
        "orion_actions",
        "orion_capabilities",
        "orion_reconciliation",
    ),
    AtlasSubsystem.ATLAS: (
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
    ),
}


class AtlasHealthMonitor:
    """Aggregates per-subsystem health status.

    The monitor writes one row per subsystem into ``atlas_health``.
    The records are metadata-only.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def _check_subsystem(self, subsystem: AtlasSubsystem) -> tuple[AtlasHealthStatus, str, str]:
        """Return (status, summary, remediation) for a subsystem."""
        tables = SUBSYSTEM_TABLES.get(subsystem, ())
        if not tables:
            return (
                DEFAULT_ATLAS_HEALTH_PROFILES[subsystem],
                "No tables configured",
                "",
            )
        missing: list[str] = []
        for table in tables:
            try:
                row = self._db.fetchone(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name = ?;",
                    (table,),
                )
            except Exception:
                return (
                    AtlasHealthStatus.FAILED,
                    f"Failed to query table {table}",
                    f"Investigate the {subsystem.value} subsystem.",
                )
            if row is None:
                missing.append(table)
        if missing:
            return (
                AtlasHealthStatus.FAILED,
                f"Missing tables: {missing}",
                f"Run migrations to create the {subsystem.value} tables.",
            )
        return (
            DEFAULT_ATLAS_HEALTH_PROFILES[subsystem],
            f"OK ({len(tables)} tables present)",
            "",
        )

    def check_all(self) -> dict[str, dict[str, Any]]:
        """Check every documented subsystem. Return a structured result."""
        result: dict[str, dict[str, Any]] = {}
        for subsystem in AtlasSubsystem:
            status, summary, remediation = self._check_subsystem(subsystem)
            result[subsystem.value] = {
                "status": status.value
                if isinstance(status, AtlasHealthStatus)
                else str(status),
                "summary": summary,
                "remediation": remediation,
            }
        return result

    def record_health(self) -> dict[str, Any]:
        """Persist a health snapshot to the ``atlas_health`` table."""
        snapshot = self.check_all()
        now = datetime.datetime.now(datetime.UTC).isoformat()
        written = 0
        for subsystem_name, info in snapshot.items():
            try:
                self._db.execute(
                    """
                    INSERT INTO atlas_health (
                        health_id, subsystem, status, timestamp,
                        summary, remediation, schema_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        generate_atlas_id("HLT"),
                        subsystem_name,
                        info["status"],
                        now,
                        info["summary"],
                        info["remediation"],
                        "1.0",
                    ),
                )
                written += 1
            except Exception:
                # One failure must not abort the snapshot.
                continue
        return {"snapshot_at": now, "subsystems": snapshot, "written": written}

    def latest_health(self, limit: int = 50) -> list[dict[str, Any]]:
        try:
            rows = self._db.fetchall(
                "SELECT * FROM atlas_health ORDER BY timestamp DESC LIMIT ?;",
                (limit,),
            )
        except Exception:
            return []
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            out.append(d)
        return out


__all__ = ["SUBSYSTEM_TABLES", "AtlasHealthMonitor"]
