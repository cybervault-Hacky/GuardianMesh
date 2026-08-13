"""GuardianMesh Atlas Phase 10 observability.

The :class:`AtlasObservability` aggregates bounded metrics from
every GuardianMesh subsystem. Metrics are read-only and never
expose private data, secrets, or frame bytes.
"""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.storage.database import Database


class AtlasObservability:
    """Bounded observability for the entire GuardianMesh system."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def _safe_count(self, table: str) -> int:
        try:
            row = self._db.fetchone(f"SELECT COUNT(*) AS c FROM {table};")
            return int(row["c"]) if row else 0
        except Exception:
            return 0

    def _safe_grouped_count(self, table: str, column: str) -> dict[str, int]:
        try:
            rows = self._db.fetchall(
                f"SELECT {column} AS k, COUNT(*) AS c FROM {table} "
                f"GROUP BY {column};"
            )
            return {str(r["k"]): int(r["c"]) for r in rows}
        except Exception:
            return {}

    def collect(self) -> dict[str, Any]:
        """Collect bounded observability metrics from every subsystem."""
        metrics: dict[str, Any] = {
            "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }

        # Genesis
        metrics["genesis"] = {
            "identity_count": self._safe_count("identities"),
            "audit_event_count": self._safe_count("audit_events"),
        }

        # Link
        metrics["link"] = {
            "trusted_device_count": self._safe_count("trusted_devices"),
            "trusted_device_by_status": self._safe_grouped_count(
                "trusted_devices", "status"
            ),
        }

        # Pulse
        metrics["pulse"] = {
            "device_health_count": self._safe_count("device_health"),
        }

        # Sentinel
        metrics["sentinel"] = {
            "policy_count": self._safe_count("policies"),
            "alert_count": self._safe_count("alerts"),
            "alert_by_status": self._safe_grouped_count("alerts", "status"),
        }

        # Nexus
        metrics["nexus"] = {
            "transport_session_count": self._safe_count("transport_sessions"),
            "transport_session_by_state": self._safe_grouped_count(
                "transport_sessions", "state"
            ),
            "transport_peer_count": self._safe_count("transport_peers"),
        }

        # Vista
        metrics["vista"] = {
            "screen_session_count": self._safe_count("screen_sessions"),
            "screen_authorization_count": self._safe_count("screen_authorizations"),
        }

        # Aegis
        metrics["aegis"] = {
            "aegis_session_count": self._safe_count("aegis_sessions"),
            "aegis_session_by_state": self._safe_grouped_count(
                "aegis_sessions", "state"
            ),
        }

        # Orion
        metrics["orion"] = {
            "event_count": self._safe_count("orion_events"),
            "action_count": self._safe_count("orion_actions"),
            "action_by_status": self._safe_grouped_count("orion_actions", "status"),
            "capability_count": self._safe_count("orion_capabilities"),
            "reconciliation_count": self._safe_count("orion_reconciliation"),
        }

        # Atlas
        metrics["atlas"] = {
            "backup_count": self._safe_count("atlas_backups"),
            "health_count": self._safe_count("atlas_health"),
            "recovery_count": self._safe_count("atlas_recovery"),
            "capability_version_count": self._safe_count("atlas_capability_versions"),
        }

        return metrics


__all__ = ["AtlasObservability"]
