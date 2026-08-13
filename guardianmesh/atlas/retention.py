"""GuardianMesh Atlas Phase 10 retention manager.

The :class:`AtlasRetentionManager` applies bounded retention
policies to metadata tables. It never collects new categories
of personal data; it only bounds the growth of existing tables.
"""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.atlas.errors import AtlasRetentionError
from guardianmesh.atlas.models import AtlasRetentionPolicy, generate_atlas_id
from guardianmesh.storage.database import Database

# Default retention policy (in days) for each metadata table.
DEFAULT_RETENTION_DAYS: dict[str, int] = {
    "audit_events": 365,
    "telemetry_events": 180,
    "transport_messages": 30,
    "orion_events": 90,
    "orion_actions": 90,
    "orion_reconciliation": 365,
    "atlas_health": 90,
    "atlas_recovery": 365,
    "atlas_capability_versions": 365,
}


class AtlasRetentionManager:
    """Bounded metadata-only retention manager."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def list_policies(self) -> list[AtlasRetentionPolicy]:
        rows = self._db.fetchall(
            "SELECT * FROM atlas_retention ORDER BY target_table;"
        )
        out: list[AtlasRetentionPolicy] = []
        for r in rows:
            d = dict(r)
            out.append(
                AtlasRetentionPolicy(
                    retention_id=str(d["retention_id"]),
                    target_table=str(d["target_table"]),
                    retention_days=int(d["retention_days"]),
                    enabled=bool(int(d.get("enabled", 1))),
                    updated_at=str(d.get("updated_at", "")),
                    notes=str(d.get("notes", "")),
                )
            )
        return out

    def ensure_defaults(self) -> list[AtlasRetentionPolicy]:
        """Ensure that a default retention policy exists for each table."""
        existing = {p.target_table for p in self.list_policies()}
        now = datetime.datetime.now(datetime.UTC).isoformat()
        created: list[AtlasRetentionPolicy] = []
        for table, days in sorted(DEFAULT_RETENTION_DAYS.items()):
            if table in existing:
                continue
            policy = AtlasRetentionPolicy(
                retention_id=generate_atlas_id("RET"),
                target_table=table,
                retention_days=days,
                enabled=True,
                updated_at=now,
                notes="Default Atlas retention policy",
            )
            self._db.execute(
                """
                INSERT INTO atlas_retention (
                    retention_id, target_table, retention_days,
                    enabled, updated_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    policy.retention_id,
                    policy.target_table,
                    policy.retention_days,
                    1,
                    policy.updated_at,
                    policy.notes,
                ),
            )
            created.append(policy)
        return created

    def apply(
        self, *, dry_run: bool = False, now: datetime.datetime | None = None
    ) -> dict[str, Any]:
        """Apply retention policies to each table.

        ``dry_run=True`` returns the projected action plan without
        modifying state. ``dry_run=False`` deletes old rows.
        """
        if now is None:
            now = datetime.datetime.now(datetime.UTC)
        plan: dict[str, Any] = {
            "dry_run": dry_run,
            "applied_at": now.isoformat(),
            "tables": {},
        }
        for policy in self.list_policies():
            if not policy.enabled:
                continue
            threshold = now - datetime.timedelta(days=policy.retention_days)
            threshold_iso = threshold.isoformat()
            # Every retention-managed table has a ``created_at`` or
            # ``timestamp`` column. We use a heuristic: try
            # ``created_at`` first, then ``timestamp``.
            count = 0
            chosen_column = None
            for col in ("created_at", "timestamp", "started_at", "captured_at"):
                try:
                    row = self._db.fetchone(
                        f"SELECT COUNT(*) AS c FROM {policy.target_table} "
                        f"WHERE {col} < ?;",
                        (threshold_iso,),
                    )
                except Exception:
                    continue
                count = int(row["c"]) if row else 0
                if count > 0:
                    chosen_column = col
                    break
            table_plan = {
                "policy_days": policy.retention_days,
                "column": chosen_column,
                "rows_to_delete": count,
                "applied": False,
            }
            if not dry_run and chosen_column is not None and count > 0:
                try:
                    self._db.execute(
                        f"DELETE FROM {policy.target_table} "
                        f"WHERE {chosen_column} < ?;",
                        (threshold_iso,),
                    )
                    table_plan["applied"] = True
                except Exception as e:
                    raise AtlasRetentionError(
                        f"Failed to apply retention to {policy.target_table}: {e}"
                    ) from e
            plan["tables"][policy.target_table] = table_plan
        return plan


__all__ = ["DEFAULT_RETENTION_DAYS", "AtlasRetentionManager"]
