"""GuardianMesh Atlas Phase 10 restore system.

The :class:`AtlasRestoreManager` restores a previously-created
backup. Restore operations are verified for integrity and
compatibility before any data is written. Restore is dry-run by
default; ``dry_run=False`` performs the restore.
"""

from __future__ import annotations

import datetime
import json
from typing import Any

from guardianmesh.atlas.backup import (
    BACKUP_ALLOWED_TABLES,
    AtlasBackupManager,
)
from guardianmesh.atlas.errors import AtlasCompatibilityError, AtlasError
from guardianmesh.storage.database import Database


class AtlasRestoreManager:
    """Restore a verified backup into the active database."""

    def __init__(
        self,
        db: Database,
        backup_manager: AtlasBackupManager,
        *,
        current_orion_version: str,
        current_schema_version: str = "10",
    ) -> None:
        self._db = db
        self._backup_manager = backup_manager
        self._current_orion_version = current_orion_version
        self._current_schema_version = current_schema_version

    def verify_compatibility(
        self, backup_id: str
    ) -> tuple[bool, str, dict[str, Any] | None]:
        """Verify a backup's integrity, format, and version compatibility."""
        ok, msg = self._backup_manager.verify_backup(backup_id)
        if not ok:
            return False, msg, None
        info = self._backup_manager.get_backup(backup_id)
        if info is None:
            return False, "Backup manifest not found.", None
        # Schema version must match the current schema version.
        if info.schema_version != self._current_schema_version:
            return (
                False,
                (
                    f"Schema mismatch: backup={info.schema_version} "
                    f"current={self._current_schema_version}"
                ),
                None,
            )
        return True, "OK", info.to_dict()

    def restore(
        self, backup_id: str, *, dry_run: bool = True
    ) -> dict[str, Any]:
        """Restore a backup.

        ``dry_run=True`` (the default) verifies the backup and
        returns the projected action plan without modifying state.
        ``dry_run=False`` performs the actual restore.
        """
        ok, msg, info = self.verify_compatibility(backup_id)
        if not ok:
            raise AtlasCompatibilityError(msg)
        assert info is not None
        path = self._backup_manager._backup_dir / f"{backup_id}.json"
        try:
            payload = json.loads(path.read_bytes().decode("utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise AtlasError(f"Failed to read backup: {e}") from e
        tables = payload.get("tables", {})
        if not isinstance(tables, dict):
            raise AtlasError("Backup tables payload is invalid.")
        plan = {
            "backup_id": backup_id,
            "dry_run": dry_run,
            "tables_to_restore": sorted(
                t for t in tables.keys() if t in BACKUP_ALLOWED_TABLES
            ),
            "tables_skipped": sorted(
                t for t in tables.keys() if t not in BACKUP_ALLOWED_TABLES
            ),
            "rows_by_table": {t: len(rows) for t, rows in tables.items()},
        }
        if dry_run:
            plan["applied"] = False
            return plan
        # Perform the actual restore inside a transaction.
        with self._db.transaction() as conn:
            for table in sorted(tables.keys()):
                if table not in BACKUP_ALLOWED_TABLES:
                    continue
                rows = tables[table]
                if not rows:
                    continue
                # Delete existing rows first; this is a destructive
                # operation. We do it only when dry_run is False.
                conn.execute(f"DELETE FROM {table};")
                columns = list(rows[0].keys())
                placeholders = ", ".join("?" for _ in columns)
                col_list = ", ".join(f'"{c}"' for c in columns)
                for row in rows:
                    values = [row.get(c) for c in columns]
                    conn.execute(
                        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders});",
                        tuple(values),
                    )
        plan["applied"] = True
        plan["applied_at"] = datetime.datetime.now(datetime.UTC).isoformat()
        return plan


__all__ = ["AtlasRestoreManager"]
