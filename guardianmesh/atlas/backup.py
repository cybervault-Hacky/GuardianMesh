"""GuardianMesh Atlas Phase 10 backup system.

The :class:`AtlasBackupManager` produces metadata-only backups of
the GuardianMesh database. Backups never contain private keys,
session keys, plaintext screen frames, command strings, or
private user content.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from guardianmesh.atlas.errors import AtlasBackupError
from guardianmesh.atlas.models import (
    AtlasBackupFormat,
    AtlasBackupInfo,
    generate_atlas_id,
)
from guardianmesh.storage.database import Database

# Tables whose contents are allowed in metadata-only backups.
# Anything not in this set is excluded.
BACKUP_ALLOWED_TABLES: frozenset[str] = frozenset(
    {
        "identities",
        "trusted_devices",
        "pairing_sessions",
        "device_health",
        "telemetry_events",
        "device_sequences",
        "policies",
        "policy_rules",
        "alerts",
        "transport_sessions",
        "transport_peers",
        "transport_sequences",
        "screen_sessions",
        "screen_authorizations",
        "aegis_sessions",
        "orion_events",
        "orion_actions",
        "orion_capabilities",
        "orion_reconciliation",
        "atlas_backups",
        "atlas_health",
        "atlas_recovery",
        "atlas_capability_versions",
        "atlas_retention",
        "config_entries",
        "schema_migrations",
    }
)

# Columns that are NEVER included in a backup, even if the table is allowed.
BACKUP_FORBIDDEN_COLUMNS: dict[str, frozenset[str]] = {
    "identities": frozenset({"private_key_pem"}),
}


def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _compute_digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


class AtlasBackupManager:
    """Backup manager for metadata-only GuardianMesh state."""

    def __init__(
        self,
        db: Database,
        backup_dir: Path,
        *,
        orion_version: str,
        schema_version: str = "10",
    ) -> None:
        self._db = db
        self._backup_dir = Path(backup_dir)
        self._backup_dir.mkdir(parents=True, exist_ok=True)
        self._orion_version = orion_version
        self._schema_version = schema_version

    def _read_table(self, table: str) -> list[dict[str, Any]]:
        forbidden_cols = BACKUP_FORBIDDEN_COLUMNS.get(table, frozenset())
        rows = self._db.fetchall(f"SELECT * FROM {table};")
        result: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            for col in forbidden_cols:
                d.pop(col, None)
            result.append(d)
        return result

    def _build_payload(self, device_id: str | None) -> dict[str, Any]:
        tables: dict[str, list[dict[str, Any]]] = {}
        for table in sorted(BACKUP_ALLOWED_TABLES):
            try:
                tables[table] = self._read_table(table)
            except Exception:
                # A missing or corrupted table is acceptable for
                # older installs; skip it.
                continue
        return {
            "format": AtlasBackupFormat.ATLAS_V1.value,
            "schema_version": self._schema_version,
            "orion_version": self._orion_version,
            "device_id": device_id,
            "tables": tables,
        }

    def create_backup(
        self, device_id: str | None = None
    ) -> AtlasBackupInfo:
        """Create a backup. Returns the metadata-only :class:`AtlasBackupInfo`."""
        backup_id = generate_atlas_id("BAK")
        created_at = datetime.datetime.now(datetime.UTC).isoformat()
        payload = self._build_payload(device_id)
        body = _canonical_json(payload).encode("utf-8")
        digest = _compute_digest(body)
        path = self._backup_dir / f"{backup_id}.json"
        try:
            path.write_bytes(body)
        except OSError as e:
            raise AtlasBackupError(f"Failed to write backup: {e}") from e
        size = path.stat().st_size
        info = AtlasBackupInfo(
            backup_id=backup_id,
            created_at=created_at,
            schema_version=self._schema_version,
            orion_version=self._orion_version,
            backup_format=AtlasBackupFormat.ATLAS_V1,
            device_id=device_id,
            integrity_digest=digest,
            size_bytes=size,
            status="VALID",
        )
        # Persist the backup manifest for later verification.
        self._db.execute(
            """
            INSERT INTO atlas_backups (
                backup_id, created_at, schema_version, orion_version,
                backup_format, device_id, integrity_digest,
                size_bytes, status, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                info.backup_id,
                info.created_at,
                info.schema_version,
                info.orion_version,
                info.backup_format.value,
                info.device_id,
                info.integrity_digest,
                info.size_bytes,
                info.status,
                info.notes,
            ),
        )
        return info

    def list_backups(self) -> list[AtlasBackupInfo]:
        rows = self._db.fetchall(
            "SELECT * FROM atlas_backups ORDER BY created_at DESC;"
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def get_backup(self, backup_id: str) -> AtlasBackupInfo | None:
        row = self._db.fetchone(
            "SELECT * FROM atlas_backups WHERE backup_id = ?;", (backup_id,)
        )
        if row is None:
            return None
        return self._row_to_info(dict(row))

    def verify_backup(self, backup_id: str) -> tuple[bool, str]:
        info = self.get_backup(backup_id)
        if info is None:
            return False, f"Backup '{backup_id}' not found."
        path = self._backup_dir / f"{backup_id}.json"
        if not path.exists():
            return False, f"Backup file missing: {path}"
        try:
            body = path.read_bytes()
        except OSError as e:
            return False, f"Failed to read backup: {e}"
        digest = _compute_digest(body)
        if digest != info.integrity_digest:
            return False, (
                f"Integrity mismatch: manifest={info.integrity_digest} "
                f"actual={digest}"
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return False, f"Backup is not valid JSON: {e}"
        if not isinstance(payload, dict):
            return False, "Backup is not a JSON object."
        if payload.get("format") != AtlasBackupFormat.ATLAS_V1.value:
            return False, f"Unsupported format: {payload.get('format')}"
        return True, "OK"

    def _row_to_info(self, row: dict[str, Any]) -> AtlasBackupInfo:
        return AtlasBackupInfo(
            backup_id=str(row["backup_id"]),
            created_at=str(row["created_at"]),
            schema_version=str(row["schema_version"]),
            orion_version=str(row["orion_version"]),
            backup_format=AtlasBackupFormat.from_str(
                str(row.get("backup_format", "atlas-1.0"))
            ),
            device_id=row.get("device_id"),
            integrity_digest=str(row.get("integrity_digest", "")),
            size_bytes=int(row.get("size_bytes", 0)),
            status=str(row.get("status", "VALID")),
            notes=str(row.get("notes", "")),
        )


__all__ = [
    "BACKUP_ALLOWED_TABLES",
    "BACKUP_FORBIDDEN_COLUMNS",
    "AtlasBackupManager",
]
