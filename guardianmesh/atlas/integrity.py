"""GuardianMesh Atlas Phase 10 integrity verification.

The :class:`AtlasIntegrityVerifier` performs non-destructive
read-only checks against the database, identity, trust, audit,
and Orion subsystems. It never modifies state and never exposes
secrets.
"""

from __future__ import annotations

import json

from guardianmesh.atlas.models import AtlasDiagnosticCheck
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager

# Required tables that must exist for a healthy install.
REQUIRED_TABLES: tuple[str, ...] = (
    "identities",
    "audit_events",
    "pairing_sessions",
    "trusted_devices",
    "device_health",
    "telemetry_events",
    "policies",
    "alerts",
    "transport_sessions",
    "transport_peers",
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
)

# Tables that must NEVER carry a sensitive column.
FORBIDDEN_TABLE_COLUMNS: dict[str, frozenset[str]] = {
    "orion_events": frozenset({"frame", "screenshot", "keylog", "command", "shell"}),
    "orion_actions": frozenset({"frame", "screenshot", "keylog", "command", "shell"}),
    "orion_capabilities": frozenset({"frame", "screenshot", "keylog", "command"}),
    "orion_reconciliation": frozenset({"frame", "screenshot", "keylog", "command"}),
    "atlas_backups": frozenset({"private_key", "password", "secret", "frame", "keylog"}),
    "atlas_health": frozenset({"private_key", "password", "secret"}),
    "atlas_recovery": frozenset({"private_key", "password", "secret"}),
    "atlas_capability_versions": frozenset({"private_key", "password", "secret"}),
    "atlas_retention": frozenset({"private_key", "password", "secret"}),
}


class AtlasIntegrityVerifier:
    """Read-only integrity verifier for the GuardianMesh database.

    The verifier performs:

    * SQLite integrity check.
    * Schema presence check.
    * Migration state check.
    * Foreign-key check.
    * Forbidden-column check.
    * Audit-event presence check.
    * Identity presence check.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def check_sqlite_integrity(self) -> AtlasDiagnosticCheck:
        ok, msg = self._db.check_integrity()
        return AtlasDiagnosticCheck(
            name="sqlite_integrity",
            ok=ok,
            subsystem="GENESIS",
            reason=msg,
        )

    def check_required_tables(self) -> AtlasDiagnosticCheck:
        try:
            rows = self._db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table';"
            )
            existing = {r["name"] for r in rows}
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="required_tables",
                ok=False,
                subsystem="GENESIS",
                reason=f"Failed to list tables: {e}",
            )
        missing = [t for t in REQUIRED_TABLES if t not in existing]
        return AtlasDiagnosticCheck(
            name="required_tables",
            ok=not missing,
            subsystem="GENESIS",
            reason=None if not missing else f"Missing tables: {missing}",
        )

    def check_migration_state(self) -> AtlasDiagnosticCheck:
        try:
            current = MigrationManager().get_current_version(self._db)
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="migration_state",
                ok=False,
                subsystem="GENESIS",
                reason=f"Failed to read migration state: {e}",
            )
        expected_max = 10
        if current < expected_max:
            return AtlasDiagnosticCheck(
                name="migration_state",
                ok=False,
                subsystem="GENESIS",
                reason=f"Database at v{current}, expected v{expected_max}.",
            )
        return AtlasDiagnosticCheck(
            name="migration_state",
            ok=True,
            subsystem="GENESIS",
        )

    def check_foreign_keys(self) -> AtlasDiagnosticCheck:
        try:
            row = self._db.fetchone("PRAGMA foreign_key_check;")
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="foreign_keys",
                ok=False,
                subsystem="GENESIS",
                reason=f"Failed to run foreign_key_check: {e}",
            )
        if row is None:
            return AtlasDiagnosticCheck(name="foreign_keys", ok=True, subsystem="GENESIS")
        return AtlasDiagnosticCheck(
            name="foreign_keys",
            ok=False,
            subsystem="GENESIS",
            reason=f"Foreign key violation: {dict(row)}",
        )

    def check_forbidden_columns(self) -> AtlasDiagnosticCheck:
        try:
            tables = self._db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table';"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="forbidden_columns",
                ok=False,
                subsystem="ATLAS",
                reason=f"Failed to enumerate tables: {e}",
            )
        bad: list[str] = []
        for r in tables:
            table = r["name"]
            forbidden = FORBIDDEN_TABLE_COLUMNS.get(table)
            if not forbidden:
                continue
            cols = {c["name"] for c in self._db.fetchall(f"PRAGMA table_info({table});")}
            leaked = forbidden & cols
            if leaked:
                bad.append(f"{table}:{sorted(leaked)}")
        return AtlasDiagnosticCheck(
            name="forbidden_columns",
            ok=not bad,
            subsystem="ATLAS",
            reason=None if not bad else f"Forbidden columns present: {bad}",
        )

    def check_audit_presence(self) -> AtlasDiagnosticCheck:
        try:
            row = self._db.fetchone("SELECT COUNT(*) AS c FROM audit_events;")
            count = int(row["c"]) if row else 0
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="audit_presence",
                ok=False,
                subsystem="GENESIS",
                reason=f"Failed to read audit_events: {e}",
            )
        # An empty audit log is acceptable on a fresh install.
        return AtlasDiagnosticCheck(
            name="audit_presence",
            ok=True,
            subsystem="GENESIS",
            reason=f"audit_events count: {count}",
        )

    def check_audit_redaction(self) -> AtlasDiagnosticCheck:
        """Verify that audit_events.details never contains forbidden keys."""
        try:
            rows = self._db.fetchall("SELECT details FROM audit_events LIMIT 500;")
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="audit_redaction",
                ok=False,
                subsystem="ATLAS",
                reason=f"Failed to read audit_events: {e}",
            )
        forbidden = {
            "private_key",
            "password",
            "secret",
            "frame",
            "screenshot",
            "keylog",
            "command",
            "shell",
            "private_key_pem",
            "session_key",
            "otp",
        }
        leaks: list[int] = []
        for idx, r in enumerate(rows):
            details = r["details"]
            try:
                parsed = json.loads(details) if isinstance(details, str) else details
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(parsed, dict):
                continue
            for key in parsed.keys():
                if str(key).lower() in forbidden:
                    leaks.append(idx)
                    break
        return AtlasDiagnosticCheck(
            name="audit_redaction",
            ok=not leaks,
            subsystem="ATLAS",
            reason=None if not leaks else f"Audit redaction violations: {leaks}",
        )

    def check_identity_presence(self) -> AtlasDiagnosticCheck:
        try:
            row = self._db.fetchone("SELECT COUNT(*) AS c FROM identities;")
            count = int(row["c"]) if row else 0
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="identity_presence",
                ok=False,
                subsystem="GENESIS",
                reason=f"Failed to read identities: {e}",
            )
        return AtlasDiagnosticCheck(
            name="identity_presence",
            ok=True,
            subsystem="GENESIS",
            reason=f"identities count: {count}",
        )

    def run_all(self) -> list[AtlasDiagnosticCheck]:
        return [
            self.check_sqlite_integrity(),
            self.check_required_tables(),
            self.check_migration_state(),
            self.check_foreign_keys(),
            self.check_forbidden_columns(),
            self.check_audit_presence(),
            self.check_audit_redaction(),
            self.check_identity_presence(),
        ]


__all__ = ["FORBIDDEN_TABLE_COLUMNS", "REQUIRED_TABLES", "AtlasIntegrityVerifier"]
