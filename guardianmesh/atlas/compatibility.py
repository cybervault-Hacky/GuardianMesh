"""GuardianMesh Atlas Phase 10 compatibility checks.

The :class:`AtlasCompatibilityChecker` verifies schema, version,
and capability compatibility. It never modifies state.
"""

from __future__ import annotations

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager

CURRENT_SCHEMA_VERSION = 10


class AtlasCompatibilityChecker:
    """Read-only compatibility checker for schema and version."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def check_schema_version(self) -> tuple[bool, str]:
        try:
            current = MigrationManager().get_current_version(self._db)
        except Exception as e:
            return False, f"Failed to read schema version: {e}"
        if current > CURRENT_SCHEMA_VERSION:
            return (
                False,
                f"Database is newer than the running code "
                f"(db=v{current}, code=v{CURRENT_SCHEMA_VERSION}).",
            )
        if current < CURRENT_SCHEMA_VERSION:
            return (
                True,
                f"Database is older than the running code "
                f"(db=v{current}, code=v{CURRENT_SCHEMA_VERSION}); "
                f"apply pending migrations.",
            )
        return True, f"Schema is up to date (v{current})."

    def check_migration_chain(self) -> tuple[bool, str]:
        """Verify that the migration chain is sequential and complete."""
        try:
            rows = self._db.fetchall(
                "SELECT version, name, applied_at FROM schema_migrations "
                "ORDER BY version ASC;"
            )
        except Exception as e:
            return False, f"Failed to read schema_migrations: {e}"
        applied = {int(r["version"]) for r in rows}
        expected = {m.version for m in MIGRATIONS}
        missing = sorted(expected - applied)
        if missing:
            return False, f"Missing applied migrations: {missing}"
        if applied - expected:
            return False, f"Unknown applied migrations: {sorted(applied - expected)}"
        return True, "Migration chain is consistent."

    def check_expected_tables(self) -> tuple[bool, str]:
        try:
            rows = self._db.fetchall(
                "SELECT name FROM sqlite_master WHERE type='table';"
            )
        except Exception as e:
            return False, f"Failed to enumerate tables: {e}"
        existing = {r["name"] for r in rows}
        expected = {
            "schema_migrations",
            "identities",
            "config_entries",
            "audit_events",
        }
        missing = expected - existing
        if missing:
            return False, f"Missing core tables: {sorted(missing)}"
        return True, "Core tables are present."

    def run_all(self) -> list[tuple[str, bool, str]]:
        results: list[tuple[str, bool, str]] = []
        for name, fn in (
            ("schema_version", self.check_schema_version),
            ("migration_chain", self.check_migration_chain),
            ("expected_tables", self.check_expected_tables),
        ):
            ok, msg = fn()
            results.append((name, ok, msg))
        return results


__all__ = ["CURRENT_SCHEMA_VERSION", "AtlasCompatibilityChecker"]
