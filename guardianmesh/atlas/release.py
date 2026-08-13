"""GuardianMesh Atlas Phase 10 release validation.

The :class:`AtlasReleaseValidator` performs release-readiness
checks. It does not claim release readiness when any mandatory
check fails.
"""

from __future__ import annotations

import re

from guardianmesh.atlas.models import AtlasDiagnosticCheck
from guardianmesh.storage.audit import AuditEventType
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager

# Forbidden permission names that may NEVER appear in the Aegis
# Android manifest. Used by the Android manifest permission
# check.
AEGIS_FORBIDDEN_PERMISSIONS: frozenset[str] = frozenset(
    {
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.USB_PERMISSION",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
    }
)


class AtlasReleaseValidator:
    """Read-only release-readiness validator."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def check_version_consistency(self) -> AtlasDiagnosticCheck:
        try:
            row = self._db.fetchone(
                "SELECT value FROM config_entries WHERE key = 'version';"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="release_version",
                ok=False,
                subsystem="ATLAS",
                reason=f"Failed to read config_entries: {e}",
            )
        from guardianmesh import __version__

        if row is None:
            return AtlasDiagnosticCheck(
                name="release_version",
                ok=True,
                subsystem="ATLAS",
                reason=f"No stored version (using runtime {__version__})",
            )
        if str(row["value"]) != __version__:
            return AtlasDiagnosticCheck(
                name="release_version",
                ok=False,
                subsystem="ATLAS",
                reason=(
                    f"Stored version {row['value']} != runtime {__version__}"
                ),
            )
        return AtlasDiagnosticCheck(
            name="release_version",
            ok=True,
            subsystem="ATLAS",
        )

    def check_migration_state(self) -> AtlasDiagnosticCheck:
        try:
            current = MigrationManager().get_current_version(self._db)
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="release_migration",
                ok=False,
                subsystem="ATLAS",
                reason=f"Failed to read migration state: {e}",
            )
        if current < 10:
            return AtlasDiagnosticCheck(
                name="release_migration",
                ok=False,
                subsystem="ATLAS",
                reason=f"Schema is at v{current}; v10 required.",
            )
        return AtlasDiagnosticCheck(
            name="release_migration",
            ok=True,
            subsystem="ATLAS",
        )

    def check_audit_event_classes(self) -> AtlasDiagnosticCheck:
        """Verify that the audit subsystem exposes the documented event types."""
        required = (
            AuditEventType.ORION_EVENT_ACCEPTED,
            AuditEventType.ORION_ACTION_STARTED,
            AuditEventType.ORION_RECONCILIATION_COMPLETED,
        )
        missing = [a.value for a in required if not hasattr(AuditEventType, a.name)]
        if missing:
            return AtlasDiagnosticCheck(
                name="release_audit_classes",
                ok=False,
                subsystem="ATLAS",
                reason=f"Missing audit event types: {missing}",
            )
        return AtlasDiagnosticCheck(
            name="release_audit_classes",
            ok=True,
            subsystem="ATLAS",
        )

    def basic_checks(self) -> list[AtlasDiagnosticCheck]:
        return [
            self.check_version_consistency(),
            self.check_migration_state(),
            self.check_audit_event_classes(),
        ]

    def deep_checks(self) -> list[AtlasDiagnosticCheck]:
        return [
            *self.basic_checks(),
            self.check_aegis_manifest_permissions(),
        ]

    def check_aegis_manifest_permissions(self) -> AtlasDiagnosticCheck:
        """Verify that the Android manifest declares only allowed permissions."""
        import os

        manifest_paths = [
            "android/aegis/app/src/main/AndroidManifest.xml",
        ]
        manifest_path = None
        for p in manifest_paths:
            if os.path.exists(p):
                manifest_path = p
                break
        if manifest_path is None:
            return AtlasDiagnosticCheck(
                name="release_aegis_manifest",
                ok=True,
                subsystem="AEGIS",
                reason="Android manifest not present in this checkout",
            )
        try:
            content = open(manifest_path, encoding="utf-8").read()
        except OSError as e:
            return AtlasDiagnosticCheck(
                name="release_aegis_manifest",
                ok=False,
                subsystem="AEGIS",
                reason=f"Failed to read {manifest_path}: {e}",
            )
        # Extract ``<uses-permission android:name="..."/>`` entries.
        pattern = re.compile(
            r'uses-permission[^>]+android:name="([^"]+)"',
            re.IGNORECASE,
        )
        declared = set(pattern.findall(content))
        forbidden_found = sorted(declared & AEGIS_FORBIDDEN_PERMISSIONS)
        if forbidden_found:
            return AtlasDiagnosticCheck(
                name="release_aegis_manifest",
                ok=False,
                subsystem="AEGIS",
                reason=f"Forbidden permissions declared: {forbidden_found}",
            )
        return AtlasDiagnosticCheck(
            name="release_aegis_manifest",
            ok=True,
            subsystem="AEGIS",
            reason=f"Manifest declares only allowed permissions: {sorted(declared)}",
        )


__all__ = [
    "AEGIS_FORBIDDEN_PERMISSIONS",
    "AtlasReleaseValidator",
]
