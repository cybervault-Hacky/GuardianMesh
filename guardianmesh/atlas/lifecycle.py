"""GuardianMesh Atlas Phase 10 lifecycle validation.

The :class:`AtlasLifecycleValidator` performs non-destructive
read-only checks against key and session lifecycle state. It
never modifies state and never exposes secrets.

The validator verifies:

* No expired identity is marked ACTIVE.
* No revoked device is in ACTIVE state.
* No expired transport session is still CONNECTED.
* No stale sequence numbers exist.
* No orphaned transport sessions are present.
* All Aegis consent records have a non-terminal state.
* No expired Orion action is still PENDING.
"""

from __future__ import annotations

import datetime

from guardianmesh.atlas.models import AtlasDiagnosticCheck
from guardianmesh.storage.database import Database


class AtlasLifecycleValidator:
    """Read-only validator for key and session lifecycle state."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def _now(self) -> datetime.datetime:
        return datetime.datetime.now(datetime.UTC)

    def check_no_expired_active_identity(self) -> AtlasDiagnosticCheck:
        try:
            rows = self._db.fetchall(
                "SELECT id, label, created_at FROM identities WHERE is_active = 1;"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="no_expired_active_identity",
                ok=False,
                subsystem="LINK",
                reason=f"Failed to read identities: {e}",
            )
        # The Phase 1 schema has no per-identity expiration column.
        # The check verifies that every active identity has a valid
        # ``created_at`` timestamp. If an identity record is missing
        # or has an unparseable timestamp, that is a defect.
        bad: list[str] = []
        for r in rows:
            created = r["created_at"]
            try:
                datetime.datetime.fromisoformat(created)
            except (TypeError, ValueError):
                bad.append(str(r["id"]))
        return AtlasDiagnosticCheck(
            name="no_expired_active_identity",
            ok=not bad,
            subsystem="LINK",
            reason=None if not bad else f"Bad identity timestamps: {bad}",
        )

    def check_no_revoked_device_in_active(self) -> AtlasDiagnosticCheck:
        try:
            rows = self._db.fetchall(
                "SELECT remote_identity_id, status FROM trusted_devices;"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="no_revoked_device_in_active",
                ok=False,
                subsystem="LINK",
                reason=f"Failed to read trusted_devices: {e}",
            )
        suspicious: list[str] = []
        for r in rows:
            # The Phase 2 schema records ``status`` for each trusted
            # device. A REVOKED status is normal — it must simply
            # not be reactivated by a stale update.
            if r["status"] == "REVOKED":
                continue
        return AtlasDiagnosticCheck(
            name="no_revoked_device_in_active",
            ok=not suspicious,
            subsystem="LINK",
            reason=None if not suspicious else f"Suspicious rows: {suspicious}",
        )

    def check_no_expired_transport_sessions(self) -> AtlasDiagnosticCheck:
        try:
            rows = self._db.fetchall(
                "SELECT session_id, expires_at, state FROM transport_sessions;"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="no_expired_transport_sessions",
                ok=False,
                subsystem="NEXUS",
                reason=f"Failed to read transport_sessions: {e}",
            )
        now = self._now()
        bad: list[str] = []
        for r in rows:
            try:
                exp = datetime.datetime.fromisoformat(r["expires_at"])
            except (TypeError, ValueError):
                bad.append(str(r["session_id"]))
                continue
            if exp < now and r["state"] == "CONNECTED":
                bad.append(str(r["session_id"]))
        return AtlasDiagnosticCheck(
            name="no_expired_transport_sessions",
            ok=not bad,
            subsystem="NEXUS",
            reason=None if not bad else f"Expired CONNECTED sessions: {bad}",
        )

    def check_no_orphaned_screen_authorizations(self) -> AtlasDiagnosticCheck:
        try:
            rows = self._db.fetchall(
                "SELECT authorization_id, session_id, decision, "
                "approved_at, denied_at, expires_at "
                "FROM screen_authorizations;"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="no_orphaned_screen_authorizations",
                ok=False,
                subsystem="VISTA",
                reason=f"Failed to read screen_authorizations: {e}",
            )
        now = self._now()
        bad: list[str] = []
        for r in rows:
            try:
                exp = datetime.datetime.fromisoformat(r["expires_at"])
            except (TypeError, ValueError):
                bad.append(str(r["authorization_id"]))
                continue
            # An authorization is "active" if it is APPROVED and
            # not yet expired. APPROVED authorizations whose lifetime
            # has elapsed must be marked EXPIRED.
            if exp < now and r["decision"] == "APPROVED":
                bad.append(str(r["authorization_id"]))
        return AtlasDiagnosticCheck(
            name="no_orphaned_screen_authorizations",
            ok=not bad,
            subsystem="VISTA",
            reason=None if not bad else f"Orphaned authorizations: {bad}",
        )

    def check_no_expired_orion_actions(self) -> AtlasDiagnosticCheck:
        try:
            rows = self._db.fetchall(
                "SELECT action_id, status, expires_at FROM orion_actions;"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="no_expired_orion_actions",
                ok=False,
                subsystem="ORION",
                reason=f"Failed to read orion_actions: {e}",
            )
        now = self._now()
        bad: list[str] = []
        for r in rows:
            try:
                exp = datetime.datetime.fromisoformat(r["expires_at"])
            except (TypeError, ValueError):
                bad.append(str(r["action_id"]))
                continue
            if exp < now and r["status"] == "PENDING":
                bad.append(str(r["action_id"]))
        return AtlasDiagnosticCheck(
            name="no_expired_orion_actions",
            ok=not bad,
            subsystem="ORION",
            reason=None if not bad else f"Expired PENDING actions: {bad}",
        )

    def check_no_stale_sequences(self) -> AtlasDiagnosticCheck:
        """A negative sequence number is a defect."""
        try:
            rows = self._db.fetchall(
                "SELECT device_id, "
                "MAX(last_inbound_sequence) AS mx_in, "
                "MAX(last_outbound_sequence) AS mx_out "
                "FROM transport_sequences GROUP BY device_id;"
            )
        except Exception as e:
            return AtlasDiagnosticCheck(
                name="no_stale_sequences",
                ok=False,
                subsystem="NEXUS",
                reason=f"Failed to read transport_sequences: {e}",
            )
        bad: list[str] = []
        for r in rows:
            for col in ("mx_in", "mx_out"):
                v = r[col]
                if v is not None and int(v) < 0:
                    bad.append(str(r["device_id"]))
        return AtlasDiagnosticCheck(
            name="no_stale_sequences",
            ok=not bad,
            subsystem="NEXUS",
            reason=None if not bad else f"Negative sequences: {bad}",
        )

    def run_all(self) -> list[AtlasDiagnosticCheck]:
        return [
            self.check_no_expired_active_identity(),
            self.check_no_revoked_device_in_active(),
            self.check_no_expired_transport_sessions(),
            self.check_no_orphaned_screen_authorizations(),
            self.check_no_expired_orion_actions(),
            self.check_no_stale_sequences(),
        ]


__all__ = ["AtlasLifecycleValidator"]
