"""GuardianMesh Atlas Phase 10 crash-recovery system.

The :class:`AtlasRecoveryManager` performs deterministic recovery
for interrupted operations. Recovery never resurrects revoked
trust, expired authorization, or expired Aegis consent. Recovery
fails closed: it never restarts a stopped screen session.
"""

from __future__ import annotations

import datetime

from guardianmesh.atlas.errors import AtlasRecoveryError
from guardianmesh.atlas.models import AtlasRecoveryRecord, generate_atlas_id
from guardianmesh.storage.database import Database


class AtlasRecoveryManager:
    """Deterministic crash-recovery manager."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def _now(self) -> datetime.datetime:
        return datetime.datetime.now(datetime.UTC)

    def _record(
        self,
        operation: str,
        device_id: str | None,
        actions_taken: int,
        status: str,
        notes: str,
    ) -> AtlasRecoveryRecord:
        rid = generate_atlas_id("REC")
        rec = AtlasRecoveryRecord(
            recovery_id=rid,
            operation=operation,
            started_at=self._now().isoformat(),
            device_id=device_id,
            status=status,
            actions_taken=actions_taken,
            notes=notes,
        )
        self._db.execute(
            """
            INSERT INTO atlas_recovery (
                recovery_id, device_id, started_at, completed_at,
                operation, status, actions_taken, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                rec.recovery_id,
                rec.device_id,
                rec.started_at,
                rec.completed_at,
                rec.operation,
                rec.status,
                rec.actions_taken,
                rec.notes,
            ),
        )
        return rec

    def recover_orion_actions(self) -> AtlasRecoveryRecord:
        """Mark expired PENDING/RUNNING Orion actions as EXPIRED.

        This is a recovery operation, not a re-execution. An
        expired action is never re-queued; it is marked EXPIRED.
        """
        try:
            rows = self._db.fetchall(
                "SELECT action_id FROM orion_actions "
                "WHERE status IN ('PENDING', 'RUNNING');"
            )
        except Exception as e:
            raise AtlasRecoveryError(f"Failed to read orion_actions: {e}") from e
        now = self._now()
        expired = 0
        for r in rows:
            try:
                row = self._db.fetchone(
                    "SELECT action_id, expires_at FROM orion_actions "
                    "WHERE action_id = ?;",
                    (r["action_id"],),
                )
            except Exception:
                continue
            if row is None:
                continue
            try:
                exp = datetime.datetime.fromisoformat(row["expires_at"])
            except (TypeError, ValueError):
                continue
            if exp < now:
                self._db.execute(
                    "UPDATE orion_actions SET status = 'EXPIRED', "
                    "updated_at = ? WHERE action_id = ?;",
                    (now.isoformat(), r["action_id"]),
                )
                expired += 1
        return self._record(
            operation="recover_orion_actions",
            device_id=None,
            actions_taken=expired,
            status="SUCCEEDED",
            notes=f"Expired {expired} PENDING/RUNNING actions.",
        )

    def recover_screen_authorizations(self) -> AtlasRecoveryRecord:
        """Mark expired APPROVED screen authorizations as EXPIRED.

        This never resurrects a revoked or denied authorization.
        """
        try:
            rows = self._db.fetchall(
                "SELECT authorization_id, expires_at, decision "
                "FROM screen_authorizations WHERE decision = 'APPROVED';"
            )
        except Exception as e:
            raise AtlasRecoveryError(
                f"Failed to read screen_authorizations: {e}"
            ) from e
        now = self._now()
        expired = 0
        for r in rows:
            try:
                exp = datetime.datetime.fromisoformat(r["expires_at"])
            except (TypeError, ValueError):
                continue
            if exp < now:
                self._db.execute(
                    "UPDATE screen_authorizations SET decision = 'EXPIRED' "
                    "WHERE authorization_id = ?;",
                    (r["authorization_id"],),
                )
                expired += 1
        return self._record(
            operation="recover_screen_authorizations",
            device_id=None,
            actions_taken=expired,
            status="SUCCEEDED",
            notes=f"Expired {expired} screen authorizations.",
        )

    def recover_aegis_sessions(self) -> AtlasRecoveryRecord:
        """Mark expired Aegis sessions as EXPIRED.

        This never resurrects a revoked Aegis session.
        """
        try:
            rows = self._db.fetchall(
                "SELECT aegis_session_id, expires_at, state "
                "FROM aegis_sessions WHERE state IN ('INITIALIZED', 'CONSENT_GRANTED', "
                "'CAPTURING');"
            )
        except Exception as e:
            raise AtlasRecoveryError(f"Failed to read aegis_sessions: {e}") from e
        now = self._now()
        expired = 0
        for r in rows:
            try:
                exp = datetime.datetime.fromisoformat(r["expires_at"])
            except (TypeError, ValueError):
                continue
            if exp < now:
                self._db.execute(
                    "UPDATE aegis_sessions SET state = 'EXPIRED' "
                    "WHERE aegis_session_id = ?;",
                    (r["aegis_session_id"],),
                )
                expired += 1
        return self._record(
            operation="recover_aegis_sessions",
            device_id=None,
            actions_taken=expired,
            status="SUCCEEDED",
            notes=f"Expired {expired} Aegis sessions.",
        )

    def recover_all(self) -> list[AtlasRecoveryRecord]:
        return [
            self.recover_orion_actions(),
            self.recover_screen_authorizations(),
            self.recover_aegis_sessions(),
        ]


__all__ = ["AtlasRecoveryManager"]
