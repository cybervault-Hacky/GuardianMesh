"""Database-backed persistence for screen authorizations (Phase 7: Vista).

The :class:`ScreenAuthorizationRegistry` persists authorization metadata
so that cross-CLI-session flows (e.g. parent requests, child approves
in a separate process) can be coordinated. The registry NEVER stores
the authorization nonce, the session key, or any frame content.
"""

from __future__ import annotations

import json
from typing import Any

from guardianmesh.screen.models import (
    AuthorizationDecision,
    ScreenAuthorization,
)
from guardianmesh.storage.database import Database


class ScreenAuthorizationRegistry:
    """Persist screen authorization metadata (no secrets, no frames)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, auth: ScreenAuthorization) -> None:
        """Insert or update an authorization record."""
        meta_json = json.dumps(auth.metadata or {})
        self.db.execute(
            """
            INSERT INTO screen_authorizations (
                authorization_id, session_id, device_id, parent_id,
                decision, requested_at, approved_at, denied_at, expires_at,
                max_duration_seconds, label, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(authorization_id) DO UPDATE SET
                decision = excluded.decision,
                approved_at = excluded.approved_at,
                denied_at = excluded.denied_at,
                metadata = excluded.metadata;
            """,
            (
                auth.authorization_id,
                auth.session_id,
                auth.device_id,
                auth.parent_id,
                auth.decision.value,
                auth.requested_at,
                auth.approved_at,
                auth.denied_at,
                auth.expires_at,
                auth.max_duration_seconds,
                auth.label,
                meta_json,
            ),
        )

    def get_by_authorization_id(self, authorization_id: str) -> ScreenAuthorization | None:
        """Look up an authorization by its primary key."""
        row = self.db.fetchone(
            "SELECT * FROM screen_authorizations WHERE authorization_id = ?;",
            (authorization_id,),
        )
        if row is None:
            return None
        return self._row_to_auth(dict(row))

    def get_by_session_id(self, session_id: str) -> ScreenAuthorization | None:
        """Look up the authorization attached to a session."""
        row = self.db.fetchone(
            "SELECT * FROM screen_authorizations WHERE session_id = ?;",
            (session_id,),
        )
        if row is None:
            return None
        return self._row_to_auth(dict(row))

    def list_pending(self) -> list[ScreenAuthorization]:
        """List authorizations currently in PENDING state."""
        rows = self.db.fetchall(
            "SELECT * FROM screen_authorizations WHERE decision = 'PENDING';"
        )
        return [self._row_to_auth(dict(r)) for r in rows]

    @staticmethod
    def _row_to_auth(row: dict[str, Any]) -> ScreenAuthorization:
        meta_raw = row.get("metadata") or "{}"
        try:
            meta = json.loads(meta_raw)
            if not isinstance(meta, dict):
                meta = {}
        except (json.JSONDecodeError, TypeError):
            meta = {}
        return ScreenAuthorization(
            authorization_id=str(row["authorization_id"]),
            session_id=str(row["session_id"]),
            device_id=str(row["device_id"]),
            parent_id=str(row["parent_id"]),
            decision=AuthorizationDecision.from_str(row.get("decision", "PENDING")),
            requested_at=str(row.get("requested_at", "")),
            approved_at=row.get("approved_at"),
            denied_at=row.get("denied_at"),
            expires_at=str(row.get("expires_at", "")),
            max_duration_seconds=int(row.get("max_duration_seconds", 300)),
            label=row.get("label"),
            metadata=meta,
        )


__all__ = ["ScreenAuthorizationRegistry"]
