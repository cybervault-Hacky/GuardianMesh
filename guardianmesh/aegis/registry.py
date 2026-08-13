"""Database registry for Aegis capture sessions (Phase 8).

The registry persists *metadata only*. It NEVER stores frame bytes,
screenshots, encoded video, or any other captured screen content. The
schema is the smallest possible one for coordination between the
parent CLI and the future Android companion.
"""

from __future__ import annotations

import json
from typing import Any

from guardianmesh.aegis.models import (
    AegisPlatform,
    AegisSessionInfo,
    EncoderBackend,
    SystemConsentState,
)
from guardianmesh.storage.database import Database


class AegisSessionRegistry:
    """Manages SQLite records for Aegis capture sessions (metadata only)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, info: AegisSessionInfo) -> None:
        """Insert or update an Aegis session record."""
        meta_json = json.dumps(info.metadata or {})
        self.db.execute(
            """
            INSERT INTO aegis_sessions (
                aegis_session_id, screen_session_id, device_id, parent_id,
                authorization_id, consent_state, platform, backend, state,
                transport_session_id, created_at, consent_requested_at,
                consent_granted_at, started_at, stopped_at, expires_at,
                last_frame_sequence, stop_reason, label, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(aegis_session_id) DO UPDATE SET
                screen_session_id = excluded.screen_session_id,
                device_id = excluded.device_id,
                parent_id = excluded.parent_id,
                authorization_id = excluded.authorization_id,
                consent_state = excluded.consent_state,
                platform = excluded.platform,
                backend = excluded.backend,
                state = excluded.state,
                transport_session_id = excluded.transport_session_id,
                consent_requested_at = excluded.consent_requested_at,
                consent_granted_at = excluded.consent_granted_at,
                started_at = excluded.started_at,
                stopped_at = excluded.stopped_at,
                expires_at = excluded.expires_at,
                last_frame_sequence = excluded.last_frame_sequence,
                stop_reason = excluded.stop_reason,
                label = excluded.label,
                metadata = excluded.metadata;
            """,
            (
                info.aegis_session_id,
                info.screen_session_id,
                info.device_id,
                info.parent_id,
                info.authorization_id,
                info.consent_state.value,
                info.platform.value,
                info.backend.value,
                info.state,
                info.transport_session_id,
                info.created_at,
                info.consent_requested_at,
                info.consent_granted_at,
                info.started_at,
                info.stopped_at,
                info.expires_at,
                info.last_frame_sequence,
                info.stop_reason,
                info.label,
                meta_json,
            ),
        )

    def get(self, aegis_session_id: str) -> AegisSessionInfo | None:
        """Retrieve an Aegis session by ID."""
        row = self.db.fetchone(
            "SELECT * FROM aegis_sessions WHERE aegis_session_id = ?;",
            (aegis_session_id,),
        )
        if row is None:
            return None
        return self._row_to_info(dict(row))

    def list_all(self, limit: int = 200) -> list[AegisSessionInfo]:
        """List all Aegis sessions, most recent first."""
        rows = self.db.fetchall(
            "SELECT * FROM aegis_sessions ORDER BY created_at DESC LIMIT ?;",
            (limit,),
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def list_for_device(self, device_id: str) -> list[AegisSessionInfo]:
        """List Aegis sessions for a specific child device."""
        rows = self.db.fetchall(
            "SELECT * FROM aegis_sessions WHERE device_id = ? ORDER BY created_at DESC;",
            (device_id,),
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def delete(self, aegis_session_id: str) -> bool:
        """Delete an Aegis session by ID. Returns True iff a row was removed."""
        with self.db.connect() as conn:
            cur = conn.execute(
                "DELETE FROM aegis_sessions WHERE aegis_session_id = ?;",
                (aegis_session_id,),
            )
            return cur.rowcount > 0

    @staticmethod
    def _row_to_info(row: dict[str, Any]) -> AegisSessionInfo:
        meta_raw = row.get("metadata") or "{}"
        try:
            meta = json.loads(meta_raw)
            if not isinstance(meta, dict):
                meta = {}
        except (json.JSONDecodeError, TypeError):
            meta = {}
        return AegisSessionInfo(
            aegis_session_id=str(row["aegis_session_id"]),
            screen_session_id=str(row["screen_session_id"]),
            device_id=str(row["device_id"]),
            parent_id=str(row["parent_id"]),
            authorization_id=row.get("authorization_id"),
            consent_state=SystemConsentState.from_str(
                row.get("consent_state", "NOT_REQUESTED")
            ),
            platform=AegisPlatform.from_str(row.get("platform", "UNKNOWN")),
            backend=EncoderBackend.from_str(row.get("backend", "TEST")),
            state=str(row.get("state", "INITIALIZED")),
            transport_session_id=row.get("transport_session_id"),
            created_at=str(row.get("created_at", "")),
            consent_requested_at=row.get("consent_requested_at"),
            consent_granted_at=row.get("consent_granted_at"),
            started_at=row.get("started_at"),
            stopped_at=row.get("stopped_at"),
            expires_at=str(row.get("expires_at", "")),
            last_frame_sequence=int(row.get("last_frame_sequence", 0)),
            stop_reason=row.get("stop_reason"),
            label=row.get("label"),
            metadata=meta,
        )


__all__ = ["AegisSessionRegistry"]
