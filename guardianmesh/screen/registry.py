"""Persistent database registry for screen sessions (Phase 7: Vista).

The registry persists *metadata only*. It NEVER stores screen frame
contents, screenshots, raw pixel data, or any private cryptographic key.
"""

from __future__ import annotations

import json
from typing import Any

from guardianmesh.screen.models import (
    ScreenCodec,
    ScreenSessionInfo,
    ScreenSessionState,
    StopReason,
)
from guardianmesh.storage.database import Database


class ScreenSessionRegistry:
    """Manages SQLite records for screen sessions (metadata only)."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, info: ScreenSessionInfo) -> None:
        """Insert or update a screen session record."""
        meta_json = json.dumps(info.metadata or {})
        self.db.execute(
            """
            INSERT INTO screen_sessions (
                session_id, device_id, parent_id, authorization_id, state,
                transport_session_id, requested_at, approved_at, started_at,
                stopped_at, expires_at, last_frame_at, frame_count,
                bytes_sent, bytes_received, width, height, codec, max_fps,
                stop_reason, label, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                device_id = excluded.device_id,
                parent_id = excluded.parent_id,
                authorization_id = excluded.authorization_id,
                state = excluded.state,
                transport_session_id = excluded.transport_session_id,
                approved_at = excluded.approved_at,
                started_at = excluded.started_at,
                stopped_at = excluded.stopped_at,
                expires_at = excluded.expires_at,
                last_frame_at = excluded.last_frame_at,
                frame_count = excluded.frame_count,
                bytes_sent = excluded.bytes_sent,
                bytes_received = excluded.bytes_received,
                width = excluded.width,
                height = excluded.height,
                codec = excluded.codec,
                max_fps = excluded.max_fps,
                stop_reason = excluded.stop_reason,
                label = excluded.label,
                metadata = excluded.metadata;
            """,
            (
                info.session_id,
                info.device_id,
                info.parent_id,
                info.authorization_id,
                info.state.value,
                info.transport_session_id,
                info.requested_at,
                info.approved_at,
                info.started_at,
                info.stopped_at,
                info.expires_at,
                info.last_frame_at,
                info.frame_count,
                info.bytes_sent,
                info.bytes_received,
                info.width,
                info.height,
                info.codec.value,
                info.max_fps,
                info.stop_reason.value if info.stop_reason else None,
                info.label,
                meta_json,
            ),
        )

    def get(self, session_id: str) -> ScreenSessionInfo | None:
        """Retrieve a screen session by ID."""
        row = self.db.fetchone(
            "SELECT * FROM screen_sessions WHERE session_id = ?;",
            (session_id,),
        )
        if not row:
            return None
        return self._row_to_info(dict(row))

    def list_for_device(self, device_id: str) -> list[ScreenSessionInfo]:
        """List all screen sessions for a child device (most recent first)."""
        rows = self.db.fetchall(
            "SELECT * FROM screen_sessions WHERE device_id = ? ORDER BY requested_at DESC;",
            (device_id,),
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def list_for_parent(self, parent_id: str) -> list[ScreenSessionInfo]:
        """List all screen sessions for a parent identity (most recent first)."""
        rows = self.db.fetchall(
            "SELECT * FROM screen_sessions WHERE parent_id = ? ORDER BY requested_at DESC;",
            (parent_id,),
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def list_all(self, limit: int = 100) -> list[ScreenSessionInfo]:
        """List all screen sessions, most recent first."""
        rows = self.db.fetchall(
            "SELECT * FROM screen_sessions ORDER BY requested_at DESC LIMIT ?;",
            (limit,),
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def list_active(self) -> list[ScreenSessionInfo]:
        """List currently ACTIVE screen sessions."""
        rows = self.db.fetchall(
            "SELECT * FROM screen_sessions WHERE state = 'ACTIVE';",
        )
        return [self._row_to_info(dict(r)) for r in rows]

    def delete(self, session_id: str) -> bool:
        """Delete a screen session record by ID. Returns True if a row was removed."""
        with self.db.connect() as conn:
            cur = conn.execute(
                "DELETE FROM screen_sessions WHERE session_id = ?;",
                (session_id,),
            )
            return cur.rowcount > 0

    @staticmethod
    def _row_to_info(row: dict[str, Any]) -> ScreenSessionInfo:
        meta_raw = row.get("metadata") or "{}"
        try:
            meta = json.loads(meta_raw)
            if not isinstance(meta, dict):
                meta = {}
        except (json.JSONDecodeError, TypeError):
            meta = {}
        return ScreenSessionInfo(
            session_id=str(row["session_id"]),
            device_id=str(row["device_id"]),
            parent_id=str(row["parent_id"]),
            authorization_id=row.get("authorization_id"),
            state=ScreenSessionState.from_str(row.get("state", "REQUESTED")),
            transport_session_id=row.get("transport_session_id"),
            requested_at=str(row.get("requested_at", "")),
            approved_at=row.get("approved_at"),
            started_at=row.get("started_at"),
            stopped_at=row.get("stopped_at"),
            expires_at=str(row.get("expires_at", "")),
            last_frame_at=row.get("last_frame_at"),
            frame_count=int(row.get("frame_count", 0)),
            bytes_sent=int(row.get("bytes_sent", 0)),
            bytes_received=int(row.get("bytes_received", 0)),
            width=int(row.get("width", 0)),
            height=int(row.get("height", 0)),
            codec=ScreenCodec.from_str(row.get("codec", "TEST")),
            max_fps=int(row.get("max_fps", 10)),
            stop_reason=(
                StopReason.from_str(row["stop_reason"]) if row.get("stop_reason") else None
            ),
            label=row.get("label"),
            metadata=meta,
        )


__all__ = ["ScreenSessionRegistry"]
