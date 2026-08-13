"""Persistent database registry for transport sessions, peer statuses, sequences, and messages."""

from __future__ import annotations

import datetime
import json
from typing import Any

from guardianmesh.security.crypto import sha256_hex
from guardianmesh.storage.database import Database
from guardianmesh.transport.models import (
    ConnectionState,
    PeerInfo,
    SessionInfo,
)
from guardianmesh.transport.session import TransportSession


class TransportRegistry:
    """Manages SQLite records for transport sessions, peer health, sequences, and message logs."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def record_session(self, session: TransportSession) -> None:
        """Persist or update transport session metadata in database."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        meta_json = json.dumps(session.metadata or {})

        self.db.execute(
            """
            INSERT INTO transport_sessions (
                session_id, local_identity_id, remote_identity_id, state,
                transport_type, created_at, established_at, last_heartbeat_at,
                expires_at, closed_at, reconnect_count, last_error, metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                state = excluded.state,
                established_at = coalesce(
                    excluded.established_at,
                    transport_sessions.established_at
                ),
                last_heartbeat_at = coalesce(
                    excluded.last_heartbeat_at,
                    transport_sessions.last_heartbeat_at
                ),
                closed_at = excluded.closed_at,
                reconnect_count = excluded.reconnect_count,
                last_error = excluded.last_error,
                metadata = excluded.metadata;
            """,
            (
                session.session_id,
                session.local_identity_id,
                session.remote_identity_id,
                session.state.value,
                session.transport_type.value,
                session.created_at,
                session.established_at,
                session.last_heartbeat_at or now,
                session.expires_at,
                session.closed_at,
                session.reconnect_count,
                session.last_error,
                meta_json,
            ),
        )

    def update_session_state(
        self,
        session_id: str,
        state: ConnectionState,
        last_error: str | None = None,
    ) -> None:
        """Update connection state for a specific session."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        term_states = (
            ConnectionState.DISCONNECTED,
            ConnectionState.FAILED,
            ConnectionState.EXPIRED,
            ConnectionState.REVOKED,
        )
        closed_at = now if state in term_states else None

        self.db.execute(
            """
            UPDATE transport_sessions
            SET state = ?,
                last_error = coalesce(?, last_error),
                closed_at = coalesce(?, closed_at)
            WHERE session_id = ?;
            """,
            (state.value, last_error, closed_at, session_id),
        )

    def get_session(self, session_id: str) -> SessionInfo | None:
        """Retrieve session record by ID."""
        row = self.db.fetchone(
            "SELECT * FROM transport_sessions WHERE session_id = ?;",
            (session_id,),
        )
        if not row:
            return None
        return SessionInfo.from_dict(dict(row))

    def list_sessions(
        self,
        device_id: str | None = None,
        state: str | None = None,
        limit: int = 50,
    ) -> list[SessionInfo]:
        """Query sessions by device ID or state."""
        query = "SELECT * FROM transport_sessions WHERE 1=1"
        params: list[Any] = []

        if device_id:
            query += " AND (local_identity_id = ? OR remote_identity_id = ?)"
            params.extend([device_id, device_id])

        if state:
            query += " AND state = ?"
            params.append(state.upper())

        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [SessionInfo.from_dict(dict(r)) for r in rows]

    def get_active_session_for_peer(
        self,
        local_identity_id: str,
        remote_identity_id: str,
    ) -> SessionInfo | None:
        """Fetch the active CONNECTED session for a peer pair."""
        row = self.db.fetchone(
            """
            SELECT * FROM transport_sessions
            WHERE local_identity_id = ? AND remote_identity_id = ? AND state = 'CONNECTED'
            ORDER BY created_at DESC LIMIT 1;
            """,
            (local_identity_id, remote_identity_id),
        )
        if not row:
            return None
        return SessionInfo.from_dict(dict(row))

    def record_peer(self, peer: PeerInfo) -> None:
        """Persist or update transport peer state."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        meta_json = json.dumps(peer.metadata or {})

        self.db.execute(
            """
            INSERT INTO transport_peers (
                device_id, role, connection_state, active_session_id,
                last_seen_at, last_sync_at, last_heartbeat_at,
                reconnect_count, endpoint, metadata, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                role = excluded.role,
                connection_state = excluded.connection_state,
                active_session_id = coalesce(excluded.active_session_id, transport_peers.active_session_id),
                last_seen_at = coalesce(excluded.last_seen_at, transport_peers.last_seen_at),
                last_sync_at = coalesce(excluded.last_sync_at, transport_peers.last_sync_at),
                last_heartbeat_at = coalesce(excluded.last_heartbeat_at, transport_peers.last_heartbeat_at),
                reconnect_count = excluded.reconnect_count,
                endpoint = coalesce(excluded.endpoint, transport_peers.endpoint),
                metadata = excluded.metadata,
                updated_at = excluded.updated_at;
            """,
            (
                peer.device_id,
                peer.role,
                peer.connection_state.value,
                peer.active_session_id,
                peer.last_seen_at or now,
                peer.last_sync_at,
                peer.last_heartbeat_at,
                peer.reconnect_count,
                peer.endpoint,
                meta_json,
                now,
            ),
        )

    def get_peer(self, device_id: str) -> PeerInfo | None:
        """Retrieve peer record by device ID."""
        row = self.db.fetchone(
            "SELECT * FROM transport_peers WHERE device_id = ?;",
            (device_id,),
        )
        if not row:
            return None
        return PeerInfo.from_dict(dict(row))

    def list_peers(self, state: str | None = None) -> list[PeerInfo]:
        """List all transport peers matching criteria."""
        query = "SELECT * FROM transport_peers WHERE 1=1"
        params: list[str] = []

        if state:
            query += " AND connection_state = ?"
            params.append(state.upper())

        query += " ORDER BY updated_at DESC;"
        rows = self.db.fetchall(query, tuple(params))
        return [PeerInfo.from_dict(dict(r)) for r in rows]

    def update_peer_state(
        self,
        device_id: str,
        state: ConnectionState,
        session_id: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        """Update connection state and active session for a peer."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO transport_peers (
                device_id, role, connection_state, active_session_id, endpoint, updated_at
            )
            VALUES (?, 'CHILD', ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                connection_state = excluded.connection_state,
                active_session_id = coalesce(excluded.active_session_id, transport_peers.active_session_id),
                endpoint = coalesce(excluded.endpoint, transport_peers.endpoint),
                updated_at = excluded.updated_at;
            """,
            (device_id, state.value, session_id, endpoint, now),
        )

    def record_peer_heartbeat(self, device_id: str, session_id: str | None = None) -> None:
        """Record a heartbeat arrival for a peer."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO transport_peers (
                device_id, role, connection_state, active_session_id,
                last_seen_at, last_heartbeat_at, updated_at
            )
            VALUES (?, 'CHILD', 'CONNECTED', ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                connection_state = 'CONNECTED',
                active_session_id = coalesce(excluded.active_session_id, transport_peers.active_session_id),
                last_seen_at = excluded.last_seen_at,
                last_heartbeat_at = excluded.last_heartbeat_at,
                updated_at = excluded.updated_at;
            """,
            (device_id, session_id, now, now, now),
        )

    def record_peer_sync(self, device_id: str) -> None:
        """Update last sync timestamp for a peer."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            UPDATE transport_peers
            SET last_sync_at = ?, last_seen_at = ?, updated_at = ?
            WHERE device_id = ?;
            """,
            (now, now, now, device_id),
        )

    def increment_peer_reconnect(self, device_id: str) -> int:
        """Increment and return reconnect counter for a peer."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO transport_peers (
                device_id, role, connection_state, reconnect_count, updated_at
            )
            VALUES (?, 'CHILD', 'RECONNECTING', 1, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                reconnect_count = transport_peers.reconnect_count + 1,
                connection_state = 'RECONNECTING',
                updated_at = excluded.updated_at;
            """,
            (device_id, now),
        )
        peer = self.get_peer(device_id)
        return peer.reconnect_count if peer else 1

    def reset_peer_reconnect(self, device_id: str) -> None:
        """Reset reconnect counter for a peer on successful connection."""
        self.db.execute(
            "UPDATE transport_peers SET reconnect_count = 0 WHERE device_id = ?;",
            (device_id,),
        )

    def record_message(
        self,
        session_id: str,
        sender_id: str,
        recipient_id: str,
        message_type: str,
        sequence: int,
        direction: str,
        status: str = "ACCEPTED",
        error_reason: str | None = None,
        payload: dict[str, Any] | None = None,
        message_id: str | None = None,
    ) -> None:
        """Record message metadata and SHA-256 digest without storing plaintext payloads."""
        import secrets

        msg_id = message_id or f"MSG-{secrets.token_hex(6).upper()}"
        now = datetime.datetime.now(datetime.UTC).isoformat()
        digest = (
            sha256_hex(json.dumps(payload, sort_keys=True).encode("utf-8")) if payload else None
        )

        self.db.execute(
            """
            INSERT INTO transport_messages (
                message_id, session_id, sender_id, recipient_id,
                message_type, sequence, direction, created_at,
                status, error_reason, payload_digest
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(message_id) DO UPDATE SET
                status = excluded.status,
                error_reason = excluded.error_reason;
            """,
            (
                msg_id,
                session_id,
                sender_id,
                recipient_id,
                message_type,
                sequence,
                direction.upper(),
                now,
                status.upper(),
                error_reason,
                digest,
            ),
        )

    def list_messages(
        self,
        device_id: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve recent message metadata logs."""
        query = "SELECT * FROM transport_messages WHERE 1=1"
        params: list[Any] = []

        if device_id:
            query += " AND (sender_id = ? OR recipient_id = ?)"
            params.extend([device_id, device_id])

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [dict(r) for r in rows]

    def update_sequences(
        self,
        session_id: str,
        device_id: str,
        inbound_seq: int,
        outbound_seq: int,
    ) -> None:
        """Persist latest inbound and outbound sequence numbers."""
        now = datetime.datetime.now(datetime.UTC).isoformat()
        self.db.execute(
            """
            INSERT INTO transport_sequences (
                session_id, device_id, last_inbound_sequence, last_outbound_sequence, updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(session_id, device_id) DO UPDATE SET
                last_inbound_sequence = max(
                    excluded.last_inbound_sequence,
                    transport_sequences.last_inbound_sequence
                ),
                last_outbound_sequence = max(
                    excluded.last_outbound_sequence,
                    transport_sequences.last_outbound_sequence
                ),
                updated_at = excluded.updated_at;
            """,
            (session_id, device_id, inbound_seq, outbound_seq, now),
        )

    def get_sequences(self, session_id: str, device_id: str) -> tuple[int, int]:
        """Fetch last recorded inbound and outbound sequence numbers."""
        row = self.db.fetchone(
            """
            SELECT last_inbound_sequence, last_outbound_sequence
            FROM transport_sequences
            WHERE session_id = ? AND device_id = ?;
            """,
            (session_id, device_id),
        )
        if not row:
            return 0, 0
        return int(row["last_inbound_sequence"]), int(row["last_outbound_sequence"])
