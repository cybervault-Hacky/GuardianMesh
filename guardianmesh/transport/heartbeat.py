"""Heartbeat generation, ping/pong exchanges, and timeout monitoring."""

from __future__ import annotations

import datetime
from typing import Any

from guardianmesh.transport.models import (
    ConnectionState,
    MessageType,
    PeerInfo,
    TransportEnvelope,
    generate_message_id,
)
from guardianmesh.transport.session import TransportSession


class HeartbeatManager:
    """Coordinates periodic liveness verification, ping/pong framing, and timeout derivation."""

    def __init__(
        self,
        interval_seconds: int = 15,
        timeout_seconds: int = 45,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.timeout_seconds = timeout_seconds

    def create_heartbeat(
        self,
        local_id: str,
        remote_id: str,
        session: TransportSession,
        metadata: dict[str, Any] | None = None,
    ) -> TransportEnvelope:
        """Construct an authenticated HEARTBEAT message envelope."""
        now = datetime.datetime.now(datetime.UTC)
        return TransportEnvelope(
            protocol_version="1.0",
            message_id=generate_message_id(),
            session_id=session.session_id,
            sender_id=local_id,
            recipient_id=remote_id,
            message_type=MessageType.HEARTBEAT,
            sequence=session.next_outbound_sequence(),
            created_at=now.isoformat(),
            expires_at=(now + datetime.timedelta(seconds=self.timeout_seconds)).isoformat(),
            payload={"timestamp": now.isoformat(), "meta": metadata or {}},
        )

    def create_ping(
        self,
        local_id: str,
        remote_id: str,
        session: TransportSession,
    ) -> TransportEnvelope:
        """Construct a PING request envelope."""
        now = datetime.datetime.now(datetime.UTC)
        return TransportEnvelope(
            protocol_version="1.0",
            message_id=generate_message_id(),
            session_id=session.session_id,
            sender_id=local_id,
            recipient_id=remote_id,
            message_type=MessageType.PING,
            sequence=session.next_outbound_sequence(),
            created_at=now.isoformat(),
            expires_at=(now + datetime.timedelta(seconds=self.timeout_seconds)).isoformat(),
            payload={"sent_at": now.isoformat()},
        )

    def create_pong(
        self,
        local_id: str,
        remote_id: str,
        session: TransportSession,
        ping_message_id: str,
    ) -> TransportEnvelope:
        """Construct a PONG response envelope."""
        now = datetime.datetime.now(datetime.UTC)
        return TransportEnvelope(
            protocol_version="1.0",
            message_id=generate_message_id(),
            session_id=session.session_id,
            sender_id=local_id,
            recipient_id=remote_id,
            message_type=MessageType.PONG,
            sequence=session.next_outbound_sequence(),
            created_at=now.isoformat(),
            expires_at=(now + datetime.timedelta(seconds=self.timeout_seconds)).isoformat(),
            payload={"ping_id": ping_message_id, "responded_at": now.isoformat()},
        )

    def is_heartbeat_overdue(
        self,
        last_heartbeat_iso: str | None,
        threshold_seconds: int | None = None,
    ) -> bool:
        """Check if time elapsed since last heartbeat exceeds threshold."""
        if not last_heartbeat_iso:
            return True
        try:
            hb_dt = datetime.datetime.fromisoformat(last_heartbeat_iso)
            now = datetime.datetime.now(datetime.UTC)
            elapsed = (now - hb_dt).total_seconds()
            limit = threshold_seconds or self.timeout_seconds
            return elapsed > limit
        except Exception:
            return True

    def evaluate_peer_state(self, peer: PeerInfo) -> ConnectionState:
        """Derive connection state for a peer based on heartbeat timeliness."""
        if peer.connection_state in (
            ConnectionState.DISCONNECTED,
            ConnectionState.REVOKED,
            ConnectionState.FAILED,
        ):
            return peer.connection_state

        if self.is_heartbeat_overdue(peer.last_heartbeat_at, self.timeout_seconds * 2):
            return ConnectionState.DISCONNECTED
        elif self.is_heartbeat_overdue(peer.last_heartbeat_at, self.timeout_seconds):
            return ConnectionState.DEGRADED

        return ConnectionState.CONNECTED
