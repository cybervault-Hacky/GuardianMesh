"""Transport session management, sequence tracking, and replay protection."""

from __future__ import annotations

import collections
import datetime
import threading
from typing import Any

from guardianmesh.core.errors import (
    TransportConnectionClosedError,
    TransportReplayError,
    TransportSequenceError,
    TransportSessionExpiredError,
)
from guardianmesh.transport.crypto import decrypt_frame_payload, encrypt_envelope_payload
from guardianmesh.transport.models import (
    ConnectionState,
    EncryptedTransportFrame,
    SessionInfo,
    TransportEnvelope,
    TransportType,
    generate_session_id,
)


class TransportSession:
    """Thread-safe stateful transport session with AEAD keys, sequences, and replay defense."""

    def __init__(
        self,
        local_identity_id: str,
        remote_identity_id: str,
        session_id: str | None = None,
        send_key: bytes | None = None,
        recv_key: bytes | None = None,
        session_salt: bytes = b"",
        transport_type: TransportType = TransportType.LOCAL,
        state: ConnectionState = ConnectionState.CONNECTING,
        created_at: str | None = None,
        established_at: str | None = None,
        expires_at: str | None = None,
        replay_window_size: int = 128,
        ttl_seconds: int = 3600,
        reconnect_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        now_dt = datetime.datetime.now(datetime.UTC)
        self.session_id = session_id or generate_session_id()
        self.local_identity_id = local_identity_id
        self.remote_identity_id = remote_identity_id
        self.send_key = send_key
        self.recv_key = recv_key
        self.session_salt = session_salt
        self.transport_type = transport_type
        self.state = state
        self.created_at = created_at or now_dt.isoformat()
        self.established_at = established_at
        self.expires_at = expires_at or (now_dt + datetime.timedelta(seconds=ttl_seconds)).isoformat()
        self.closed_at: str | None = None
        self.last_heartbeat_at: str | None = established_at or self.created_at
        self.reconnect_count = reconnect_count
        self.last_error: str | None = None
        self.metadata = metadata or {}

        # Sequences and Replay Defense
        self._outbound_seq = 0
        self._inbound_seq = 0
        self._replay_window_size = replay_window_size
        self._seen_sequences: set[int] = set()
        self._seen_message_ids: collections.deque[str] = collections.deque(maxlen=1000)
        self._seen_message_id_set: set[str] = set()
        self._lock = threading.RLock()

    @property
    def is_expired(self) -> bool:
        """Check if session duration has passed its expiration limit."""
        if not self.expires_at:
            return False
        try:
            exp = datetime.datetime.fromisoformat(self.expires_at)
            return datetime.datetime.now(datetime.UTC) > exp
        except Exception:
            return True

    @property
    def is_active(self) -> bool:
        """Check if session is currently connected and unexpired."""
        return self.state == ConnectionState.CONNECTED and not self.is_expired

    @property
    def inbound_sequence(self) -> int:
        with self._lock:
            return self._inbound_seq

    @property
    def outbound_sequence(self) -> int:
        with self._lock:
            return self._outbound_seq

    def next_outbound_sequence(self) -> int:
        """Atomically increment and return the next outbound sequence number."""
        with self._lock:
            self._outbound_seq += 1
            return self._outbound_seq

    def validate_and_advance_inbound_sequence(self, sequence: int, message_id: str) -> None:
        """Verify inbound sequence number and message ID against replay attacks.

        Args:
            sequence: Inbound message sequence number.
            message_id: Inbound message UUID/ID.

        Raises:
            TransportSessionExpiredError: If session lifetime is over.
            TransportReplayError: If sequence or message ID has already been processed.
            TransportSequenceError: If sequence number is invalid (<= 0).
        """
        with self._lock:
            if self.is_expired:
                self.state = ConnectionState.EXPIRED
                raise TransportSessionExpiredError(
                    f"Session '{self.session_id}' expired at {self.expires_at}."
                )

            if sequence <= 0:
                raise TransportSequenceError(
                    f"Invalid sequence number {sequence}: must be a positive integer."
                )

            # Check message ID uniqueness in recent memory cache
            if message_id in self._seen_message_id_set:
                raise TransportReplayError(
                    f"Duplicate message ID '{message_id}' rejected by replay defense."
                )

            # Check sequence against sliding window
            if sequence in self._seen_sequences:
                raise TransportReplayError(
                    f"Duplicate sequence number {sequence} rejected for session '{self.session_id}'."
                )

            min_valid_seq = max(1, self._inbound_seq - self._replay_window_size)
            if sequence < min_valid_seq:
                raise TransportReplayError(
                    f"Sequence number {sequence} is older than sliding window boundary ({min_valid_seq})."
                )

            # Record accepted sequence and message ID
            self._seen_sequences.add(sequence)
            if len(self._seen_message_ids) == self._seen_message_ids.maxlen:
                oldest_id = self._seen_message_ids.popleft()
                self._seen_message_id_set.discard(oldest_id)

            self._seen_message_ids.append(message_id)
            self._seen_message_id_set.add(message_id)

            if sequence > self._inbound_seq:
                self._inbound_seq = sequence

            # Prune sequences that fell outside the sliding window
            cutoff = max(0, self._inbound_seq - self._replay_window_size)
            self._seen_sequences = {s for s in self._seen_sequences if s >= cutoff}

            now_iso = datetime.datetime.now(datetime.UTC).isoformat()
            self.last_heartbeat_at = now_iso

    def encrypt_envelope(self, envelope: TransportEnvelope) -> EncryptedTransportFrame:
        """Encrypt an outbound message envelope using the session send key."""
        with self._lock:
            if not self.send_key:
                raise TransportConnectionClosedError(
                    "Cannot encrypt: session send key is missing or session closed."
                )
            if self.is_expired:
                self.state = ConnectionState.EXPIRED
                raise TransportSessionExpiredError(f"Session '{self.session_id}' has expired.")

            envelope.session_id = self.session_id
            envelope.sequence = self.next_outbound_sequence()
            envelope.validate()

            return encrypt_envelope_payload(
                send_key=self.send_key,
                session_salt=self.session_salt,
                envelope=envelope,
            )

    def decrypt_frame(self, frame: EncryptedTransportFrame) -> TransportEnvelope:
        """Decrypt an inbound encrypted frame using the session receive key and advance sequence."""
        with self._lock:
            if not self.recv_key:
                raise TransportConnectionClosedError(
                    "Cannot decrypt: session receive key is missing or session closed."
                )
            if self.is_expired:
                self.state = ConnectionState.EXPIRED
                raise TransportSessionExpiredError(f"Session '{self.session_id}' has expired.")

            if frame.session_id != self.session_id:
                raise TransportSequenceError(
                    f"Frame session ID '{frame.session_id}' does not match session '{self.session_id}'."
                )

            # Decrypt envelope payload
            envelope = decrypt_frame_payload(
                recv_key=self.recv_key,
                session_salt=self.session_salt,
                frame=frame,
            )

            # Verify and advance sequence
            self.validate_and_advance_inbound_sequence(envelope.sequence, envelope.message_id)
            return envelope

    def touch_heartbeat(self) -> None:
        """Update last heartbeat timestamp to current time."""
        with self._lock:
            self.last_heartbeat_at = datetime.datetime.now(datetime.UTC).isoformat()

    def close(self, reason: str = "Session closed") -> None:
        """Zero and wipe in-memory cryptographic keys and transition state to DISCONNECTED."""
        with self._lock:
            self.state = ConnectionState.DISCONNECTED
            self.closed_at = datetime.datetime.now(datetime.UTC).isoformat()
            self.last_error = reason

            # Wipe symmetric session keys from memory
            self.send_key = None
            self.recv_key = None
            self.session_salt = b""

    def to_info(self) -> SessionInfo:
        """Export read-only session metadata representation."""
        with self._lock:
            return SessionInfo(
                session_id=self.session_id,
                local_identity_id=self.local_identity_id,
                remote_identity_id=self.remote_identity_id,
                state=self.state,
                transport_type=self.transport_type,
                created_at=self.created_at,
                established_at=self.established_at,
                expires_at=self.expires_at,
                closed_at=self.closed_at,
                last_heartbeat_at=self.last_heartbeat_at,
                reconnect_count=self.reconnect_count,
                last_error=self.last_error,
                inbound_sequence=self._inbound_seq,
                outbound_sequence=self._outbound_seq,
                metadata=self.metadata,
            )
