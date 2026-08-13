"""Monotonic sequence number management and replay prevention."""

from __future__ import annotations

import datetime

from guardianmesh.core.errors import TelemetryReplayError
from guardianmesh.storage.database import Database


class SequenceManager:
    """Manages persistent monotonic sequence numbers per device to prevent replay attacks."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def get_next_outgoing_sequence(self, device_id: str) -> int:
        """Atomically generate the next outgoing monotonic sequence number for local device."""
        now = datetime.datetime.now(datetime.UTC).isoformat()

        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO device_sequences (
                    device_id, last_outgoing_sequence, last_incoming_sequence, updated_at
                )
                VALUES (?, 1, 0, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    last_outgoing_sequence = device_sequences.last_outgoing_sequence + 1,
                    updated_at = excluded.updated_at;
                """,
                (device_id, now),
            )
            row = conn.execute(
                "SELECT last_outgoing_sequence FROM device_sequences WHERE device_id = ?;",
                (device_id,),
            ).fetchone()
            return int(row[0]) if row else 1

    def get_last_incoming_sequence(self, device_id: str) -> int:
        """Fetch the highest accepted incoming sequence number for a remote device."""
        row = self.db.fetchone(
            "SELECT last_incoming_sequence FROM device_sequences WHERE device_id = ?;",
            (device_id,),
        )
        if not row:
            return 0
        return int(row["last_incoming_sequence"])

    def validate_and_advance_incoming_sequence(self, device_id: str, sequence: int) -> None:
        """Validate that incoming sequence number is strictly greater than previously accepted sequence.

        Raises:
            TelemetryReplayError: If sequence <= last accepted sequence number.
        """
        now = datetime.datetime.now(datetime.UTC).isoformat()

        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT last_incoming_sequence FROM device_sequences WHERE device_id = ?;",
                (device_id,),
            ).fetchone()
            last_seq = int(row[0]) if row else 0

            if sequence <= last_seq:
                err_msg = (
                    f"Replay detected: sequence {sequence} <= last accepted "
                    f"sequence {last_seq} for device '{device_id}'."
                )
                raise TelemetryReplayError(err_msg)

            conn.execute(
                """
                INSERT INTO device_sequences (
                    device_id, last_outgoing_sequence, last_incoming_sequence, updated_at
                )
                VALUES (?, 0, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    last_incoming_sequence = excluded.last_incoming_sequence,
                    updated_at = excluded.updated_at;
                """,
                (device_id, sequence, now),
            )
