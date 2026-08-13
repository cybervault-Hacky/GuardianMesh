"""Tests for SequenceManager monotonic tracking and replay prevention."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.errors import TelemetryReplayError
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.sequence import SequenceManager


def test_sequence_manager_monotonic_flow(tmp_path: Path) -> None:
    """Test SequenceManager allocates strictly incrementing outgoing sequences and validates incoming."""
    db = Database(tmp_path / "seq_test.db")
    MigrationManager().apply_migrations(db)
    seq_mgr = SequenceManager(db)

    device_id = "GM-C-19A84E72"

    # Outgoing allocation
    seq1 = seq_mgr.get_next_outgoing_sequence(device_id)
    assert seq1 == 1

    seq2 = seq_mgr.get_next_outgoing_sequence(device_id)
    assert seq2 == 2

    seq3 = seq_mgr.get_next_outgoing_sequence(device_id)
    assert seq3 == 3

    # Incoming validation: first acceptance
    assert seq_mgr.get_last_incoming_sequence(device_id) == 0
    seq_mgr.validate_and_advance_incoming_sequence(device_id, 1)
    assert seq_mgr.get_last_incoming_sequence(device_id) == 1

    # Advance to sequence 5
    seq_mgr.validate_and_advance_incoming_sequence(device_id, 5)
    assert seq_mgr.get_last_incoming_sequence(device_id) == 5

    # Replay: duplicate sequence 5 must raise TelemetryReplayError
    with pytest.raises(TelemetryReplayError) as excinfo:
        seq_mgr.validate_and_advance_incoming_sequence(device_id, 5)
    assert "Replay detected" in str(excinfo.value)

    # Replay: older sequence 3 must raise TelemetryReplayError
    with pytest.raises(TelemetryReplayError):
        seq_mgr.validate_and_advance_incoming_sequence(device_id, 3)
