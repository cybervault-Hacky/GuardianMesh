"""Tests for TransportRegistry database operations, sequences, peers, and messages."""

from __future__ import annotations

import datetime
from pathlib import Path

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager
from guardianmesh.transport.models import (
    ConnectionState,
    PeerInfo,
    TransportType,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.session import TransportSession


def setup_test_db(tmp_path: Path) -> Database:
    """Initialize test database with all migrations applied."""
    db_path = tmp_path / "transport_reg_test.db"
    db = Database(db_path)
    mgr = MigrationManager(migrations=MIGRATIONS)
    mgr.apply_migrations(db)
    return db


def test_registry_session_lifecycle(tmp_path: Path) -> None:
    """Test session creation, retrieval, filtering, and state updates."""
    db = setup_test_db(tmp_path)
    reg = TransportRegistry(db)

    now = datetime.datetime.now(datetime.UTC).isoformat()
    session = TransportSession(
        session_id="SES-REG-01",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        transport_type=TransportType.LOCAL,
        state=ConnectionState.CONNECTED,
        created_at=now,
    )

    reg.record_session(session)
    fetched = reg.get_session("SES-REG-01")
    assert fetched is not None
    assert fetched.session_id == "SES-REG-01"
    assert fetched.state == ConnectionState.CONNECTED

    # Active session query
    active = reg.get_active_session_for_peer("GM-P-83A1F72C", "GM-C-19A84E72")
    assert active is not None
    assert active.session_id == "SES-REG-01"

    # State update
    reg.update_session_state("SES-REG-01", ConnectionState.DISCONNECTED, last_error="User disconnected")
    updated = reg.get_session("SES-REG-01")
    assert updated is not None
    assert updated.state == ConnectionState.DISCONNECTED
    assert updated.last_error == "User disconnected"

    # List sessions with filter
    sessions = reg.list_sessions(device_id="GM-C-19A84E72")
    assert len(sessions) == 1
    assert sessions[0].session_id == "SES-REG-01"


def test_registry_peer_lifecycle(tmp_path: Path) -> None:
    """Test peer tracking, heartbeats, syncs, and reconnect counters."""
    db = setup_test_db(tmp_path)
    reg = TransportRegistry(db)

    peer = PeerInfo(
        device_id="GM-C-19A84E72",
        role="CHILD",
        connection_state=ConnectionState.CONNECTED,
        active_session_id="SES-REG-01",
        reconnect_count=0,
    )
    reg.record_peer(peer)

    p = reg.get_peer("GM-C-19A84E72")
    assert p is not None
    assert p.device_id == "GM-C-19A84E72"
    assert p.connection_state == ConnectionState.CONNECTED

    # Update state
    reg.update_peer_state("GM-C-19A84E72", ConnectionState.DEGRADED)
    p_deg = reg.get_peer("GM-C-19A84E72")
    assert p_deg is not None
    assert p_deg.connection_state == ConnectionState.DEGRADED

    # Record heartbeat & sync
    reg.record_peer_heartbeat("GM-C-19A84E72", "SES-REG-01")
    reg.record_peer_sync("GM-C-19A84E72")
    p_synced = reg.get_peer("GM-C-19A84E72")
    assert p_synced is not None
    assert p_synced.last_heartbeat_at is not None
    assert p_synced.last_sync_at is not None

    # Reconnect counter
    assert reg.increment_peer_reconnect("GM-C-19A84E72") == 1
    assert reg.increment_peer_reconnect("GM-C-19A84E72") == 2
    p_rec = reg.get_peer("GM-C-19A84E72")
    assert p_rec is not None
    assert p_rec.reconnect_count == 2

    reg.reset_peer_reconnect("GM-C-19A84E72")
    p_rst = reg.get_peer("GM-C-19A84E72")
    assert p_rst is not None
    assert p_rst.reconnect_count == 0


def test_registry_message_logs_and_privacy(tmp_path: Path) -> None:
    """Test message metadata logging and verify no plaintext payload is stored."""
    db = setup_test_db(tmp_path)
    reg = TransportRegistry(db)

    reg.record_message(
        session_id="SES-001",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type="TELEMETRY",
        sequence=1,
        direction="OUTBOUND",
        status="ACCEPTED",
        payload={"battery_percent": 80},
    )

    msgs = reg.list_messages(device_id="GM-C-19A84E72")
    assert len(msgs) == 1
    m = msgs[0]
    assert m["message_type"] == "TELEMETRY"
    assert m["payload_digest"] is not None
    assert "battery_percent" not in str(m.values())

    # Raw database verification: plaintext is nowhere in transport_messages
    row = db.fetchone("SELECT * FROM transport_messages WHERE session_id = 'SES-001';")
    assert row is not None
    raw_row_str = str(dict(row))
    assert "battery_percent" not in raw_row_str


def test_registry_sequence_tracking(tmp_path: Path) -> None:
    """Test persistent sequence number updates and retrieval."""
    db = setup_test_db(tmp_path)
    reg = TransportRegistry(db)

    reg.update_sequences("SES-001", "GM-C-19A84E72", inbound_seq=5, outbound_seq=10)
    in_seq, out_seq = reg.get_sequences("SES-001", "GM-C-19A84E72")
    assert in_seq == 5
    assert out_seq == 10

    # Advance sequences
    reg.update_sequences("SES-001", "GM-C-19A84E72", inbound_seq=7, outbound_seq=12)
    in_seq2, out_seq2 = reg.get_sequences("SES-001", "GM-C-19A84E72")
    assert in_seq2 == 7
    assert out_seq2 == 12
