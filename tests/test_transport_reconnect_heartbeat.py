"""Tests for ReconnectManager exponential backoff and HeartbeatManager liveness."""

from __future__ import annotations

import datetime

from guardianmesh.transport.heartbeat import HeartbeatManager
from guardianmesh.transport.models import (
    ConnectionState,
    MessageType,
    PeerInfo,
)
from guardianmesh.transport.reconnect import ReconnectManager
from guardianmesh.transport.session import TransportSession


def test_reconnect_manager_backoff_delays() -> None:
    """Test exponential backoff delay calculation and bounds."""
    mgr = ReconnectManager(
        initial_delay_seconds=1.0,
        max_delay_seconds=30.0,
        backoff_factor=2.0,
        max_retries=5,
        enable_jitter=False,
    )

    assert mgr.get_delay(0) == 1.0
    assert mgr.get_delay(1) == 1.0
    assert mgr.get_delay(2) == 2.0
    assert mgr.get_delay(3) == 4.0
    assert mgr.get_delay(4) == 8.0
    assert mgr.get_delay(5) == 16.0
    assert mgr.get_delay(6) == 30.0  # Capped at max_delay
    assert mgr.get_delay(10) == 30.0


def test_reconnect_manager_jitter() -> None:
    """Test retry delay with jitter enabled."""
    mgr = ReconnectManager(
        initial_delay_seconds=2.0,
        max_delay_seconds=10.0,
        backoff_factor=2.0,
        max_retries=3,
        enable_jitter=True,
    )
    d = mgr.get_delay(1)
    assert 2.0 <= d <= 3.0


def test_reconnect_manager_retry_limits_and_reset() -> None:
    """Test retry limit checking, attempt tracking, and reset."""
    mgr = ReconnectManager(max_retries=3)
    dev_id = "GM-C-19A84E72"

    assert mgr.get_attempt_count(dev_id) == 0
    assert mgr.can_retry(1) is True
    assert mgr.can_retry(3) is True
    assert mgr.can_retry(4) is False

    assert mgr.record_attempt(dev_id) == 1
    assert mgr.record_attempt(dev_id) == 2
    assert mgr.record_attempt(dev_id) == 3
    assert mgr.get_attempt_count(dev_id) == 3

    mgr.reset(dev_id)
    assert mgr.get_attempt_count(dev_id) == 0


def test_heartbeat_manager_envelope_construction() -> None:
    """Test constructing HEARTBEAT, PING, and PONG envelopes."""
    hb_mgr = HeartbeatManager(interval_seconds=15, timeout_seconds=45)
    session = TransportSession(
        session_id="SES-001",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
    )

    # 1. Heartbeat
    hb = hb_mgr.create_heartbeat(
        local_id="GM-P-83A1F72C",
        remote_id="GM-C-19A84E72",
        session=session,
    )
    assert hb.message_type == MessageType.HEARTBEAT
    assert hb.sequence == 1
    assert hb.sender_id == "GM-P-83A1F72C"

    # 2. Ping
    ping = hb_mgr.create_ping(
        local_id="GM-P-83A1F72C",
        remote_id="GM-C-19A84E72",
        session=session,
    )
    assert ping.message_type == MessageType.PING
    assert ping.sequence == 2

    # 3. Pong
    pong = hb_mgr.create_pong(
        local_id="GM-C-19A84E72",
        remote_id="GM-P-83A1F72C",
        session=session,
        ping_message_id=ping.message_id,
    )
    assert pong.message_type == MessageType.PONG
    assert pong.payload["ping_id"] == ping.message_id
    assert pong.sequence == 3


def test_heartbeat_manager_timeout_detection() -> None:
    """Test timeout checking against elapsed time."""
    hb_mgr = HeartbeatManager(timeout_seconds=30)
    now = datetime.datetime.now(datetime.UTC)

    # Recent heartbeat
    recent = (now - datetime.timedelta(seconds=10)).isoformat()
    assert hb_mgr.is_heartbeat_overdue(recent) is False

    # Overdue heartbeat
    overdue = (now - datetime.timedelta(seconds=40)).isoformat()
    assert hb_mgr.is_heartbeat_overdue(overdue) is True

    # None / empty
    assert hb_mgr.is_heartbeat_overdue(None) is True
    assert hb_mgr.is_heartbeat_overdue("invalid") is True


def test_heartbeat_manager_peer_state_evaluation() -> None:
    """Test peer connection state derivation based on heartbeat freshness."""
    hb_mgr = HeartbeatManager(timeout_seconds=30)
    now = datetime.datetime.now(datetime.UTC)

    # 1. Fresh peer -> CONNECTED
    p1 = PeerInfo(
        device_id="GM-C-01",
        role="CHILD",
        connection_state=ConnectionState.CONNECTED,
        last_heartbeat_at=(now - datetime.timedelta(seconds=10)).isoformat(),
    )
    assert hb_mgr.evaluate_peer_state(p1) == ConnectionState.CONNECTED

    # 2. Degraded peer (> 30s) -> DEGRADED
    p2 = PeerInfo(
        device_id="GM-C-02",
        role="CHILD",
        connection_state=ConnectionState.CONNECTED,
        last_heartbeat_at=(now - datetime.timedelta(seconds=35)).isoformat(),
    )
    assert hb_mgr.evaluate_peer_state(p2) == ConnectionState.DEGRADED

    # 3. Disconnected peer (> 60s) -> DISCONNECTED
    p3 = PeerInfo(
        device_id="GM-C-03",
        role="CHILD",
        connection_state=ConnectionState.CONNECTED,
        last_heartbeat_at=(now - datetime.timedelta(seconds=70)).isoformat(),
    )
    assert hb_mgr.evaluate_peer_state(p3) == ConnectionState.DISCONNECTED

    # 4. Terminal states preserved
    p_term = PeerInfo(
        device_id="GM-C-04",
        role="CHILD",
        connection_state=ConnectionState.REVOKED,
    )
    assert hb_mgr.evaluate_peer_state(p_term) == ConnectionState.REVOKED
