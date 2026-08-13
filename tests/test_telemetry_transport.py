"""Tests for Telemetry Transport abstractions (LocalTransport, TestTransport, FutureNetworkTransport)."""

from __future__ import annotations

import pytest

from guardianmesh.core.errors import TelemetryTransportError
from guardianmesh.telemetry.models import TelemetryEnvelope
from guardianmesh.telemetry.transport import (
    FutureNetworkTransport,
    LocalTransport,
    TestTransport,
)


def test_local_transport() -> None:
    """Test LocalTransport in-memory queue send and receive."""
    transport = LocalTransport(maxsize=5)

    envelope = TelemetryEnvelope(
        device_id="GM-C-19A84E72",
        sequence=1,
        payload={"battery_percent": 90, "agent_version": "0.3.0"},
        captured_at="2026-08-12T19:00:00+00:00",
    )

    assert transport.send(envelope) is True
    received = transport.receive(timeout=0.1)
    assert received is not None
    assert received.device_id == "GM-C-19A84E72"

    transport.close()
    with pytest.raises(TelemetryTransportError):
        transport.send(envelope)


def test_test_transport() -> None:
    """Test TestTransport recording and simulated failure."""
    t_ok = TestTransport(should_fail=False)
    envelope = TelemetryEnvelope(
        device_id="GM-C-19A84E72",
        sequence=1,
        payload={"battery_percent": 90, "agent_version": "0.3.0"},
        captured_at="2026-08-12T19:00:00+00:00",
    )

    assert t_ok.send(envelope) is True
    assert len(t_ok.sent_envelopes) == 1

    t_ok.inject_incoming(envelope)
    assert t_ok.receive() == envelope

    # Failure mode
    t_fail = TestTransport(should_fail=True)
    with pytest.raises(TelemetryTransportError):
        t_fail.send(envelope)


def test_future_network_transport() -> None:
    """Verify FutureNetworkTransport indicates production transport is not yet implemented."""
    fut = FutureNetworkTransport()
    envelope = TelemetryEnvelope(
        device_id="GM-C-19A84E72",
        sequence=1,
        payload={"battery_percent": 90, "agent_version": "0.3.0"},
        captured_at="2026-08-12T19:00:00+00:00",
    )
    with pytest.raises(NotImplementedError):
        fut.send(envelope)
    with pytest.raises(NotImplementedError):
        fut.receive()
