"""Transport abstractions for telemetry envelope exchange.

Phase 3 defines local and test transports. Production network transport is scheduled for Phase 6.
"""

from __future__ import annotations

import abc
import queue

from guardianmesh.core.errors import TelemetryTransportError
from guardianmesh.telemetry.models import TelemetryEnvelope


class Transport(abc.ABC):
    """Abstract telemetry transport contract."""

    @abc.abstractmethod
    def send(self, envelope: TelemetryEnvelope) -> bool:
        """Transmit a telemetry envelope."""
        raise NotImplementedError

    @abc.abstractmethod
    def receive(self, timeout: float | None = None) -> TelemetryEnvelope | None:
        """Receive the next available telemetry envelope."""
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        """Close transport resources."""
        raise NotImplementedError


class LocalTransport(Transport):
    """Thread-safe in-memory queue transport for local inter-component processing."""

    def __init__(self, maxsize: int = 100) -> None:
        self._queue: queue.Queue[TelemetryEnvelope] = queue.Queue(maxsize=maxsize)
        self._closed = False

    def send(self, envelope: TelemetryEnvelope) -> bool:
        if self._closed:
            raise TelemetryTransportError("Cannot send on closed LocalTransport.")
        try:
            self._queue.put(envelope, block=False)
            return True
        except queue.Full as e:
            raise TelemetryTransportError("LocalTransport queue buffer is full.") from e

    def receive(self, timeout: float | None = None) -> TelemetryEnvelope | None:
        if self._closed:
            return None
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self) -> None:
        self._closed = True


class TestTransport(Transport):
    """Deterministic test transport for unit, integration, and security test harnesses."""

    __test__ = False

    def __init__(self, should_fail: bool = False) -> None:
        self.sent_envelopes: list[TelemetryEnvelope] = []
        self.inbox: list[TelemetryEnvelope] = []
        self.should_fail = should_fail
        self.is_closed = False

    def send(self, envelope: TelemetryEnvelope) -> bool:
        if self.should_fail:
            raise TelemetryTransportError("Simulated transport failure.")
        self.sent_envelopes.append(envelope)
        return True

    def receive(self, timeout: float | None = None) -> TelemetryEnvelope | None:
        if self.inbox:
            return self.inbox.pop(0)
        return None

    def inject_incoming(self, envelope: TelemetryEnvelope) -> None:
        """Inject a test envelope into the inbox."""
        self.inbox.append(envelope)

    def close(self) -> None:
        self.is_closed = True


class FutureNetworkTransport(Transport):
    """Placeholder interface for future Phase 6 end-to-end encrypted relay transport."""

    def send(self, envelope: TelemetryEnvelope) -> bool:
        raise NotImplementedError("Production network transport is scheduled for Phase 6 (Secure Transport).")

    def receive(self, timeout: float | None = None) -> TelemetryEnvelope | None:
        raise NotImplementedError("Production network transport is scheduled for Phase 6 (Secure Transport).")

    def close(self) -> None:
        pass
