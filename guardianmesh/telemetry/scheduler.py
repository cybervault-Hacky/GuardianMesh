"""Controlled telemetry emitter and scheduler with bounded backoff and graceful shutdown."""

from __future__ import annotations

import datetime
import threading
import time

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import TelemetryTransportError
from guardianmesh.device.collectors import DeviceCollector
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.telemetry.models import TelemetryEnvelope, validate_health_payload
from guardianmesh.telemetry.sequence import SequenceManager
from guardianmesh.telemetry.transport import Transport


class TelemetryScheduler:
    """Manages scheduled heartbeat emissions and health snapshot generation."""

    def __init__(
        self,
        device_id: str,
        key_storage: KeyStorageManager,
        sequence_manager: SequenceManager,
        transport: Transport,
        collector: DeviceCollector | None = None,
        config: GuardianConfig | None = None,
    ) -> None:
        self.device_id = device_id
        self.key_storage = key_storage
        self.sequence_manager = sequence_manager
        self.transport = transport
        self.collector = collector or DeviceCollector()
        self.config = config or GuardianConfig()

        self._running = False
        self._paused = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._consecutive_failures = 0

    def emit_health_snapshot(self) -> TelemetryEnvelope:
        """Collect technical health metrics, construct signed envelope, and transmit via transport.

        Returns:
            The signed TelemetryEnvelope.
        """
        # 1. Collect allowlisted technical health metrics
        payload = self.collector.collect_health_data()
        validate_health_payload(payload)

        # 2. Allocate next monotonic outgoing sequence number
        seq = self.sequence_manager.get_next_outgoing_sequence(self.device_id)

        # 3. Construct TelemetryEnvelope
        now = datetime.datetime.now(datetime.UTC).isoformat()
        envelope = TelemetryEnvelope(
            device_id=self.device_id,
            sequence=seq,
            payload=payload,
            captured_at=now,
            protocol_version="1.0",
        )

        # 4. Sign canonical envelope with device private key
        private_key = self.key_storage.load_private_key(self.device_id)
        envelope.sign(private_key)

        # 5. Transmit over transport
        self.transport.send(envelope)
        self._consecutive_failures = 0
        return envelope

    def tick(self) -> TelemetryEnvelope | None:
        """Execute a single scheduler emission cycle with bounded backoff on failure."""
        if self._paused:
            return None

        try:
            envelope = self.emit_health_snapshot()
            self._consecutive_failures = 0
            return envelope
        except Exception as e:
            self._consecutive_failures += 1
            if self._consecutive_failures > self.config.telemetry_max_retries:
                # Bounded backoff
                backoff = min(
                    self.config.telemetry_backoff_max_seconds,
                    self.config.telemetry_backoff_base_seconds ** (self._consecutive_failures - 1),
                )
                time.sleep(min(1.0, backoff))
            raise TelemetryTransportError(f"Scheduler tick emission failed: {e}") from e

    def pause(self) -> None:
        """Pause emission cycles."""
        self._paused = True

    def resume(self) -> None:
        """Resume emission cycles."""
        self._paused = False

    def is_paused(self) -> bool:
        """Check if emissions are currently paused."""
        return self._paused

    def is_running(self) -> bool:
        """Check if background worker thread is active."""
        return self._running and bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        """Start background worker thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Gracefully stop background worker thread."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

    def _run_loop(self) -> None:
        """Internal background loop running at configured heartbeat interval."""
        interval = max(1.0, float(self.config.heartbeat_interval_seconds))
        while self._running and not self._stop_event.is_set():
            try:
                self.tick()
            except Exception:
                pass
            self._stop_event.wait(interval)
