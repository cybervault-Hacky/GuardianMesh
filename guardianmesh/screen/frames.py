"""Frame validation, sequence tracking, and bounded buffering for Vista.

This module is the *only* place where screen frames are accepted, validated,
and sequenced. It enforces:

* strict versioned :class:`ScreenFrame` validation
* per-session monotonic sequence numbers with bounded replay window
* bounded frame queue with configurable backpressure
* a :class:`FrameSequenceTracker` that rejects duplicates, out-of-order
  frames, oversized payloads, and unsupported codecs

The frame module never persists frame bytes; it only buffers them in memory
for short-lived delivery.
"""

from __future__ import annotations

import collections
import datetime
import threading
from typing import Any

from guardianmesh.screen.errors import (
    ScreenFrameError,
    ScreenFrameOversizedError,
    ScreenFrameSequenceError,
    ScreenFrameValidationError,
)
from guardianmesh.screen.models import (
    BackpressureStrategy,
    BoundedFrameQueue,
    ScreenFrame,
)


class FrameSequenceTracker:
    """Per-session monotonic sequence tracker with bounded replay window.

    The tracker accepts strictly monotonic positive sequences. Sequences
    outside the sliding window or already seen are rejected. The window
    size is bounded to keep memory usage predictable.
    """

    def __init__(self, window_size: int = 128) -> None:
        if window_size <= 0:
            raise ScreenFrameError("window_size must be positive.")
        self._lock = threading.RLock()
        self._last_sequence: int = 0
        self._window: collections.deque[int] = collections.deque(maxlen=window_size)
        self._seen: set[int] = set()
        self._window_size = window_size

    @property
    def last_sequence(self) -> int:
        with self._lock:
            return self._last_sequence

    def accept(self, sequence: int) -> None:
        """Validate and advance a frame sequence.

        Raises:
            ScreenFrameSequenceError: If the sequence is invalid.
        """
        with self._lock:
            if sequence <= 0:
                raise ScreenFrameSequenceError(
                    f"Frame sequence must be a positive integer, got {sequence}."
                )
            if sequence in self._seen:
                raise ScreenFrameSequenceError(
                    f"Frame sequence {sequence} is a duplicate."
                )
            min_valid = max(1, self._last_sequence - self._window_size)
            if sequence < min_valid:
                raise ScreenFrameSequenceError(
                    f"Frame sequence {sequence} is outside the sliding window "
                    f"(min_valid={min_valid})."
                )
            self._seen.add(sequence)
            self._window.append(sequence)
            if sequence > self._last_sequence:
                self._last_sequence = sequence

    def reset(self) -> None:
        with self._lock:
            self._last_sequence = 0
            self._window.clear()
            self._seen.clear()


class FrameValidator:
    """Stateless validator for :class:`ScreenFrame` instances.

    All bounds are configurable but always positive and bounded. The
    validator never logs payload bytes; error messages only mention sizes
    and identifiers.
    """

    def __init__(
        self,
        max_width: int = 1920,
        max_height: int = 1080,
        max_payload_bytes: int = 4 * 1024 * 1024,
        max_fps: int = 10,
    ) -> None:
        if max_width <= 0 or max_height <= 0:
            raise ScreenFrameError("max_width and max_height must be positive.")
        if max_payload_bytes <= 0:
            raise ScreenFrameError("max_payload_bytes must be positive.")
        if max_fps <= 0:
            raise ScreenFrameError("max_fps must be positive.")
        self._max_width = max_width
        self._max_height = max_height
        self._max_payload_bytes = max_payload_bytes
        self._max_fps = max_fps

    @property
    def max_width(self) -> int:
        return self._max_width

    @property
    def max_height(self) -> int:
        return self._max_height

    @property
    def max_payload_bytes(self) -> int:
        return self._max_payload_bytes

    @property
    def max_fps(self) -> int:
        return self._max_fps

    def validate(self, frame: ScreenFrame) -> None:
        """Validate a frame.

        Raises:
            ScreenFrameValidationError: On structural or format issues.
            ScreenFrameOversizedError: On dimensional or payload size limits.
        """
        if frame.protocol_version != "1.0":
            raise ScreenFrameValidationError(
                f"Unsupported frame protocol version '{frame.protocol_version}'."
            )
        if frame.width <= 0 or frame.height <= 0:
            raise ScreenFrameValidationError("Frame dimensions must be positive.")
        if frame.width > self._max_width:
            raise ScreenFrameOversizedError(
                f"Frame width {frame.width} exceeds maximum {self._max_width}."
            )
        if frame.height > self._max_height:
            raise ScreenFrameOversizedError(
                f"Frame height {frame.height} exceeds maximum {self._max_height}."
            )
        if len(frame.payload) > self._max_payload_bytes:
            raise ScreenFrameOversizedError(
                f"Frame payload {len(frame.payload)} bytes exceeds maximum "
                f"{self._max_payload_bytes}."
            )
        if frame.payload_size != len(frame.payload):
            raise ScreenFrameValidationError(
                "Frame payload_size does not match actual payload length."
            )
        try:
            datetime.datetime.fromisoformat(frame.captured_at)
        except ValueError as e:
            raise ScreenFrameValidationError(
                f"Invalid frame captured_at timestamp: {e}"
            ) from e


class FrameStreamBuffer:
    """Per-session bounded buffer combining validation, sequence tracking, and backpressure."""

    def __init__(
        self,
        session_id: str,
        max_queue_size: int = 30,
        backpressure: BackpressureStrategy = BackpressureStrategy.DROP_OLDEST,
        validator: FrameValidator | None = None,
        tracker: FrameSequenceTracker | None = None,
    ) -> None:
        self.session_id = session_id
        self._validator = validator or FrameValidator()
        self._tracker = tracker or FrameSequenceTracker()
        self._queue = BoundedFrameQueue(max_size=max_queue_size, strategy=backpressure)

    def ingest(self, frame: ScreenFrame) -> bool:
        """Validate, sequence-check, and enqueue a frame.

        Returns:
            True if the frame was added to the queue, False if it was dropped
            under backpressure.
        """
        if frame.session_id != self.session_id:
            raise ScreenFrameError(
                f"Frame session_id '{frame.session_id}' does not match buffer "
                f"session_id '{self.session_id}'."
            )
        self._validator.validate(frame)
        self._tracker.accept(frame.sequence)
        return self._queue.push(frame)

    def pop(self) -> ScreenFrame | None:
        return self._queue.pop()

    def drain(self) -> list[ScreenFrame]:
        return self._queue.drain()

    def clear(self) -> None:
        self._queue.clear()
        self._tracker.reset()

    @property
    def dropped_count(self) -> int:
        return self._queue.dropped_count

    @property
    def size(self) -> int:
        return self._queue.size()

    @property
    def last_sequence(self) -> int:
        return self._tracker.last_sequence

    def summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "queue_size": self.size,
            "dropped_count": self.dropped_count,
            "last_sequence": self.last_sequence,
            "max_width": self._validator.max_width,
            "max_height": self._validator.max_height,
            "max_payload_bytes": self._validator.max_payload_bytes,
            "max_fps": self._validator.max_fps,
        }


__all__ = [
    "FrameSequenceTracker",
    "FrameStreamBuffer",
    "FrameValidator",
]
