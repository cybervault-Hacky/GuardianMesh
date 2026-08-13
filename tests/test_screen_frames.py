"""Tests for frame validation, sequence tracking, and bounded buffering."""

from __future__ import annotations

import pytest

from guardianmesh.screen.errors import (
    ScreenFrameError,
    ScreenFrameOversizedError,
    ScreenFrameSequenceError,
    ScreenFrameValidationError,
)
from guardianmesh.screen.frames import (
    FrameSequenceTracker,
    FrameStreamBuffer,
    FrameValidator,
)
from guardianmesh.screen.models import (
    BackpressureStrategy,
    PixelFormat,
    ScreenCodec,
    ScreenFrame,
)


def _frame(sequence: int, payload_size: int = 4, width: int = 320, height: int = 240) -> ScreenFrame:
    return ScreenFrame(
        session_id="SCN-FRAME",
        device_id="GM-C-19A84E72",
        sequence=sequence,
        width=width,
        height=height,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
        payload_size=payload_size,
        payload=b"a" * payload_size,
    )


# ---------------------------------------------------------------------------
# FrameSequenceTracker
# ---------------------------------------------------------------------------


def test_sequence_tracker_accepts_monotonic_sequences() -> None:
    """The tracker accepts strictly increasing positive sequences."""
    tracker = FrameSequenceTracker(window_size=10)
    for s in (1, 2, 3, 4, 5):
        tracker.accept(s)
    assert tracker.last_sequence == 5


def test_sequence_tracker_rejects_zero_or_negative() -> None:
    """Sequences must be positive integers."""
    tracker = FrameSequenceTracker(window_size=10)
    with pytest.raises(ScreenFrameSequenceError):
        tracker.accept(0)
    with pytest.raises(ScreenFrameSequenceError):
        tracker.accept(-3)


def test_sequence_tracker_rejects_duplicates() -> None:
    """Duplicate sequences are rejected as replays."""
    tracker = FrameSequenceTracker(window_size=10)
    tracker.accept(1)
    with pytest.raises(ScreenFrameSequenceError):
        tracker.accept(1)


def test_sequence_tracker_rejects_outside_window() -> None:
    """Sequences below the sliding window boundary are rejected."""
    tracker = FrameSequenceTracker(window_size=3)
    for s in (10, 11, 12):
        tracker.accept(s)
    # Sequence 8 is now outside the window (min valid = 12 - 3 = 9).
    with pytest.raises(ScreenFrameSequenceError):
        tracker.accept(8)


def test_sequence_tracker_reset_clears_state() -> None:
    """Reset returns the tracker to its initial state."""
    tracker = FrameSequenceTracker(window_size=10)
    tracker.accept(1)
    tracker.accept(2)
    tracker.reset()
    assert tracker.last_sequence == 0
    # After reset we can accept 1 again.
    tracker.accept(1)
    assert tracker.last_sequence == 1


def test_sequence_tracker_invalid_window_size() -> None:
    """A non-positive window size is rejected at construction."""
    with pytest.raises(ScreenFrameError):
        FrameSequenceTracker(window_size=0)


# ---------------------------------------------------------------------------
# FrameValidator
# ---------------------------------------------------------------------------


def test_validator_accepts_valid_frame() -> None:
    """A well-formed frame is accepted by the validator."""
    v = FrameValidator()
    v.validate(_frame(sequence=1))


def test_validator_rejects_bad_protocol_version() -> None:
    """Unknown protocol version is rejected."""
    v = FrameValidator()
    f = _frame(sequence=1)
    f.protocol_version = "0.0"
    with pytest.raises(ScreenFrameValidationError):
        v.validate(f)


def test_validator_rejects_zero_dimensions() -> None:
    """Width and height must be positive."""
    v = FrameValidator()
    f = _frame(sequence=1, width=0, height=240)
    with pytest.raises(ScreenFrameValidationError):
        v.validate(f)
    f = _frame(sequence=1, width=320, height=0)
    with pytest.raises(ScreenFrameValidationError):
        v.validate(f)


def test_validator_rejects_oversized_dimensions() -> None:
    """Dimensions above the configured limits are rejected."""
    v = FrameValidator(max_width=1280, max_height=720)
    f = _frame(sequence=1, width=1920, height=720)
    with pytest.raises(ScreenFrameOversizedError):
        v.validate(f)


def test_validator_rejects_oversized_payload() -> None:
    """Payload above the configured maximum is rejected."""
    v = FrameValidator(max_payload_bytes=100)
    f = _frame(sequence=1, payload_size=500)
    with pytest.raises(ScreenFrameOversizedError):
        v.validate(f)


def test_validator_rejects_size_mismatch() -> None:
    """Mismatched payload_size and actual payload length is rejected."""
    v = FrameValidator()
    f = _frame(sequence=1, payload_size=4)
    f.payload_size = 99
    with pytest.raises(ScreenFrameValidationError):
        v.validate(f)


def test_validator_rejects_invalid_timestamp() -> None:
    """A non-ISO timestamp is rejected."""
    v = FrameValidator()
    f = _frame(sequence=1)
    f.captured_at = "not-a-timestamp"
    with pytest.raises(ScreenFrameValidationError):
        v.validate(f)


def test_validator_rejects_non_positive_max_dimensions() -> None:
    """Construction rejects non-positive limits."""
    with pytest.raises(ScreenFrameError):
        FrameValidator(max_width=0, max_height=720)


# ---------------------------------------------------------------------------
# FrameStreamBuffer
# ---------------------------------------------------------------------------


def test_buffer_rejects_cross_session_frame() -> None:
    """Frames with a different session_id than the buffer are rejected."""
    buf = FrameStreamBuffer("SCN-A")
    f = _frame(sequence=1)
    f.session_id = "SCN-B"
    with pytest.raises(ScreenFrameError):
        buf.ingest(f)


def test_buffer_ingest_and_drain() -> None:
    """Ingested frames can be drained in order."""
    buf = FrameStreamBuffer("SCN-FRAME", max_queue_size=10)
    for i in range(1, 6):
        accepted = buf.ingest(_frame(sequence=i))
        assert accepted is True
    assert buf.size == 5
    drained = buf.drain()
    assert [f.sequence for f in drained] == [1, 2, 3, 4, 5]
    assert buf.size == 0


def test_buffer_backpressure_drops_oldest() -> None:
    """When the queue is full, DROP_OLDEST drops the oldest frame."""
    buf = FrameStreamBuffer(
        "SCN-FRAME",
        max_queue_size=3,
        backpressure=BackpressureStrategy.DROP_OLDEST,
    )
    for i in range(1, 6):
        buf.ingest(_frame(sequence=i))
    assert buf.size == 3
    assert buf.dropped_count == 2
    drained = buf.drain()
    assert [f.sequence for f in drained] == [3, 4, 5]


def test_buffer_rejects_oversized_frame() -> None:
    """Oversized frames are rejected at the boundary."""
    buf = FrameStreamBuffer(
        "SCN-FRAME",
        max_queue_size=5,
    )
    buf._validator = FrameValidator(max_payload_bytes=10)  # type: ignore[attr-defined]
    with pytest.raises(ScreenFrameOversizedError):
        buf.ingest(_frame(sequence=1, payload_size=64))


def test_buffer_summary_metadata_only() -> None:
    """The buffer summary exposes metadata only — no payloads."""
    buf = FrameStreamBuffer("SCN-FRAME", max_queue_size=3)
    buf.ingest(_frame(sequence=1))
    s = buf.summary()
    assert s["session_id"] == "SCN-FRAME"
    assert s["queue_size"] == 1
    assert "payload" not in s
    assert "payload_hex" not in s


def test_buffer_clear_resets_sequences() -> None:
    """Clearing the buffer also resets the sequence tracker."""
    buf = FrameStreamBuffer("SCN-FRAME", max_queue_size=5)
    buf.ingest(_frame(sequence=1))
    buf.ingest(_frame(sequence=2))
    buf.clear()
    assert buf.size == 0
    # Sequence 1 is acceptable again after reset.
    accepted = buf.ingest(_frame(sequence=1))
    assert accepted is True
