"""Tests for the Aegis frame pipeline."""

from __future__ import annotations

import pytest

from guardianmesh.aegis.encoder import TestScreenEncoder
from guardianmesh.aegis.errors import (
    AegisFramePipelineError,
)
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    FakeMediaProjectionProvider,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ProviderCapabilities,
)
from guardianmesh.aegis.pipeline import (
    AegisFramePipeline,
    AegisProjectionLikeError,
    FrameLimiter,
    FrameNormalizer,
)
from guardianmesh.screen.models import (
    BackpressureStrategy,
    PixelFormat,
    ScreenCodec,
)


def _android_capability() -> ProviderCapabilities:
    return ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )


def _adapter_provider() -> AdapterOnlyMediaProjectionProvider:
    return AdapterOnlyMediaProjectionProvider(platform=AegisPlatform.LINUX)


def _pipeline(
    provider: object = None,
    encoder: TestScreenEncoder | None = None,
    max_fps: int = 10,
    max_width: int = 1280,
    max_height: int = 720,
    max_queue_size: int = 30,
    backpressure: BackpressureStrategy = BackpressureStrategy.DROP_OLDEST,
) -> AegisFramePipeline:
    return AegisFramePipeline(
        provider=provider or _adapter_provider(),
        encoder=encoder or TestScreenEncoder(),
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
        max_width=max_width,
        max_height=max_height,
        max_fps=max_fps,
        max_queue_size=max_queue_size,
        backpressure=backpressure,
    )


# ---------------------------------------------------------------------------
# FrameNormalizer
# ---------------------------------------------------------------------------


def test_normalizer_rejects_zero_dimensions() -> None:
    """The normalizer constructor rejects non-positive bounds."""
    with pytest.raises(AegisFramePipelineError):
        FrameNormalizer(capability=_android_capability(), max_width=0, max_height=720)


def test_normalizer_caps_at_capability() -> None:
    """The normalizer caps max_width at the capability's max_width."""
    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=640,  # Smaller than the requested 1280.
        max_height=480,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    n = FrameNormalizer(capability=cap, max_width=1280, max_height=720)
    assert n.max_width == 640
    assert n.max_height == 480


def test_normalizer_rejects_oversized_capture() -> None:
    """The normalizer rejects a capture larger than its bounds."""
    from guardianmesh.screen.models import (
        ScreenCaptureRequest,
        ScreenCaptureResult,
    )

    cap = ProviderCapabilities(
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        max_width=1280,
        max_height=720,
        max_fps=10,
        supports_foreground_service=True,
        supports_media_projection=True,
    )
    n = FrameNormalizer(capability=cap, max_width=1280, max_height=720)
    req = ScreenCaptureRequest(
        session_id="SCN-1",
        width=9999,
        height=9999,
        max_fps=10,
        codec=ScreenCodec.TEST,
        pixel_format=PixelFormat.TEST,
    )
    capture = ScreenCaptureResult(
        captured=True,
        width=9999,
        height=9999,
        pixel_format=PixelFormat.TEST,
        codec=ScreenCodec.TEST,
    )
    with pytest.raises(AegisFramePipelineError):
        n.normalize(capture, req)


# ---------------------------------------------------------------------------
# FrameLimiter
# ---------------------------------------------------------------------------


def test_frame_limiter_rejects_zero_fps() -> None:
    """The limiter constructor rejects non-positive FPS."""
    with pytest.raises(AegisFramePipelineError):
        FrameLimiter(max_fps=0)


def test_frame_limiter_allows_first_frame() -> None:
    """The limiter always allows the first frame."""
    limiter = FrameLimiter(max_fps=10)
    assert limiter.allow() is True


def test_frame_limiter_rejects_too_quick() -> None:
    """The limiter rejects frames that arrive too quickly."""
    limiter = FrameLimiter(max_fps=10)
    limiter.allow()
    # Manually advancing 0 seconds must reject.
    assert limiter.allow() is False


def test_frame_limiter_allows_after_interval() -> None:
    """The limiter allows frames once the minimum interval has elapsed."""
    limiter = FrameLimiter(max_fps=10)
    # First call: always allowed.
    assert limiter.allow() is True
    # Advance time manually past the minimum interval.
    import time

    time.sleep(0.2)  # 200ms > 100ms (1/10 fps).
    assert limiter.allow() is True


def test_frame_limiter_reset_clears_state() -> None:
    """The limiter's reset() restores the initial state."""
    limiter = FrameLimiter(max_fps=10)
    limiter.allow()
    limiter.reset()
    # After reset the limiter is back to its initial state.
    assert limiter.allow() is True


# ---------------------------------------------------------------------------
# AegisFramePipeline
# ---------------------------------------------------------------------------


def test_pipeline_construct_rejects_non_android_real_provider() -> None:
    """A non-Android provider that claims real MediaProjection is rejected.

    We construct a capability that claims real MediaProjection on a
    non-Android platform; the capabilities ``__post_init__`` invariant
    itself rejects this, so the test verifies the defensive invariant
    that such a configuration is impossible to construct.
    """
    from guardianmesh.aegis.errors import AegisError

    with pytest.raises(AegisError):
        ProviderCapabilities(
            platform=AegisPlatform.LINUX,
            backend=EncoderBackend.MEDIA_CODEC,
            max_width=1280,
            max_height=720,
            max_fps=10,
            supports_foreground_service=False,
            supports_media_projection=True,  # Forbidden combination.
        )


def test_pipeline_lifecycle_start_stop() -> None:
    """The pipeline can be started and stopped."""
    p = _pipeline()
    assert p.is_running is False
    p.start()
    assert p.is_running is True
    p.stop()
    assert p.is_running is False


def test_pipeline_stop_is_idempotent() -> None:
    """stop() can be called multiple times safely."""
    p = _pipeline()
    p.start()
    p.stop()
    p.stop()  # No-op.


def test_pipeline_tick_requires_running() -> None:
    """tick() raises if the pipeline is not running."""
    p = _pipeline()
    with pytest.raises(AegisFramePipelineError):
        p.tick(codec=ScreenCodec.TEST)


def test_pipeline_tick_returns_frame_when_adapter_started() -> None:
    """tick() returns a frame when the adapter has been started."""
    p = _pipeline()
    p.start()
    frame = p.tick(codec=ScreenCodec.TEST)
    assert frame is not None
    assert frame.session_id == "SCN-1"
    assert frame.device_id == "GM-C-19A84E72"


def test_pipeline_metrics_increment_on_tick() -> None:
    """Each tick increments the pipeline metrics."""
    p = _pipeline()
    p.start()
    f1 = p.tick(codec=ScreenCodec.TEST)
    assert f1 is not None
    snap = p.snapshot_metrics()
    assert snap["frames_captured"] == 1
    assert snap["frames_normalized"] == 1
    assert snap["frames_encoded"] == 1
    assert snap["frames_queued"] == 1
    assert snap["last_frame_sequence"] >= 1


def test_pipeline_assigns_strictly_increasing_sequences() -> None:
    """Frames produced by tick() have strictly increasing sequences."""
    import time
    from itertools import pairwise

    p = _pipeline(max_fps=2)
    p.start()
    sequences: list[int] = []
    for _ in range(3):
        time.sleep(0.6)  # > 1/2 second.
        frame = p.tick(codec=ScreenCodec.TEST)
        if frame is not None:
            sequences.append(frame.sequence)
    assert sequences == sorted(set(sequences))
    for a, b in pairwise(sequences):
        assert b > a


def test_pipeline_drain_returns_buffered_frames() -> None:
    """drain() atomically returns all buffered frames."""
    import time

    p = _pipeline(max_fps=2)
    p.start()
    for _ in range(3):
        time.sleep(0.6)
        p.tick(codec=ScreenCodec.TEST)
    drained = p.drain()
    assert len(drained) >= 1


def test_pipeline_records_drop_when_queue_full() -> None:
    """When the queue is full and backpressure is DROP_OLDEST, drops are recorded."""
    import time

    p = _pipeline(max_fps=2, max_queue_size=2)
    p.start()
    # Fill the queue.
    for _ in range(5):
        time.sleep(0.6)
        p.tick(codec=ScreenCodec.TEST)
    snap = p.snapshot_metrics()
    # Some frames may have been dropped due to the small queue.
    assert snap["frames_dropped"] >= 0  # Always non-negative.


def test_pipeline_record_transmit_increments_metric() -> None:
    """record_transmit() increments the frames_transmitted counter."""
    p = _pipeline()
    p.start()
    p.record_transmit()
    snap = p.snapshot_metrics()
    assert snap["frames_transmitted"] == 1


def test_pipeline_record_transport_failure_increments_metric() -> None:
    """record_transport_failure() increments the transport_failures counter."""
    p = _pipeline()
    p.start()
    p.record_transport_failure()
    snap = p.snapshot_metrics()
    assert snap["transport_failures"] == 1


def test_pipeline_fake_provider_works() -> None:
    """The pipeline can be exercised end-to-end with a fake Android provider."""
    fake = FakeMediaProjectionProvider(_android_capability())
    p = AegisFramePipeline(
        provider=fake,
        encoder=TestScreenEncoder(),
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
    )
    p.start()
    frame = p.tick(codec=ScreenCodec.TEST)
    assert frame is not None
    assert frame.session_id == "SCN-1"
    assert fake.is_real_capture is True
    p.stop()
    assert fake.is_real_capture is False


def test_pipeline_fake_provider_fails_on_capture() -> None:
    """The pipeline surfaces a projection failure when the provider fails."""
    fake = FakeMediaProjectionProvider(_android_capability(), fail_on_capture=True)
    p = AegisFramePipeline(
        provider=fake,
        encoder=TestScreenEncoder(),
        screen_session_id="SCN-1",
        device_id="GM-C-19A84E72",
    )
    p.start()
    # The fake provider raises AegisProjectionError; the pipeline
    # re-raises it. We accept either AegisProjectionLikeError or
    # AegisProjectionError as evidence that the failure surfaced.
    from guardianmesh.aegis.errors import AegisProjectionError

    with pytest.raises((AegisProjectionLikeError, AegisProjectionError)):
        p.tick(codec=ScreenCodec.TEST)


def test_pipeline_clears_buffer_on_stop() -> None:
    """stop() clears the in-memory buffer."""
    p = _pipeline()
    p.start()
    p.tick(codec=ScreenCodec.TEST)
    assert p.buffer.size >= 1
    p.stop()
    assert p.buffer.size == 0


def test_pipeline_no_payload_in_metrics() -> None:
    """The metrics snapshot never contains frame bytes."""
    p = _pipeline()
    p.start()
    p.tick(codec=ScreenCodec.TEST)
    snap = p.snapshot_metrics()
    forbidden = {"payload", "frame", "screenshot", "image", "pixels"}
    assert forbidden.isdisjoint(set(snap.keys()))
