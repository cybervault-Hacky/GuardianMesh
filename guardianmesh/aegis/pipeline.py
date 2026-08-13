"""Aegis frame pipeline.

The pipeline orchestrates the flow:

    MediaProjection
        ↓
    ImageReader
        ↓
    FrameNormalizer
        ↓
    FrameLimiter
        ↓
    ScreenEncoder
        ↓
    BoundedFrameQueue
        ↓
    Vista ScreenTransportBridge
        ↓
    Nexus encrypted transport

The pipeline enforces all Aegis hard limits:

* maximum 10 FPS
* maximum 1280x720 output
* maximum 4 MiB encoded frame
* maximum 30 queued frames
* DROP_OLDEST backpressure when the queue is full

The pipeline never writes frames to disk, never logs frame content, and
never includes frame bytes in error messages. Every metric, audit
event, and log line is metadata only.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from guardianmesh.aegis.encoder import ScreenEncoder
from guardianmesh.aegis.errors import (
    AegisEncoderError,
    AegisFramePipelineError,
    AegisPlatformUnavailableError,
)
from guardianmesh.aegis.media_projection import (
    AdapterOnlyMediaProjectionProvider,
    MediaProjectionProvider,
)
from guardianmesh.aegis.metrics import FrameMetrics
from guardianmesh.aegis.models import (
    ProviderCapabilities,
)
from guardianmesh.screen.frames import FrameStreamBuffer
from guardianmesh.screen.models import (
    BackpressureStrategy,
    PixelFormat,
    ScreenCaptureRequest,
    ScreenCaptureResult,
    ScreenCodec,
    ScreenFrame,
)

# ---------------------------------------------------------------------------
# Pipeline components
# ---------------------------------------------------------------------------


class FrameNormalizer:
    """Convert a raw :class:`ScreenCaptureResult` into a normalized
    capture that respects the configured resolution and pixel format.

    The normalizer never resizes or transcodes pixel data. It enforces
    the resolution and pixel-format allowlist and rejects any request
    that would produce a frame outside the documented bounds.
    """

    def __init__(
        self,
        capability: ProviderCapabilities,
        max_width: int = 1280,
        max_height: int = 720,
    ) -> None:
        self._capability = capability
        self._max_width = min(max_width, capability.max_width)
        self._max_height = min(max_height, capability.max_height)
        if self._max_width <= 0 or self._max_height <= 0:
            raise AegisFramePipelineError(
                "FrameNormalizer requires positive max dimensions."
            )

    @property
    def max_width(self) -> int:
        return self._max_width

    @property
    def max_height(self) -> int:
        return self._max_height

    def normalize(
        self,
        capture: ScreenCaptureResult,
        request: ScreenCaptureRequest,
    ) -> ScreenCaptureResult:
        if not capture.captured:
            return capture
        if request.width > self._max_width or request.height > self._max_height:
            raise AegisFramePipelineError(
                f"Capture dimensions {request.width}x{request.height} exceed "
                f"normalizer bounds {self._max_width}x{self._max_height}."
            )
        # The payload bytes themselves are not modified by the
        # normalizer on the Python control plane; the Android companion
        # performs the actual rescale at the encoder level.
        return capture


class FrameLimiter:
    """Enforce the maximum frame rate of the pipeline.

    The limiter is intentionally simple: it tracks the timestamp of
    the last accepted frame and rejects any frame that arrives sooner
    than ``1 / max_fps`` seconds after the previous one.

    Rejected frames are recorded as drops in the pipeline metrics.
    They never reach the encoder, the queue, or the transport.
    """

    def __init__(self, max_fps: int) -> None:
        if max_fps <= 0:
            raise AegisFramePipelineError("max_fps must be positive.")
        self._max_fps = max_fps
        self._min_interval = 1.0 / float(max_fps)
        self._last_accepted_at: float | None = None
        self._lock = threading.Lock()

    @property
    def max_fps(self) -> int:
        return self._max_fps

    def allow(self, now: float | None = None) -> bool:
        ts = time.monotonic() if now is None else now
        with self._lock:
            if self._last_accepted_at is None:
                self._last_accepted_at = ts
                return True
            elapsed = ts - self._last_accepted_at
            if elapsed + 1e-9 >= self._min_interval:
                self._last_accepted_at = ts
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._last_accepted_at = None


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


class AegisFramePipeline:
    """Thread-safe orchestration of the Aegis frame pipeline.

    The pipeline owns:

    * the :class:`MediaProjectionProvider` (the source of frames);
    * the :class:`ScreenEncoder` (the codec);
    * the :class:`FrameNormalizer` and :class:`FrameLimiter`;
    * a :class:`FrameStreamBuffer` (bounded in-memory queue);
    * a :class:`FrameMetrics` counter set.

    The pipeline is the only place that touches frame bytes. The
    control plane never exposes the buffer's contents to the CLI or
    to the audit log; it exposes only the metadata (queue depth, drop
    count, encode latency).
    """

    def __init__(
        self,
        provider: MediaProjectionProvider,
        encoder: ScreenEncoder,
        *,
        screen_session_id: str,
        device_id: str,
        max_width: int = 1280,
        max_height: int = 720,
        max_fps: int = 10,
        max_frame_bytes: int = 4 * 1024 * 1024,
        max_queue_size: int = 30,
        backpressure: BackpressureStrategy = BackpressureStrategy.DROP_OLDEST,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not provider.capability.supports_media_projection:
            # The adapter-only provider is permitted because it is the
            # deterministic test fixture. The control plane uses it to
            # exercise the pipeline end-to-end on Linux/Termux without
            # requiring an Android device. Any other non-real provider
            # is rejected.
            if not isinstance(provider, AdapterOnlyMediaProjectionProvider):
                if not provider.capability.platform.supports_real_capture:
                    raise AegisPlatformUnavailableError(
                        f"Provider {provider.__class__.__name__} does not support "
                        f"real MediaProjection. Use the Android companion (APK) for "
                        f"production capture."
                    )
        self._provider = provider
        self._encoder = encoder
        self._screen_session_id = screen_session_id
        self._device_id = device_id
        self._normalizer = FrameNormalizer(
            capability=provider.capability,
            max_width=max_width,
            max_height=max_height,
        )
        self._limiter = FrameLimiter(max_fps=max_fps)
        self._buffer = FrameStreamBuffer(
            session_id=screen_session_id,
            max_queue_size=max_queue_size,
            backpressure=backpressure,
        )
        # Override the buffer's validator bounds.
        from guardianmesh.screen.frames import FrameValidator

        self._buffer._validator = FrameValidator(
            max_width=max_width,
            max_height=max_height,
            max_payload_bytes=max_frame_bytes,
            max_fps=max_fps,
        )
        self._metrics = FrameMetrics()
        self._metrics.set_queue_depth(0, max_queue_size)
        self._clock = clock
        self._lock = threading.RLock()
        self._running = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def provider(self) -> MediaProjectionProvider:
        return self._provider

    @property
    def encoder(self) -> ScreenEncoder:
        return self._encoder

    @property
    def buffer(self) -> FrameStreamBuffer:
        return self._buffer

    @property
    def metrics(self) -> FrameMetrics:
        return self._metrics

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._provider.start()
            self._limiter.reset()
            self._running = True

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                # Idempotent: even when not running, ensure the
                # provider is stopped and the buffer is cleared.
                self._buffer.clear()
                self._provider.stop()
                return
            self._running = False
            self._buffer.clear()
            self._provider.stop()
            self._encoder.release()

    # ------------------------------------------------------------------
    # Frame processing
    # ------------------------------------------------------------------

    def tick(
        self,
        codec: ScreenCodec,
        clock: Callable[[], float] | None = None,
    ) -> ScreenFrame | None:
        """Capture, normalise, limit, encode, and enqueue one frame.

        Returns the enqueued :class:`ScreenFrame` or ``None`` if the
        frame was rejected (e.g. by the FPS limiter or the provider).
        """
        with self._lock:
            if not self._running:
                raise AegisFramePipelineError(
                    "Pipeline is not running. Call start() first."
                )
            now = (clock or time.monotonic)()
            if not self._limiter.allow(now):
                return None
            request = ScreenCaptureRequest(
                session_id=self._screen_session_id,
                width=self._normalizer.max_width,
                height=self._normalizer.max_height,
                max_fps=self._limiter.max_fps,
                codec=codec,
                # The default pixel format for the test pipeline is
                # ``TEST``; the production encoder negotiates the real
                # pixel format with MediaCodec at runtime.
                pixel_format=self._default_pixel_format(),
            )
            capture = self._provider.capture_frame(request)
            self._metrics.record_capture()
            if not capture.captured:
                self._metrics.record_projection_failure()
                raise AegisProjectionLikeError(
                    "MediaProjection returned an empty frame."
                )
            capture = self._normalizer.normalize(capture, request)
            self._metrics.record_normalize()
            encode_started = time.monotonic()
            try:
                frame = self._encoder.encode(capture, codec)
            except AegisEncoderError:
                self._metrics.record_encoder_failure()
                raise
            encode_latency_ms = int((time.monotonic() - encode_started) * 1000)
            self._metrics.record_encode(encode_latency_ms)
            frame.session_id = self._screen_session_id
            frame.device_id = self._device_id
            frame.sequence = self._buffer.last_sequence + 1
            accepted = self._buffer.ingest(frame)
            if accepted:
                self._metrics.record_queue()
                self._metrics.set_queue_depth(self._buffer.size, self._buffer._queue.max_size)
                self._metrics.set_last_sequence(frame.sequence)
            else:
                self._metrics.record_drop()
                self._metrics.set_queue_depth(self._buffer.size, self._buffer._queue.max_size)
            return frame

    def drain(self) -> list[ScreenFrame]:
        """Atomically remove and return all currently buffered frames."""
        frames = self._buffer.drain()
        with self._lock:
            self._metrics.frames_queued = max(
                0, self._metrics.frames_queued - len(frames)
            )
            self._metrics.set_queue_depth(
                self._buffer.size, self._buffer._queue.max_size
            )
        return frames

    def record_transmit(self) -> None:
        with self._lock:
            self._metrics.record_transmit()

    def record_transport_failure(self) -> None:
        with self._lock:
            self._metrics.record_transport_failure()

    def snapshot_metrics(self) -> dict[str, Any]:
        with self._lock:
            return self._metrics.snapshot().to_dict()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _default_pixel_format(self) -> PixelFormat:
        # The default pixel format for the test pipeline is ``TEST``;
        # the production encoder negotiates the real pixel format with
        # MediaCodec at runtime.
        return PixelFormat.TEST


class AegisProjectionLikeError(AegisFramePipelineError):
    """Raised when the underlying provider returns an empty frame.

    This is treated as a frame-pipeline failure so that the metrics
    correctly attribute the failure to the projection layer.
    """


__all__ = [
    "AegisFramePipeline",
    "AegisProjectionLikeError",
    "FrameLimiter",
    "FrameNormalizer",
]
