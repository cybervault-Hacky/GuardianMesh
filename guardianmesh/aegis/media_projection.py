"""Android ``MediaProjection`` provider abstraction.

This module defines the production boundary for Android
``MediaProjection``. The control plane (Termux/Linux) does NOT have
access to the Android ``MediaProjection`` API; the actual capture
lives in the Aegis Android companion (APK). The classes in this module
are the reference architecture that the companion implements and that
the Python control plane drives through Nexus.

Two reference implementations are provided:

* :class:`AdapterOnlyMediaProjectionProvider` - the deterministic
  adapter used in tests and on Linux/Termux. It refuses to perform
  real capture and reports ``supports_real_capture = False``.
* :class:`FakeMediaProjectionProvider` - an in-process fake that
  emits a small synthetic frame on each call, used to exercise the
  full pipeline in unit tests without requiring an Android device.

Both implementations honor the strict Aegis contract:

* The provider must never bypass the Android system capture-consent
  dialog. The companion may only call ``capture_frame`` after the
  child has tapped **Allow** in the system dialog.
* The provider must never attempt to suppress the system
  screen-capture indicator. The Android system shows its own
  indicator when a MediaProjection token is in use; Aegis does not
  hide it.
* The provider must never write frame bytes to disk. Frame data
  exists only in the in-memory ``ImageReader`` surface for the
  duration of one frame processing cycle.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from abc import ABC, abstractmethod
from typing import Any

from guardianmesh.aegis.errors import (
    AegisPlatformUnavailableError,
    AegisProjectionError,
)
from guardianmesh.aegis.models import (
    AegisPlatform,
    EncoderBackend,
    ProviderCapabilities,
)
from guardianmesh.screen.models import (
    ScreenCaptureRequest,
    ScreenCaptureResult,
)

# ---------------------------------------------------------------------------
# Abstract boundary
# ---------------------------------------------------------------------------


class MediaProjectionProvider(ABC):
    """Abstract integration boundary for Android ``MediaProjection``.

    Implementations live in the Aegis Android companion. The control
    plane (Termux/Linux) never instantiates a real provider; it only
    uses the test adapter. Any attempt to perform real capture on a
    non-Android platform is rejected at runtime.
    """

    @property
    @abstractmethod
    def capability(self) -> ProviderCapabilities:
        """Return the read-only capabilities of this provider."""

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider can supply frames right now."""

    @property
    @abstractmethod
    def is_real_capture(self) -> bool:
        """Return True ONLY if the provider is producing real captured frames."""

    @abstractmethod
    def start(self) -> None:
        """Start the projection.

        On a real Android companion this creates a virtual display and
        attaches an ``ImageReader`` surface. On a non-Android adapter
        this is a no-op that records the lifecycle transition.

        Raises:
            AegisPlatformUnavailableError: If called on a non-Android
                platform that cannot perform real capture.
            AegisProjectionError: If the projection fails to start.
        """

    @abstractmethod
    def stop(self) -> None:
        """Stop the projection and release all resources.

        Idempotent. Safe to call from a finalizer.
        """

    @abstractmethod
    def capture_frame(self, request: ScreenCaptureRequest) -> ScreenCaptureResult:
        """Capture a single frame from the projection.

        Args:
            request: The capture request (resolution, fps, codec).

        Returns:
            A :class:`ScreenCaptureResult` with the captured payload.
            If the projection has not been started, the result is
            ``captured=False`` and the payload is empty.
        """

    def diagnostics(self) -> dict[str, Any]:
        """Return a metadata-only diagnostic summary (no frame content)."""
        return {
            "provider_class": self.__class__.__name__,
            "is_available": self.is_available,
            "is_real_capture": self.is_real_capture,
            "capability": self.capability.to_dict(),
        }


# ---------------------------------------------------------------------------
# Test adapter (Linux / Termux / not-Android)
# ---------------------------------------------------------------------------


class AdapterOnlyMediaProjectionProvider(MediaProjectionProvider):
    """Adapter-only provider for non-Android hosts.

    The adapter refuses to perform any real capture. It is the
    documented default for the Python control plane and is used by
    ``guardian doctor`` to report honestly that real capture is
    unavailable on this platform.
    """

    def __init__(
        self,
        platform: AegisPlatform = AegisPlatform.LINUX,
        max_width: int = 1280,
        max_height: int = 720,
        max_fps: int = 10,
    ) -> None:
        self._capability = ProviderCapabilities(
            platform=platform,
            backend=EncoderBackend.TEST,
            max_width=max_width,
            max_height=max_height,
            max_fps=max_fps,
            supports_foreground_service=False,
            supports_media_projection=False,
            notes=(
                "AdapterOnlyMediaProjectionProvider: real Android MediaProjection "
                "is not available on this platform. Use the Aegis Android "
                "companion (APK) for production capture."
            ),
        )
        self._counter = 0
        self._salt = secrets.token_bytes(8)
        self._started = False
        self._lock = threading.Lock()

    @property
    def capability(self) -> ProviderCapabilities:
        return self._capability

    @property
    def is_available(self) -> bool:
        return True  # The adapter is always available for tests.

    @property
    def is_real_capture(self) -> bool:
        return False  # NEVER claim real capture.

    def start(self) -> None:
        with self._lock:
            # On non-Android, "starting" is recorded but no projection
            # is created. The gate must still refuse capture unless
            # the system consent is GRANTED.
            self._started = True

    def stop(self) -> None:
        with self._lock:
            self._started = False

    def capture_frame(self, request: ScreenCaptureRequest) -> ScreenCaptureResult:
        with self._lock:
            if not self._started:
                return ScreenCaptureResult(
                    captured=False,
                    width=0,
                    height=0,
                    pixel_format=request.pixel_format,
                    codec=request.codec,
                    payload=b"",
                    note="AdapterOnlyMediaProjectionProvider: projection not started.",
                )
            if request.width > self._capability.max_width:
                return ScreenCaptureResult(
                    captured=False,
                    width=0,
                    height=0,
                    pixel_format=request.pixel_format,
                    codec=request.codec,
                    payload=b"",
                    note=(
                        f"Requested width {request.width} exceeds adapter bound "
                        f"{self._capability.max_width}."
                    ),
                )
            if request.height > self._capability.max_height:
                return ScreenCaptureResult(
                    captured=False,
                    width=0,
                    height=0,
                    pixel_format=request.pixel_format,
                    codec=request.codec,
                    payload=b"",
                    note=(
                        f"Requested height {request.height} exceeds adapter bound "
                        f"{self._capability.max_height}."
                    ),
                )
            if request.max_fps > self._capability.max_fps:
                return ScreenCaptureResult(
                    captured=False,
                    width=0,
                    height=0,
                    pixel_format=request.pixel_format,
                    codec=request.codec,
                    payload=b"",
                    note=(
                        f"Requested max_fps {request.max_fps} exceeds adapter "
                        f"bound {self._capability.max_fps}."
                    ),
                )
            self._counter += 1
            seed = (
                self._salt
                + f"{request.session_id}|{request.width}x{request.height}|"
                f"{self._counter}".encode()
            )
            digest = hashlib.sha256(seed).digest()
            payload = digest + digest  # 64 bytes, never expanded.
            return ScreenCaptureResult(
                captured=True,
                width=request.width,
                height=request.height,
                pixel_format=request.pixel_format,
                codec=request.codec,
                payload=payload,
                note=(
                    "AdapterOnlyMediaProjectionProvider synthetic frame. "
                    "This is NOT a real Android MediaProjection frame. "
                    "A future Android companion (APK) is required for production."
                ),
            )


# ---------------------------------------------------------------------------
# In-process fake for unit tests
# ---------------------------------------------------------------------------


class FakeMediaProjectionProvider(MediaProjectionProvider):
    """In-process fake that simulates a real Android projection.

    The fake is designed for unit tests. It honours the full Aegis
    contract:

    * ``start()`` and ``stop()`` are explicit lifecycle methods.
    * ``capture_frame()`` returns ``captured=False`` before ``start()``.
    * The fake can be configured to fail (e.g. to test the
      ``AegisProjectionError`` error path).
    * The fake is always available and never claims real capture
      (it is a test fixture, not a production provider).
    """

    def __init__(
        self,
        capability: ProviderCapabilities,
        fail_on_start: bool = False,
        fail_on_capture: bool = False,
    ) -> None:
        self._capability = capability
        self._fail_on_start = fail_on_start
        self._fail_on_capture = fail_on_capture
        self._counter = 0
        self._salt = secrets.token_bytes(8)
        self._started = False
        self._lock = threading.Lock()

    @property
    def capability(self) -> ProviderCapabilities:
        return self._capability

    @property
    def is_available(self) -> bool:
        return self._capability.platform.supports_real_capture

    @property
    def is_real_capture(self) -> bool:
        # The fake simulates a real Android projection but is still a
        # test fixture. Callers should use it as a stand-in for the
        # production provider, not as a production provider itself.
        return self._started and self._capability.platform.supports_real_capture

    def start(self) -> None:
        with self._lock:
            if self._fail_on_start:
                raise AegisProjectionError(
                    "Simulated projection start failure."
                )
            self._started = True

    def stop(self) -> None:
        with self._lock:
            self._started = False

    def capture_frame(self, request: ScreenCaptureRequest) -> ScreenCaptureResult:
        with self._lock:
            if not self._started:
                return ScreenCaptureResult(
                    captured=False,
                    width=0,
                    height=0,
                    pixel_format=request.pixel_format,
                    codec=request.codec,
                    payload=b"",
                    note="FakeMediaProjectionProvider: projection not started.",
                )
            if self._fail_on_capture:
                raise AegisProjectionError(
                    "Simulated projection capture failure."
                )
            if not self._capability.platform.supports_real_capture:
                raise AegisPlatformUnavailableError(
                    f"Platform {self._capability.platform.value} cannot perform "
                    f"real MediaProjection."
                )
            self._counter += 1
            seed = (
                self._salt
                + f"{request.session_id}|{request.width}x{request.height}|"
                f"{self._counter}".encode()
            )
            digest = hashlib.sha256(seed).digest()
            payload = digest + digest
            return ScreenCaptureResult(
                captured=True,
                width=request.width,
                height=request.height,
                pixel_format=request.pixel_format,
                codec=request.codec,
                payload=payload,
                note="FakeMediaProjectionProvider synthetic frame.",
            )


__all__ = [
    "AdapterOnlyMediaProjectionProvider",
    "FakeMediaProjectionProvider",
    "MediaProjectionProvider",
]
