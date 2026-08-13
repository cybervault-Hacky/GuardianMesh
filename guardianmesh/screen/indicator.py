"""Android screen provider abstraction for the Vista Phase 7 subsystem.

The current GuardianMesh codebase is a Termux/Linux developer tool. It does
NOT — and cannot, from Python alone — capture the real Android screen.

This module defines :class:`AndroidScreenProvider`, an explicit
integration boundary. The default implementation,
:class:`AdapterOnlyScreenProvider`, is a clearly-marked adapter that
returns deterministic test frames and refuses to claim that any real
screen capture is active.

A future Android companion component (an APK) would implement the
:class:`AndroidScreenProvider` protocol. The companion must use Android's
``MediaProjection`` API with the user-visible consent dialog and must run
inside the child-side GuardianMesh agent (NOT a hidden service).

Strict rules:

* No root-only access. No hidden APIs. No system-level bypass.
* No attempt to suppress the system screen-capture indicator.
* The child must be able to see the active screen share and revoke it at
  any time (enforced by the :class:`ScreenIndicator` below).
"""

from __future__ import annotations

import hashlib
import secrets
from abc import ABC, abstractmethod
from typing import Any

from guardianmesh.screen.models import (
    PixelFormat,
    ScreenCaptureRequest,
    ScreenCaptureResult,
    ScreenCodec,
)


class AndroidScreenProvider(ABC):
    """Abstract integration boundary for an Android screen capture provider.

    Implementations must NEVER bypass the Android ``MediaProjection`` consent
    flow. Implementations must NEVER attempt to suppress the system
    screen-capture indicator. The provider is purely a *capture* boundary;
    the visible indicator is the responsibility of the companion UI, not
    this provider.
    """

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider can supply frames right now."""

    @property
    @abstractmethod
    def is_real_capture(self) -> bool:
        """Return True ONLY if the provider is producing real captured frames.

        Test/adapter implementations must return False.
        """

    @abstractmethod
    def capture(self, request: ScreenCaptureRequest) -> ScreenCaptureResult:
        """Capture a single frame according to the request.

        The provider must enforce the resolution and fps bounds declared in
        the request. The provider must never capture microphone, camera,
        clipboard, IME input, or notifications.
        """

    def diagnostics(self) -> dict[str, Any]:
        """Return a metadata-only diagnostic summary (NEVER frame content)."""
        return {
            "provider_class": self.__class__.__name__,
            "is_available": self.is_available,
            "is_real_capture": self.is_real_capture,
        }


class AdapterOnlyScreenProvider(AndroidScreenProvider):
    """Adapter-only screen provider that emits deterministic test frames.

    This implementation does NOT capture any real screen. It exists to make
    the end-to-end Vista pipeline testable on Termux and Linux without an
    Android companion component. It refuses any request that exceeds the
    documented resolution / fps bounds, and it always reports
    ``is_real_capture = False``.
    """

    def __init__(self, max_width: int = 1920, max_height: int = 1080, max_fps: int = 10) -> None:
        self._max_width = max_width
        self._max_height = max_height
        self._max_fps = max_fps
        # Sequence counter is local to the provider; frame-level sequencing
        # is handled in ScreenSession.
        self._counter = 0
        # Tiny in-memory salt so test frames are not bit-identical.
        self._salt = secrets.token_bytes(8)

    @property
    def is_available(self) -> bool:
        return True  # The adapter is always available for tests.

    @property
    def is_real_capture(self) -> bool:
        return False  # NEVER claim real capture.

    def capture(self, request: ScreenCaptureRequest) -> ScreenCaptureResult:
        if request.width > self._max_width or request.height > self._max_height:
            return ScreenCaptureResult(
                captured=False,
                width=0,
                height=0,
                pixel_format=request.pixel_format,
                codec=request.codec,
                payload=b"",
                note=(
                    f"Requested {request.width}x{request.height} exceeds adapter "
                    f"bounds {self._max_width}x{self._max_height}."
                ),
            )
        if request.max_fps > self._max_fps:
            return ScreenCaptureResult(
                captured=False,
                width=0,
                height=0,
                pixel_format=request.pixel_format,
                codec=request.codec,
                payload=b"",
                note=(
                    f"Requested max_fps {request.max_fps} exceeds adapter "
                    f"bound {self._max_fps}."
                ),
            )

        self._counter += 1
        # Deterministic synthetic payload. NEVER derived from any real screen.
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
                "AdapterOnlyScreenProvider synthetic frame. "
                "This is NOT a real Android screen capture. "
                "Android MediaProjection is required for production capture."
            ),
        )


class ScreenIndicator:
    """State model for the child-side visible screen-share indicator.

    The :class:`ScreenIndicator` is the only place that tracks whether the
    child UI should be displaying the on-screen warning. It is intentionally
    separate from the screen provider and from the session lifecycle so that
    *nothing* in the system can suppress it without being visible to the
    child.
    """

    def __init__(self) -> None:
        self._active = False
        self._session_id: str | None = None
        self._parent_label: str | None = None
        self._remaining_seconds: int = 0
        self._max_duration_seconds: int = 0
        self._started_at: str | None = None

    def activate(
        self,
        session_id: str,
        parent_label: str | None,
        max_duration_seconds: int,
        started_at: str,
    ) -> None:
        """Mark the indicator as active. Idempotent per session."""
        self._active = True
        self._session_id = session_id
        self._parent_label = parent_label
        self._max_duration_seconds = max_duration_seconds
        self._remaining_seconds = max_duration_seconds
        self._started_at = started_at

    def deactivate(self) -> None:
        """Immediately deactivate the indicator."""
        self._active = False
        self._session_id = None
        self._parent_label = None
        self._remaining_seconds = 0
        self._max_duration_seconds = 0
        self._started_at = None

    def update_remaining(self, remaining_seconds: int) -> None:
        self._remaining_seconds = max(0, int(remaining_seconds))

    @property
    def is_active(self) -> bool:
        return self._active

    def render(self) -> str:
        """Return a fixed-width text representation of the indicator."""
        if not self._active:
            return "SCREEN VIEW INACTIVE"
        lines = [
            "┌──────────────────────────────────┐",
            "│ GuardianMesh                     │",
            "│                                  │",
            "│  ● SCREEN VIEW ACTIVE            │",
            "│                                  │",
            f"│  Parent: {self._parent_label or 'Guardian':<22} │",
            f"│  Session: {self._format_remaining():<20} │",
            "│                                  │",
            "│       [ STOP SHARING ]            │",
            "└──────────────────────────────────┘",
        ]
        return "\n".join(lines)

    def _format_remaining(self) -> str:
        secs = self._remaining_seconds
        mins, s = divmod(max(0, secs), 60)
        return f"{mins:02d}:{s:02d} remaining"


__all__ = [
    "AdapterOnlyScreenProvider",
    "AndroidScreenProvider",
    "ScreenIndicator",
]


# Defensive: re-export a small union of the most common request/result types
# so callers can import them from this module without depending on models.
_ = (ScreenCaptureRequest, ScreenCaptureResult, ScreenCodec, PixelFormat)
