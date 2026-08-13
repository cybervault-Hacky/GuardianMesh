"""Child-side visible indicator model for the Android companion.

Aegis requires that the Android companion shows a persistent foreground
service notification for the entire duration of an active capture
session. The notification is the child-side counterpart of the
Phase 7 :class:`ScreenIndicator` text banner; it is the user-visible
affordance on Android.

The notification model is purely declarative. The actual Android
``Notification`` object is built in the companion. The Python control
plane uses this module to:

* Verify that the notification would be displayed (e.g. in tests).
* Provide a single source of truth for the indicator's title, body,
  and ``STOP SHARING`` action label.
* Detect attempts to suppress or hide the indicator.

The indicator is an invariant of Aegis. It MUST be visible for every
active capture session. There is no programmatic way to hide it
through this module; the only way to remove it is to call
:meth:`ForegroundServiceIndicator.stop`, which corresponds to ending
the active capture session.
"""

from __future__ import annotations

import secrets
import threading
from typing import Any

from guardianmesh.aegis.errors import (
    AegisForegroundServiceError,
    AegisPlatformUnavailableError,
)
from guardianmesh.aegis.models import (
    ForegroundServiceNotification,
    ProviderCapabilities,
)


class ForegroundServiceIndicator:
    """State model for the Android companion's foreground service indicator.

    The indicator is a state object, not a UI element. The Android
    companion is responsible for actually displaying the notification;
    the Python control plane only verifies that the indicator is in
    the *active* state while a capture session is in the *capturing*
    phase.

    The class refuses to operate on a platform that does not support
    real Android foreground services. This is a documented boundary,
    not a runtime error to be silenced.
    """

    def __init__(
        self,
        capability: ProviderCapabilities,
        notification: ForegroundServiceNotification | None = None,
    ) -> None:
        self._capability = capability
        self._notification = notification or ForegroundServiceNotification()
        self._active = False
        self._session_id: str | None = None
        self._parent_label: str | None = None
        self._started_at: str | None = None
        self._lock = threading.RLock()

    @property
    def capability(self) -> ProviderCapabilities:
        return self._capability

    @property
    def notification(self) -> ForegroundServiceNotification:
        return self._notification

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._active

    @property
    def session_id(self) -> str | None:
        with self._lock:
            return self._session_id

    def start(
        self,
        session_id: str,
        parent_label: str | None,
    ) -> None:
        """Mark the indicator as active.

        Raises:
            AegisPlatformUnavailableError: If the platform does not
                support foreground services.
            AegisForegroundServiceError: If the indicator is already
                active for a different session.
        """
        if not self._capability.supports_foreground_service:
            if not self._capability.platform.supports_real_capture:
                raise AegisPlatformUnavailableError(
                    f"Platform {self._capability.platform.value} does not support "
                    f"foreground services. The Android companion (APK) is required."
                )
        with self._lock:
            if self._active and self._session_id and self._session_id != session_id:
                raise AegisForegroundServiceError(
                    f"Indicator already active for session '{self._session_id}'."
                )
            self._active = True
            self._session_id = session_id
            self._parent_label = parent_label
            self._started_at = _now_iso()

    def stop(self) -> None:
        """Mark the indicator as inactive. Idempotent."""
        with self._lock:
            self._active = False
            self._session_id = None
            self._parent_label = None
            self._started_at = None

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "is_active": self._active,
                "session_id": self._session_id,
                "parent_label": self._parent_label,
                "started_at": self._started_at,
                "notification": self._notification.to_dict(),
                "platform": self._capability.platform.value,
                "supports_foreground_service": self._capability.supports_foreground_service,
            }


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO format."""
    import datetime

    return datetime.datetime.now(datetime.UTC).isoformat()


def default_linux_indicator() -> ForegroundServiceIndicator:
    """Return an indicator configured for a Linux/Termux development host.

    The indicator refuses to start on this platform. It exists for the
    unit suite and for ``guardian doctor`` to report the platform
    limitation honestly.
    """
    from guardianmesh.aegis.consent import default_linux_capability

    return ForegroundServiceIndicator(capability=default_linux_capability())


# Sentinel token used by the unit suite to verify that the indicator
# is bound to a unique session each time it is started.
def new_indicator_session_token() -> str:
    """Generate a unique token for an indicator session."""
    return secrets.token_hex(8)


__all__ = [
    "ForegroundServiceIndicator",
    "default_linux_indicator",
    "new_indicator_session_token",
]
