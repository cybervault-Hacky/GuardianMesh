"""Orion Phase 9 device capability registry.

The :class:`OrionCapabilityRegistry` records per-device capabilities
and exposes them to the rest of Orion. Capabilities are stored
in-memory by default; the registry can be persisted to the database
through :class:`guardianmesh.orion.registry.OrionRegistry`.
"""

from __future__ import annotations

import threading
from typing import Any

from guardianmesh.orion.errors import OrionCapabilityError
from guardianmesh.orion.models import (
    DEFAULT_CONTROL_PLANE_CAPABILITIES,
    OrionCapability,
    OrionDeviceCapabilities,
)


class OrionCapabilityRegistry:
    """In-memory registry of per-device capabilities.

    The registry is thread-safe. Negative-default capabilities
    (microphone, camera, remote input, etc.) are ALWAYS False; the
    registry refuses to record them as True.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, OrionDeviceCapabilities] = {}
        # Pre-populate with the control-plane profile.
        self._records["ORION"] = self._build_default_control_plane_profile()

    @staticmethod
    def _build_default_control_plane_profile() -> OrionDeviceCapabilities:
        """Construct the control-plane profile from the documented defaults.

        The :func:`OrionDeviceCapabilities.discover` factory uses lowercase
        parameter names (e.g. ``health_telemetry=``), so we map the
        uppercase enum values to the lowercase kwargs explicitly.
        """
        from guardianmesh.orion.models import OrionDeviceCapabilities as _Caps

        return _Caps.discover(
            "ORION",
            health_telemetry=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.HEALTH_TELEMETRY],
            policies=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.POLICIES],
            alerts=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.ALERTS],
            secure_transport=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.SECURE_TRANSPORT],
            screen_session=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.SCREEN_SESSION],
            system_consent=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.SYSTEM_CONSENT],
            orchestration=DEFAULT_CONTROL_PLANE_CAPABILITIES[OrionCapability.ORCHESTRATION],
            source="default-control-plane",
        )

    def register(
        self,
        capabilities: OrionDeviceCapabilities,
    ) -> None:
        """Register or replace the capabilities for a device."""
        if not isinstance(capabilities, OrionDeviceCapabilities):
            raise OrionCapabilityError("capabilities must be an OrionDeviceCapabilities.")
        with self._lock:
            self._records[capabilities.device_id] = capabilities

    def get(self, device_id: str) -> OrionDeviceCapabilities | None:
        with self._lock:
            return self._records.get(device_id)

    def require(self, device_id: str) -> OrionDeviceCapabilities:
        """Return the capabilities for a device or raise an error."""
        caps = self.get(device_id)
        if caps is None:
            raise OrionCapabilityError(
                f"Unknown device '{device_id}'. No capabilities recorded."
            )
        return caps

    def all(self) -> list[OrionDeviceCapabilities]:
        with self._lock:
            return list(self._records.values())

    def device_ids(self) -> list[str]:
        with self._lock:
            return list(self._records.keys())

    def supports(
        self, device_id: str, capability: OrionCapability | str
    ) -> bool:
        """Return True if the device explicitly supports the capability."""
        caps = self.get(device_id)
        if caps is None:
            return False
        return caps.supports(capability)

    def set_capability(
        self,
        device_id: str,
        capability: OrionCapability | str,
        enabled: bool,
    ) -> None:
        """Enable or disable a capability for a device."""
        with self._lock:
            caps = self._records.get(device_id)
            if caps is None:
                caps = OrionDeviceCapabilities.discover(
                    device_id,
                    source="explicit-discovery",
                )
                self._records[device_id] = caps
            if enabled:
                caps.enable(capability)
            else:
                caps.disable(capability)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            # Re-add the control-plane profile.
            self._records["ORION"] = self._build_default_control_plane_profile()

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "device_count": len(self._records),
                "positive_capability_count": sum(
                    len(c.positive_capabilities()) for c in self._records.values()
                ),
                "negative_capability_count": sum(
                    len(c.negative_capabilities()) for c in self._records.values()
                ),
            }


__all__ = ["OrionCapabilityRegistry"]
