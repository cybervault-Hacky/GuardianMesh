"""GuardianMesh Atlas Phase 10 capability registry.

The :class:`AtlasCapabilityRegistry` records versioned capability
descriptors for every GuardianMesh subsystem. Capabilities are
informational; they are never inferred from the platform.

Atlas capabilities are SEPARATE from the existing
:class:`guardianmesh.orion.capabilities.OrionCapabilityRegistry`.
The Atlas registry adds version, status, security classification,
and authorization requirements.
"""

from __future__ import annotations

import threading
from typing import Any

from guardianmesh.atlas.errors import AtlasCapabilityError
from guardianmesh.atlas.models import (
    AtlasCapabilityVersion,
    AtlasSecurityLevel,
)

# Default capability descriptors for every documented GuardianMesh
# subsystem. Each subsystem is a single capability with version
# 1.0, ACTIVE status, and LOW risk.
DEFAULT_ATLAS_CAPABILITIES: tuple[AtlasCapabilityVersion, ...] = (
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-GENESIS",
        capability_name="genesis",
        version="1.0",
        status="ACTIVE",
        requires_trust=False,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.LOW,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-LINK",
        capability_name="link",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.MEDIUM,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-PULSE",
        capability_name="pulse",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.MEDIUM,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-SENTINEL",
        capability_name="sentinel",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.MEDIUM,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-CONSOLE",
        capability_name="console",
        version="1.0",
        status="ACTIVE",
        requires_trust=False,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.LOW,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-NEXUS",
        capability_name="nexus",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.MEDIUM,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-VISTA",
        capability_name="vista",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=True,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.HIGH,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-AEGIS",
        capability_name="aegis",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=True,
        requires_aegis=True,
        risk_level=AtlasSecurityLevel.CRITICAL,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-ORION",
        capability_name="orion",
        version="1.0",
        status="ACTIVE",
        requires_trust=True,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.MEDIUM,
    ),
    AtlasCapabilityVersion(
        capability_id="ATL-CAP-ATLAS",
        capability_name="atlas",
        version="1.0",
        status="ACTIVE",
        requires_trust=False,
        requires_vista=False,
        requires_aegis=False,
        risk_level=AtlasSecurityLevel.LOW,
    ),
)


class AtlasCapabilityRegistry:
    """In-memory registry of versioned capability descriptors."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, AtlasCapabilityVersion] = {}
        for cap in DEFAULT_ATLAS_CAPABILITIES:
            self._records[cap.capability_id] = cap

    def register(self, cap: AtlasCapabilityVersion) -> None:
        if not isinstance(cap, AtlasCapabilityVersion):
            raise AtlasCapabilityError("cap must be an AtlasCapabilityVersion.")
        with self._lock:
            self._records[cap.capability_id] = cap

    def get(self, capability_id: str) -> AtlasCapabilityVersion | None:
        with self._lock:
            return self._records.get(capability_id)

    def all(self) -> list[AtlasCapabilityVersion]:
        with self._lock:
            return list(self._records.values())

    def known(self, capability_id: str) -> bool:
        with self._lock:
            return capability_id in self._records

    def supports(self, capability_id: str) -> bool:
        cap = self.get(capability_id)
        if cap is None:
            return False
        return cap.status == "ACTIVE"

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return {
                "capability_count": len(self._records),
                "active": sum(1 for c in self._records.values() if c.status == "ACTIVE"),
                "deprecated": sum(
                    1 for c in self._records.values() if c.status == "DEPRECATED"
                ),
                "experimental": sum(
                    1 for c in self._records.values() if c.status == "EXPERIMENTAL"
                ),
            }


__all__ = [
    "DEFAULT_ATLAS_CAPABILITIES",
    "AtlasCapabilityRegistry",
]
