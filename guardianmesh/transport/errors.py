"""Transport domain exceptions for GuardianMesh Phase 6 (Nexus)."""

from __future__ import annotations

from guardianmesh.core.errors import (
    TransportAuthenticationError,
    TransportConnectionClosedError,
    TransportError,
    TransportFramingError,
    TransportHandshakeError,
    TransportMessageError,
    TransportOversizedMessageError,
    TransportPayloadError,
    TransportReplayError,
    TransportRevokedError,
    TransportSequenceError,
    TransportSessionExpiredError,
    TransportStateError,
    TransportTimeoutError,
)

__all__ = [
    "TransportAuthenticationError",
    "TransportConnectionClosedError",
    "TransportError",
    "TransportFramingError",
    "TransportHandshakeError",
    "TransportMessageError",
    "TransportOversizedMessageError",
    "TransportPayloadError",
    "TransportReplayError",
    "TransportRevokedError",
    "TransportSequenceError",
    "TransportSessionExpiredError",
    "TransportStateError",
    "TransportTimeoutError",
]
