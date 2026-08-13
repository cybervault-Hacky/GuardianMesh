"""Identity management for GuardianMesh: models, generation, and validation."""

from __future__ import annotations

from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import (
    IDENTITY_REGEX,
    Identity,
    IdentityRole,
    parse_identity_role,
    validate_identity_id,
)

__all__ = [
    "IDENTITY_REGEX",
    "Identity",
    "IdentityManager",
    "IdentityRole",
    "parse_identity_role",
    "validate_identity_id",
]
