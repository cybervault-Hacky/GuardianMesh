"""Identity data models and format validation for GuardianMesh."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guardianmesh.core.errors import InvalidIdentityError

# Regex pattern for strict identity format: GM-P-XXXXXXXX or GM-C-XXXXXXXX (8 uppercase hex digits)
IDENTITY_REGEX = re.compile(r"^GM-(P|C)-([0-9A-F]{8})$")


class IdentityRole(str, Enum):
    """Role associated with a GuardianMesh identity."""

    PARENT = "PARENT"
    CHILD = "CHILD"

    @classmethod
    def from_str(cls, role_str: str) -> IdentityRole:
        """Parse role from string case-insensitively."""
        normalized = role_str.strip().upper()
        if normalized in ("PARENT", "P"):
            return cls.PARENT
        elif normalized in ("CHILD", "C"):
            return cls.CHILD
        raise InvalidIdentityError(f"Invalid identity role '{role_str}'. Must be PARENT or CHILD.")


def validate_identity_id(identity_id: str) -> tuple[bool, str | None]:
    """Validate a GuardianMesh identity identifier against strict format rules.

    Format:
      Parent: GM-P-XXXXXXXX (where X is uppercase hex 0-9, A-F)
      Child:  GM-C-XXXXXXXX (where X is uppercase hex 0-9, A-F)

    Args:
        identity_id: The identifier string to check.

    Returns:
        Tuple of (is_valid, error_reason).
    """
    if not isinstance(identity_id, str):
        return False, "Identity ID must be a string."

    if not identity_id:
        return False, "Identity ID cannot be empty."

    if len(identity_id) != 13:
        return False, f"Identity ID must be exactly 13 characters, got {len(identity_id)}."

    match = IDENTITY_REGEX.match(identity_id)
    if not match:
        if identity_id.lower().startswith("gm-") and identity_id != identity_id.upper():
            return False, "Identity ID must contain only uppercase hexadecimal characters."
        return False, "Identity ID does not match required format (GM-P-XXXXXXXX or GM-C-XXXXXXXX)."

    return True, None


def parse_identity_role(identity_id: str) -> IdentityRole:
    """Extract the IdentityRole from a valid identity ID.

    Args:
        identity_id: Valid GuardianMesh identity ID.

    Returns:
        IdentityRole.PARENT or IdentityRole.CHILD.

    Raises:
        InvalidIdentityError: If the ID is invalid.
    """
    is_valid, error = validate_identity_id(identity_id)
    if not is_valid:
        raise InvalidIdentityError(f"Cannot parse role from invalid identity ID '{identity_id}': {error}")

    role_char = identity_id[3]
    if role_char == "P":
        return IdentityRole.PARENT
    elif role_char == "C":
        return IdentityRole.CHILD
    raise InvalidIdentityError(f"Unknown role identifier '{role_char}' in '{identity_id}'.")


@dataclass
class Identity:
    """Representation of a local GuardianMesh identity."""

    id: str
    role: IdentityRole
    public_key_fingerprint: str
    public_key_pem: str
    created_at: str
    label: str | None = None
    is_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate identity properties on initialization."""
        is_valid, error = validate_identity_id(self.id)
        if not is_valid:
            raise InvalidIdentityError(f"Invalid identity ID '{self.id}': {error}")

        if isinstance(self.role, str):
            self.role = IdentityRole.from_str(self.role)

        expected_role = parse_identity_role(self.id)
        if self.role != expected_role:
            err_msg = (
                f"Role mismatch: identity ID '{self.id}' indicates "
                f"{expected_role.value}, but role is {self.role.value}."
            )
            raise InvalidIdentityError(err_msg)

    @property
    def role_display(self) -> str:
        """User-friendly display name for role."""
        return "Parent" if self.role == IdentityRole.PARENT else "Child"

    def to_dict(self) -> dict[str, Any]:
        """Serialize Identity to dictionary."""
        return {
            "id": self.id,
            "role": self.role.value,
            "public_key_fingerprint": self.public_key_fingerprint,
            "public_key_pem": self.public_key_pem,
            "created_at": self.created_at,
            "label": self.label,
            "is_active": self.is_active,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Identity:
        """Construct an Identity instance from dictionary data."""
        raw_meta = data.get("metadata", {})
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except json.JSONDecodeError:
                meta = {}
        else:
            meta = raw_meta or {}

        return cls(
            id=data["id"],
            role=IdentityRole.from_str(data["role"]),
            public_key_fingerprint=data["public_key_fingerprint"],
            public_key_pem=data["public_key_pem"],
            created_at=data["created_at"],
            label=data.get("label"),
            is_active=bool(data.get("is_active", True)),
            metadata=meta,
        )
