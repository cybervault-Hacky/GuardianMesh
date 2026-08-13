"""Identity lifecycle manager: cryptographic generation, database persistence, and integrity checks."""

from __future__ import annotations

import datetime
import json
import secrets
from pathlib import Path

from guardianmesh.core.errors import (
    IdentityError,
    IdentityNotFoundError,
    StorageError,
)
from guardianmesh.identity.models import (
    Identity,
    IdentityRole,
    validate_identity_id,
)
from guardianmesh.security.crypto import (
    generate_keypair,
    public_key_from_pem,
    public_key_to_pem,
)
from guardianmesh.security.fingerprints import compute_public_key_fingerprint
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


class IdentityManager:
    """Manages the creation, retrieval, activation, and verification of GuardianMesh identities."""

    def __init__(
        self,
        db: Database,
        key_storage: KeyStorageManager,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.key_storage = key_storage
        self.audit_logger = audit_logger or AuditLogger(db)

    @staticmethod
    def generate_identity_id(role: IdentityRole) -> str:
        """Generate a random 8-hex-digit identifier with cryptographic entropy.

        Example:
          Parent: GM-P-83A1F72C
          Child:  GM-C-19A84E72
        """
        prefix = "GM-P-" if role == IdentityRole.PARENT else "GM-C-"
        random_hex = secrets.token_hex(4).upper()
        return f"{prefix}{random_hex}"

    def create_identity(
        self,
        role: IdentityRole = IdentityRole.PARENT,
        label: str | None = None,
        set_active: bool = True,
        metadata: dict | None = None,
    ) -> tuple[Identity, Path]:
        """Generate a new cryptographic identity, keypair, and database record.

        Args:
            role: PARENT or CHILD role.
            label: Optional user-friendly label (e.g. "Primary Parent Device").
            set_active: Whether to set this identity as the active identity.
            metadata: Optional dictionary of arbitrary non-sensitive metadata.

        Returns:
            Tuple of (Identity, private_key_file_path).
        """
        # Ensure unique ID with retry loop (statistically collision is 1 in 2^32, but check DB)
        max_attempts = 10
        identity_id = ""
        for _ in range(max_attempts):
            candidate = self.generate_identity_id(role)
            existing = self.db.fetchone("SELECT id FROM identities WHERE id = ?;", (candidate,))
            if not existing:
                identity_id = candidate
                break

        if not identity_id:
            raise IdentityError("Failed to generate a unique identity identifier.")

        # Generate cryptographic Ed25519 keypair
        private_key, public_key = generate_keypair()
        pub_pem_bytes = public_key_to_pem(public_key)
        pub_pem_str = pub_pem_bytes.decode("utf-8")
        fingerprint = compute_public_key_fingerprint(public_key)

        # Save private & public key material with strict permissions
        priv_path, _ = self.key_storage.save_keypair(identity_id, private_key, public_key)

        now = datetime.datetime.now(datetime.UTC).isoformat()
        meta = metadata or {}
        meta_json = json.dumps(meta)

        try:
            with self.db.transaction() as conn:
                if set_active:
                    conn.execute("UPDATE identities SET is_active = 0;")

                conn.execute(
                    """
                    INSERT INTO identities (
                        id, role, public_key_fingerprint, public_key_pem,
                        created_at, label, is_active, metadata
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        identity_id,
                        role.value,
                        fingerprint,
                        pub_pem_str,
                        now,
                        label,
                        1 if set_active else 0,
                        meta_json,
                    ),
                )
        except Exception as e:
            # Clean up key material if DB insert fails
            self.key_storage.secure_delete_keypair(identity_id)
            raise StorageError(f"Failed to persist identity '{identity_id}' to database: {e}") from e

        identity = Identity(
            id=identity_id,
            role=role,
            public_key_fingerprint=fingerprint,
            public_key_pem=pub_pem_str,
            created_at=now,
            label=label,
            is_active=set_active,
            metadata=meta,
        )

        # Record audit event
        self.audit_logger.record(
            event_type=AuditEventType.IDENTITY_CREATED,
            details={
                "identity_id": identity_id,
                "role": role.value,
                "fingerprint": fingerprint,
                "label": label,
            },
            actor_id=identity_id,
            success=True,
        )

        return identity, priv_path

    def get_active_identity(self) -> Identity | None:
        """Fetch the currently active local identity."""
        row = self.db.fetchone("SELECT * FROM identities WHERE is_active = 1 ORDER BY rowid DESC LIMIT 1;")
        if not row:
            return None
        return Identity.from_dict(dict(row))

    def get_identity(self, identity_id: str) -> Identity | None:
        """Fetch an identity by its ID."""
        row = self.db.fetchone("SELECT * FROM identities WHERE id = ?;", (identity_id,))
        if not row:
            return None
        return Identity.from_dict(dict(row))

    def list_identities(self) -> list[Identity]:
        """List all identities ordered by creation time."""
        rows = self.db.fetchall("SELECT * FROM identities ORDER BY created_at DESC;")
        return [Identity.from_dict(dict(row)) for row in rows]

    def set_active_identity(self, identity_id: str) -> bool:
        """Activate the specified identity and deactivate others."""
        identity = self.get_identity(identity_id)
        if not identity:
            raise IdentityNotFoundError(f"Identity '{identity_id}' not found.")

        with self.db.transaction() as conn:
            conn.execute("UPDATE identities SET is_active = 0;")
            conn.execute("UPDATE identities SET is_active = 1 WHERE id = ?;", (identity_id,))

        self.audit_logger.record(
            event_type=AuditEventType.IDENTITY_ACTIVATED,
            details={"identity_id": identity_id},
            actor_id=identity_id,
            success=True,
        )
        return True

    def validate_identity_integrity(self, identity_id: str) -> tuple[bool, str | None]:
        """Verify that an identity's database record, key material, and fingerprint are valid and matching."""
        is_valid_format, err = validate_identity_id(identity_id)
        if not is_valid_format:
            return False, f"Invalid format: {err}"

        identity = self.get_identity(identity_id)
        if not identity:
            return False, f"Identity '{identity_id}' not found in database."

        if not self.key_storage.has_keys(identity_id):
            return False, f"Key files missing on disk for '{identity_id}'."

        perms_ok, perms_err = self.key_storage.verify_permissions(identity_id)
        if not perms_ok:
            return False, f"Key permission error: {perms_err}"

        try:
            pub_key = public_key_from_pem(identity.public_key_pem.encode("utf-8"))
            computed_fp = compute_public_key_fingerprint(pub_key)
            if computed_fp != identity.public_key_fingerprint:
                return False, "Public key fingerprint mismatch."
        except Exception as e:
            return False, f"Cryptographic verification error: {e}"

        return True, None
