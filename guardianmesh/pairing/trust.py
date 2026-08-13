"""Cryptographic trust establishment, verification, and revocation management."""

from __future__ import annotations

import datetime
import json

from guardianmesh.core.errors import (
    DeviceNotTrustedError,
    SecurityError,
    TrustError,
    TrustRevokedError,
)
from guardianmesh.identity.models import parse_identity_role, validate_identity_id
from guardianmesh.pairing.models import TrustedDevice
from guardianmesh.security.crypto import public_key_from_pem
from guardianmesh.security.fingerprints import compute_public_key_fingerprint
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


class TrustManager:
    """Manages persistent cryptographic trust records and revocation states."""

    def __init__(self, db: Database, audit_logger: AuditLogger | None = None) -> None:
        self.db = db
        self.audit_logger = audit_logger or AuditLogger(db)

    def establish_trust(
        self,
        local_identity_id: str,
        remote_identity_id: str,
        remote_public_key_pem: str,
        pairing_session_id: str | None = None,
        label: str | None = None,
        metadata: dict | None = None,
    ) -> TrustedDevice:
        """Establish or update an authenticated trust relationship with a remote device.

        Args:
            local_identity_id: Local device identity.
            remote_identity_id: Remote device identity.
            remote_public_key_pem: Remote Ed25519 public key in PEM format.
            pairing_session_id: Optional pairing session that authorized this trust.
            label: Optional user-friendly label.
            metadata: Optional non-sensitive metadata.

        Returns:
            The established TrustedDevice model.
        """
        # Validate remote identity ID format
        is_valid, err = validate_identity_id(remote_identity_id)
        if not is_valid:
            raise SecurityError(f"Invalid remote identity format: {err}")

        remote_role = parse_identity_role(remote_identity_id)

        # Cryptographically verify public key PEM and compute fingerprint
        try:
            pub_key = public_key_from_pem(remote_public_key_pem.encode("utf-8"))
            computed_fp = compute_public_key_fingerprint(pub_key)
        except Exception as e:
            raise SecurityError(f"Invalid remote public key: {e}") from e

        now = datetime.datetime.now(datetime.UTC).isoformat()
        meta = metadata or {}
        meta_json = json.dumps(meta)

        try:
            with self.db.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO trusted_devices (
                        local_identity_id, remote_identity_id, remote_role,
                        remote_public_key_fingerprint, remote_public_key_pem,
                        label, status, created_at, last_verified_at,
                        trust_version, pairing_session_id, metadata
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, 1, ?, ?)
                    ON CONFLICT(local_identity_id, remote_identity_id) DO UPDATE SET
                        remote_public_key_fingerprint = excluded.remote_public_key_fingerprint,
                        remote_public_key_pem = excluded.remote_public_key_pem,
                        label = coalesce(excluded.label, trusted_devices.label),
                        status = 'ACTIVE',
                        last_verified_at = excluded.last_verified_at,
                        trust_version = trusted_devices.trust_version + 1,
                        pairing_session_id = excluded.pairing_session_id,
                        metadata = excluded.metadata;
                    """,
                    (
                        local_identity_id,
                        remote_identity_id,
                        remote_role.value,
                        computed_fp,
                        remote_public_key_pem,
                        label,
                        now,
                        now,
                        pairing_session_id,
                        meta_json,
                    ),
                )
        except Exception as e:
            raise TrustError(f"Failed to record trust relationship: {e}") from e

        device = TrustedDevice(
            local_identity_id=local_identity_id,
            remote_identity_id=remote_identity_id,
            remote_role=remote_role,
            remote_public_key_fingerprint=computed_fp,
            remote_public_key_pem=remote_public_key_pem,
            label=label,
            status="ACTIVE",
            created_at=now,
            last_verified_at=now,
            trust_version=1,
            pairing_session_id=pairing_session_id,
            metadata=meta,
        )

        self.audit_logger.record(
            event_type=AuditEventType.TRUST_ESTABLISHED,
            details={
                "local_identity": local_identity_id,
                "remote_identity": remote_identity_id,
                "remote_role": remote_role.value,
                "fingerprint": computed_fp,
                "session_id": pairing_session_id,
            },
            actor_id=local_identity_id,
            success=True,
        )

        return device

    def get_trusted_device(self, local_identity_id: str, remote_identity_id: str) -> TrustedDevice | None:
        """Fetch a specific trusted device record."""
        row = self.db.fetchone(
            """
            SELECT * FROM trusted_devices
            WHERE local_identity_id = ? AND remote_identity_id = ?;
            """,
            (local_identity_id, remote_identity_id),
        )
        if not row:
            return None
        return TrustedDevice.from_dict(dict(row))

    def list_trusted_devices(
        self, local_identity_id: str | None = None, status: str | None = None
    ) -> list[TrustedDevice]:
        """List all trusted devices matching criteria."""
        query = "SELECT * FROM trusted_devices WHERE 1=1"
        params: list[str] = []

        if local_identity_id:
            query += " AND local_identity_id = ?"
            params.append(local_identity_id)

        if status:
            query += " AND status = ?"
            params.append(status.upper())

        query += " ORDER BY created_at DESC;"

        rows = self.db.fetchall(query, tuple(params))
        return [TrustedDevice.from_dict(dict(row)) for row in rows]

    def is_trusted(self, local_identity_id: str, remote_identity_id: str) -> bool:
        """Check if an active trust relationship exists."""
        device = self.get_trusted_device(local_identity_id, remote_identity_id)
        if not device:
            return False
        return device.is_active

    def verify_device_trust_or_raise(self, local_identity_id: str, remote_identity_id: str) -> TrustedDevice:
        """Verify trust relationship and return record, raising appropriate error if untrusted or revoked."""
        device = self.get_trusted_device(local_identity_id, remote_identity_id)
        if not device:
            raise DeviceNotTrustedError(
                f"Device '{remote_identity_id}' is not in the trusted devices registry."
            )
        if device.status == "REVOKED":
            raise TrustRevokedError(f"Trust relationship with '{remote_identity_id}' has been REVOKED.")
        return device

    def revoke_trust(
        self,
        local_identity_id: str,
        remote_identity_id: str,
        actor_id: str | None = None,
        reason: str = "User revoked",
    ) -> bool:
        """Revoke trust for a device and invalidate any associated active pairing sessions."""
        device = self.get_trusted_device(local_identity_id, remote_identity_id)
        if not device:
            raise DeviceNotTrustedError(
                f"Cannot revoke: device '{remote_identity_id}' not found in trusted devices."
            )

        now = datetime.datetime.now(datetime.UTC).isoformat()

        with self.db.transaction() as conn:
            # Mark trust revoked
            conn.execute(
                """
                UPDATE trusted_devices
                SET status = 'REVOKED', last_verified_at = ?
                WHERE local_identity_id = ? AND remote_identity_id = ?;
                """,
                (now, local_identity_id, remote_identity_id),
            )

            # Invalidate any pending or active pairing sessions involving this remote device
            conn.execute(
                """
                UPDATE pairing_sessions
                SET state = 'REVOKED'
                WHERE (parent_identity_id = ? AND child_identity_id = ?)
                   OR (parent_identity_id = ? AND child_identity_id = ?)
                   AND state NOT IN ('DENIED', 'EXPIRED', 'CANCELLED', 'REVOKED');
                """,
                (local_identity_id, remote_identity_id, remote_identity_id, local_identity_id),
            )

        self.audit_logger.record(
            event_type=AuditEventType.TRUST_REVOKED,
            details={
                "local_identity": local_identity_id,
                "remote_identity": remote_identity_id,
                "reason": reason,
            },
            actor_id=actor_id or local_identity_id,
            success=True,
        )
        return True

    def rename_trusted_device(self, local_identity_id: str, remote_identity_id: str, new_label: str) -> bool:
        """Update label for a trusted device."""
        device = self.get_trusted_device(local_identity_id, remote_identity_id)
        if not device:
            raise DeviceNotTrustedError(f"Device '{remote_identity_id}' not found.")

        self.db.execute(
            """
            UPDATE trusted_devices
            SET label = ?
            WHERE local_identity_id = ? AND remote_identity_id = ?;
            """,
            (new_label.strip(), local_identity_id, remote_identity_id),
        )
        return True
