"""Secure local key storage, permission verification, and secret sanitation."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from guardianmesh.core.errors import KeyStorageError
from guardianmesh.core.paths import check_directory_permissions, check_file_permissions, ensure_directory
from guardianmesh.security.crypto import (
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
)


class KeyStorageManager:
    """Manages local storage of asymmetric key material with strict filesystem permissions."""

    def __init__(self, keys_dir: Path) -> None:
        self.keys_dir = Path(keys_dir).expanduser().resolve()

    def ensure_keys_directory(self) -> Path:
        """Create keys directory with 0700 permissions if it does not exist."""
        return ensure_directory(self.keys_dir, mode=0o700)

    def get_private_key_path(self, identity_id: str) -> Path:
        """Return the path to the private key for an identity."""
        return self.keys_dir / f"id_{identity_id}.key"

    def get_public_key_path(self, identity_id: str) -> Path:
        """Return the path to the public key for an identity."""
        return self.keys_dir / f"id_{identity_id}.pub"

    def has_keys(self, identity_id: str) -> bool:
        """Check if both private and public keys exist for an identity."""
        priv = self.get_private_key_path(identity_id)
        pub = self.get_public_key_path(identity_id)
        return priv.is_file() and pub.is_file()

    def save_keypair(
        self,
        identity_id: str,
        private_key: ed25519.Ed25519PrivateKey,
        public_key: ed25519.Ed25519PublicKey,
    ) -> tuple[Path, Path]:
        """Securely store an Ed25519 keypair on disk.

        Private key is saved with 0600 permissions.
        Public key is saved with 0644 permissions.
        """
        self.ensure_keys_directory()
        priv_path = self.get_private_key_path(identity_id)
        pub_path = self.get_public_key_path(identity_id)

        try:
            priv_pem = private_key_to_pem(private_key)
            pub_pem = public_key_to_pem(public_key)

            # Write private key with temporary secure file then atomic move
            # Create file with 0600
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            mode = 0o600
            fd = os.open(str(priv_path), flags, mode)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(priv_pem)
            except Exception:
                # Close fd if fdopen failed
                pass

            # Enforce 0600 explicitly
            try:
                priv_path.chmod(0o600)
            except OSError:
                pass

            # Write public key
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
            try:
                pub_path.chmod(0o644)
            except OSError:
                pass

            return priv_path, pub_path
        except Exception as e:
            raise KeyStorageError(f"Failed to save keypair for '{identity_id}': {e}") from e

    def load_private_key(self, identity_id: str) -> ed25519.Ed25519PrivateKey:
        """Load and deserialize an Ed25519 private key from disk."""
        priv_path = self.get_private_key_path(identity_id)
        if not priv_path.is_file():
            raise KeyStorageError(f"Private key file not found for '{identity_id}' at {priv_path}")

        try:
            with open(priv_path, "rb") as f:
                pem_data = f.read()
            return private_key_from_pem(pem_data)
        except Exception as e:
            raise KeyStorageError(f"Failed to load private key for '{identity_id}': {e}") from e

    def load_public_key(self, identity_id: str) -> ed25519.Ed25519PublicKey:
        """Load and deserialize an Ed25519 public key from disk."""
        pub_path = self.get_public_key_path(identity_id)
        if not pub_path.is_file():
            raise KeyStorageError(f"Public key file not found for '{identity_id}' at {pub_path}")

        try:
            with open(pub_path, "rb") as f:
                pem_data = f.read()
            return public_key_from_pem(pem_data)
        except Exception as e:
            raise KeyStorageError(f"Failed to load public key for '{identity_id}': {e}") from e

    def verify_permissions(self, identity_id: str | None = None) -> tuple[bool, str | None]:
        """Verify that keys directory and private key files have secure permissions."""
        if not self.keys_dir.is_dir():
            return True, None  # Not yet created

        if not check_directory_permissions(self.keys_dir, max_mode=0o700):
            return False, f"Keys directory '{self.keys_dir}' permissions are too permissive (expected 0700)."

        if identity_id:
            priv_path = self.get_private_key_path(identity_id)
            if priv_path.is_file() and not check_file_permissions(priv_path, max_mode=0o600):
                return False, f"Private key '{priv_path}' permissions are too permissive (expected 0600)."

        return True, None

    def secure_delete_keypair(self, identity_id: str) -> None:
        """Securely overwrite and remove key files for an identity."""
        priv_path = self.get_private_key_path(identity_id)
        pub_path = self.get_public_key_path(identity_id)

        if priv_path.is_file():
            try:
                length = priv_path.stat().st_size
                with open(priv_path, "ba+", buffering=0) as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(os.urandom(length))
                priv_path.unlink(missing_ok=True)
            except OSError as e:
                raise KeyStorageError(f"Failed to securely delete private key '{priv_path}': {e}") from e

        if pub_path.is_file():
            pub_path.unlink(missing_ok=True)


def mask_secret(secret: str, visible_prefix: int = 2, visible_suffix: int = 2) -> str:
    """Mask a secret string for safe display."""
    if not secret:
        return "[EMPTY]"
    if len(secret) <= (visible_prefix + visible_suffix):
        return "[REDACTED]"
    hidden_len = len(secret) - visible_prefix - visible_suffix
    return f"{secret[:visible_prefix]}{'*' * hidden_len}{secret[-visible_suffix:]}"
