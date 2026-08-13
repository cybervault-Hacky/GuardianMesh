"""Tests for KeyStorageManager, filesystem permissions, and secret redaction."""

from __future__ import annotations

import stat
from pathlib import Path

from guardianmesh.security.crypto import generate_keypair
from guardianmesh.security.secrets import KeyStorageManager, mask_secret


def test_key_storage_save_load_permissions(tmp_path: Path) -> None:
    """Test saving keypair sets strict permissions and loading works."""
    keys_dir = tmp_path / "keys"
    manager = KeyStorageManager(keys_dir)

    identity_id = "GM-P-83A1F72C"
    priv, pub = generate_keypair()

    priv_path, pub_path = manager.save_keypair(identity_id, priv, pub)
    assert priv_path.is_file()
    assert pub_path.is_file()

    # Verify filesystem permissions: private key should be 0600
    priv_mode = stat.S_IMODE(priv_path.stat().st_mode)
    assert (priv_mode & 0o077) == 0  # No group or other access

    # Verify keys_dir mode: 0700
    dir_mode = stat.S_IMODE(keys_dir.stat().st_mode)
    assert (dir_mode & 0o077) == 0

    # Verify verify_permissions helper
    ok, err = manager.verify_permissions(identity_id)
    assert ok is True
    assert err is None

    # Load back
    loaded_priv = manager.load_private_key(identity_id)
    loaded_pub = manager.load_public_key(identity_id)
    assert loaded_priv is not None
    assert loaded_pub is not None

    assert manager.has_keys(identity_id) is True
    assert manager.has_keys("GM-P-00000000") is False


def test_key_storage_permission_violation_detection(tmp_path: Path) -> None:
    """Test detection when key permissions are too permissive."""
    keys_dir = tmp_path / "keys"
    manager = KeyStorageManager(keys_dir)

    identity_id = "GM-P-83A1F72C"
    priv, pub = generate_keypair()
    priv_path, _ = manager.save_keypair(identity_id, priv, pub)

    # Intentionally loosen private key permissions to 0666 (rw-rw-rw-)
    priv_path.chmod(0o666)
    ok, err = manager.verify_permissions(identity_id)
    assert ok is False
    assert "too permissive" in str(err)


def test_secure_delete_keypair(tmp_path: Path) -> None:
    """Test secure key deletion overwrites and unlinks keys."""
    keys_dir = tmp_path / "keys"
    manager = KeyStorageManager(keys_dir)

    identity_id = "GM-P-83A1F72C"
    priv, pub = generate_keypair()
    priv_path, pub_path = manager.save_keypair(identity_id, priv, pub)

    assert priv_path.is_file()
    assert pub_path.is_file()

    manager.secure_delete_keypair(identity_id)

    assert not priv_path.exists()
    assert not pub_path.exists()
    assert not manager.has_keys(identity_id)


def test_mask_secret() -> None:
    """Test secret masking helper."""
    assert mask_secret("") == "[EMPTY]"
    assert mask_secret("123") == "[REDACTED]"
    assert mask_secret("supersecretkey12345") == "su***************45"
