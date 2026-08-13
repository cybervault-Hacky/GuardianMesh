"""Deep coverage tests covering error handling branches, CLI exceptions, and edge cases."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from guardianmesh.cli.commands import (
    cmd_audit,
    cmd_doctor,
    cmd_identity,
    cmd_status,
    get_terminal_width,
)
from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import CryptoError, GuardianMeshError, KeyStorageError
from guardianmesh.core.paths import (
    check_directory_permissions,
    check_file_permissions,
    ensure_directory,
    is_termux,
    set_file_permissions,
)
from guardianmesh.security.crypto import (
    generate_keypair,
    private_key_to_pem,
    public_key_to_pem,
    public_key_to_raw_bytes,
    sign_data,
    verify_signature,
)
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_terminal_width_fallback() -> None:
    """Test get_terminal_width exception fallback."""
    with patch("shutil.get_terminal_size", side_effect=Exception("Terminal error")):
        w = get_terminal_width()
        assert w == 80


def test_main_keyboard_interrupt_and_exceptions(capsys: pytest.CaptureFixture[str]) -> None:
    """Test main handles KeyboardInterrupt and unexpected errors with/without debug."""
    with patch("guardianmesh.cli.main.cmd_status", side_effect=KeyboardInterrupt):
        code = main(["status"])
        assert code == 130
        assert "cancelled by user" in capsys.readouterr().out

    with patch("guardianmesh.cli.main.cmd_status", side_effect=RuntimeError("Fatal boom")):
        code = main(["status"])
        assert code == 1
        assert "Unexpected error: Fatal boom" in capsys.readouterr().err

    with patch("guardianmesh.cli.main.cmd_status", side_effect=RuntimeError("Fatal boom with debug")):
        code = main(["--debug", "status"])
        assert code == 1
        assert "Fatal boom with debug" in capsys.readouterr().err

    with patch("guardianmesh.cli.main.cmd_status", side_effect=GuardianMeshError("Domain error")):
        code = main(["status"])
        assert code == 1
        assert "Error: Domain error" in capsys.readouterr().err

    with patch("guardianmesh.cli.main.cmd_status", side_effect=GuardianMeshError("Domain error debug")):
        code = main(["--debug", "status"])
        assert code == 1
        assert "Error: Domain error debug" in capsys.readouterr().err


def test_paths_os_errors(tmp_path: Path) -> None:
    """Test OSError handling in path and permission utilities."""
    # Test ensure_directory chmod error
    with patch.object(Path, "chmod", side_effect=OSError("Read-only")):
        p = ensure_directory(tmp_path / "ro_dir")
        assert p.is_dir()

    # Test set_file_permissions OSError
    with patch.object(Path, "chmod", side_effect=OSError("Read-only")):
        assert set_file_permissions(tmp_path / "file.txt") is False

    # Test check_file_permissions on non-file returns False
    assert check_file_permissions(tmp_path / "missing_file.txt") is False

    # Test check_directory_permissions on non-directory returns False
    assert check_directory_permissions(tmp_path / "missing_dir") is False

    # Test is_termux with sys.executable match
    with patch("sys.executable", "/data/data/com.termux/files/usr/bin/python3"):
        assert is_termux() is True


def test_crypto_exceptions() -> None:
    """Test exception branches in crypto.py."""
    patch_target = "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate"
    with patch(patch_target, side_effect=Exception("Entropy failure")):
        with pytest.raises(CryptoError):
            generate_keypair()

    mock_priv = MagicMock()
    mock_priv.private_bytes.side_effect = Exception("Serialize fail")
    with pytest.raises(CryptoError):
        private_key_to_pem(mock_priv)

    mock_pub = MagicMock()
    mock_pub.public_bytes.side_effect = Exception("Serialize fail")
    with pytest.raises(CryptoError):
        public_key_to_pem(mock_pub)

    with pytest.raises(CryptoError):
        public_key_to_raw_bytes(mock_pub)

    mock_priv.sign.side_effect = Exception("Sign fail")
    with pytest.raises(CryptoError):
        sign_data(mock_priv, b"message")

    # verify_signature catches generic exception
    mock_pub.verify.side_effect = Exception("Corrupt verify")
    assert verify_signature(mock_pub, b"sig", b"msg") is False


def test_key_storage_exceptions(tmp_path: Path) -> None:
    """Test KeyStorageManager exception branches."""
    mgr = KeyStorageManager(tmp_path / "keys_exc")
    priv, pub = generate_keypair()

    # Save keypair error
    with patch("guardianmesh.security.secrets.private_key_to_pem", side_effect=Exception("PEM fail")):
        with pytest.raises(KeyStorageError):
            mgr.save_keypair("GM-P-12345678", priv, pub)

    # Load corrupt private key
    mgr.ensure_keys_directory()
    priv_file = mgr.get_private_key_path("GM-P-CORRUPT1")
    priv_file.write_text("NOT A VALID PEM")
    with pytest.raises(KeyStorageError):
        mgr.load_private_key("GM-P-CORRUPT1")

    # Load corrupt public key
    pub_file = mgr.get_public_key_path("GM-P-CORRUPT2")
    pub_file.write_text("NOT A VALID PEM")
    with pytest.raises(KeyStorageError):
        mgr.load_public_key("GM-P-CORRUPT2")

    # Secure delete OSError
    mgr.save_keypair("GM-P-DELTEST1", priv, pub)
    with patch("builtins.open", side_effect=OSError("Cannot open")), pytest.raises(KeyStorageError):
        mgr.secure_delete_keypair("GM-P-DELTEST1")


def test_commands_additional_branches(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test remaining command branches: empty identity list, corrupted status, doctor checks."""
    home_dir = tmp_path / "gm_cmd_branch"
    config = GuardianConfig(home_dir=home_dir)
    config.ensure_directories()
    db = Database(config.database_path)
    MigrationManager().apply_migrations(db)

    # Status when database has 0 identities
    cmd_status(None, config)  # type: ignore
    status_out = capsys.readouterr().out
    assert "NO ACTIVE IDENTITY" in status_out

    # Status when database integrity raises an exception
    with patch.object(Database, "check_integrity", side_effect=Exception("DB broke")):
        cmd_status(None, config)  # type: ignore
        assert "UNAVAILABLE" in capsys.readouterr().out

    # Status when key storage throws exception
    with patch("guardianmesh.security.secrets.KeyStorageManager.has_keys", side_effect=Exception("Key err")):
        cmd_status(None, config)  # type: ignore
        assert "Key material" in capsys.readouterr().out

    # Identity list when DB is initialized but 0 identities exist
    cmd_identity(MagicMock(identity_action="list"), config)
    assert "No identities found" in capsys.readouterr().out

    # Identity show with 0 identities
    cmd_identity(MagicMock(identity_action="show", id=None), config)
    assert "Identity not found" in capsys.readouterr().out

    # Audit list with 0 events
    cmd_audit(MagicMock(limit=10, type=None), config)
    assert "No audit events found" in capsys.readouterr().out

    # Doctor when database migration version is 0
    with patch("guardianmesh.storage.migrations.MigrationManager.get_current_version", return_value=0):
        code = cmd_doctor(None, config)  # type: ignore
        assert code == 1
        assert "Database           ✗" in capsys.readouterr().out

    # Doctor when config fails to load
    with patch("guardianmesh.cli.commands.load_config", side_effect=Exception("Config broken")):
        code = cmd_doctor(None, config)  # type: ignore
        assert code == 1
        assert "Configuration      ✗" in capsys.readouterr().out
