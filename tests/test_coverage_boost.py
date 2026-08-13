"""Comprehensive tests covering all edge cases, exceptions, fallbacks, and boundary conditions."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from guardianmesh.cli.commands import (
    cmd_audit,
    cmd_config,
    cmd_doctor,
    cmd_identity,
    cmd_init,
    cmd_status,
)
from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    CryptoError,
    DatabaseMigrationError,
    KeyStorageError,
    StorageError,
)
from guardianmesh.core.paths import (
    check_directory_permissions,
    check_file_permissions,
    get_default_home_dir,
    is_android,
    is_root,
)
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.security.crypto import (
    private_key_from_pem,
    public_key_from_pem,
)
from guardianmesh.security.fingerprints import (
    compute_public_key_fingerprint,
    compute_public_key_hex_fingerprint,
    compute_short_fingerprint,
)
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import Migration, MigrationManager

# ---------------------------------------------------------------------
# Path & Platform Edge Cases
# ---------------------------------------------------------------------


def test_paths_edge_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test path resolution and permissions edge cases."""
    # Test GUARDIANMESH_HOME
    custom_home = tmp_path / "custom_home"
    monkeypatch.setenv("GUARDIANMESH_HOME", str(custom_home))
    assert get_default_home_dir() == custom_home.resolve()

    monkeypatch.delenv("GUARDIANMESH_HOME", raising=False)

    # Test ANDROID_DATA detection
    monkeypatch.setenv("ANDROID_DATA", "/data")
    assert is_android() is True
    monkeypatch.delenv("ANDROID_DATA", raising=False)

    # Test check_file_permissions on non-existent file
    assert check_file_permissions(tmp_path / "nonexistent.txt") is False

    # Test check_directory_permissions on non-existent directory
    assert check_directory_permissions(tmp_path / "nonexistent_dir") is False

    # Test is_root fallback when geteuid raises AttributeError
    with patch("os.geteuid", side_effect=AttributeError):
        assert is_root() is False


# ---------------------------------------------------------------------
# Crypto Edge Cases & Exceptions
# ---------------------------------------------------------------------


def test_crypto_fingerprint_types() -> None:
    """Test computing fingerprints from raw bytes and strings."""
    raw = b"32-byte-raw-public-key-material-here"
    fp_raw = compute_public_key_fingerprint(raw)
    assert fp_raw.startswith("SHA256:")

    fp_str = compute_public_key_fingerprint("string_pub_key")
    assert fp_str.startswith("SHA256:")

    fp_hex_raw = compute_public_key_hex_fingerprint(raw)
    assert ":" in fp_hex_raw

    fp_hex_str = compute_public_key_hex_fingerprint("string_pub_key")
    assert ":" in fp_hex_str

    fp_short_raw = compute_short_fingerprint(raw)
    assert fp_short_raw.startswith("SHA256:")

    fp_short_str = compute_short_fingerprint("string_pub_key")
    assert fp_short_str.startswith("SHA256:")


def test_crypto_invalid_key_types() -> None:
    """Test error handling when loading non-Ed25519 keys."""
    # Generate RSA key and export PEM
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives import serialization

    rsa_priv_pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    rsa_pub_pem = rsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with pytest.raises(CryptoError):
        private_key_from_pem(rsa_priv_pem)

    with pytest.raises(CryptoError):
        public_key_from_pem(rsa_pub_pem)

    with pytest.raises(CryptoError):
        private_key_from_pem(b"invalid-pem-data")

    with pytest.raises(CryptoError):
        public_key_from_pem(b"invalid-pem-data")


# ---------------------------------------------------------------------
# Secrets & Key Storage Edge Cases
# ---------------------------------------------------------------------


def test_key_storage_missing_files(tmp_path: Path) -> None:
    """Test KeyStorageManager errors on missing keys."""
    mgr = KeyStorageManager(tmp_path / "keys")
    with pytest.raises(KeyStorageError):
        mgr.load_private_key("GM-P-00000000")

    with pytest.raises(KeyStorageError):
        mgr.load_public_key("GM-P-00000000")


# ---------------------------------------------------------------------
# Database & Migration Edge Cases
# ---------------------------------------------------------------------


def test_database_sqlite_errors(tmp_path: Path) -> None:
    """Test database error handling for invalid SQL and migration errors."""
    db = Database(tmp_path / "test_err.db")

    with pytest.raises(StorageError):
        db.execute("INVALID SQL SYNTAX;")

    with pytest.raises(StorageError):
        db.executemany("INVALID SQL SYNTAX;", [(), ()])

    with pytest.raises(StorageError):
        db.fetchone("INVALID SQL SYNTAX;")

    with pytest.raises(StorageError):
        db.fetchall("INVALID SQL SYNTAX;")

    # Test migration failure
    bad_migration = Migration(version=99, name="099_bad", up_sql="INVALID SQL SCRIPT;")
    mgr = MigrationManager(migrations=[bad_migration])
    with pytest.raises(DatabaseMigrationError):
        mgr.apply_migrations(db)


def test_database_wal_fallback(tmp_path: Path) -> None:
    """Test WAL mode fallback when journal_mode WAL raises OperationalError."""
    db_path = tmp_path / "wal_fallback.db"
    db = Database(db_path)

    mock_conn = MagicMock()

    def side_effect(sql):
        if "journal_mode = WAL" in sql:
            raise sqlite3.OperationalError("WAL not supported")
        return MagicMock()

    mock_conn.execute.side_effect = side_effect
    db._configure_connection(mock_conn)
    executed_sqls = [call[0][0] for call in mock_conn.execute.call_args_list]
    assert any("journal_mode = DELETE" in s for s in executed_sqls)


# ---------------------------------------------------------------------
# Identity Manager Edge Cases
# ---------------------------------------------------------------------


def test_identity_manager_integrity_checks(tmp_path: Path) -> None:
    """Test validate_identity_integrity failure paths."""
    db = Database(tmp_path / "ident_integ.db")
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(tmp_path / "keys")
    mgr = IdentityManager(db, key_storage)

    # 1. Invalid format
    valid, err = mgr.validate_identity_integrity("invalid-id")
    assert valid is False
    assert "Invalid format" in str(err)

    # 2. Not in DB
    valid, err = mgr.validate_identity_integrity("GM-P-12345678")
    assert valid is False
    assert "not found in database" in str(err)

    # 3. Create identity then remove private key file
    ident, priv_path = mgr.create_identity(IdentityRole.PARENT)
    priv_path.unlink()
    valid, err = mgr.validate_identity_integrity(ident.id)
    assert valid is False
    assert "missing on disk" in str(err)

    # 4. Fingerprint mismatch
    ident2, _ = mgr.create_identity(IdentityRole.CHILD)
    db.execute(
        "UPDATE identities SET public_key_fingerprint = 'SHA256:corrupted' WHERE id = ?;",
        (ident2.id,),
    )
    valid, err = mgr.validate_identity_integrity(ident2.id)
    assert valid is False
    assert "mismatch" in str(err)


# ---------------------------------------------------------------------
# CLI Subcommands & Diagnostics Edge Cases
# ---------------------------------------------------------------------


def test_cli_additional_subcommands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test audit filter, empty identity list, empty audit log, config show."""
    home_dir = tmp_path / "gm_extra"
    config = GuardianConfig(home_dir=home_dir)

    # Status on uninitialized
    cmd_status(None, config)  # type: ignore
    assert "NOT INITIALIZED" in capsys.readouterr().out

    # Audit list on uninitialized
    cmd_audit(None, config)  # type: ignore
    assert "Database not initialized" in capsys.readouterr().out

    # Identity list on uninitialized
    cmd_identity(MagicMock(identity_action="list"), config)
    assert "No identities found" in capsys.readouterr().out

    # Identity show on uninitialized
    cmd_identity(MagicMock(identity_action="show", id=None), config)
    assert "Database not initialized" in capsys.readouterr().out

    # Initialize
    cmd_init(MagicMock(role="parent", label="Primary", force=False), config)
    capsys.readouterr()

    # Audit list with type filter
    cmd_audit(MagicMock(limit=10, type="IDENTITY_CREATED"), config)
    out = capsys.readouterr().out
    assert "IDENTITY_CREATED" in out

    # Config show
    cmd_config(MagicMock(config_action="show"), config)
    cfg_out = capsys.readouterr().out
    assert "version" in cfg_out

    # Main with no subcommands
    assert main(["--home-dir", str(home_dir), "config"]) == 0
    assert main(["--home-dir", str(home_dir), "audit"]) == 0
    assert main(["--home-dir", str(home_dir), "identity"]) == 0


def test_cli_doctor_python_version_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test doctor failure when Python version is < 3.11."""
    config = GuardianConfig(home_dir=tmp_path / "gm_py_fail")
    config.ensure_directories()
    db = Database(config.database_path)
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(config.keys_dir)
    IdentityManager(db, key_storage).create_identity(IdentityRole.PARENT)

    with patch("sys.version_info", (3, 9, 0, "final", 0)):
        code = cmd_doctor(None, config)  # type: ignore
        assert code == 1
        out = capsys.readouterr().out
        assert "Python             ✗" in out
