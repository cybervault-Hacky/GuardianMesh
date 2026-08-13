"""Tests for GuardianMesh configuration, persistence, validation, and environment overrides."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh import __phase__, __version__
from guardianmesh.core.config import GuardianConfig, load_config, save_config
from guardianmesh.core.errors import ConfigError


def test_config_defaults(tmp_path: Path) -> None:
    """Test default configuration paths and values."""
    config = GuardianConfig(home_dir=tmp_path)
    assert config.version == __version__
    assert config.phase == __phase__
    assert config.home_dir == tmp_path
    assert config.data_dir == tmp_path / "data"
    assert config.database_path == tmp_path / "data" / "guardian.db"
    assert config.keys_dir == tmp_path / "keys"
    assert config.log_dir == tmp_path / "logs"
    assert config.log_level == "INFO"
    assert config.default_role == "PARENT"
    assert config.pairing_enabled is True
    assert config.telemetry_enabled is True


def test_config_validation(tmp_path: Path) -> None:
    """Test validation of invalid config parameters."""
    with pytest.raises(ConfigError):
        GuardianConfig(home_dir=tmp_path, default_role="INVALID_ROLE")

    with pytest.raises(ConfigError):
        GuardianConfig(home_dir=tmp_path, log_level="INVALID_LEVEL")


def test_config_save_and_load(tmp_path: Path) -> None:
    """Test saving and loading configuration from disk."""
    config = GuardianConfig(
        home_dir=tmp_path,
        log_level="DEBUG",
        default_role="CHILD",
    )
    saved_path = save_config(config)
    assert saved_path.is_file()

    loaded = load_config(tmp_path)
    assert loaded.log_level == "DEBUG"
    assert loaded.default_role == "CHILD"
    assert loaded.database_path == tmp_path / "data" / "guardian.db"


def test_config_env_var_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test environment variable overrides for configuration."""
    custom_data = tmp_path / "custom_data"
    monkeypatch.setenv("GUARDIANMESH_HOME", str(tmp_path))
    monkeypatch.setenv("GUARDIANMESH_DATA_DIR", str(custom_data))
    monkeypatch.setenv("GUARDIANMESH_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("GUARDIANMESH_DEFAULT_ROLE", "CHILD")

    loaded = load_config()
    assert loaded.home_dir == tmp_path
    assert loaded.data_dir == custom_data
    assert loaded.log_level == "WARNING"
    assert loaded.default_role == "CHILD"
