"""Tests for platform detection, Termux compatibility, and non-root requirements."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.paths import (
    check_directory_permissions,
    check_file_permissions,
    ensure_directory,
    is_android,
    is_termux,
    set_file_permissions,
)
from guardianmesh.device.platform import get_platform_info


def test_platform_info_detection() -> None:
    """Test get_platform_info returns structured host details."""
    info = get_platform_info()
    assert info.system != ""
    assert info.python_version != ""
    assert isinstance(info.is_termux, bool)
    assert isinstance(info.is_android, bool)
    assert isinstance(info.is_linux, bool)
    assert isinstance(info.is_root, bool)

    d = info.to_dict()
    assert "platform_name" in d
    assert "machine" in d


def test_termux_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test Termux detection triggers via env vars."""
    # When TERMUX_VERSION is present
    monkeypatch.setenv("TERMUX_VERSION", "0.118.0")
    assert is_termux() is True
    assert is_android() is True

    # When PREFIX is set to Termux path
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    assert is_termux() is True
    assert is_android() is True

    # When neither is set
    monkeypatch.delenv("PREFIX", raising=False)
    # If not on an actual Termux box, is_termux is False
    # (Unless python executable path contains com.termux)


def test_ensure_directory_and_permissions(tmp_path: Path) -> None:
    """Test directory creation with strict 0700 permissions."""
    test_dir = tmp_path / "sub" / "secure_dir"
    ensured = ensure_directory(test_dir, mode=0o700)
    assert ensured.is_dir()
    assert check_directory_permissions(ensured, max_mode=0o700) is True

    # Test file permissions
    test_file = ensured / "secret.txt"
    test_file.write_text("sensitive")
    assert set_file_permissions(test_file, mode=0o600) is True
    assert check_file_permissions(test_file, max_mode=0o600) is True
