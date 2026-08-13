"""Final comprehensive coverage tests for Console, Devices, and CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from guardianmesh.cli.commands import cmd_console, cmd_devices
from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig


def test_cli_console_subcommands_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test console subcommands in terminal and JSON mode."""
    home_dir = str(tmp_path / "gm_con_cov")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # console devices --json
    code = main(["--home-dir", home_dir, "console", "devices", "--json"])
    assert code == 0
    assert "devices" in capsys.readouterr().out

    # console alerts --json
    code = main(["--home-dir", home_dir, "console", "alerts", "--json"])
    assert code == 0
    assert "alerts" in capsys.readouterr().out

    # console policies --json
    code = main(["--home-dir", home_dir, "console", "policies", "--json"])
    assert code == 0
    assert "policies" in capsys.readouterr().out

    # console pairing --json
    code = main(["--home-dir", home_dir, "console", "pairing", "--json"])
    assert code == 0
    assert "pairing" in capsys.readouterr().out

    # console audit --json
    code = main(["--home-dir", home_dir, "console", "audit", "--json", "--limit", "5"])
    assert code == 0
    assert "audit_events" in capsys.readouterr().out

    # console status --json
    code = main(["--home-dir", home_dir, "console", "status", "--json"])
    assert code == 0
    assert "subsystems" in capsys.readouterr().out

    # devices health on non-existent
    code = main(["--home-dir", home_dir, "devices", "health", "GM-C-NONEXIST"])
    assert code == 0
    assert "No health telemetry" in capsys.readouterr().out


def test_cmd_devices_and_console_uninitialized(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test commands when database is uninitialized."""
    cfg_uninit = GuardianConfig(home_dir=tmp_path / "uninit_dir")

    # devices uninitialized
    assert cmd_devices(MagicMock(), cfg_uninit) == 1
    assert "Database not initialized" in capsys.readouterr().out

    # console uninitialized
    assert cmd_console(MagicMock(), cfg_uninit) == 1
    assert "Database not initialized" in capsys.readouterr().out
