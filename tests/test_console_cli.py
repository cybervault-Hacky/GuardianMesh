"""Tests for `guardian console` CLI commands, non-interactive mode, JSON exports, and watch mode."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from guardianmesh.cli.main import main


def test_cli_console_dashboard_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test `guardian console` and subcommands in non-interactive and JSON mode."""
    home_dir = str(tmp_path / "gm_con_cli")

    # 1. Initialize
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # 2. Console dashboard non-interactive
    code_dash = main(["--home-dir", home_dir, "console", "dashboard"])
    assert code_dash == 0
    dash_out = capsys.readouterr().out
    assert "GuardianMesh" in dash_out
    assert "Console" in dash_out
    assert "DEVICES" in dash_out
    assert "HEALTH" in dash_out
    assert "ALERTS" in dash_out

    # 3. Console dashboard --json
    code_json = main(["--home-dir", home_dir, "console", "dashboard", "--json"])
    assert code_json == 0
    json_out = capsys.readouterr().out
    parsed = json.loads(json_out)
    assert "device_count" in parsed
    assert "subsystem_status" in parsed

    # 4. Console subcommands: devices, alerts, policies, pairing, audit, status
    assert main(["--home-dir", home_dir, "console", "devices"]) == 0
    assert "No trusted devices" in capsys.readouterr().out

    assert main(["--home-dir", home_dir, "console", "alerts"]) == 0
    assert "No alerts found" in capsys.readouterr().out

    assert main(["--home-dir", home_dir, "console", "policies"]) == 0
    assert "No policies configured" in capsys.readouterr().out

    assert main(["--home-dir", home_dir, "console", "pairing"]) == 0
    assert "Pairing Overview" in capsys.readouterr().out

    assert main(["--home-dir", home_dir, "console", "audit"]) == 0
    assert "Recent Activity" in capsys.readouterr().out

    assert main(["--home-dir", home_dir, "console", "status"]) == 0
    assert "System Status" in capsys.readouterr().out


def test_cli_console_watch_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test watch mode runs bounded iterations."""
    home_dir = str(tmp_path / "gm_con_watch")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    from guardianmesh.console.dashboard import DashboardController

    with patch.object(DashboardController, "watch") as mock_watch:
        code = main(["--home-dir", home_dir, "console", "--watch", "--refresh-interval", "2"])
        assert code == 0
        mock_watch.assert_called_once_with(interval_seconds=2, format_json=False)


def test_cli_console_interactive_menu(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test interactive menu options 1, 2, 7, and 8 (exit)."""
    home_dir = str(tmp_path / "gm_con_menu")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    with (
        patch("sys.stdout.isatty", return_value=True),
        patch("builtins.input", side_effect=["1", "2", "7", "8"]),
    ):
        code = main(["--home-dir", home_dir, "console"])
        assert code == 0
        out = capsys.readouterr().out
        assert "GuardianMesh Console" in out
        assert "Exiting console." in out
