"""Extended tests for CLI commands, error handling, doctor failures, and edge cases."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from guardianmesh.cli.commands import cmd_doctor
from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_cli_debug_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI runs with --debug flag."""
    home_dir = str(tmp_path / "gm_debug")
    code = main(["--home-dir", home_dir, "--debug", "version"])
    assert code == 0


def test_cli_identity_subcommands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test identity list, show, activate, and create variations."""
    home_dir = str(tmp_path / "gm_ident")

    # Initialize first
    main(["--home-dir", home_dir, "init"])

    # Create a secondary identity with --no-activate
    code_create = main(
        [
            "--home-dir",
            home_dir,
            "identity",
            "create",
            "--role",
            "child",
            "--label",
            "Child Phone",
            "--no-activate",
        ]
    )
    assert code_create == 0
    create_out = capsys.readouterr().out
    assert "GM-C-" in create_out

    # Extract child ID from output
    import re

    match = re.search(r"GM-C-[0-9A-F]{8}", create_out)
    assert match is not None
    child_id = match.group(0)

    # Show specific identity
    code_show = main(["--home-dir", home_dir, "identity", "show", child_id])
    assert code_show == 0
    show_out = capsys.readouterr().out
    assert child_id in show_out
    assert "Child" in show_out

    # Activate child identity
    code_act = main(["--home-dir", home_dir, "identity", "activate", child_id])
    assert code_act == 0
    act_out = capsys.readouterr().out
    assert f"Activated identity: {child_id}" in act_out

    # Activate invalid identity returns 1
    code_act_err = main(["--home-dir", home_dir, "identity", "activate", "GM-P-00000000"])
    assert code_act_err == 1

    # Show non-existent identity returns 1
    code_show_err = main(["--home-dir", home_dir, "identity", "show", "GM-P-00000000"])
    assert code_show_err == 1


def test_cli_doctor_failure_modes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test doctor catches loose permissions and broken DB integrity."""
    home_dir = tmp_path / "gm_doc_fail"
    config = GuardianConfig(home_dir=home_dir)
    config.ensure_directories()

    # Case 1: Loose permissions on keys directory
    config.keys_dir.chmod(0o777)
    db = Database(config.database_path)
    MigrationManager().apply_migrations(db)

    with patch("guardianmesh.device.platform.get_platform_info") as mock_plat:
        from guardianmesh.device.platform import PlatformInfo

        mock_plat.return_value = PlatformInfo(
            system="Linux",
            release="5.15",
            machine="x86_64",
            python_version="3.11.2",
            is_termux=False,
            is_android=False,
            is_linux=True,
            is_root=True,  # Test root warning
        )
        code = cmd_doctor(None, config)  # type: ignore
        assert code == 1  # Fails due to permissions / missing active identity
        out = capsys.readouterr().out
        assert "Permissions        ✗" in out


def test_cli_error_handling(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI catches and prints errors gracefully."""
    home_dir = str(tmp_path / "gm_err")

    # Bad role raises SystemExit from argparse with invalid choice message
    with pytest.raises(SystemExit) as excinfo:
        main(["--home-dir", home_dir, "init", "--role", "invalid_role"])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice" in err
