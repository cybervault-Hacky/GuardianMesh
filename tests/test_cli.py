"""Tests for GuardianMesh CLI interface, subcommands, output formatting, and exit codes."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh import __phase__, __version__
from guardianmesh.cli.commands import get_terminal_width, print_divider
from guardianmesh.cli.main import main


def test_cli_bare_invocation(capsys: pytest.CaptureFixture[str]) -> None:
    """Test calling `guardian` with no arguments prints usage and exits 0."""
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert f"GuardianMesh {__version__} ({__phase__})" in captured.out
    assert "guardian version" in captured.out
    assert "guardian doctor" in captured.out
    assert "guardian status" in captured.out


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Test `guardian version` and `--version` flags."""
    code1 = main(["version"])
    assert code1 == 0
    out1 = capsys.readouterr().out
    assert f"GuardianMesh {__version__}" in out1
    assert f"{__phase__}" in out1

    code2 = main(["--version"])
    assert code2 == 0
    out2 = capsys.readouterr().out
    assert f"GuardianMesh {__version__}" in out2

    code3 = main(["-v"])
    assert code3 == 0
    out3 = capsys.readouterr().out
    assert f"GuardianMesh {__version__}" in out3


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Test `guardian --help`."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "usage: guardian" in out
    assert "Consent-based parental device supervision system" in out


def test_cli_uninitialized_doctor_and_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test doctor and status commands on a clean, uninitialized environment."""
    home_dir = str(tmp_path / "gm_clean")

    # Status on uninitialized environment
    status_code = main(["--home-dir", home_dir, "status"])
    assert status_code == 0
    status_out = capsys.readouterr().out
    assert "NOT INITIALIZED" in status_out

    # Doctor on uninitialized environment: should return exit code 1
    doctor_code = main(["--home-dir", home_dir, "doctor"])
    assert doctor_code == 1
    doctor_out = capsys.readouterr().out
    assert "Database           ✗" in doctor_out
    assert "Identity           ✗" in doctor_out


def test_cli_full_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test full workflow: init -> status -> doctor -> identity -> audit -> config."""
    home_dir = str(tmp_path / "gm_full")

    # 1. Initialize
    init_code = main(["--home-dir", home_dir, "init", "--role", "parent", "--label", "Main Laptop"])
    assert init_code == 0
    init_out = capsys.readouterr().out
    assert "GuardianMesh" in init_out
    assert "Initialized" in init_out
    assert "GM-P-" in init_out
    assert "Parent" in init_out
    assert "READY" in init_out

    # 2. Re-init without --force is idempotent and reports already initialized
    reinit_code = main(["--home-dir", home_dir, "init"])
    assert reinit_code == 0
    reinit_out = capsys.readouterr().out
    assert "already initialized" in reinit_out

    # 3. Status
    status_code = main(["--home-dir", home_dir, "status"])
    assert status_code == 0
    status_out = capsys.readouterr().out
    assert "Parent ID     GM-P-" in status_out
    assert "Database      READY" in status_out
    assert "Key material  READY" in status_out
    assert "Pairing:" in status_out

    # 4. Doctor (should now pass 100% with exit code 0)
    doctor_code = main(["--home-dir", home_dir, "doctor"])
    assert doctor_code == 0
    doctor_out = capsys.readouterr().out
    assert "Python             ✓" in doctor_out
    assert "Platform           ✓" in doctor_out
    assert "Data directory     ✓" in doctor_out
    assert "Database           ✓" in doctor_out
    assert "Identity           ✓" in doctor_out
    assert "Key storage        ✓" in doctor_out
    assert "Permissions        ✓" in doctor_out
    assert "Configuration      ✓" in doctor_out

    # 5. Identity management
    # List identities
    list_code = main(["--home-dir", home_dir, "identity", "list"])
    assert list_code == 0
    list_out = capsys.readouterr().out
    assert "GM-P-" in list_out
    assert "PARENT" in list_out
    assert "ACTIVE" in list_out

    # Show active identity
    show_code = main(["--home-dir", home_dir, "identity", "show"])
    assert show_code == 0
    show_out = capsys.readouterr().out
    assert "Identity Details" in show_out
    assert "GM-P-" in show_out

    # Create child identity
    create_child_code = main(
        ["--home-dir", home_dir, "identity", "create", "--role", "child", "--label", "Child Tablet"]
    )
    assert create_child_code == 0
    create_child_out = capsys.readouterr().out
    assert "Identity Created" in create_child_out
    assert "GM-C-" in create_child_out
    assert "Child" in create_child_out

    # 6. Audit log
    audit_code = main(["--home-dir", home_dir, "audit", "list"])
    assert audit_code == 0
    audit_out = capsys.readouterr().out
    assert "GuardianMesh Audit Trail" in audit_out
    assert "IDENTITY_CREATED" in audit_out
    assert "DOCTOR_RUN" in audit_out

    # 7. Config
    cfg_code = main(["--home-dir", home_dir, "config", "show"])
    assert cfg_code == 0
    cfg_out = capsys.readouterr().out
    assert "GuardianMesh Configuration" in cfg_out
    assert "version" in cfg_out


def test_cli_narrow_terminal_and_formatting(capsys: pytest.CaptureFixture[str]) -> None:
    """Test formatting and terminal width helpers."""
    width = get_terminal_width()
    assert 40 <= width <= 100

    print_divider(width=20)
    out = capsys.readouterr().out
    assert out.strip() == "─" * 20
