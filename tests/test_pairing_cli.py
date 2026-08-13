"""Tests for `guardian pair` CLI subcommands and user interface workflows."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.cli.main import main


def test_cli_pair_full_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test full CLI pairing workflow: init -> pair -> verify -> authorize -> list -> revoke -> status."""
    home_dir = str(tmp_path / "gm_pair_cli")

    # 1. Init parent
    main(["--home-dir", home_dir, "init", "--role", "parent", "--label", "Parent Dev"])
    capsys.readouterr()

    # 2. Init child
    child_args = [
        "--home-dir",
        home_dir,
        "identity",
        "create",
        "--role",
        "child",
        "--label",
        "Kid Tablet",
        "--no-activate",
    ]
    main(child_args)
    capsys.readouterr()

    # 3. Create pairing session via demo method
    code_start = main(["--home-dir", home_dir, "pair", "--method", "demo"])
    assert code_start == 0
    start_out = capsys.readouterr().out
    assert "Pairing Session Created" in start_out
    assert "DEMO VERIFICATION MODE" in start_out

    # Extract session ID and verification code
    import re

    session_match = re.search(r"PAIR-[0-9A-F]{6}", start_out)
    otp_match = re.search(r"Verification code:\s*(\d{6})", start_out)
    assert session_match is not None
    assert otp_match is not None
    session_id = session_match.group(0)
    otp_code = otp_match.group(1)

    # 4. Check pair status
    code_status = main(["--home-dir", home_dir, "pair", "status", "--session", session_id])
    assert code_status == 0
    status_out = capsys.readouterr().out
    assert session_id in status_out
    assert "VERIFICATION_PENDING" in status_out

    # 5. Verify OTP via CLI
    code_verify = main(["--home-dir", home_dir, "pair", "verify", session_id, otp_code])
    assert code_verify == 0
    verify_out = capsys.readouterr().out
    assert "Verification Successful" in verify_out

    # 6. Authorize via CLI test adapter
    code_auth = main(["--home-dir", home_dir, "pair", "authorize", session_id, "--label", "Child Tablet"])
    assert code_auth == 0
    auth_out = capsys.readouterr().out
    assert "Trust Established" in auth_out
    assert "ACTIVE" in auth_out

    # 7. List trusted devices
    code_list = main(["--home-dir", home_dir, "pair", "list"])
    assert code_list == 0
    list_out = capsys.readouterr().out
    assert "Trusted Devices" in list_out
    assert "GM-C-" in list_out
    assert "ACTIVE" in list_out

    # Extract child device ID from list output
    child_id_match = re.search(r"GM-C-[0-9A-F]{8}", list_out)
    assert child_id_match is not None
    child_id = child_id_match.group(0)

    # 8. Rename trusted device
    code_rename = main(["--home-dir", home_dir, "pair", "rename", child_id, "Renamed Tablet"])
    assert code_rename == 0
    assert "Renamed device" in capsys.readouterr().out

    # 9. Top-level status reflects trusted devices
    code_top_status = main(["--home-dir", home_dir, "status"])
    assert code_top_status == 0
    top_status_out = capsys.readouterr().out
    assert "1 active device(s)" in top_status_out

    # 10. Revoke device trust
    code_revoke = main(["--home-dir", home_dir, "pair", "revoke", child_id])
    assert code_revoke == 0
    revoke_out = capsys.readouterr().out
    assert "REVOKED" in revoke_out

    # List shows REVOKED status
    main(["--home-dir", home_dir, "pair", "list"])
    assert "REVOKED" in capsys.readouterr().out


def test_cli_pair_denial(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI child authorization denial."""
    home_dir = str(tmp_path / "gm_pair_deny")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    main(["--home-dir", home_dir, "identity", "create", "--role", "child", "--no-activate"])
    capsys.readouterr()

    # Start session
    main(["--home-dir", home_dir, "pair", "--method", "demo"])
    out = capsys.readouterr().out
    import re

    session_id = re.search(r"PAIR-[0-9A-F]{6}", out).group(0)
    otp_code = re.search(r"Verification code:\s*(\d{6})", out).group(1)

    # Verify
    main(["--home-dir", home_dir, "pair", "verify", session_id, otp_code])
    capsys.readouterr()

    # Authorize with --deny
    code_deny = main(["--home-dir", home_dir, "pair", "authorize", session_id, "--deny"])
    assert code_deny == 1
    deny_out = capsys.readouterr().out
    assert "DENIED" in deny_out


def test_cli_pair_cancel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test cancelling a session via CLI."""
    home_dir = str(tmp_path / "gm_pair_cancel")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    main(["--home-dir", home_dir, "pair", "--method", "demo"])
    out = capsys.readouterr().out
    import re

    session_id = re.search(r"PAIR-[0-9A-F]{6}", out).group(0)

    code_cancel = main(["--home-dir", home_dir, "pair", "cancel", session_id])
    assert code_cancel == 0
    assert "CANCELLED" in capsys.readouterr().out
