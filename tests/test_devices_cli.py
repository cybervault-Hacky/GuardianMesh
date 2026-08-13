"""Tests for `guardian devices` CLI commands and JSON export options."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardianmesh.cli.main import main


def test_cli_devices_full_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test `guardian devices` subcommands: list, show, health, rename, revoke, and JSON mode."""
    home_dir = str(tmp_path / "gm_dev_cli")

    # 1. Initialize & pair
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    main(["--home-dir", home_dir, "identity", "create", "--role", "child", "--no-activate"])
    capsys.readouterr()

    main(["--home-dir", home_dir, "pair", "--method", "demo"])
    out_pair = capsys.readouterr().out
    import re

    session_id = re.search(r"PAIR-[0-9A-F]{6}", out_pair).group(0)
    otp_code = re.search(r"Verification code:\s*(\d{6})", out_pair).group(1)

    main(["--home-dir", home_dir, "pair", "verify", session_id, otp_code])
    main(["--home-dir", home_dir, "pair", "authorize", session_id, "--label", "Kid Galaxy Tab"])
    capsys.readouterr()

    # Get child ID
    main(["--home-dir", home_dir, "pair", "list"])
    child_id = re.search(r"GM-C-[0-9A-F]{8}", capsys.readouterr().out).group(0)

    # 2. Devices list
    code_list = main(["--home-dir", home_dir, "devices", "list"])
    assert code_list == 0
    list_out = capsys.readouterr().out
    assert "GuardianMesh Devices" in list_out
    assert child_id in list_out
    assert "Kid Galaxy Tab" in list_out

    # 3. Devices list --json
    code_json = main(["--home-dir", home_dir, "devices", "list", "--json"])
    assert code_json == 0
    json_out = capsys.readouterr().out
    parsed = json.loads(json_out)
    assert "devices" in parsed
    assert parsed["devices"][0]["device_id"] == child_id

    # 4. Refresh telemetry then check devices show & health
    main(["--home-dir", home_dir, "telemetry", "refresh", child_id])
    capsys.readouterr()

    code_show = main(["--home-dir", home_dir, "devices", "show", child_id])
    assert code_show == 0
    show_out = capsys.readouterr().out
    assert "Device Details" in show_out
    assert child_id in show_out
    assert "ONLINE" in show_out

    code_health = main(["--home-dir", home_dir, "devices", "health", child_id])
    assert code_health == 0
    health_out = capsys.readouterr().out
    assert "Device Health" in health_out
    assert "ONLINE" in health_out

    # 5. Rename device
    code_rename = main(["--home-dir", home_dir, "devices", "rename", child_id, "Kid Smart Tablet"])
    assert code_rename == 0
    assert "Renamed device" in capsys.readouterr().out

    # 6. Revoke device
    code_revoke = main(["--home-dir", home_dir, "devices", "revoke", child_id])
    assert code_revoke == 0
    assert "REVOKED" in capsys.readouterr().out
