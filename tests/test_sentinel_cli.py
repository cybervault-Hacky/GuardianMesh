"""Tests for Sentinel CLI commands: `guardian policy` and `guardian alerts`."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.cli.main import main


def test_cli_policy_and_alerts_workflows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test full Sentinel CLI workflow: pair -> policy list -> policy show -> disable -> enable -> alerts."""
    home_dir = str(tmp_path / "gm_sentinel_cli")

    # 1. Initialize parent & pair child
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    main(["--home-dir", home_dir, "identity", "create", "--role", "child", "--no-activate"])
    capsys.readouterr()

    main(["--home-dir", home_dir, "pair", "--method", "demo"])
    out_pair = capsys.readouterr().out
    import re

    session_id = re.search(r"PAIR-[0-9A-F]{6}", out_pair).group(0)
    otp_code = re.search(r"Verification code:\s*(\d{6})", out_pair).group(1)

    main(["--home-dir", home_dir, "pair", "verify", session_id, otp_code])
    main(["--home-dir", home_dir, "pair", "authorize", session_id, "--label", "Child Tablet"])
    capsys.readouterr()

    # Get child ID
    main(["--home-dir", home_dir, "pair", "list"])
    child_id = re.search(r"GM-C-[0-9A-F]{8}", capsys.readouterr().out).group(0)

    # 2. Policy create
    create_args = [
        "--home-dir",
        home_dir,
        "policy",
        "create",
        "--device",
        child_id,
        "--name",
        "Tablet Health Policy",
    ]
    code_p_create = main(create_args)
    assert code_p_create == 0
    p_create_out = capsys.readouterr().out
    assert "Created policy" in p_create_out
    policy_id = re.search(r"POL-[0-9A-F]{6}", p_create_out).group(0)

    # 3. Policy list
    code_p_list = main(["--home-dir", home_dir, "policy", "list"])
    assert code_p_list == 0
    p_list_out = capsys.readouterr().out
    assert policy_id in p_list_out
    assert "ENABLED" in p_list_out

    # 4. Policy show
    code_p_show = main(["--home-dir", home_dir, "policy", "show", policy_id])
    assert code_p_show == 0
    p_show_out = capsys.readouterr().out
    assert "Policy Details" in p_show_out
    assert "LOW_BATTERY" in p_show_out

    # 5. Policy disable & enable
    assert main(["--home-dir", home_dir, "policy", "disable", policy_id]) == 0
    assert "DISABLED" in capsys.readouterr().out

    assert main(["--home-dir", home_dir, "policy", "enable", policy_id]) == 0
    assert "ENABLED" in capsys.readouterr().out

    # 6. Refresh telemetry to generate alert (or inspect alerts)
    main(["--home-dir", home_dir, "telemetry", "refresh", child_id])
    capsys.readouterr()

    # 7. Alerts active overview
    code_al = main(["--home-dir", home_dir, "alerts"])
    assert code_al == 0
    al_out = capsys.readouterr().out
    assert "Sentinel" in al_out

    # 8. Alerts list
    code_al_list = main(["--home-dir", home_dir, "alerts", "list"])
    assert code_al_list == 0
