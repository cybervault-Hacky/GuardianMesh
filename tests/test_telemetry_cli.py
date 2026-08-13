"""Tests for `guardian telemetry` CLI commands and terminal outputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.cli.main import main


def test_cli_telemetry_full_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test full CLI telemetry workflow: refresh -> status -> history -> pause -> resume."""
    home_dir = str(tmp_path / "gm_tel_cli")

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
    main(["--home-dir", home_dir, "pair", "authorize", session_id, "--label", "Child Phone"])
    capsys.readouterr()

    # Get child ID from list
    main(["--home-dir", home_dir, "pair", "list"])
    child_id = re.search(r"GM-C-[0-9A-F]{8}", capsys.readouterr().out).group(0)

    # 2. Overview: guardian telemetry
    code_ov = main(["--home-dir", home_dir, "telemetry"])
    assert code_ov == 0
    assert "Telemetry" in capsys.readouterr().out

    # 3. Refresh telemetry on-demand
    code_ref = main(["--home-dir", home_dir, "telemetry", "refresh", child_id])
    assert code_ref == 0
    ref_out = capsys.readouterr().out
    assert "Telemetry Refreshed" in ref_out
    assert "ONLINE" in ref_out

    # 4. Status
    code_stat = main(["--home-dir", home_dir, "telemetry", "status", child_id])
    assert code_stat == 0
    stat_out = capsys.readouterr().out
    assert "GuardianMesh Pulse" in stat_out
    assert "ONLINE" in stat_out
    assert "Last heartbeat" in stat_out

    # 5. History
    code_hist = main(["--home-dir", home_dir, "telemetry", "history", child_id, "--today"])
    assert code_hist == 0
    hist_out = capsys.readouterr().out
    assert "Device Health History" in hist_out
    assert "ONLINE" in hist_out

    # 6. Pause telemetry
    code_p = main(["--home-dir", home_dir, "telemetry", "pause", child_id])
    assert code_p == 0
    assert "paused" in capsys.readouterr().out

    # 7. Resume telemetry
    code_r = main(["--home-dir", home_dir, "telemetry", "resume", child_id])
    assert code_r == 0
    assert "resumed" in capsys.readouterr().out

    # 8. Top-level status reflects telemetry
    code_top = main(["--home-dir", home_dir, "status"])
    assert code_top == 0
    top_out = capsys.readouterr().out
    assert "Telemetry" in top_out
    assert "Monitored" in top_out
