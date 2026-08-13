"""Deep coverage tests for Sentinel policy CRUD, alert lifecycle actions, and CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig
from guardianmesh.policy.alerts import AlertManager
from guardianmesh.policy.models import AlertSeverity, RuleType
from guardianmesh.storage.database import Database


def test_cli_policy_errors_and_missing_arguments(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test policy CLI subcommands with missing and non-existent IDs."""
    home_dir = str(tmp_path / "gm_pol_err")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # Show non-existent
    code_s = main(["--home-dir", home_dir, "policy", "show", "POL-NONEXIST"])
    assert code_s == 1
    assert "not found" in capsys.readouterr().out

    # Enable non-existent
    code_e = main(["--home-dir", home_dir, "policy", "enable", "POL-NONEXIST"])
    assert code_e == 1
    assert "Error" in capsys.readouterr().out

    # Disable non-existent
    code_d = main(["--home-dir", home_dir, "policy", "disable", "POL-NONEXIST"])
    assert code_d == 1
    assert "Error" in capsys.readouterr().out

    # Delete non-existent
    code_del = main(["--home-dir", home_dir, "policy", "delete", "POL-NONEXIST"])
    assert code_del == 1
    assert "Error" in capsys.readouterr().out

    # Create missing --device
    with pytest.raises(SystemExit) as excinfo:
        main(["--home-dir", home_dir, "policy", "create"])
    assert excinfo.value.code == 2


def test_cli_alerts_actions_and_filters(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test alert show, acknowledge, dismiss, resolve, and filters."""
    home_dir = str(tmp_path / "gm_alt_actions")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    main(["--home-dir", home_dir, "identity", "create", "--role", "child", "--no-activate"])
    capsys.readouterr()

    # Pair
    main(["--home-dir", home_dir, "pair", "--method", "demo"])
    out_pair = capsys.readouterr().out
    import re

    session_id = re.search(r"PAIR-[0-9A-F]{6}", out_pair).group(0)
    otp_code = re.search(r"Verification code:\s*(\d{6})", out_pair).group(1)
    main(["--home-dir", home_dir, "pair", "verify", session_id, otp_code])
    main(["--home-dir", home_dir, "pair", "authorize", session_id, "--label", "Child Tablet"])
    capsys.readouterr()

    # Directly create an alert in DB
    db = Database(Path(home_dir) / "data" / "guardian.db")
    config = GuardianConfig(home_dir=Path(home_dir))
    alert_mgr = AlertManager(db, config)
    alert = alert_mgr.create_or_update_alert(
        device_id="GM-C-TEST0001",
        policy_id="POL-01",
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery is 12%",
        trigger_value="12%",
    )

    # 1. Show alert
    code_s = main(["--home-dir", home_dir, "alerts", "show", alert.id])
    assert code_s == 0
    s_out = capsys.readouterr().out
    assert "Alert Details" in s_out
    assert "12%" in s_out

    # 2. Acknowledge alert
    code_ack = main(["--home-dir", home_dir, "alerts", "acknowledge", alert.id])
    assert code_ack == 0
    assert "ACKNOWLEDGED" in capsys.readouterr().out

    # 3. Dismiss alert
    code_dis = main(["--home-dir", home_dir, "alerts", "dismiss", alert.id])
    assert code_dis == 0
    assert "DISMISSED" in capsys.readouterr().out

    # 4. Resolve alert
    code_res = main(["--home-dir", home_dir, "alerts", "resolve", alert.id])
    assert code_res == 0
    assert "RESOLVED" in capsys.readouterr().out

    # 5. Show non-existent alert
    code_none = main(["--home-dir", home_dir, "alerts", "show", "ALT-NONEXIST"])
    assert code_none == 1
    assert "not found" in capsys.readouterr().out

    # 6. Action on non-existent alert
    assert main(["--home-dir", home_dir, "alerts", "acknowledge", "ALT-NONEXIST"]) == 1
    assert main(["--home-dir", home_dir, "alerts", "dismiss", "ALT-NONEXIST"]) == 1
    assert main(["--home-dir", home_dir, "alerts", "resolve", "ALT-NONEXIST"]) == 1
