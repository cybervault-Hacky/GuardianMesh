"""CLI integration tests for the Phase 9: Orion orchestrate command."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run the guardian CLI in a temporary home directory."""
    env = os.environ.copy()
    env["GUARDIANMESH_HOME"] = str(tmp_path)
    env["GUARDIANMESH_LOG_LEVEL"] = "ERROR"
    return subprocess.run(
        [sys.executable, "-m", "guardianmesh.cli.main", *args],
        env=env,
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )


def _init(tmp_path: Path) -> None:
    """Initialize the repository in the temp home."""
    res = _run_cli(tmp_path, "init", "--role=parent")
    assert res.returncode == 0, res.stderr


def test_orchestrate_help(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "orchestrate", "--help")
    assert res.returncode == 0
    assert "orchestrate" in res.stdout.lower() or "orion" in res.stdout.lower()


def test_orchestrate_status_before_init(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "orchestrate", "status")
    # Should not crash; either returns 1 with an error message OR prints a
    # status. We accept both, but require no Python traceback.
    assert "Traceback" not in res.stderr


def test_orchestrate_status_after_init(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "status")
    assert res.returncode == 0
    # Output should reference Orion or status fields.
    assert "Orion" in res.stdout or "orion" in res.stdout.lower()


def test_orchestrate_status_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "status", "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "running" in data
    assert "queue" in data
    assert "bus" in data
    assert "capabilities" in data


def test_orchestrate_events_empty(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "events")
    assert res.returncode == 0


def test_orchestrate_events_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "events", "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "events" in data


def test_orchestrate_actions_empty(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "actions")
    assert res.returncode == 0


def test_orchestrate_actions_status_filter(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "actions", "--status", "pending")
    assert res.returncode == 0


def test_orchestrate_action_not_found(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "action", "OAC-DOES-NOT-EXIST")
    # Returns 1 with error.
    assert res.returncode == 1


def test_orchestrate_reconcile(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "reconcile", "GM-C-19A84E72")
    assert res.returncode == 0
    assert "ORC-" in res.stdout


def test_orchestrate_reconcile_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "reconcile", "GM-C-19A84E72", "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["device_id"] == "GM-C-19A84E72"
    assert data["report_id"].startswith("ORC-")


def test_orchestrate_capabilities_listing(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "capabilities")
    assert res.returncode == 0


def test_orchestrate_capabilities_for_known_device(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "capabilities", "ORION")
    assert res.returncode == 0
    # Should mention ORION device id or capabilities.
    assert "ORION" in res.stdout


def test_orchestrate_capabilities_for_unknown_device(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "orchestrate", "capabilities", "GM-C-UNKNOWN")
    # Returns 1 because no capabilities recorded.
    assert res.returncode == 1


def test_capabilities_shorthand(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "capabilities", "ORION")
    assert res.returncode == 0


def test_capabilities_shorthand_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "capabilities", "ORION", "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["device_id"] == "ORION"


def test_capabilities_shorthand_requires_device(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "capabilities")
    # argparse exits with 2 on missing required args; either 1 or 2 is acceptable.
    assert res.returncode in (1, 2)


def test_orchestrate_retry_missing_action_id(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "orchestrate", "retry")
    assert res.returncode in (1, 2)


def test_orchestrate_cancel_missing_action_id(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "orchestrate", "cancel")
    assert res.returncode in (1, 2)


def test_orchestrate_reconcile_missing_device(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "orchestrate", "reconcile")
    assert res.returncode in (1, 2)
