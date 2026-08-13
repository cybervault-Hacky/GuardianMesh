"""CLI integration tests for the Aegis Phase 8 screen-related commands."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run_cli(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
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
    res = _run_cli(tmp_path, "init", "--role=parent")
    assert res.returncode == 0, res.stderr


def test_doctor_reports_aegis_state(tmp_path: Path) -> None:
    """`guardian doctor` includes Aegis checks."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "doctor")
    assert res.returncode == 0, res.stdout + res.stderr
    # Aegis-specific check names.
    for key in (
        "Aegis module",
        "Screen authorization",
        "Nexus integration",
        "Resource limits",
        "Visible indicator",
    ):
        assert key in res.stdout, f"Missing doctor check: {key}"


def test_screen_diagnostics_includes_aegis(tmp_path: Path) -> None:
    """`guardian screen diagnostics --json` includes Aegis information."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "diagnostics", "--json")
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    # The Vista diagnostics may include the Aegis provider metadata.
    # We just check that the JSON is valid and contains expected keys.
    assert "provider_is_real_capture" in payload
    assert "transport_only" in payload


def test_doctor_on_linux_reports_adapter_only(tmp_path: Path) -> None:
    """`guardian doctor` on Linux reports the Android provider as adapter only."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "doctor")
    assert res.returncode == 0
    # The doctor output includes the visible indicator check, which on
    # Linux reports the adapter-only note.
    assert "Android screen provider: integration adapter only" in res.stdout


def test_no_aegis_remote_control_help(tmp_path: Path) -> None:
    """The Aegis CLI does not expose any remote-control commands."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "--help")
    assert res.returncode == 0
    forbidden = (
        "remote",
        "input",
        "tap",
        "click",
        "swipe",
        "gesture",
        "shell",
        "exec",
        "command",
        "keylog",
        "keystroke",
    )
    for word in forbidden:
        assert word not in res.stdout.lower(), f"Forbidden word in help: {word}"
