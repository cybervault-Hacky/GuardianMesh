"""CLI integration tests for the Phase 10: Atlas platform."""

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


def test_atlas_help(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "atlas", "--help")
    assert res.returncode == 0
    assert "atlas" in res.stdout.lower() or "orion" in res.stdout.lower()


def test_atlas_status_before_init(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "atlas", "status")
    assert "Traceback" not in res.stderr


def test_atlas_status_after_init(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "status")
    assert res.returncode == 0
    assert "Atlas" in res.stdout


def test_atlas_status_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "status")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "genesis" in data


def test_atlas_backup(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "backup")
    assert res.returncode == 0
    assert "BAK-" in res.stdout


def test_atlas_backup_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "backup")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["backup_id"].startswith("BAK-")


def test_atlas_backup_with_device(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "backup", "--device=GM-C-19A84E72")
    assert res.returncode == 0


def test_atlas_restore_requires_backup_id(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "restore")
    assert res.returncode in (1, 2)


def test_atlas_restore_dry_run(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "backup")
    assert res.returncode == 0
    # Extract backup ID from output.
    lines = res.stdout.splitlines()
    backup_id = None
    for line in lines:
        if "backup_id" in line:
            backup_id = line.split()[-1].strip()
    assert backup_id is not None
    res = _run_cli(tmp_path, "atlas", "restore", backup_id)
    assert res.returncode == 0


def test_atlas_recover(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "recover")
    assert res.returncode == 0
    assert "Recovery" in res.stdout


def test_atlas_recover_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "recover")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert len(data) == 3


def test_atlas_retention_dry_run(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "retention")
    assert res.returncode == 0
    assert "DRY RUN" in res.stdout


def test_atlas_retention_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "retention")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["dry_run"] is True


def test_atlas_health(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "health")
    assert res.returncode == 0
    assert "Health" in res.stdout


def test_atlas_health_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "health")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "subsystems" in data


def test_atlas_capabilities(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "capabilities")
    assert res.returncode == 0
    assert "genesis" in res.stdout


def test_atlas_capabilities_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "capabilities")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "capabilities" in data
    assert len(data["capabilities"]) >= 1


def test_atlas_version(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "version")
    assert res.returncode == 0
    assert "GuardianMesh" in res.stdout


def test_atlas_version_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "atlas", "--json", "version")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert data["orion_version"] == "1.1.0"


def test_diagnostics_help(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "diagnostics", "--help")
    assert res.returncode == 0


def test_diagnostics_before_init(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "diagnostics")
    assert "Traceback" not in res.stderr


def test_diagnostics_after_init(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "diagnostics")
    assert res.returncode == 0


def test_diagnostics_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "diagnostics", "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "checks" in data
    assert "passed" in data


def test_diagnostics_full(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "diagnostics", "--full")
    assert res.returncode == 0
    assert "Diagnostics" in res.stdout


def test_release_before_init(tmp_path: Path) -> None:
    res = _run_cli(tmp_path, "release")
    assert "Traceback" not in res.stderr


def test_release_after_init(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "release")
    assert res.returncode == 0
    assert "READY" in res.stdout


def test_release_json(tmp_path: Path) -> None:
    _init(tmp_path)
    res = _run_cli(tmp_path, "release", "--json")
    assert res.returncode == 0
    data = json.loads(res.stdout)
    assert "ready" in data
    assert data["ready"] is True
