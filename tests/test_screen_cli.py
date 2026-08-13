"""CLI integration tests for the Phase 7: Vista screen command."""

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


def _init(tmp_path: Path, role: str = "parent") -> None:
    """Initialize the repository in the temp home."""
    res = _run_cli(tmp_path, "init", f"--role={role}")
    assert res.returncode == 0, res.stderr


def test_screen_help(tmp_path: Path) -> None:
    """`guardian screen --help` returns 0 and lists subcommands."""
    res = _run_cli(tmp_path, "screen", "--help")
    assert res.returncode == 0
    assert "status" in res.stdout
    assert "request" in res.stdout
    assert "approve" in res.stdout
    assert "deny" in res.stdout
    assert "stop" in res.stdout
    assert "view" in res.stdout
    assert "diagnostics" in res.stdout


def test_screen_status_no_sessions(tmp_path: Path) -> None:
    """`guardian screen status` runs cleanly on an empty database."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "status")
    assert res.returncode == 0
    assert "Vista" in res.stdout or "No screen" in res.stdout


def test_screen_status_json(tmp_path: Path) -> None:
    """`guardian screen status --json` returns valid JSON."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "status", "--json")
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    assert "active_identity" in payload
    assert "sessions" in payload


def test_screen_diagnostics(tmp_path: Path) -> None:
    """`guardian screen diagnostics --json` exposes the documented fields."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "diagnostics", "--json")
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    for key in (
        "total_sessions",
        "active_sessions",
        "pending_authorizations",
        "denied_sessions",
        "expired_sessions",
        "revoked_sessions",
        "indicator_provider_class",
        "provider_is_real_capture",
        "transport_only",
    ):
        assert key in payload
    assert payload["provider_is_real_capture"] is False
    assert payload["transport_only"] is True


def test_screen_list_empty(tmp_path: Path) -> None:
    """`guardian screen list` runs cleanly on an empty database."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "list")
    assert res.returncode == 0
    assert "No screen" in res.stdout or "Sessions" in res.stdout


def test_screen_request_requires_trusted_device(tmp_path: Path) -> None:
    """Requesting a view from an untrusted device is rejected."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "screen", "request", "GM-C-UNTRUSTED1")
    assert res.returncode != 0
    # Error message about trust.
    assert (
        "trust" in res.stderr.lower()
        or "not found" in res.stderr.lower()
        or "identity id" in res.stderr.lower()
        or "invalid" in res.stderr.lower()
    )


def test_screen_full_workflow(tmp_path: Path) -> None:
    """End-to-end happy path: pair -> request -> approve -> start -> stop."""
    # Initialize parent
    _init(tmp_path, role="parent")

    # We need a trusted child device. Use a second identity and trust it
    # via the trust manager directly.
    from guardianmesh.core.config import GuardianConfig
    from guardianmesh.identity.manager import IdentityManager
    from guardianmesh.identity.models import IdentityRole
    from guardianmesh.pairing.trust import TrustManager
    from guardianmesh.security.secrets import KeyStorageManager
    from guardianmesh.storage.audit import AuditLogger
    from guardianmesh.storage.database import Database
    from guardianmesh.storage.migrations import MigrationManager

    config = GuardianConfig(home_dir=tmp_path)
    config.ensure_directories()
    db = Database(config.database_path)
    MigrationManager().apply_migrations(db)
    key_storage = KeyStorageManager(config.keys_dir)
    identity_mgr = IdentityManager(db, key_storage)
    audit = AuditLogger(db)
    active = identity_mgr.get_active_identity()
    assert active is not None

    child_ident, _ = identity_mgr.create_identity(
        role=IdentityRole.CHILD, label="CLI Child", set_active=False
    )
    trust_mgr = TrustManager(db, audit)
    trust_mgr.establish_trust(
        local_identity_id=active.id,
        remote_identity_id=child_ident.id,
        remote_public_key_pem=child_ident.public_key_pem,
    )

    # Request screen view.
    res = _run_cli(tmp_path, "screen", "request", child_ident.id)
    assert res.returncode == 0, res.stderr
    assert "Screen view requested" in res.stdout

    # Parse session id from output.
    import re

    m = re.search(r"Session ID: (SCN-[A-F0-9]+)", res.stdout)
    assert m is not None
    session_id = m.group(1)

    # Approve.
    res = _run_cli(tmp_path, "screen", "approve", session_id)
    assert res.returncode == 0, res.stderr
    assert "APPROVED" in res.stdout

    # Start.
    res = _run_cli(tmp_path, "screen", "start", session_id)
    assert res.returncode == 0, res.stderr
    assert "ACTIVE" in res.stdout

    # Status.
    res = _run_cli(tmp_path, "screen", "status", "--json")
    assert res.returncode == 0
    payload = json.loads(res.stdout)
    assert any(s.get("session_id") == session_id for s in payload["sessions"])

    # View (metadata only).
    res = _run_cli(tmp_path, "screen", "view", session_id)
    assert res.returncode == 0, res.stderr
    assert "SCREEN VIEW ACTIVE" in res.stdout

    # Stop.
    res = _run_cli(tmp_path, "screen", "stop", session_id)
    assert res.returncode == 0, res.stderr
    assert "stopped" in res.stdout.lower()


def test_doctor_passes_after_init(tmp_path: Path) -> None:
    """`guardian doctor` passes after a fresh init, including all Vista checks."""
    _init(tmp_path)
    res = _run_cli(tmp_path, "doctor")
    assert res.returncode == 0, res.stdout + res.stderr
    # Spot-check Vista-specific output.
    assert "Vista module" in res.stdout
    assert "Screen authorization" in res.stdout
    assert "Frame validation" in res.stdout
    assert "Nexus integration" in res.stdout
    assert "Visible indicator" in res.stdout
    assert "Screen session manager" in res.stdout
    assert "Child stop mechanism" in res.stdout
