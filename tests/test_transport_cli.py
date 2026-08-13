"""Tests for `guardian transport` CLI subcommands and JSON machine-readable outputs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardianmesh.cli.main import main
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.storage.database import Database


def setup_cli_transport_env(tmp_path: Path) -> tuple[str, str, str]:
    """Initialize environment, create parent identity, and pair a child device."""
    home_dir = str(tmp_path / "gm_transport_cli")

    # 1. Init parent
    init_code = main(["--home-dir", home_dir, "init", "--role", "parent", "--label", "Parent Hub"])
    assert init_code == 0

    # 2. Establish trusted child device in database
    db = Database(Path(home_dir) / "data" / "guardian.db")
    trust_mgr = TrustManager(db)

    parent_row = db.fetchone("SELECT id, public_key_pem FROM identities WHERE role = 'PARENT';")
    assert parent_row is not None
    parent_id = parent_row["id"]
    parent_pem = parent_row["public_key_pem"]
    child_id = "GM-C-19A84E72"

    child_priv, child_pub = generate_keypair()
    child_pem = public_key_to_pem(child_pub).decode("utf-8")

    from guardianmesh.security.secrets import KeyStorageManager
    key_storage = KeyStorageManager(Path(home_dir) / "keys")
    key_storage.save_keypair(child_id, child_priv, child_pub)

    trust_mgr.establish_trust(
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        remote_public_key_pem=child_pem,
        label="Kid Phone",
    )
    trust_mgr.establish_trust(
        local_identity_id=child_id,
        remote_identity_id=parent_id,
        remote_public_key_pem=parent_pem,
        label="Parent Device",
    )

    return home_dir, parent_id, child_id


def test_cli_transport_uninitialized(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test transport subcommands against clean, uninitialized directory."""
    home_dir = str(tmp_path / "clean_dir")

    # Text output
    code = main(["--home-dir", home_dir, "transport", "status"])
    assert code == 1
    err = capsys.readouterr().err
    assert "Database not initialized" in err

    # JSON output
    code_json = main(["--home-dir", home_dir, "transport", "status", "--json"])
    assert code_json == 1
    out_json = capsys.readouterr().out
    data = json.loads(out_json)
    assert "error" in data


def test_cli_transport_status_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test `guardian transport status` human and JSON outputs."""
    home_dir, _, _ = setup_cli_transport_env(tmp_path)

    # 1. Text status
    code = main(["--home-dir", home_dir, "transport", "status"])
    assert code == 0
    out = capsys.readouterr().out
    assert "GuardianMesh Transport Status" in out
    assert "Listen Endpoint:" in out
    assert "READY" in out

    # 2. JSON status
    code_json = main(["--home-dir", home_dir, "transport", "status", "--json"])
    assert code_json == 0
    out_json = capsys.readouterr().out
    d = json.loads(out_json)
    assert d["status"] == "READY"
    assert d["transport_enabled"] is True
    assert "listen_port" in d


def test_cli_transport_peers_and_sessions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test `guardian transport peers` and `sessions` commands."""
    home_dir, _, child_id = setup_cli_transport_env(tmp_path)

    # 1. Peers list (text)
    code_peers = main(["--home-dir", home_dir, "transport", "peers"])
    assert code_peers == 0
    out_peers = capsys.readouterr().out
    assert child_id in out_peers

    # 2. Peers list (JSON)
    code_peers_json = main(["--home-dir", home_dir, "transport", "peers", "--json"])
    assert code_peers_json == 0
    peers_data = json.loads(capsys.readouterr().out)
    assert "peers" in peers_data
    assert len(peers_data["peers"]) >= 1

    # 3. Sessions list (text & JSON)
    code_sess = main(["--home-dir", home_dir, "transport", "sessions"])
    assert code_sess == 0
    capsys.readouterr()

    code_sess_json = main(["--home-dir", home_dir, "transport", "sessions", "--json"])
    assert code_sess_json == 0
    sess_data = json.loads(capsys.readouterr().out)
    assert "sessions" in sess_data


def test_cli_transport_connect_disconnect_reconnect(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test connect, disconnect, and reconnect CLI workflows."""
    home_dir, _, child_id = setup_cli_transport_env(tmp_path)

    # 1. Connect
    code_conn = main(["--home-dir", home_dir, "transport", "connect", child_id])
    assert code_conn == 0
    out_conn = capsys.readouterr().out
    assert f"Connected to device '{child_id}'." in out_conn
    assert "CONNECTED" in out_conn

    # 2. Connect via JSON
    code_conn_json = main(["--home-dir", home_dir, "transport", "connect", child_id, "--json"])
    assert code_conn_json == 0
    d_conn = json.loads(capsys.readouterr().out)
    assert d_conn["status"] == "CONNECTED"
    assert d_conn["device_id"] == child_id

    # 3. Reconnect
    code_reconn = main(["--home-dir", home_dir, "transport", "reconnect", child_id])
    assert code_reconn == 0
    out_reconn = capsys.readouterr().out
    assert f"Reconnected to device '{child_id}'." in out_reconn

    # 4. Reconnect via JSON
    code_reconn_json = main(["--home-dir", home_dir, "transport", "reconnect", child_id, "--json"])
    assert code_reconn_json == 0
    d_reconn = json.loads(capsys.readouterr().out)
    assert d_reconn["status"] == "RECONNECTED"

    # 5. Disconnect
    code_disc = main(["--home-dir", home_dir, "transport", "disconnect", child_id])
    assert code_disc == 0
    out_disc = capsys.readouterr().out
    assert f"Disconnected from device '{child_id}'." in out_disc

    # 6. Disconnect via JSON
    code_disc_json = main(["--home-dir", home_dir, "transport", "disconnect", child_id, "--json"])
    assert code_disc_json == 0
    d_disc = json.loads(capsys.readouterr().out)
    assert d_disc["status"] == "DISCONNECTED"


def test_cli_transport_error_handling(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI error handling on invalid device IDs, revoked devices, and missing targets."""
    home_dir, parent_id, child_id = setup_cli_transport_env(tmp_path)

    # 1. Connect to non-existent / untrusted device
    code_untrusted = main(["--home-dir", home_dir, "transport", "connect", "GM-C-00000000"])
    assert code_untrusted == 1
    err_untrusted = capsys.readouterr().err
    assert "not in the trusted devices registry" in err_untrusted

    # 2. Connect to revoked device
    db = Database(Path(home_dir) / "data" / "guardian.db")
    trust_mgr = TrustManager(db)
    trust_mgr.revoke_trust(parent_id, child_id)

    code_revoked = main(["--home-dir", home_dir, "transport", "connect", child_id])
    assert code_revoked == 1
    err_revoked = capsys.readouterr().err
    assert "REVOKED" in err_revoked
