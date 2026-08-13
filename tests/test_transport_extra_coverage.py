"""Additional unit and coverage tests for Nexus transport, renderer views, framing, and CLI branches."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from guardianmesh.cli.main import main
from guardianmesh.console.formatters import TerminalFormatter
from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager
from guardianmesh.transport.client import (
    LocalSocketTransportClient,
    RelayTransport,
)
from guardianmesh.transport.models import (
    MessageType,
    TransportEnvelope,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.server import (
    LocalSocketTransportServer,
)


def test_renderer_transport_views() -> None:
    """Test ConsoleRenderer transport status, peers, and sessions views (both terminal and JSON)."""
    renderer = ConsoleRenderer(TerminalFormatter(color_enabled=False))

    # 1. Status view
    status_data = {
        "status": "READY",
        "listen_host": "0.0.0.0",
        "listen_port": 8443,
        "active_sessions": 2,
        "connected_peers": 1,
        "total_peers": 3,
        "mode": "LOCAL",
    }
    rendered_status = renderer.render_transport_status(status_data, format_json=False)
    assert "GuardianMesh Transport Status" in rendered_status
    assert "0.0.0.0:8443" in rendered_status

    json_status = renderer.render_transport_status(status_data, format_json=True)
    assert '"status": "READY"' in json_status

    # 2. Peers view
    peers = [
        {
            "device_id": "GM-C-19A84E72",
            "role": "CHILD",
            "connection_state": "CONNECTED",
            "active_session_id": "SES-01",
            "last_seen_at": "2026-08-13T02:00:00Z",
            "reconnect_count": 0,
        }
    ]
    rendered_peers = renderer.render_peers(peers, format_json=False)
    assert "GM-C-19A84E72" in rendered_peers
    assert "CONNECTED" in rendered_peers

    json_peers = renderer.render_peers(peers, format_json=True)
    assert '"GM-C-19A84E72"' in json_peers

    empty_peers = renderer.render_peers([], format_json=False)
    assert "No transport peers registered yet" in empty_peers

    # 3. Sessions view
    sessions = [
        {
            "session_id": "SES-01",
            "remote_identity_id": "GM-C-19A84E72",
            "state": "CONNECTED",
            "transport_type": "LOCAL",
            "established_at": "2026-08-13T02:00:00Z",
            "expires_at": "2026-08-13T03:00:00Z",
        }
    ]
    rendered_sess = renderer.render_sessions(sessions, format_json=False)
    assert "SES-01" in rendered_sess
    assert "LOCAL" in rendered_sess

    json_sess = renderer.render_sessions(sessions, format_json=True)
    assert '"SES-01"' in json_sess

    empty_sess = renderer.render_sessions([], format_json=False)
    assert "No transport sessions recorded" in empty_sess


def test_relay_transport_abstract_methods() -> None:
    """Verify RelayTransport abstract base class contract."""
    class ConcreteRelay(RelayTransport):
        def forward_relay_message(self, message: Any) -> bool:
            return super().forward_relay_message(message)

    relay = ConcreteRelay()
    with pytest.raises(NotImplementedError):
        relay.forward_relay_message(None)


def test_transport_cli_missing_arguments_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI connect, disconnect, and reconnect commands missing device arguments."""
    home_dir = str(tmp_path / "cli_missing_args")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # 1. Connect missing device ID
    code_conn_json = main(["--home-dir", home_dir, "transport", "connect", "", "--json"])
    assert code_conn_json == 1
    out_conn_json = capsys.readouterr().out
    assert "Device ID is required" in out_conn_json

    # 2. Disconnect missing device ID
    code_disc_json = main(["--home-dir", home_dir, "transport", "disconnect", "", "--json"])
    assert code_disc_json == 1
    out_disc_json = capsys.readouterr().out
    assert "Device ID is required" in out_disc_json

    # 3. Reconnect missing device ID
    code_reconn_json = main(["--home-dir", home_dir, "transport", "reconnect", "", "--json"])
    assert code_reconn_json == 1
    out_reconn_json = capsys.readouterr().out
    assert "Device ID is required" in out_reconn_json


def test_local_socket_transport_unix_socket(tmp_path: Path) -> None:
    """Test LocalSocketTransportServer and Client communicating over UNIX domain sockets."""
    sock_path = tmp_path / "test_unix.sock"
    db_path = tmp_path / "unix_db.db"
    db = Database(db_path)
    mgr = MigrationManager(migrations=MIGRATIONS)
    mgr.apply_migrations(db)

    audit = AuditLogger(db)
    trust_mgr = TrustManager(db, audit)
    registry = TransportRegistry(db)

    parent_id = "GM-P-83A1F72C"
    child_id = "GM-C-19A84E72"
    p_priv, p_pub = generate_keypair()
    c_priv, c_pub = generate_keypair()
    p_pem = public_key_to_pem(p_pub).decode("utf-8")
    c_pem = public_key_to_pem(c_pub).decode("utf-8")

    trust_mgr.establish_trust(parent_id, child_id, c_pem)
    trust_mgr.establish_trust(child_id, parent_id, p_pem)

    server = LocalSocketTransportServer(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
        socket_path=sock_path,
        use_unix_socket=True,
        registry=registry,
        audit_logger=audit,
    )
    server.start()
    assert server.is_running is True

    client = LocalSocketTransportClient(
        db=db,
        local_identity_id=child_id,
        local_private_key=c_priv,
        trust_manager=trust_mgr,
        socket_path=sock_path,
        use_unix_socket=True,
        registry=registry,
        audit_logger=audit,
    )

    try:
        session = client.connect(parent_id, timeout=3.0)
        assert session.is_active is True

        # Send and receive envelope
        env = TransportEnvelope(
            sender_id=child_id,
            recipient_id=parent_id,
            message_type=MessageType.PING,
        )
        assert client.send_envelope(env) is True

        # Read response from server
        resp = client.receive_envelope(timeout=3.0)
        if resp:
            assert resp.message_type == MessageType.PONG

        client.disconnect()
        client.close()
    finally:
        server.stop()
        assert server.is_running is False
