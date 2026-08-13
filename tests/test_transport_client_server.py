"""Integration tests for Memory, LocalSocket, FutureNetwork, and Relay transport implementations."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    TransportRevokedError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager
from guardianmesh.telemetry.models import TelemetryEnvelope
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.transport.client import (
    FutureNetworkTransport,
    LocalSocketTransportClient,
    MemoryTransportClient,
    RelayMessage,
)
from guardianmesh.transport.models import (
    EncryptedTransportFrame,
    MessageType,
    TransportEnvelope,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.router import MessageRouter
from guardianmesh.transport.server import (
    LocalSocketTransportServer,
    MemoryTransportServer,
)


def setup_transport_env(
    tmp_path: Path,
) -> tuple[Database, TrustManager, str, Any, str, Any, TransportRegistry, AuditLogger, GuardianConfig]:
    """Helper to set up keys, trust relationships, registry, and audit logger."""
    db_path = tmp_path / "transport_test.db"
    db = Database(db_path)
    mgr = MigrationManager(migrations=MIGRATIONS)
    mgr.apply_migrations(db)

    config = GuardianConfig(home_dir=tmp_path)
    audit = AuditLogger(db)
    trust_mgr = TrustManager(db, audit)
    registry = TransportRegistry(db)

    parent_id = "GM-P-83A1F72C"
    child_id = "GM-C-19A84E72"

    p_priv, p_pub = generate_keypair()
    p_pem = public_key_to_pem(p_pub).decode("utf-8")

    c_priv, c_pub = generate_keypair()
    c_pem = public_key_to_pem(c_pub).decode("utf-8")

    trust_mgr.establish_trust(parent_id, child_id, c_pem)
    trust_mgr.establish_trust(child_id, parent_id, p_pem)

    return db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, config


def test_memory_client_server_full_exchange(tmp_path: Path) -> None:
    """Test full authenticated handshake and bidirectional messaging via MemoryTransport."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, config = (
        setup_transport_env(tmp_path)
    )

    processor = TelemetryProcessor(db, config, trust_mgr, audit_logger=audit)
    server_router = MessageRouter(
        db=db,
        local_identity_id=parent_id,
        trust_manager=trust_mgr,
        telemetry_processor=processor,
        registry=registry,
        audit_logger=audit,
    )

    server = MemoryTransportServer(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
        router=server_router,
        registry=registry,
        audit_logger=audit,
    )

    client = MemoryTransportClient(
        db=db,
        local_identity_id=child_id,
        local_private_key=c_priv,
        trust_manager=trust_mgr,
        registry=registry,
        audit_logger=audit,
    )
    client.attach_server(server)

    # 1. Connect and Handshake
    session = client.connect(parent_id)
    assert session.is_active is True
    assert client.is_connected is True

    # 2. Client sends Telemetry Envelope
    now = datetime.datetime.now(datetime.UTC).isoformat()
    raw_tel = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        captured_at=now,
        payload={"battery_percent": 88, "charging": True, "connectivity": "ONLINE"},
    )
    raw_tel.sign(c_priv)

    tel_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.TELEMETRY,
        payload=raw_tel.to_dict(),
    )
    assert client.send_envelope(tel_env) is True

    # 3. Server processes frame
    result = server.process_next_frame(timeout=1.0)
    assert result is not None
    assert result.battery_percent == 88

    # 4. Client disconnect
    client.disconnect()
    assert client.is_connected is False


def test_memory_client_untrusted_device_rejection(tmp_path: Path) -> None:
    """Test client refuses to connect to an untrusted device ID."""
    db, trust_mgr, parent_id, p_priv, _, c_priv, registry, audit, _ = setup_transport_env(tmp_path)

    client = MemoryTransportClient(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
        registry=registry,
        audit_logger=audit,
    )

    with pytest.raises(TransportRevokedError):
        client.connect("GM-C-UNKNOWN0")


def test_memory_client_revoked_device_rejection(tmp_path: Path) -> None:
    """Test connection attempt to revoked device is rejected."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, _ = setup_transport_env(tmp_path)
    trust_mgr.revoke_trust(parent_id, child_id)

    client = MemoryTransportClient(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
        registry=registry,
        audit_logger=audit,
    )

    with pytest.raises(TransportRevokedError):
        client.connect(child_id)


def test_local_socket_client_server_tcp(tmp_path: Path) -> None:
    """Test LocalSocketTransportServer and Client communicating over local loopback TCP."""
    import socket

    # Find free port
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_sock.bind(("127.0.0.1", 0))
    port = temp_sock.getsockname()[1]
    temp_sock.close()

    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, _ = setup_transport_env(tmp_path)

    server = LocalSocketTransportServer(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
        host="127.0.0.1",
        port=port,
        use_unix_socket=False,
        registry=registry,
        audit_logger=audit,
    )
    server.start()

    client = LocalSocketTransportClient(
        db=db,
        local_identity_id=child_id,
        local_private_key=c_priv,
        trust_manager=trust_mgr,
        host="127.0.0.1",
        port=port,
        use_unix_socket=False,
        registry=registry,
        audit_logger=audit,
    )

    try:
        session = client.connect(parent_id, timeout=3.0)
        assert session.is_active is True
        assert client.is_connected is True

        # Send heartbeat
        hb_env = TransportEnvelope(
            sender_id=child_id,
            recipient_id=parent_id,
            message_type=MessageType.HEARTBEAT,
            sequence=1,
        )
        assert client.send_envelope(hb_env) is True

        client.disconnect()
        assert client.is_connected is False
    finally:
        server.stop()


def test_future_network_transport_interface() -> None:
    """Verify FutureNetworkTransport interface placeholder contracts."""
    ft = FutureNetworkTransport()
    env = TransportEnvelope(sender_id="GM-P-83A1F72C", recipient_id="GM-C-19A84E72")

    with pytest.raises(NotImplementedError):
        ft.send_envelope(env)

    with pytest.raises(NotImplementedError):
        ft.receive_envelope()

    ft.close()


def test_relay_message_model() -> None:
    """Verify RelayMessage container for zero-knowledge payload forwarding."""
    frame = EncryptedTransportFrame(
        session_id="SES-001",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        ciphertext_hex="abcd",
        nonce_hex="1234",
    )
    relay_msg = RelayMessage(
        relay_version="1.0",
        recipient_device_id="GM-C-19A84E72",
        sender_device_id="GM-P-83A1F72C",
        encrypted_frame=frame,
    )
    assert relay_msg.recipient_device_id == "GM-C-19A84E72"
    assert relay_msg.encrypted_frame.ciphertext_hex == "abcd"
