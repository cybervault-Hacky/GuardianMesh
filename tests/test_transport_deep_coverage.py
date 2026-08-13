"""Deep coverage and edge case tests for Nexus transport, router, server, crypto, and CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from guardianmesh.cli.main import main
from guardianmesh.core.errors import (
    CryptoError,
    TransportHandshakeError,
    TransportMessageError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager
from guardianmesh.transport.client import (
    MemoryTransportClient,
)
from guardianmesh.transport.crypto import (
    ephemeral_public_from_bytes,
    verify_session_ack,
    verify_session_init,
)
from guardianmesh.transport.models import (
    ConnectionState,
    EncryptedTransportFrame,
    MessageType,
    SessionInfo,
    TransportEnvelope,
    TransportType,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.router import MessageRouter
from guardianmesh.transport.server import (
    MemoryTransportServer,
)
from guardianmesh.transport.session import TransportSession


def setup_env(
    tmp_path: Path,
) -> tuple[Database, TrustManager, str, Any, str, Any, TransportRegistry, AuditLogger]:
    """Test setup helper."""
    db_path = tmp_path / "deep_test.db"
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

    return db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit


def test_crypto_edge_cases() -> None:
    """Test crypto error handling and malformed payloads."""
    with pytest.raises(CryptoError):
        ephemeral_public_from_bytes(b"too_short")

    # verify_session_init missing fields
    bad_init_env = TransportEnvelope(
        message_type=MessageType.SESSION_INIT,
        payload={},
        authentication={},
    )
    with pytest.raises(TransportHandshakeError):
        verify_session_init(bad_init_env, "dummy_pem")

    # verify_session_ack missing fields
    bad_ack_env = TransportEnvelope(
        message_type=MessageType.SESSION_ACK,
        payload={},
        authentication={},
    )
    with pytest.raises(TransportHandshakeError):
        verify_session_ack(bad_ack_env, "dummy_pem", b"0" * 32, "nonce")


def test_models_edge_cases() -> None:
    """Test model deserialization errors and formatting fallbacks."""
    with pytest.raises(TransportMessageError):
        TransportEnvelope.from_dict("not_a_dict")  # type: ignore[arg-type]

    with pytest.raises(TransportMessageError):
        TransportEnvelope.from_dict({"protocol_version": "1.0"})

    with pytest.raises(TransportMessageError):
        TransportEnvelope.from_json("invalid json {")

    with pytest.raises(TransportMessageError):
        EncryptedTransportFrame.from_dict("not_a_dict")  # type: ignore[arg-type]

    with pytest.raises(TransportMessageError):
        EncryptedTransportFrame.from_dict({"protocol_version": "1.0"})

    with pytest.raises(TransportMessageError):
        EncryptedTransportFrame.from_json("invalid json {")

    # Expired session model check with invalid date
    sess = SessionInfo(
        session_id="SES-01",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        state=ConnectionState.CONNECTED,
        transport_type=TransportType.LOCAL,
        created_at="2026-08-13T00:00:00Z",
        expires_at="corrupt_date",
    )
    assert sess.is_expired is True


def test_router_edge_cases_and_handlers(tmp_path: Path) -> None:
    """Test error handler, policy sync, device status, and unknown fallback in MessageRouter."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit = setup_env(tmp_path)
    router = MessageRouter(
        db=db,
        local_identity_id=parent_id,
        trust_manager=trust_mgr,
        telemetry_processor=None,
        registry=registry,
        audit_logger=audit,
    )
    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )

    # 1. ERROR envelope
    err_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.ERROR,
        payload={"error": "Test transport error"},
    )
    res_err = router.route(err_env, session)
    assert res_err["status"] == "ERROR_LOGGED"

    # 2. POLICY_SYNC envelope
    sync_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.POLICY_SYNC,
        payload={"policy_version": 1},
    )
    res_sync = router.route(sync_env, session)
    assert res_sync["status"] == "POLICY_SYNCED"

    # 3. DEVICE_STATUS envelope
    stat_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.DEVICE_STATUS,
        payload={"status": "ACTIVE"},
    )
    res_stat = router.route(stat_env, session)
    assert res_stat["status"] == "STATUS_RECORDED"

    # 4. Telemetry with no processor
    tel_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.TELEMETRY,
        payload={"battery_percent": 75},
    )
    res_tel = router.route(tel_env, session)
    assert res_tel["status"] == "NO_PROCESSOR"


def test_memory_server_and_client_additional_branches(tmp_path: Path) -> None:
    """Test MemoryTransportServer pending processing, stopping, and receive timeouts."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit = setup_env(tmp_path)

    server = MemoryTransportServer(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
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

    session = client.connect(parent_id)
    assert server.get_session(session.session_id) is not None

    # Send heartbeat
    hb_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.HEARTBEAT,
    )
    client.send_envelope(hb_env)

    # Process all pending
    results = server.process_all_pending()
    assert len(results) == 1
    assert results[0]["status"] == "HEARTBEAT_ACK"

    # Client receive timeout
    assert client.receive_envelope(timeout=0.01) is None

    # Server stop
    server.stop()
    assert server.is_running is False
    assert len(server._sessions) == 0


def test_registry_filters_and_missing_records(tmp_path: Path) -> None:
    """Test registry filtering by state and missing item queries."""
    db, _, _, _, _, _, registry, _ = setup_env(tmp_path)

    assert registry.get_peer("NON_EXISTENT") is None
    assert registry.get_session("NON_EXISTENT") is None
    assert registry.get_sequences("NON_EXISTENT", "NON_EXISTENT") == (0, 0)
    assert len(registry.list_peers(state="NON_EXISTENT")) == 0
    assert len(registry.list_sessions(state="NON_EXISTENT")) == 0


def test_cli_transport_empty_lists_and_missing_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test CLI commands when no peers or sessions are registered."""
    home_dir = str(tmp_path / "gm_empty_transport")
    init_code = main(["--home-dir", home_dir, "init", "--role", "parent"])
    assert init_code == 0
    capsys.readouterr()

    # Peers with 0 registered
    code_p = main(["--home-dir", home_dir, "transport", "peers"])
    assert code_p == 0
    out_p = capsys.readouterr().out
    assert "No transport peers registered yet" in out_p

    # Sessions with 0 registered
    code_s = main(["--home-dir", home_dir, "transport", "sessions"])
    assert code_s == 0
    out_s = capsys.readouterr().out
    assert "No transport sessions recorded" in out_s

    # Status in doctor
    doc_code = main(["--home-dir", home_dir, "doctor"])
    assert doc_code == 0
    doc_out = capsys.readouterr().out
    assert "Transport module   ✓" in doc_out
    assert "Cryptographic backend" in doc_out
    assert "Trust registry     ✓" in doc_out
    assert "Session database   ✓" in doc_out
    assert "Replay protection  ✓" in doc_out
    assert "Local transport    ✓" in doc_out
    assert "Message router     ✓" in doc_out
