"""Comprehensive security review tests for GuardianMesh Nexus (Phase 6)."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    TransportAuthenticationError,
    TransportMessageError,
    TransportOversizedMessageError,
    TransportReplayError,
    TransportRevokedError,
    TransportSequenceError,
    TransportSessionExpiredError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager
from guardianmesh.transport.client import MemoryTransportClient
from guardianmesh.transport.crypto import (
    create_session_init,
    generate_ephemeral_keypair,
    verify_session_init,
)
from guardianmesh.transport.models import (
    ConnectionState,
    MessageType,
    TransportEnvelope,
)
from guardianmesh.transport.reconnect import ReconnectManager
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.server import MemoryTransportServer
from guardianmesh.transport.session import TransportSession


def setup_security_env(
    tmp_path: Path,
) -> tuple[Database, TrustManager, str, Any, str, Any, TransportRegistry, AuditLogger, GuardianConfig]:
    """Initialize security test harness with SQLite database and mutual trust."""
    db_path = tmp_path / "security_test.db"
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


def test_successful_authenticated_handshake(tmp_path: Path) -> None:
    """Security Test: Verify mutual cryptographic handshake establishes forward-secret session."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, config = setup_security_env(tmp_path)

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
    assert session is not None
    assert session.is_active is True
    assert session.send_key is not None
    assert len(session.send_key) == 32

    # Verify audit trail
    events = audit.get_recent(limit=10)
    event_types = [e["event_type"] for e in events]
    assert AuditEventType.TRANSPORT_SESSION_CREATED.value in event_types
    assert AuditEventType.TRANSPORT_AUTHENTICATED.value in event_types


def test_unknown_and_revoked_device_rejections(tmp_path: Path) -> None:
    """Security Test: Unknown devices and revoked trust records are immediately rejected."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, _ = setup_security_env(tmp_path)

    client = MemoryTransportClient(
        db=db,
        local_identity_id=parent_id,
        local_private_key=p_priv,
        trust_manager=trust_mgr,
        registry=registry,
        audit_logger=audit,
    )

    # Unknown device
    with pytest.raises(TransportRevokedError):
        client.connect("GM-C-00000000")

    # Revoked device
    trust_mgr.revoke_trust(parent_id, child_id)
    with pytest.raises(TransportRevokedError):
        client.connect(child_id)


def test_wrong_public_key_and_signature_tamper_rejection(tmp_path: Path) -> None:
    """Security Test: Handshakes with wrong keys or forged signatures are rejected."""
    _, p_pub = generate_keypair()
    p_pem = public_key_to_pem(p_pub).decode("utf-8")
    c_priv, _ = generate_keypair()
    _, c_eph_pub = generate_ephemeral_keypair()

    init_env, _ = create_session_init(
        sender_id="GM-C-19A84E72",
        recipient_id="GM-P-83A1F72C",
        sender_private_key=c_priv,
        ephemeral_public_key=c_eph_pub,
    )

    # Verification with wrong public key must fail
    with pytest.raises(TransportAuthenticationError):
        verify_session_init(init_env, p_pem)

    # Tampered signature
    bad_init = TransportEnvelope.from_dict(init_env.to_dict())
    bad_init.authentication["signature_hex"] = "00" * 64
    with pytest.raises(TransportAuthenticationError):
        verify_session_init(bad_init, p_pem)


def test_session_expiration_security(tmp_path: Path) -> None:
    """Security Test: Expired sessions reject encryption and sequence advances."""
    now = datetime.datetime.now(datetime.UTC)
    past = (now - datetime.timedelta(seconds=1)).isoformat()

    expired_session = TransportSession(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        expires_at=past,
        send_key=b"k" * 32,
        recv_key=b"k" * 32,
    )
    assert expired_session.is_expired is True

    # Sequence advance rejection
    with pytest.raises(TransportSessionExpiredError):
        expired_session.validate_and_advance_inbound_sequence(1, "MSG-1")

    # Encryption rejection
    env = TransportEnvelope(sender_id="GM-P-83A1F72C", recipient_id="GM-C-19A84E72")
    with pytest.raises(TransportSessionExpiredError):
        expired_session.encrypt_envelope(env)


def test_replay_and_sequence_rollback_rejections() -> None:
    """Security Test: Sequences and message IDs cannot be replayed or rolled back."""
    session = TransportSession(
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        replay_window_size=16,
    )

    # Valid in-order messages
    session.validate_and_advance_inbound_sequence(1, "MSG-1")
    session.validate_and_advance_inbound_sequence(2, "MSG-2")
    session.validate_and_advance_inbound_sequence(3, "MSG-3")

    # 1. Exact sequence replay
    with pytest.raises(TransportReplayError):
        session.validate_and_advance_inbound_sequence(2, "MSG-NEW")

    # 2. Exact message ID replay
    with pytest.raises(TransportReplayError):
        session.validate_and_advance_inbound_sequence(4, "MSG-1")

    # 3. Invalid zero sequence
    with pytest.raises(TransportSequenceError):
        session.validate_and_advance_inbound_sequence(0, "MSG-ZERO")


def test_malformed_oversized_and_unsupported_envelopes() -> None:
    """Security Test: Validate rejection of oversized or unsupported envelopes."""
    env = TransportEnvelope(
        protocol_version="1.0",
        message_id="MSG-112233445566",
        sender_id="GM-P-83A1F72C",
        recipient_id="GM-C-19A84E72",
        message_type=MessageType.HEARTBEAT,
        sequence=1,
    )

    # Oversized payload
    with pytest.raises(TransportOversizedMessageError):
        env.validate(max_size_bytes=10)

    # Unsupported message type in restricted context
    with pytest.raises(TransportMessageError):
        env.validate(allowed_types={MessageType.TELEMETRY, MessageType.ALERT})


def test_invalid_sender_and_recipient_rejections() -> None:
    """Security Test: Invalid identity formats are rejected."""
    bad_sender_env = TransportEnvelope(
        sender_id="MALFORMED_ID",
        recipient_id="GM-C-19A84E72",
    )
    with pytest.raises(TransportMessageError):
        bad_sender_env.validate()

    bad_recip_env = TransportEnvelope(
        sender_id="GM-P-83A1F72C",
        recipient_id="MALFORMED_ID",
    )
    with pytest.raises(TransportMessageError):
        bad_recip_env.validate()


def test_reconnect_bounded_backoff_security() -> None:
    """Security Test: Reconnection attempts do not infinite loop and observe max limits."""
    mgr = ReconnectManager(
        initial_delay_seconds=1.0,
        max_delay_seconds=10.0,
        backoff_factor=2.0,
        max_retries=3,
    )
    dev_id = "GM-C-19A84E72"

    for i in range(1, 4):
        att = mgr.record_attempt(dev_id)
        assert att == i
        assert mgr.can_retry(att) is True

    # 4th attempt exceeds max 3
    att4 = mgr.record_attempt(dev_id)
    assert mgr.can_retry(att4) is False
    assert mgr.get_delay(att4) == 8.0
    assert mgr.get_delay(5) == 10.0  # Capped at max delay


def test_audit_redaction_and_no_secret_persistence(tmp_path: Path) -> None:
    """Security Test: Verify session keys, private keys, and payloads are never stored in SQLite."""
    db, trust_mgr, parent_id, p_priv, child_id, c_priv, registry, audit, _ = setup_security_env(tmp_path)

    # 1. Record audit event with sensitive dictionary
    audit.record(
        event_type=AuditEventType.TRANSPORT_SESSION_CREATED,
        details={
            "session_id": "SES-001",
            "session_key": "SUPER_SECRET_KEY_123",
            "private_key": "-----BEGIN PRIVATE KEY-----",
            "payload_data": {"secret": "secret_data"},
        },
    )

    recent_events = audit.get_recent(limit=5)
    evt = recent_events[0]
    details = evt["details"]
    assert details["session_key"] == "[REDACTED]"
    assert details["private_key"] == "[REDACTED]"
    assert details["payload_data"]["secret"] == "[REDACTED]"

    # 2. Direct database query to ensure secrets are not in plaintext in SQLite
    raw_audit = db.fetchone("SELECT details FROM audit_events ORDER BY id DESC LIMIT 1;")
    assert raw_audit is not None
    assert "SUPER_SECRET_KEY" not in raw_audit["details"]
    assert "BEGIN PRIVATE KEY" not in raw_audit["details"]

    # 3. Verify transport_sessions table does NOT store session keys
    columns = [r[1] for r in db.fetchall("PRAGMA table_info(transport_sessions);")]
    assert "send_key" not in columns
    assert "recv_key" not in columns
    assert "session_key" not in columns
    assert "private_key" not in columns


def test_concurrent_sessions_isolation() -> None:
    """Security Test: Ensure concurrent sessions maintain separate sequence counters and keys."""
    s1 = TransportSession(
        session_id="SES-01",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-19A84E72",
        send_key=b"1" * 32,
        recv_key=b"1" * 32,
        state=ConnectionState.CONNECTED,
    )
    s2 = TransportSession(
        session_id="SES-02",
        local_identity_id="GM-P-83A1F72C",
        remote_identity_id="GM-C-22B95F83",
        send_key=b"2" * 32,
        recv_key=b"2" * 32,
        state=ConnectionState.CONNECTED,
    )

    s1.next_outbound_sequence()
    s1.next_outbound_sequence()
    assert s1.outbound_sequence == 2
    assert s2.outbound_sequence == 0

    s1.validate_and_advance_inbound_sequence(1, "MSG-S1-1")
    s2.validate_and_advance_inbound_sequence(1, "MSG-S2-1")
    assert s1.inbound_sequence == 1
    assert s2.inbound_sequence == 1
