"""Tests for MessageRouter dispatching to Telemetry, Alert, and Policy subsystems."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    TransportMessageError,
    TransportRevokedError,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.models import AlertStatus
from guardianmesh.security.crypto import generate_keypair, public_key_to_pem
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MIGRATIONS, MigrationManager
from guardianmesh.telemetry.models import TelemetryEnvelope
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.transport.models import (
    ConnectionState,
    MessageType,
    TransportEnvelope,
)
from guardianmesh.transport.registry import TransportRegistry
from guardianmesh.transport.router import MessageRouter
from guardianmesh.transport.session import TransportSession


def setup_router_env(
    tmp_path: Path,
) -> tuple[Database, MessageRouter, TrustManager, str, str, Any, str]:
    """Helper to set up test database, trust records, processor, and MessageRouter."""
    db_path = tmp_path / "router_test.db"
    db = Database(db_path)
    mgr = MigrationManager(migrations=MIGRATIONS)
    mgr.apply_migrations(db)

    config = GuardianConfig(home_dir=tmp_path)
    audit = AuditLogger(db)
    trust_mgr = TrustManager(db, audit)
    registry = TransportRegistry(db)
    processor = TelemetryProcessor(db, config, trust_mgr, audit_logger=audit)

    parent_id = "GM-P-83A1F72C"
    child_id = "GM-C-19A84E72"
    child_priv, child_pub = generate_keypair()
    child_pem = public_key_to_pem(child_pub).decode("utf-8")

    trust_mgr.establish_trust(
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        remote_public_key_pem=child_pem,
    )

    router = MessageRouter(
        db=db,
        local_identity_id=parent_id,
        trust_manager=trust_mgr,
        telemetry_processor=processor,
        registry=registry,
        audit_logger=audit,
    )
    return db, router, trust_mgr, parent_id, child_id, child_priv, child_pem


def test_router_telemetry_dispatch(tmp_path: Path) -> None:
    """Test router delivers TELEMETRY message to TelemetryProcessor."""
    db, router, trust_mgr, parent_id, child_id, child_priv, _ = setup_router_env(tmp_path)

    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )
    now = datetime.datetime.now(datetime.UTC).isoformat()
    raw_tel_env = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        captured_at=now,
        payload={"battery_percent": 82, "connectivity": "ONLINE", "agent_version": "0.6.0"},
    )
    raw_tel_env.sign(child_priv)

    envelope = TransportEnvelope(
        session_id="SES-001",
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.TELEMETRY,
        sequence=1,
        created_at=now,
        payload=raw_tel_env.to_dict(),
    )

    result = router.route(envelope, session)
    assert result is not None
    assert result.battery_percent == 82
    assert result.device_id == child_id


def test_router_alert_dispatch(tmp_path: Path) -> None:
    """Test router delivers ALERT message to AlertManager."""
    db, router, trust_mgr, parent_id, child_id, _, _ = setup_router_env(tmp_path)

    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )
    envelope = TransportEnvelope(
        session_id="SES-001",
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.ALERT,
        sequence=2,
        payload={
            "policy_id": "POL-BATTERY",
            "rule_type": "LOW_BATTERY",
            "severity": "WARNING",
            "message": "Battery is low (14%)",
            "trigger_value": "14",
        },
    )

    alert = router.route(envelope, session)
    assert alert.device_id == child_id
    assert alert.status == AlertStatus.ACTIVE
    assert alert.message == "Battery is low (14%)"


def test_router_heartbeat_ping_pong(tmp_path: Path) -> None:
    """Test router handles HEARTBEAT, PING (returns PONG), and PONG."""
    db, router, _, parent_id, child_id, _, _ = setup_router_env(tmp_path)
    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )

    # 1. HEARTBEAT
    hb_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.HEARTBEAT,
        sequence=1,
    )
    hb_res = router.route(hb_env, session)
    assert hb_res["status"] == "HEARTBEAT_ACK"

    # 2. PING
    ping_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.PING,
        sequence=2,
    )
    pong_env = router.route(ping_env, session)
    assert isinstance(pong_env, TransportEnvelope)
    assert pong_env.message_type == MessageType.PONG
    assert pong_env.recipient_id == child_id

    # 3. PONG
    pong_in = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.PONG,
        sequence=3,
        payload={"ping_id": "MSG-PING"},
    )
    pong_res = router.route(pong_in, session)
    assert pong_res["status"] == "PONG_RECEIVED"


def test_router_goodbye_and_disconnect(tmp_path: Path) -> None:
    """Test router gracefully closes session on GOODBYE message."""
    db, router, _, parent_id, child_id, _, _ = setup_router_env(tmp_path)
    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )
    goodbye_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.GOODBYE,
        sequence=1,
    )
    res = router.route(goodbye_env, session)
    assert res["status"] == "DISCONNECTED"
    assert session.is_active is False
    assert session.state == ConnectionState.DISCONNECTED


def test_router_recipient_mismatch(tmp_path: Path) -> None:
    """Test rejection when message recipient is not the local identity."""
    db, router, _, parent_id, child_id, _, _ = setup_router_env(tmp_path)
    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )
    wrong_recip_env = TransportEnvelope(
        sender_id=child_id,
        recipient_id="GM-P-99999999",
        message_type=MessageType.HEARTBEAT,
        sequence=1,
    )
    with pytest.raises(TransportMessageError):
        router.route(wrong_recip_env, session)


def test_router_revoked_device_rejection(tmp_path: Path) -> None:
    """Test that message from revoked device terminates session and raises TransportRevokedError."""
    db, router, trust_mgr, parent_id, child_id, _, _ = setup_router_env(tmp_path)
    trust_mgr.revoke_trust(parent_id, child_id)

    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )
    env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.HEARTBEAT,
        sequence=1,
    )
    with pytest.raises(TransportRevokedError):
        router.route(env, session)

    assert session.is_active is False
    assert session.state == ConnectionState.DISCONNECTED


def test_router_custom_handler_registration(tmp_path: Path) -> None:
    """Test custom handler callback execution."""
    db, router, _, parent_id, child_id, _, _ = setup_router_env(tmp_path)
    session = TransportSession(
        session_id="SES-001",
        local_identity_id=parent_id,
        remote_identity_id=child_id,
        state=ConnectionState.CONNECTED,
    )

    custom_called = []

    def _custom_cb(env: TransportEnvelope, sess: TransportSession) -> dict[str, str]:
        custom_called.append(env.message_id)
        return {"custom": "ok"}

    router.register_handler(MessageType.DEVICE_STATUS, _custom_cb)

    env = TransportEnvelope(
        sender_id=child_id,
        recipient_id=parent_id,
        message_type=MessageType.DEVICE_STATUS,
        sequence=1,
    )
    res = router.route(env, session)
    assert res == {"custom": "ok"}
    assert len(custom_called) == 1
