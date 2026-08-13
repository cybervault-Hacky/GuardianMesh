"""Security and privacy boundary tests for Pulse device health telemetry."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    TelemetryAuthenticationError,
    TelemetryValidationError,
)
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.crypto import public_key_to_pem
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import TelemetryEnvelope, validate_health_payload
from guardianmesh.telemetry.processor import TelemetryProcessor
from guardianmesh.telemetry.sequence import SequenceManager


def test_strict_privacy_field_rejection() -> None:
    """Security verification: personal surveillance fields are strictly rejected."""
    forbidden_samples = [
        {"messages": ["hello", "where are you"]},
        {"sms": "2FA code 1234"},
        {"contacts": [{"name": "Alice", "phone": "555-1234"}]},
        {"photos": ["DCIM/camera/photo1.jpg"]},
        {"files": ["/storage/emulated/0/Download/doc.pdf"]},
        {"browser_history": ["https://example.com"]},
        {"clipboard": "pasted_password_text"},
        {"keyboard_input": "user keystroke logging"},
        {"location": {"latitude": 37.7749, "longitude": -122.4194}},
        {"microphone": "audio stream data"},
        {"camera": "video frame data"},
        {"screen": "screen pixel capture"},
        {"app_usage": {"com.example.app": 3600}},
    ]

    for sample in forbidden_samples:
        payload = {"battery_percent": 80, **sample}
        with pytest.raises(TelemetryValidationError):
            validate_health_payload(payload)


def test_revoked_device_telemetry_rejected(tmp_path: Path) -> None:
    """Security verification: revoked device cannot submit telemetry."""
    db = Database(tmp_path / "rev_tel.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    child_priv = key_storage.load_private_key(child.id)
    child_pub = key_storage.load_public_key(child.id)

    trust_mgr = TrustManager(db)
    trust_mgr.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=public_key_to_pem(child_pub).decode("utf-8"),
    )

    processor = TelemetryProcessor(db, config, trust_mgr, SequenceManager(db))

    # Revoke device trust
    trust_mgr.revoke_trust(parent.id, child.id)

    envelope = TelemetryEnvelope(
        device_id=child.id,
        sequence=1,
        payload={"battery_percent": 90, "agent_version": "0.3.0"},
        captured_at="2026-08-12T19:00:00+00:00",
    )
    envelope.sign(child_priv)

    with pytest.raises(TelemetryAuthenticationError):
        processor.process_envelope(envelope, local_identity_id=parent.id)
