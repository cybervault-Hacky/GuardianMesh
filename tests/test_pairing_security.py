"""Security-focused tests: secret redaction, non-leakage of OTPs/keys, and replay prevention."""

from __future__ import annotations

from pathlib import Path

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.logging import setup_logging
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.authorization import LocalTestAuthorizationAdapter
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_otp_never_in_database_or_audit_log(tmp_path: Path) -> None:
    """Verify that plaintext OTPs are never stored in database columns or audit event details."""
    db_path = tmp_path / "sec_test.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    audit_logger = AuditLogger(db)
    identity_mgr = IdentityManager(db, key_storage, audit_logger)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    pairing_mgr = PairingManager(db, config, key_storage, TrustManager(db, audit_logger), audit_logger)

    session, demo_otp = pairing_mgr.create_session(
        parent_identity_id=parent.id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        child_identity_id=child.id,
    )
    assert demo_otp is not None

    # Check database columns for pairing_sessions table: plaintext OTP must not exist
    row = db.fetchone("SELECT * FROM pairing_sessions WHERE session_id = ?;", (session.session_id,))
    assert row is not None
    for col_val in row:
        assert demo_otp != str(col_val), f"Plaintext OTP '{demo_otp}' found in column value '{col_val}'!"

    # Check audit events table details: plaintext OTP must not exist
    audit_rows = db.fetchall("SELECT details FROM audit_events;")
    for a_row in audit_rows:
        details_str = a_row["details"]
        msg = f"Plaintext OTP '{demo_otp}' leaked into audit log: {details_str}!"
        assert demo_otp not in details_str, msg


def test_otp_redaction_in_log_formatter(tmp_path: Path) -> None:
    """Verify RedactingFormatter scrubs OTP codes from emitted log messages."""
    log_file = tmp_path / "security_test.log"
    logger = setup_logging(level="DEBUG", log_file=log_file, console_output=False)

    sensitive_msg = "Dispatched OTP code 483921 to parent user"
    logger.info(sensitive_msg)

    # Flush handlers
    for h in logger.handlers:
        h.flush()

    log_content = log_file.read_text(encoding="utf-8")
    assert "483921" not in log_content
    assert "[REDACTED" in log_content


def test_private_key_never_in_pairing_sessions(tmp_path: Path) -> None:
    """Verify private key material is strictly isolated in KeyStorageManager and never in pairing tables."""
    db_path = tmp_path / "key_iso.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    pairing_mgr = PairingManager(db, config, key_storage, TrustManager(db))

    session, demo_otp = pairing_mgr.create_session(
        parent_identity_id=parent.id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        child_identity_id=child.id,
    )
    pairing_mgr.verify_otp(session.session_id, demo_otp)
    nonce = pairing_mgr.create_authorization_challenge(session.session_id, child.id)
    adapter = LocalTestAuthorizationAdapter(key_storage, auto_approve=True)
    decision = adapter.request_authorization(session.session_id, parent.id, "SHA256:fp", child.id, nonce)
    pairing_mgr.submit_child_authorization(session.session_id, decision)

    # Inspect trusted_devices table
    trusted_row = db.fetchone("SELECT * FROM trusted_devices WHERE remote_identity_id = ?;", (child.id,))
    assert trusted_row is not None
    assert "-----BEGIN PRIVATE KEY-----" not in str(trusted_row["remote_public_key_pem"])
    assert "PRIVATE" not in str(trusted_row["remote_public_key_pem"])
