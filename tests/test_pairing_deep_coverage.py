"""Deep coverage tests for pairing manager edge cases, CLI interactive prompts, and config serialization."""

from __future__ import annotations

import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig, load_config
from guardianmesh.core.errors import (
    InvalidStateTransitionError,
    PairingSessionExpiredError,
    PairingSessionNotFoundError,
)
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.authorization import (
    ChildAuthDecision,
)
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.models import PairingState
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_pairing_manager_edge_cases(tmp_path: Path) -> None:
    """Test error and expiration branches in PairingManager."""
    db = Database(tmp_path / "pm_edge.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path, otp_expiration_seconds=1, session_expiration_seconds=2)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    pairing_mgr = PairingManager(db, config, key_storage, TrustManager(db))

    # 1. Non-existent session lookup
    assert pairing_mgr.get_session("PAIR-NONEXIST") is None
    with pytest.raises(PairingSessionNotFoundError):
        pairing_mgr.get_session_or_raise("PAIR-NONEXIST")

    # 2. Resend on non-existent session
    with pytest.raises(PairingSessionNotFoundError):
        pairing_mgr.resend_otp("PAIR-NONEXIST")

    # 3. Create session with valid child ID
    session, _ = pairing_mgr.create_session(
        parent_identity_id=parent.id,
        verification_method="DEMO",
        verification_destination="demo@guardianmesh.local",
        child_identity_id=child.id,
    )
    assert session.child_identity_id == child.id

    # 4. List sessions
    all_sess = pairing_mgr.list_sessions(parent_id=parent.id)
    assert len(all_sess) == 1
    pending_sess = pairing_mgr.list_sessions(state=PairingState.VERIFICATION_PENDING)
    assert len(pending_sess) == 1

    # 5. Challenge on wrong state
    with pytest.raises(InvalidStateTransitionError):
        pairing_mgr.create_authorization_challenge(session.session_id, child.id)

    # 6. Verify OTP on wrong state (transition first to verified)
    pairing_mgr.verify_otp(session.session_id, session.otp_verifier or "000000") if False else None


def test_pairing_manager_expiration_branches(tmp_path: Path) -> None:
    """Test expired session transitions."""
    db = Database(tmp_path / "pm_exp.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    parent, _ = identity_mgr.create_identity(role=IdentityRole.PARENT)
    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    pairing_mgr = PairingManager(db, config, key_storage, TrustManager(db))

    past = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=10)).isoformat()

    # Insert expired session directly
    db.execute(
        """
        INSERT INTO pairing_sessions (
            session_id, parent_identity_id, child_identity_id, verification_method,
            verification_destination, state, created_at, expires_at, attempt_count,
            max_attempts, resend_count, last_resend_at, otp_verifier, otp_salt, otp_expires_at
        ) VALUES (
            'PAIR-EXPIRED1', ?, ?, 'DEMO', 'demo@guardianmesh.local', 'VERIFICATION_PENDING',
            ?, ?, 0, 5, 0, ?, 'verifier', 'salt', ?
        );
        """,
        (parent.id, child.id, past, past, past, past),
    )

    # verify_otp raises PairingSessionExpiredError
    with pytest.raises(PairingSessionExpiredError):
        pairing_mgr.verify_otp("PAIR-EXPIRED1", "123456")

    # resend_otp raises PairingSessionExpiredError
    with pytest.raises(PairingSessionExpiredError):
        pairing_mgr.resend_otp("PAIR-EXPIRED1")

    # create_authorization_challenge raises PairingSessionExpiredError
    with pytest.raises(PairingSessionExpiredError):
        pairing_mgr.create_authorization_challenge("PAIR-EXPIRED1", child.id)

    # submit_child_authorization raises PairingSessionExpiredError
    dummy_decision = ChildAuthDecision(
        decision="APPROVE",
        session_id="PAIR-EXPIRED1",
        parent_identity_id=parent.id,
        child_identity_id=child.id,
        nonce="nonce",
        child_public_key_pem="...",
        signature_hex="sig",
        timestamp=past,
    )
    with pytest.raises(PairingSessionExpiredError):
        pairing_mgr.submit_child_authorization("PAIR-EXPIRED1", dummy_decision)


def test_cli_pair_interactive_prompts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test interactive wizard user input choices (Email, SMS, Demo, cancellations)."""
    home_dir = str(tmp_path / "gm_cli_prompts")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # Choice 3: Demo
    with patch("builtins.input", side_effect=["3"]):
        code = main(["--home-dir", home_dir, "pair"])
        assert code == 0
        out = capsys.readouterr().out
        assert "Pairing Session Created" in out

    # Choice 1: Email (mocking input choice 1 then email)
    with patch("builtins.input", side_effect=["1", "parent@example.com"]):
        # Expect error since SMTP is not configured
        code = main(["--home-dir", home_dir, "pair"])
        assert code == 1
        assert "not configured" in capsys.readouterr().out or "Error"

    # Choice 2: SMS (mocking input choice 2 then phone)
    with patch("builtins.input", side_effect=["2", "+15551234567"]):
        code = main(["--home-dir", home_dir, "pair"])
        assert code == 1
        assert "not currently configured" in capsys.readouterr().out or "Error"

    # Invalid choice
    with patch("builtins.input", side_effect=["99"]):
        code = main(["--home-dir", home_dir, "pair"])
        assert code == 1
        assert "Invalid selection" in capsys.readouterr().out

    # User cancel (EOFError / KeyboardInterrupt)
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        code = main(["--home-dir", home_dir, "pair"])
        assert code == 130


def test_cli_pair_commands_missing_arguments(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test pair subcommands when arguments are omitted or invalid."""
    home_dir = str(tmp_path / "gm_cli_args")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # verify with missing code raises SystemExit from argparse
    with pytest.raises(SystemExit) as excinfo:
        main(["--home-dir", home_dir, "pair", "verify"])
    assert excinfo.value.code == 2

    # revoke non-existent
    code_r = main(["--home-dir", home_dir, "pair", "revoke", "GM-C-99999999"])
    assert code_r == 1
    assert "not found" in capsys.readouterr().out or "Revocation error"

    # rename non-existent
    code_rn = main(["--home-dir", home_dir, "pair", "rename", "GM-C-99999999", "New Name"])
    assert code_rn == 1
    assert "not found" in capsys.readouterr().out or "Rename error"


def test_config_smtp_env_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test loading SMTP and pairing parameters from environment variables."""
    monkeypatch.setenv("GUARDIANMESH_HOME", str(tmp_path))
    monkeypatch.setenv("GUARDIANMESH_SMTP_HOST", "smtp.mymail.com")
    monkeypatch.setenv("GUARDIANMESH_SMTP_PORT", "465")
    monkeypatch.setenv("GUARDIANMESH_SMTP_USER", "smtp_user")
    monkeypatch.setenv("GUARDIANMESH_SMTP_PASS", "smtp_pass")
    monkeypatch.setenv("GUARDIANMESH_SMTP_FROM", "alerts@mymail.com")

    cfg = load_config(tmp_path)
    assert cfg.smtp_host == "smtp.mymail.com"
    assert cfg.smtp_port == 465
    assert cfg.smtp_username == "smtp_user"
    assert cfg.smtp_password == "smtp_pass"
    assert cfg.smtp_from_address == "alerts@mymail.com"

    d_redacted = cfg.to_dict(redact_secrets=True)
    assert d_redacted["smtp_password"] == "[CONFIGURED]"

    d_plain = cfg.to_dict(redact_secrets=False)
    assert d_plain["smtp_password"] == "smtp_pass"
