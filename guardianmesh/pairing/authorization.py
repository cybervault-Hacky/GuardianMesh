"""Child device authorization protocol, challenge-nonce verification, and adapters."""

from __future__ import annotations

import abc
import datetime
import secrets
import sqlite3
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519

from guardianmesh.core.errors import (
    InvalidNonceError,
    ReplayedNonceError,
)
from guardianmesh.security.crypto import (
    public_key_from_pem,
    public_key_to_pem,
    sign_data,
    verify_signature,
)
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database


def generate_auth_nonce() -> str:
    """Generate a 256-bit cryptographically secure random challenge nonce."""
    return secrets.token_hex(32)


def build_auth_challenge_payload(
    session_id: str,
    parent_identity_id: str,
    child_identity_id: str,
    nonce: str,
    decision: str,
) -> bytes:
    """Construct deterministic byte payload for Ed25519 authorization signature."""
    return f"GM-AUTH-V1:{session_id}:{parent_identity_id}:{child_identity_id}:{nonce}:{decision}".encode()


@dataclass
class ChildAuthDecision:
    """Signed decision returned by child device authorizing or denying pairing."""

    decision: str  # "APPROVE" or "DENY"
    session_id: str
    parent_identity_id: str
    child_identity_id: str
    nonce: str
    child_public_key_pem: str
    signature_hex: str
    timestamp: str

    @property
    def is_approved(self) -> bool:
        return self.decision.upper() == "APPROVE"


def create_signed_child_decision(
    private_key: ed25519.Ed25519PrivateKey,
    public_key: ed25519.Ed25519PublicKey,
    session_id: str,
    parent_identity_id: str,
    child_identity_id: str,
    nonce: str,
    approve: bool = True,
) -> ChildAuthDecision:
    """Generate and cryptographically sign a child authorization decision."""
    decision = "APPROVE" if approve else "DENY"
    payload = build_auth_challenge_payload(
        session_id=session_id,
        parent_identity_id=parent_identity_id,
        child_identity_id=child_identity_id,
        nonce=nonce,
        decision=decision,
    )
    sig_bytes = sign_data(private_key, payload)
    pub_pem = public_key_to_pem(public_key).decode("utf-8")
    now = datetime.datetime.now(datetime.UTC).isoformat()

    return ChildAuthDecision(
        decision=decision,
        session_id=session_id,
        parent_identity_id=parent_identity_id,
        child_identity_id=child_identity_id,
        nonce=nonce,
        child_public_key_pem=pub_pem,
        signature_hex=sig_bytes.hex(),
        timestamp=now,
    )


def verify_child_decision_signature(decision: ChildAuthDecision) -> bool:
    """Verify the Ed25519 cryptographic signature of a child authorization decision."""
    try:
        pub_key = public_key_from_pem(decision.child_public_key_pem.encode("utf-8"))
        payload = build_auth_challenge_payload(
            session_id=decision.session_id,
            parent_identity_id=decision.parent_identity_id,
            child_identity_id=decision.child_identity_id,
            nonce=decision.nonce,
            decision=decision.decision,
        )
        sig_bytes = bytes.fromhex(decision.signature_hex)
        return verify_signature(pub_key, sig_bytes, payload)
    except Exception:
        return False


def register_nonce(
    db_or_conn: Database | sqlite3.Connection,
    nonce: str,
    session_id: str,
    child_identity_id: str,
    lifetime_seconds: int = 300,
) -> None:
    """Register a new challenge nonce in the database."""
    now = datetime.datetime.now(datetime.UTC)
    expiry = now + datetime.timedelta(seconds=lifetime_seconds)
    sql = """
        INSERT INTO pairing_nonces (nonce, session_id, child_identity_id, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, ?, 0);
    """
    params = (nonce, session_id, child_identity_id, now.isoformat(), expiry.isoformat())

    if isinstance(db_or_conn, Database):
        db_or_conn.execute(sql, params)
    else:
        db_or_conn.execute(sql, params)


def validate_and_consume_nonce(
    db_or_conn: Database | sqlite3.Connection,
    nonce: str,
    session_id: str,
    child_identity_id: str,
) -> None:
    """Validate challenge nonce freshness and mark it as consumed.

    Raises:
        InvalidNonceError: If nonce is unknown or expired.
        ReplayedNonceError: If nonce has already been used.
    """
    query = """
        SELECT nonce, session_id, child_identity_id, expires_at, used
        FROM pairing_nonces
        WHERE nonce = ? AND session_id = ?;
    """
    if isinstance(db_or_conn, Database):
        row = db_or_conn.fetchone(query, (nonce, session_id))
    else:
        cursor = db_or_conn.execute(query, (nonce, session_id))
        row = cursor.fetchone()

    if not row:
        raise InvalidNonceError(f"Challenge nonce '{nonce[:8]}...' not found for session '{session_id}'.")

    if bool(row["used"]):
        raise ReplayedNonceError(
            f"Challenge nonce '{nonce[:8]}...' has already been used. Replay attempt rejected."
        )

    exp_str = row["expires_at"]
    try:
        exp = datetime.datetime.fromisoformat(exp_str)
        if datetime.datetime.now(datetime.UTC) >= exp:
            raise InvalidNonceError(f"Challenge nonce '{nonce[:8]}...' has expired.")
    except Exception as e:
        if isinstance(e, InvalidNonceError):
            raise
        raise InvalidNonceError(f"Corrupted nonce expiration timestamp: {e}") from e

    # Mark as consumed atomically
    update_sql = "UPDATE pairing_nonces SET used = 1 WHERE nonce = ?;"
    if isinstance(db_or_conn, Database):
        db_or_conn.execute(update_sql, (nonce,))
    else:
        db_or_conn.execute(update_sql, (nonce,))


class ChildAuthorizationAdapter(abc.ABC):
    """Abstract interface for receiving child device authorization decisions."""

    @abc.abstractmethod
    def request_authorization(
        self,
        session_id: str,
        parent_identity_id: str,
        parent_public_key_fingerprint: str,
        child_identity_id: str,
        nonce: str,
    ) -> ChildAuthDecision:
        """Request explicit pairing approval from the child device."""
        raise NotImplementedError


class LocalTestAuthorizationAdapter(ChildAuthorizationAdapter):
    """Explicitly gated local test adapter for Termux/Linux development and automated testing."""

    def __init__(
        self,
        key_storage: KeyStorageManager,
        auto_approve: bool = True,
    ) -> None:
        self.key_storage = key_storage
        self.auto_approve = auto_approve

    def request_authorization(
        self,
        session_id: str,
        parent_identity_id: str,
        parent_public_key_fingerprint: str,
        child_identity_id: str,
        nonce: str,
    ) -> ChildAuthDecision:
        """Sign and return an authorization decision using the child's local private key."""
        priv_key = self.key_storage.load_private_key(child_identity_id)
        pub_key = self.key_storage.load_public_key(child_identity_id)

        return create_signed_child_decision(
            private_key=priv_key,
            public_key=pub_key,
            session_id=session_id,
            parent_identity_id=parent_identity_id,
            child_identity_id=child_identity_id,
            nonce=nonce,
            approve=self.auto_approve,
        )


class FutureAndroidAuthorizationAdapter(ChildAuthorizationAdapter):
    """Placeholder interface for Phase 7 Android System Companion authorization dialog."""

    def request_authorization(
        self,
        session_id: str,
        parent_identity_id: str,
        parent_public_key_fingerprint: str,
        child_identity_id: str,
        nonce: str,
    ) -> ChildAuthDecision:
        raise NotImplementedError(
            "Android Companion APK authorization protocol is scheduled for a future phase."
        )
