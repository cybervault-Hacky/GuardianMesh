"""Pairing lifecycle manager coordinating OTP verification, child authorization, and trust establishment."""

from __future__ import annotations

import datetime
import secrets

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import (
    ChildAuthorizationDeniedError,
    InvalidStateTransitionError,
    OTPAttemptLimitExceededError,
    OTPExpiredError,
    OTPVerificationError,
    PairingSessionExpiredError,
    PairingSessionNotFoundError,
    RateLimitExceededError,
    SecurityError,
    ValidationError,
)
from guardianmesh.identity.models import IdentityRole, parse_identity_role, validate_identity_id
from guardianmesh.pairing.authorization import (
    ChildAuthDecision,
    generate_auth_nonce,
    register_nonce,
    validate_and_consume_nonce,
    verify_child_decision_signature,
)
from guardianmesh.pairing.models import PairingSession, PairingState, TrustedDevice
from guardianmesh.pairing.otp import (
    calculate_expiry_iso,
    compute_otp_verifier,
    generate_otp_code,
    generate_otp_salt,
    validate_otp_format,
    verify_otp_code,
)
from guardianmesh.pairing.providers import (
    get_delivery_provider,
)
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditEventType, AuditLogger
from guardianmesh.storage.database import Database


class PairingManager:
    """Orchestrates end-to-end pairing workflows with strict verification and mandatory child consent."""

    def __init__(
        self,
        db: Database,
        config: GuardianConfig,
        key_storage: KeyStorageManager,
        trust_manager: TrustManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = db
        self.config = config
        self.key_storage = key_storage
        self.trust_manager = trust_manager or TrustManager(db, audit_logger)
        self.audit_logger = audit_logger or AuditLogger(db)

    def _generate_session_id(self) -> str:
        """Generate a compact, unique pairing session identifier (e.g. PAIR-7F2A91)."""
        for _ in range(10):
            token = secrets.token_hex(3).upper()
            sid = f"PAIR-{token}"
            existing = self.db.fetchone(
                "SELECT session_id FROM pairing_sessions WHERE session_id = ?;",
                (sid,),
            )
            if not existing:
                return sid
        return f"PAIR-{secrets.token_hex(4).upper()}"

    def create_session(
        self,
        parent_identity_id: str,
        verification_method: str,
        verification_destination: str,
        child_identity_id: str | None = None,
        metadata: dict | None = None,
    ) -> tuple[PairingSession, str | None]:
        """Create a new pairing session and dispatch a secure one-time passcode.

        Args:
            parent_identity_id: Initiating parent device identity (GM-P-XXXXXXXX).
            verification_method: Method ("EMAIL", "SMS", "DEMO").
            verification_destination: Email, phone, or "demo".
            child_identity_id: Optional target child device identity.
            metadata: Optional non-sensitive metadata.

        Returns:
            Tuple of (PairingSession, demo_otp_code_if_applicable).
        """
        # Validate parent identity format
        is_valid, err = validate_identity_id(parent_identity_id)
        if not is_valid:
            raise ValidationError(f"Invalid parent identity ID: {err}")

        if parse_identity_role(parent_identity_id) != IdentityRole.PARENT:
            raise ValidationError("Pairing sessions can only be initiated by a PARENT identity.")

        if child_identity_id:
            c_valid, c_err = validate_identity_id(child_identity_id)
            if not c_valid:
                raise ValidationError(f"Invalid child identity ID: {c_err}")
            if parse_identity_role(child_identity_id) != IdentityRole.CHILD:
                raise ValidationError("Target pairing identity must have CHILD role.")

        norm_method = verification_method.strip().upper()
        provider = get_delivery_provider(norm_method, self.config)

        session_id = self._generate_session_id()
        raw_otp = generate_otp_code()
        salt = generate_otp_salt()
        verifier = compute_otp_verifier(session_id, raw_otp, salt)

        now = datetime.datetime.now(datetime.UTC).isoformat()
        session_exp = calculate_expiry_iso(self.config.session_expiration_seconds)
        otp_exp = calculate_expiry_iso(self.config.otp_expiration_seconds)

        session = PairingSession(
            session_id=session_id,
            parent_identity_id=parent_identity_id,
            child_identity_id=child_identity_id,
            verification_method=norm_method,
            verification_destination=verification_destination.strip(),
            state=PairingState.CREATED,
            created_at=now,
            expires_at=session_exp,
            attempt_count=0,
            max_attempts=self.config.max_otp_attempts,
            resend_count=0,
            last_resend_at=now,
            otp_verifier=verifier,
            otp_salt=salt,
            otp_expires_at=otp_exp,
            metadata=metadata or {},
        )

        # Persist session in database
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO pairing_sessions (
                    session_id, parent_identity_id, child_identity_id,
                    verification_method, verification_destination, state,
                    created_at, expires_at, attempt_count, max_attempts,
                    resend_count, last_resend_at, otp_verifier, otp_salt,
                    otp_expires_at, metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?, ?, ?);
                """,
                (
                    session.session_id,
                    session.parent_identity_id,
                    session.child_identity_id,
                    session.verification_method,
                    session.verification_destination,
                    session.state.value,
                    session.created_at,
                    session.expires_at,
                    session.max_attempts,
                    session.last_resend_at,
                    session.otp_verifier,
                    session.otp_salt,
                    session.otp_expires_at,
                    "{}",
                ),
            )

        # Dispatch OTP via delivery provider
        self.audit_logger.record(
            event_type=AuditEventType.OTP_DELIVERY_STARTED,
            details={"session_id": session_id, "method": norm_method},
            actor_id=parent_identity_id,
            success=True,
        )

        try:
            provider.send_verification_code(session.verification_destination, raw_otp)
            session.transition_to(PairingState.VERIFICATION_PENDING)
            self._update_session_db(session)

            self.audit_logger.record(
                event_type=AuditEventType.OTP_DELIVERED,
                details={"session_id": session_id, "method": norm_method},
                actor_id=parent_identity_id,
                success=True,
            )
            self.audit_logger.record(
                event_type=AuditEventType.PAIRING_CREATED,
                details={"session_id": session_id, "parent": parent_identity_id},
                actor_id=parent_identity_id,
                success=True,
            )
        except Exception:
            # Transition to cancelled if initial dispatch fails
            session.state = PairingState.CANCELLED
            self._update_session_db(session)
            raise

        demo_code = raw_otp if norm_method == "DEMO" else None
        return session, demo_code

    def resend_otp(self, session_id: str) -> tuple[PairingSession, str | None]:
        """Generate and resend a fresh OTP passcode adhering to rate limits and cooldowns."""
        session = self.get_session_or_raise(session_id)

        if session.is_expired():
            session.transition_to(PairingState.EXPIRED)
            self._update_session_db(session)
            raise PairingSessionExpiredError(f"Pairing session '{session_id}' has expired.")

        if session.state not in (PairingState.CREATED, PairingState.VERIFICATION_PENDING):
            raise InvalidStateTransitionError(
                f"Cannot resend OTP for session in state '{session.state.value}'."
            )

        can_resend, remaining = session.can_resend(self.config.otp_resend_cooldown_seconds)
        if not can_resend:
            raise RateLimitExceededError(
                f"OTP resend cooldown active. Please wait {remaining} seconds before requesting a new code."
            )

        raw_otp = generate_otp_code()
        salt = generate_otp_salt()
        verifier = compute_otp_verifier(session_id, raw_otp, salt)
        now = datetime.datetime.now(datetime.UTC).isoformat()
        otp_exp = calculate_expiry_iso(self.config.otp_expiration_seconds)

        session.otp_verifier = verifier
        session.otp_salt = salt
        session.otp_expires_at = otp_exp
        session.resend_count += 1
        session.last_resend_at = now
        session.state = PairingState.VERIFICATION_PENDING

        provider = get_delivery_provider(session.verification_method, self.config)
        provider.send_verification_code(session.verification_destination, raw_otp)
        self._update_session_db(session)

        self.audit_logger.record(
            event_type=AuditEventType.OTP_DELIVERED,
            details={"session_id": session_id, "resend_count": session.resend_count},
            actor_id=session.parent_identity_id,
            success=True,
        )

        demo_code = raw_otp if session.verification_method == "DEMO" else None
        return session, demo_code

    def verify_otp(self, session_id: str, entered_code: str) -> PairingSession:
        """Validate an entered one-time passcode against the session verifier."""
        session = self.get_session_or_raise(session_id)

        if session.is_expired():
            session.state = PairingState.EXPIRED
            self._update_session_db(session)
            self.audit_logger.record(
                event_type=AuditEventType.PAIRING_EXPIRED,
                details={"session_id": session_id},
                actor_id=session.parent_identity_id,
                success=False,
            )
            raise PairingSessionExpiredError(f"Pairing session '{session_id}' has expired.")

        if session.state != PairingState.VERIFICATION_PENDING:
            raise InvalidStateTransitionError(
                f"Session is not awaiting verification (current state: {session.state.value})."
            )

        if session.attempt_count >= session.max_attempts:
            session.state = PairingState.EXPIRED
            self._update_session_db(session)
            self.audit_logger.record(
                event_type=AuditEventType.OTP_REJECTED,
                details={"session_id": session_id, "reason": "Max attempts exceeded"},
                actor_id=session.parent_identity_id,
                success=False,
            )
            raise OTPAttemptLimitExceededError(
                f"Maximum verification attempts ({session.max_attempts}) exceeded. Session invalidated."
            )

        if session.is_otp_expired():
            session.attempt_count += 1
            self._update_session_db(session)
            self.audit_logger.record(
                event_type=AuditEventType.OTP_REJECTED,
                details={"session_id": session_id, "reason": "OTP expired"},
                actor_id=session.parent_identity_id,
                success=False,
            )
            raise OTPExpiredError("Verification code has expired. Request a new code.")

        clean_code = validate_otp_format(entered_code)
        is_correct = verify_otp_code(
            session_id=session.session_id,
            entered_code=clean_code,
            salt=session.otp_salt,
            expected_verifier=session.otp_verifier,
        )

        if not is_correct:
            session.attempt_count += 1
            if session.attempt_count >= session.max_attempts:
                session.state = PairingState.EXPIRED
                self._update_session_db(session)
                self.audit_logger.record(
                    event_type=AuditEventType.OTP_REJECTED,
                    details={"session_id": session_id, "reason": "Max attempts exceeded"},
                    actor_id=session.parent_identity_id,
                    success=False,
                )
                raise OTPAttemptLimitExceededError(
                    f"Maximum verification attempts ({session.max_attempts}) exceeded. Session invalidated."
                )

            self._update_session_db(session)
            self.audit_logger.record(
                event_type=AuditEventType.OTP_REJECTED,
                details={
                    "session_id": session_id,
                    "attempt": session.attempt_count,
                    "max_attempts": session.max_attempts,
                },
                actor_id=session.parent_identity_id,
                success=False,
            )
            attempts_left = session.max_attempts - session.attempt_count
            raise OTPVerificationError(f"Invalid verification code. {attempts_left} attempt(s) remaining.")

        # Successful verification: single-use, clear verifier hash immediately
        now = datetime.datetime.now(datetime.UTC).isoformat()
        session.verified_at = now
        session.otp_verifier = None
        session.otp_salt = None

        # Transition: VERIFICATION_PENDING -> VERIFIED -> CHILD_AUTHORIZATION_PENDING
        session.transition_to(PairingState.VERIFIED)
        session.transition_to(PairingState.CHILD_AUTHORIZATION_PENDING)
        self._update_session_db(session)

        self.audit_logger.record(
            event_type=AuditEventType.OTP_VERIFIED,
            details={"session_id": session_id},
            actor_id=session.parent_identity_id,
            success=True,
        )

        return session

    def create_authorization_challenge(self, session_id: str, child_identity_id: str) -> str:
        """Create a fresh replay-resistant cryptographic challenge nonce for child authorization."""
        session = self.get_session_or_raise(session_id)

        if session.is_expired():
            session.state = PairingState.EXPIRED
            self._update_session_db(session)
            raise PairingSessionExpiredError(f"Pairing session '{session_id}' has expired.")

        if session.state != PairingState.CHILD_AUTHORIZATION_PENDING:
            raise InvalidStateTransitionError(
                f"Session not in CHILD_AUTHORIZATION_PENDING state (current: {session.state.value})."
            )

        c_valid, c_err = validate_identity_id(child_identity_id)
        if not c_valid:
            raise ValidationError(f"Invalid child identity ID: {c_err}")

        nonce = generate_auth_nonce()
        nonce_exp = calculate_expiry_iso(self.config.nonce_expiration_seconds)

        session.child_identity_id = child_identity_id
        session.auth_nonce = nonce
        session.auth_nonce_expires_at = nonce_exp

        with self.db.transaction() as conn:
            register_nonce(
                conn,
                nonce=nonce,
                session_id=session_id,
                child_identity_id=child_identity_id,
                lifetime_seconds=self.config.nonce_expiration_seconds,
            )
            conn.execute(
                """
                UPDATE pairing_sessions
                SET child_identity_id = ?, auth_nonce = ?, auth_nonce_expires_at = ?
                WHERE session_id = ?;
                """,
                (child_identity_id, nonce, nonce_exp, session_id),
            )

        self.audit_logger.record(
            event_type=AuditEventType.CHILD_AUTHORIZATION_REQUESTED,
            details={"session_id": session_id, "child": child_identity_id},
            actor_id=session.parent_identity_id,
            success=True,
        )

        return nonce

    def submit_child_authorization(
        self,
        session_id: str,
        decision: ChildAuthDecision,
        label: str | None = None,
    ) -> TrustedDevice:
        """Process and verify child authorization decision with cryptographic proof."""
        session = self.get_session_or_raise(session_id)

        if session.is_expired():
            session.state = PairingState.EXPIRED
            self._update_session_db(session)
            raise PairingSessionExpiredError(f"Pairing session '{session_id}' has expired.")

        if session.state != PairingState.CHILD_AUTHORIZATION_PENDING:
            raise InvalidStateTransitionError(
                f"Session not awaiting child authorization (current state: {session.state.value})."
            )

        # Replay & Freshness Check: validate and consume challenge nonce
        validate_and_consume_nonce(
            db_or_conn=self.db,
            nonce=decision.nonce,
            session_id=session_id,
            child_identity_id=decision.child_identity_id,
        )

        # Verify Ed25519 digital signature
        if not verify_child_decision_signature(decision):
            raise SecurityError("Child authorization signature verification failed. Authentication rejected.")

        now = datetime.datetime.now(datetime.UTC).isoformat()
        session.child_identity_id = decision.child_identity_id
        session.authorized_at = now

        # Case 1: Child explicitly DENIED pairing
        if not decision.is_approved:
            session.transition_to(PairingState.DENIED)
            self._update_session_db(session)
            self.audit_logger.record(
                event_type=AuditEventType.CHILD_DENIED,
                details={"session_id": session_id, "child": decision.child_identity_id},
                actor_id=decision.child_identity_id,
                success=True,
            )
            raise ChildAuthorizationDeniedError(
                "Pairing authorization was explicitly DENIED by the child device."
            )

        # Case 2: Child APPROVED pairing -> Establish Trust
        session.transition_to(PairingState.AUTHORIZED)
        session.transition_to(PairingState.TRUST_ESTABLISHED)
        session.transition_to(PairingState.PAIRED)
        session.completed_at = now
        self._update_session_db(session)

        self.audit_logger.record(
            event_type=AuditEventType.CHILD_APPROVED,
            details={"session_id": session_id, "child": decision.child_identity_id},
            actor_id=decision.child_identity_id,
            success=True,
        )

        # Persist cryptographic trust
        trusted_device = self.trust_manager.establish_trust(
            local_identity_id=session.parent_identity_id,
            remote_identity_id=decision.child_identity_id,
            remote_public_key_pem=decision.child_public_key_pem,
            pairing_session_id=session.session_id,
            label=label or "Child Device",
        )

        return trusted_device

    def cancel_session(self, session_id: str, reason: str = "User cancelled") -> bool:
        """Cancel a pending pairing session."""
        session = self.get_session_or_raise(session_id)
        terminal_states = (
            PairingState.DENIED,
            PairingState.EXPIRED,
            PairingState.CANCELLED,
            PairingState.REVOKED,
        )
        if session.state in terminal_states:
            return False

        session.state = PairingState.CANCELLED
        self._update_session_db(session)
        self.audit_logger.record(
            event_type=AuditEventType.PAIRING_CANCELLED,
            details={"session_id": session_id, "reason": reason},
            actor_id=session.parent_identity_id,
            success=True,
        )
        return True

    def get_session(self, session_id: str) -> PairingSession | None:
        """Fetch pairing session by ID."""
        row = self.db.fetchone("SELECT * FROM pairing_sessions WHERE session_id = ?;", (session_id,))
        if not row:
            return None
        return PairingSession.from_dict(dict(row))

    def get_session_or_raise(self, session_id: str) -> PairingSession:
        """Fetch pairing session or raise PairingSessionNotFoundError."""
        session = self.get_session(session_id)
        if not session:
            raise PairingSessionNotFoundError(f"Pairing session '{session_id}' not found.")
        return session

    def list_sessions(
        self, parent_id: str | None = None, state: PairingState | None = None
    ) -> list[PairingSession]:
        """List pairing sessions matching criteria."""
        query = "SELECT * FROM pairing_sessions WHERE 1=1"
        params: list[str] = []

        if parent_id:
            query += " AND parent_identity_id = ?"
            params.append(parent_id)

        if state:
            query += " AND state = ?"
            params.append(state.value)

        query += " ORDER BY created_at DESC;"

        rows = self.db.fetchall(query, tuple(params))
        return [PairingSession.from_dict(dict(row)) for row in rows]

    def _update_session_db(self, session: PairingSession) -> None:
        """Persist updated session state to database."""
        self.db.execute(
            """
            UPDATE pairing_sessions
            SET state = ?, child_identity_id = ?, verified_at = ?, authorized_at = ?,
                completed_at = ?, attempt_count = ?, resend_count = ?, last_resend_at = ?,
                otp_verifier = ?, otp_salt = ?, otp_expires_at = ?, auth_nonce = ?,
                auth_nonce_expires_at = ?
            WHERE session_id = ?;
            """,
            (
                session.state.value,
                session.child_identity_id,
                session.verified_at,
                session.authorized_at,
                session.completed_at,
                session.attempt_count,
                session.resend_count,
                session.last_resend_at,
                session.otp_verifier,
                session.otp_salt,
                session.otp_expires_at,
                session.auth_nonce,
                session.auth_nonce_expires_at,
                session.session_id,
            ),
        )
