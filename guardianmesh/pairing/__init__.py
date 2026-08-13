"""Pairing and trust establishment subsystem for GuardianMesh (Phase 2: Link)."""

from __future__ import annotations

from guardianmesh.pairing.authorization import (
    ChildAuthDecision,
    ChildAuthorizationAdapter,
    FutureAndroidAuthorizationAdapter,
    LocalTestAuthorizationAdapter,
    create_signed_child_decision,
    generate_auth_nonce,
    register_nonce,
    validate_and_consume_nonce,
    verify_child_decision_signature,
)
from guardianmesh.pairing.manager import PairingManager
from guardianmesh.pairing.models import (
    VALID_TRANSITIONS,
    PairingSession,
    PairingState,
    TrustedDevice,
    validate_state_transition,
)
from guardianmesh.pairing.otp import (
    calculate_expiry_iso,
    compute_otp_verifier,
    generate_otp_code,
    generate_otp_salt,
    validate_otp_format,
    verify_otp_code,
)
from guardianmesh.pairing.providers import (
    DeliveryProvider,
    DemoDeliveryProvider,
    EmailDeliveryProvider,
    SmsDeliveryProvider,
    get_delivery_provider,
)
from guardianmesh.pairing.trust import TrustManager

__all__ = [
    "VALID_TRANSITIONS",
    "ChildAuthDecision",
    "ChildAuthorizationAdapter",
    "DeliveryProvider",
    "DemoDeliveryProvider",
    "EmailDeliveryProvider",
    "FutureAndroidAuthorizationAdapter",
    "LocalTestAuthorizationAdapter",
    "PairingManager",
    "PairingSession",
    "PairingState",
    "SmsDeliveryProvider",
    "TrustManager",
    "TrustedDevice",
    "calculate_expiry_iso",
    "compute_otp_verifier",
    "create_signed_child_decision",
    "generate_auth_nonce",
    "generate_otp_code",
    "generate_otp_salt",
    "get_delivery_provider",
    "register_nonce",
    "validate_and_consume_nonce",
    "validate_otp_format",
    "validate_state_transition",
    "verify_child_decision_signature",
    "verify_otp_code",
]
