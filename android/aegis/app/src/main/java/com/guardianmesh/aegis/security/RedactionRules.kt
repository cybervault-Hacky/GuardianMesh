/*
 * Aegis Android Companion — redaction rules.
 *
 * Defines the keys that must never appear in logs, audit events, or
 * any persisted state. Mirrors the Python control plane's
 * AuditLogger redaction list.
 */
package com.guardianmesh.aegis.security

object RedactionRules {
    val REDACTED_KEYS: Set<String> = setOf(
        "password",
        "private_key",
        "private_key_pem",
        "secret",
        "token",
        "auth_token",
        "otp",
        "otp_code",
        "pin",
        "credential",
        "key_material",
        "shared_secret",
        "session_key",
        "send_key",
        "recv_key",
        "encryption_key",
        "ciphertext",
        "nonce",
        "nonce_hex",
        "payload",
        "screenshot",
        "frame_data",
        "raw_pixels",
        "clipboard",
        "microphone",
        "camera",
        "location",
    )

    fun redact(value: String): String {
        return if (value.length > 8) "[REDACTED]" else "[REDACTED]"
    }
}
