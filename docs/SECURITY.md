# GuardianMesh Security Model & Boundaries

## 1. Security Philosophy & Mandate

GuardianMesh is founded on the principle that **effective parental supervision is built on trust, transparency, and explicit mutual consent**.

### Fundamental Non-Negotiable Boundaries
- **No Covert Surveillance**: Monitoring must never operate silently or without the child's clear knowledge.
- **No Keylogging**: Keystrokes, passwords, and form inputs are never captured or transmitted.
- **No Communication Interception**: Private SMS, chat, email, and call audio are strictly outside the system boundary.
- **No Microphone or Camera Tapping**: GuardianMesh will never capture microphone audio or camera feeds.
- **No Behavioral Inferences**: Sentinel evaluates only explicit technical conditions (`battery_percent`, `storage_free_bytes`, `uptime_seconds`, `connectivity`). It never infers user behavior or personal habits.
- **Zero Secrets in Console & JSON Outputs**: Private keys, OTPs, and SMTP passwords are never rendered or serialized into machine-readable JSON exports.
- **Strict Telemetry Allowlist**: Telemetry is bounded strictly to allowlisted technical metrics. All personal content fields are rejected.
- **Mandatory Child Authorization**: OTP verification alone never completes pairing. The child device must explicitly authorize pairing via a signed cryptographic challenge.

---

## 2. Console Security & Data Protection

The GuardianMesh Console enforces strict presentation hygiene:

1. **Secret Masking & Sanitization**: Configuration summaries and JSON exports mask sensitive values (`[CONFIGURED]` or `[REDACTED]`).
2. **Revocation Enforcement**: Revoked devices are explicitly rendered as `REVOKED` and blocked from generating active telemetry or alerts.
3. **No Network Shell**: Console is completely local-first. Watch mode and dashboard rendering execute purely in memory and local SQLite storage without external socket connections.
4. **Audit Immutability**: All management actions (`DEVICE_RENAMED`, `ALERT_ACKNOWLEDGED`, `POLICY_ENABLED`, `TRUST_REVOKED`) are logged in the immutable audit log without recording sensitive keys or passwords.

---

## 3. Nexus Transport Security (Phase 6)

The Nexus transport layer enforces multi-device communication security:

1. **Mutual Cryptographic Authentication**: Every session handshake requires Ed25519 identity signatures verified against active records in `trusted_devices`.
2. **Forward Secrecy**: Ephemeral X25519 Diffie-Hellman keys are used for session negotiation. Ephemeral keys are wiped from memory on session termination and never stored on disk.
3. **AEAD Channel Encryption**: All payloads are encrypted using AES-256-GCM with deterministic 12-byte sequence nonces and authenticated header data.
4. **Anti-Replay Defense**: Enforces strictly increasing per-session sequence numbers with sliding-window validation and message ID deduplication caching.
5. **Instant Revocation Reaction**: If `TrustManager` reports a device status as `REVOKED`, active transport sessions are immediately terminated, in-memory keys zeroed, and further packets rejected.
6. **Zero Plaintext Secret Persistence**: Session keys, private keys, OTPs, and plaintext payloads are never written to database tables, logs, or exceptions.
7. **No Remote Execution**: Arbitrary remote commands, shell access, screen streaming, or remote input injection are strictly impossible across the transport protocol.
