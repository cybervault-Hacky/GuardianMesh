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
7. **No Remote Execution**: Arbitrary remote commands, shell access, or remote input injection are strictly impossible across the transport protocol.

---

## 4. Vista Screen-Session Security (Phase 7)

The Vista screen subsystem is the only GuardianMesh feature that ever
processes pixel data. Its security and privacy model is the strictest in
the project.

> **GuardianMesh Vista is NOT a covert monitoring system.**

1. **Trust != Screen Authorization**. A device that is in the
   `trusted_devices` registry is not automatically authorized to
   receive screen frames. Every screen session requires a fresh,
   explicit child-side authorization, recorded in the
   `screen_authorizations` table.
2. **No Remote Control Protocol**. The screen message type allowlist
   contains exactly 7 names: `SCREEN_VIEW_REQUEST`,
   `SCREEN_VIEW_APPROVAL`, `SCREEN_VIEW_DENIAL`,
   `SCREEN_SESSION_START`, `SCREEN_FRAME`, `SCREEN_SESSION_STOP`,
   `SCREEN_SESSION_EXPIRED`. The forbidden names (`SCREEN_CONTROL`,
   `REMOTE_INPUT`, `EXECUTE`, `SHELL`, `COMMAND`, `KEYLOG`,
   `KEYSTROKE`, `MIC`, `CAMERA`, `GPS`, etc.) are rejected at
   construction time by `assert_no_remote_control_type`.
3. **Bounded Session Lifetime**. The default authorization lifetime is
   5 minutes (300 s) and the hard cap is 1 hour (3600 s). Inactivity
   timeouts and trust revocation terminate the session immediately.
4. **Visible Child-Side Indicator**. A persistent
   `SCREEN VIEW ACTIVE` banner is rendered for the entire session
   lifetime. The child can stop the session at any moment.
5. **No Frame Persistence**. The `screen_sessions` and
   `screen_authorizations` tables store metadata only. Frame payloads
   are held only in a bounded in-memory `FrameStreamBuffer` with
   `DROP_OLDEST` backpressure and are cleared on session termination.
6. **No Bypass of OS Consent**. The shipped `AndroidScreenProvider` is
   a documented integration boundary; production capture requires a
   future Android companion component that uses `MediaProjection` with
   the system consent dialog. The current build never claims real
   capture is active.
7. **No Secret Persistence**. The audit redaction list in
   `guardianmesh.storage.audit` is exhaustive and includes every known
   sensitive key. The authorization table does not store the
   authorization nonce, the session key, or any other secret.
8. **Strict Frame Validation**. Every `ScreenFrame` is rejected if
   any of the following holds: invalid protocol version, invalid
   `device_id` format, empty `session_id`, non-positive sequence,
   non-positive width/height, oversized resolution (>1920x1080),
   oversized payload (>4 MiB by default), mismatched `payload_size`
   vs `len(payload)`, invalid `captured_at` timestamp.
9. **Sequence Replay Defense**. The `FrameSequenceTracker` maintains a
   sliding window of accepted sequences and rejects duplicates, gaps
   outside the window, and non-positive sequences.
10. **Encryption Reuse**. All screen traffic is encrypted by the
    existing Nexus transport. The `ScreenTransportBridge` does not
    introduce a new encryption system. The same AEAD keys, the same
    replay defense, and the same authentication guarantees protect
    every screen frame.
11. **Audit Redaction**. The audit logger's redaction list includes
    every known sensitive key (`payload`, `screenshot`,
    `frame_data`, `raw_pixels`, `password`, `private_key`, `otp`,
    `session_key`, `send_key`, `recv_key`, `encryption_key`,
    `shared_secret`, `ciphertext`, `nonce_hex`, etc.). The
    `test_audit_log_never_contains_frame_payload` test verifies that
    a unique frame payload is never recorded in any audit event.


---

## 5. Aegis Android Companion Security (Phase 8)

The Aegis subsystem is the only GuardianMesh feature that ever
performs real ``MediaProjection`` capture. Its security and privacy
model is the strictest in the project.

> **Aegis is a consent-based screen-sharing companion, NOT a surveillance engine.**

1. **Three-Key Consent Gate**. Capture is forbidden unless all three
   are present and unexpired:
   - **Trust** (Phase 2): the device is in the trusted registry.
   - **Authorization** (Phase 7): the child has approved the view in
     GuardianMesh.
   - **System consent** (Phase 8): the child has tapped **Allow** in
     the Android ``MediaProjection`` system dialog.
2. **No New Encryption Protocol**. The companion's ``NexusClient``
   reuses Phase 6 primitives. No new cryptographic code is
   introduced in Aegis.
3. **No Bypass of OS Consent**. The companion is forbidden from
   bypassing the Android ``MediaProjection`` system dialog. The
   consent flow is documented in
   ``android/aegis/README.md`` and the relevant Kotlin files.
4. **No Hidden APIs**. The companion uses only public Android APIs.
   No root. No Magisk. No system-level bypass. The manifest
   declares only the documented minimum permissions.
5. **No Remote Control Protocol**. The ``ScreenMessageType`` allowlist
   (Phase 7) contains exactly seven narrowly-scoped names. The
   companion's ``ScreenTransportAdapter`` produces only
   ``SCREEN_FRAME`` and metadata over the existing Nexus transport.
6. **Foreground Service Indicator**. The companion MUST start a
   foreground service with a persistent notification before
   delivering frames and MUST stop the service the moment the
   session ends. The notification exposes a ``STOP SHARING`` action
   that performs an immediate local cancellation.
7. **Bounded Session Lifetime**. The default authorization lifetime
   is 5 minutes (300 s) and the hard cap is 1 hour (3600 s).
   Inactivity timeouts and trust revocation terminate the session
   immediately.
8. **No Frame Persistence**. The companion never writes frame bytes
   to disk. Frames exist only in the in-memory ``BoundedFrameQueue``
   for the duration of one frame processing cycle. The
   ``aegis_sessions`` database table stores metadata only.
9. **Strict Frame Validation**. Every ``ScreenFrame`` is rejected if
   any of the following holds: invalid protocol version, invalid
   ``device_id`` format, empty ``session_id``, non-positive sequence,
   non-positive width/height, oversized resolution, oversized
   payload, mismatched ``payload_size`` vs ``len(payload)``,
   invalid ``captured_at`` timestamp.
10. **Bounded Resources**. Maximum 10 FPS, 1280x720, 4 MiB encoded
    frame, 30 queued frames, ``DROP_OLDEST`` backpressure. Memory
    usage is bounded by the queue capacity plus the size of one
    in-flight frame.
11. **Audit Redaction**. The Python ``AuditLogger`` redaction list
    includes every known sensitive key. The Kotlin ``RedactionRules``
    mirror the Python list. The ``test_audit_log_never_contains_frame_payload``
    test verifies that a unique frame payload is never recorded in
    any audit event.
12. **Bounded Metrics**. The companion records counters, latencies,
    and queue stats. Metrics NEVER contain frame bytes, screenshot
    blobs, or any captured screen content.
13. **Local Stop Works Without Network**. The companion's
    ``STOP SHARING`` notification action tears the pipeline down
    locally — the action is honoured even if the Nexus transport is
    unavailable. The companion then notifies the parent when the
    network is available.
14. **Permissions Minimum**. The Android manifest declares only
    ``FOREGROUND_SERVICE``, ``FOREGROUND_SERVICE_MEDIA_PROJECTION``,
    and ``POST_NOTIFICATIONS``. None of the following are declared:
    ``INTERNET`` (not needed; the companion uses the existing
    Nexus loopback or LAN), ``RECORD_AUDIO``, ``CAMERA``,
    ``ACCESS_FINE_LOCATION``, ``READ_CONTACTS``, ``READ_SMS``,
    ``BIND_ACCESSIBILITY_SERVICE``, ``SYSTEM_ALERT_WINDOW``,
    ``MANAGE_EXTERNAL_STORAGE``, ``READ_CALL_LOG``.
15. **Honest Doctor**. ``guardian doctor`` reports the Aegis
    platform honestly. On Linux it shows
    ``Android screen provider: integration adapter only`` as a Notice
    (not a failure). It never falsely reports real Android capture
    as operational from Linux/Termux.
