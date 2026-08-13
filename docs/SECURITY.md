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

---

## 6. Orion Orchestration Security (Phase 9)

> **Orion is orchestration, NOT surveillance.**

Orion's security and privacy model is the strictest in the project
for metadata. It exists to *coordinate* the existing subsystems —
Pulse, Sentinel, Console, Nexus, Vista, Aegis, Trust — without
introducing any new surveillance or remote-control capability.

### Non-Negotiable Boundaries

Orion **never** implements, in any form, on any platform:

1. Covert monitoring of any kind.
2. Remote control, remote input, or remote command execution.
3. Shell execution or arbitrary command execution.
4. Microphone or camera activation or capture.
5. Hidden or unauthorized screen capture.
6. Location tracking.
7. Clipboard collection.
8. Message collection (SMS, chat, email).
9. Browser-history collection.
10. Bypass of Vista, Aegis, or TrustManager consent.
11. Persistence of sensitive payloads in any Orion table.
12. Persistence of secrets in any Orion audit log.

### Allowlist Enforcement

The `OrionEventType`, `OrionActionType`, and `OrionCapability` enums
are strict allowlists. Forbidden names are rejected at construction
time. The set of forbidden names is verified by automated tests
(`tests/test_orion_security.py`).

### Payload & Parameter Redaction

The `FORBIDDEN_PAYLOAD_KEYS` set rejects every form of sensitive
content in event payloads (frame, screenshot, keylog, message,
clipboard, microphone, audio, camera, video, location, gps,
browser_history, contacts, photos, files, command, shell, exec,
execute, remote_input, password, private_key, secret, token, otp).

The `FORBIDDEN_ACTION_PARAM_KEYS` set rejects the same categories
in action parameters (with the addition of code, script, keylog,
keystrokes).

### Database Column Safety

Migration 9's four tables — `orion_events`, `orion_actions`,
`orion_capabilities`, `orion_reconciliation` — have no column for
frame bytes, command strings, private keys, session keys,
passwords, OTPs, or any other sensitive content. The schema is
verified by automated tests
(`tests/test_orion_security.py::test_orion_tables_never_store_*`).

### Consent Is Delegated, Not Invented

`OrionConsentValidator` is a thin wrapper that delegates to:

* `TrustManager` for `TRUST_REQUIRED`.
* `ScreenAuthorizationManager` for `VISTA_AUTHORIZATION_REQUIRED`.
* `SystemConsentGate` for `AEGIS_SYSTEM_CONSENT_REQUIRED`.
* The active session registry for `EXISTING_ACTIVE_SESSION`.

Orion never invents new consent. It propagates the existing
subsystems' verdicts and surfaces them as
`OrionConsentViolationError` when an action would otherwise bypass
consent.

### Capability Is Explicit, Never Inferred

`OrionCapabilityRegistry` is pre-populated with a control-plane
profile. Negative defaults (`AUDIO_CAPTURE`, `CAMERA_CAPTURE`,
`REMOTE_INPUT`, `REMOTE_SHELL`, `KEYLOGGING`, `LOCATION_TRACKING`,
`CLIPBOARD_ACCESS`, `MESSAGE_COLLECTION`, `BROWSER_HISTORY`,
`HIDDEN_SCREEN_CAPTURE`) are **always False** and the registry
refuses to set them to True.

Orion never infers a capability from the platform. Every
capability is enabled only if the caller passes `True` explicitly.

### Audit Log Redaction

The 11 new `ORION_*` audit event types record only metadata:

* `ORION_EVENT_ACCEPTED`, `ORION_EVENT_REJECTED`.
* `ORION_ACTION_CREATED`, `ORION_ACTION_STARTED`,
  `ORION_ACTION_COMPLETED`, `ORION_ACTION_FAILED`,
  `ORION_ACTION_EXPIRED`.
* `ORION_RECONCILIATION_STARTED`, `ORION_RECONCILIATION_COMPLETED`,
  `ORION_CONFLICT_RESOLVED`, `ORION_CAPABILITY_CHANGED`.

Audit records never contain command strings, frame bytes, keylogs,
passwords, private keys, secrets, or tokens. This is verified by
automated tests
(`tests/test_orion_privacy.py::test_audit_does_not_record_secrets_*`).

### Bounded Queue & Retry

The action queue has a configurable maximum size (default 10,000).
`enqueue()` raises `OrionQueueError` at capacity. Each action has a
`max_retries` cap; the executor respects it. The executor also has
a `max_consecutive_failures` cap.

### Action Expiry

Actions past their `expires_at` are marked `EXPIRED` at sweep time
and never executed. The sweep is invoked at the start of every
executor drain cycle.

### Idempotency

Duplicate `idempotency_key` values are silently rejected. The queue
enforces a UNIQUE INDEX on `idempotency_key` in the `orion_actions`
table. This is the at-most-once guarantee.

### Reconciliation Is Metadata-Only

`OrionReconciliationReport` never contains frame bytes, command
strings, or secrets. It records only counters and timestamps:

* `events_processed`, `conflicts_detected`, `conflicts_resolved`,
  `stale_events`, `failed_actions`.
* `final_state` (one of `SYNCED`, `RESYNC_REQUIRED`, `FAILED`).

### Handler Safety

Each of the 12 action handlers delegates to an existing subsystem.
Handlers never execute arbitrary code; they only call documented
methods on subsystems that have their own consent model
(`TelemetryProcessor`, `AlertManager`, `TransportClient`,
`ScreenController`, `AegisController`, `OrionStateReconciler`,
`OrionCapabilityRegistry`).

### Doctor Coverage

`guardian doctor` includes 11 new Orion-specific checks:

* Orion module — all 15 documented public symbols are present.
* Orion event bus — initial state and configuration.
* Orion action queue — round-trip and persistence.
* Orion idempotency — duplicate `idempotency_key` is rejected.
* Orion reconciliation — `report_id` format and `completed_at` is set.
* Orion capability registry — control-plane profile and negative
  defaults are all False.
* Orion database schema — all four tables are present.
* Orion audit integration — all 11 ORION_* audit event types exist.
* Orion consent integration — safe actions validate without
  configured subsystems.
* Orion offline queue — actions persist across queue reopens.
* Orion handler registry — handler dispatch map is populated.

All 11 checks pass on a healthy install.

