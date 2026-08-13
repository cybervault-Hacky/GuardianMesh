# GuardianMesh Privacy

> **GuardianMesh is consent-based. Every feature that touches user
> data requires explicit, fresh consent. The system makes the safe
> behavior the easiest behavior.**

This document is the canonical statement of the privacy guarantees
of the GuardianMesh project across all phases. It complements
``docs/SECURITY.md`` (the project-wide security model) and
``docs/SCREEN_PRIVACY.md`` (the Phase 7/Vista-specific privacy
guarantees).

---

## 1. Cross-cutting invariants

The following invariants hold across every GuardianMesh phase:

* **No silent capture.** Every feature that touches user data
  requires explicit, fresh consent.
* **No frame persistence.** Pixel data exists only in memory for the
  duration of one processing cycle.
* **No secret persistence.** Private keys, session keys, OTPs,
  nonces, and other secrets are never written to the database or
  logs.
* **Audit redaction.** The audit log's redaction list is exhaustive
  and includes every known sensitive key.
* **Bounded lifetime.** Every feature has a documented maximum
  lifetime. The lifetime is enforced at the state machine level,
  not at the user interface level.
* **No remote control.** The protocol message-type allowlist
  contains zero remote-control names. Remote input, taps, clicks,
  swipes, gestures, and arbitrary shell execution are forbidden.
* **Permissions minimum.** Every system integration uses only the
  permissions that are genuinely required for the documented
  behaviour.

---

## 2. Per-phase guarantees

### Phase 1 (Genesis)

* Ed25519 keypairs are stored in the ``keys/`` directory with ``0600``
  permissions.
* The audit log is sanitized at write time. The redaction list is
  enforced by ``AuditLogger.sanitize_audit_details``.

### Phase 2 (Link)

* Pairing requires the child to explicitly approve the trust
  relationship via the in-GuardianMesh authorization step. The
  authorization is single-use and expires.
* The OTP verifier is salted and stored as a SHA-256 hash. The
  plaintext OTP is never persisted.

### Phase 3 (Pulse)

* Telemetry is restricted to the allowlist
  ``ALLOWED_HEALTH_FIELDS``. Any other field is rejected at the
  boundary.
* Telemetry retention is bounded at ``telemetry_retention_days``
  (default 7 days).

### Phase 4 (Sentinel)

* Policy evaluation is restricted to explicit technical
  conditions. No behavioral inferences.
* Alert retention is bounded at ``alert_retention_days`` (default
  30 days).

### Phase 5 (Console)

* The dashboard exposes only metadata. No raw payloads.
* ``--json`` output is redacted by the same audit redaction list.

### Phase 6 (Nexus)

* Session keys are wiped from memory on session termination.
* The transport refuses any payload with forbidden keys.
* Trust revocation immediately tears down the transport session.

### Phase 7 (Vista)

* See ``docs/SCREEN_PRIVACY.md`` for the full privacy statement.
* Highlights: no remote control, no frame persistence, no
  automatic authorization, no child-side indicator suppression.

### Phase 8 (Aegis)

* See ``docs/AEGIS.md`` and ``docs/ANDROID.md`` for the full
  privacy statement.
* Highlights: three-key consent gate, foreground service
  indicator, ``MediaProjection`` system consent, no new encryption
  protocol, no new Android permissions, bounded metrics.

### Phase 9 (Orion)

* See ``docs/ORION.md`` and ``docs/SECURITY.md#6-orion-orchestration-security-phase-9``
  for the full privacy statement.
* Highlights: strict allowlist of event types, action types, and
  capabilities; forbidden payload and parameter keys (frame,
  screenshot, keylog, message, clipboard, microphone, audio,
  camera, video, location, gps, browser_history, contacts, photos,
  files, command, shell, exec, execute, remote_input, password,
  private_key, secret, token, otp); four Orion database tables
  with no column for sensitive content; 11 ORION_* audit event
  types record only metadata; consent is delegated, never
  invented; reconciliation reports are metadata-only; the
  capability registry refuses to enable any negative default.

### Phase 10 (Atlas)

* See ``docs/ATLAS.md`` and ``docs/SECURITY.md#7-atlas-production-platform-security-phase-10``
  for the full privacy statement.
* Highlights: production hardening layer with read-only integrity
  verification, deterministic crash recovery, and metadata-only
  backup. Five Atlas database tables with no column for sensitive
  content. ``BACKUP_ALLOWED_TABLES`` excludes
  ``transport_messages``; ``BACKUP_FORBIDDEN_COLUMNS`` strips
  ``private_key_pem`` from ``identities``. Recovery never
  resurrects revoked trust, expired authorization, or expired
  Aegis consent. Android manifest verification rejects
  ``RECORD_AUDIO``, ``CAMERA``, ``ACCESS_FINE_LOCATION``,
  ``READ_SMS``, ``BIND_ACCESSIBILITY_SERVICE``, and others.
  9 new doctor checks cover the full Atlas subsystem.

---

## 3. What GuardianMesh never does

Across every phase, the following are forbidden:

* Silent or hidden screen capture
* Keystroke logging or input interception
* Microphone capture
* Camera capture
* Clipboard capture
* SMS, MMS, chat, email capture
* Contact extraction
* Browser history
* Location tracking
* Notification interception
* Password or credential scraping
* Remote control / remote input injection
* Bypassing Android OS permissions or child consent
* Disabling or hiding the Android system screen-capture indicator
* Disabling or hiding the GuardianMesh child-side visible indicator
* Automatic authorization without child approval

Any feature that would deliver one of the above capabilities is
**prohibited by design** in every phase of GuardianMesh.

---

## 4. Operator controls

A parent can:

* Pair with a child device (Phase 2)
* Inspect device health (Phase 3)
* Configure health surveillance policies (Phase 4)
* View the unified dashboard (Phase 5)
* Establish secure transport (Phase 6)
* Request a view-only screen session (Phase 7)
* Approve or deny a screen view (the child can also approve/deny)
* Stop an active view at any time
* Inspect Aegis diagnostics (Phase 8)

A child can:

* Approve or deny a view request (Phase 7)
* Stop an active view at any moment (Phase 7)
* See a persistent "SCREEN VIEW ACTIVE" indicator for the entire
  session (Phase 7)
* See a persistent Android foreground service notification (Phase 8)
* Tap "STOP SHARING" to end the session locally (Phase 8)
* See and approve the Android ``MediaProjection`` system consent
  dialog (Phase 8)

A future Android companion component must additionally honor:

* The Android system screen-capture indicator (cannot be hidden)
* The Android ``MediaProjection`` consent dialog (cannot be bypassed)

---

## 5. Verification

The privacy invariants are verified by an explicit test suite
(``tests/test_screen_security.py`` and
``tests/test_aegis_security.py``) that:

* Iterates every message-type enum and asserts the absence of every
  remote-control name.
* Iterates every database table schema and asserts the absence of
  every payload-bearing column.
* Inserts a unique secret payload, ingests frames, stops the
  session, and verifies that the secret bytes do not appear in any
  audit event, log file, or database row.
* Asserts that trust revocation tears down the active session.
* Asserts that bounded session lifetime, inactivity timeout, and
  transport disconnect all terminate the session.
* Asserts that the ``BoundedFrameQueue`` applies ``DROP_OLDEST``
  backpressure and never grows beyond the documented queue size.
* Asserts that local stop works without contacting the parent.

A test failure in any of the above cases is treated as a
**critical privacy regression** and must be fixed before the build
is released.
