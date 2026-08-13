# GuardianMesh Screen Privacy — Phase 7 (v0.7.0)

> **GuardianMesh Vista is NOT a covert monitoring system.**

This document is the canonical statement of the privacy guarantees of
the Vista screen-view subsystem. It complements
``docs/SECURITY.md`` (the project-wide security model) and
``docs/VISTA.md`` (the operational guide).

---

## 1. What Vista Is

Vista is a **consent-based, view-only screen session** subsystem. It
allows a parent device to observe the **current screen** of a child
device in real time, with:

* Explicit child-side authorization per session
* A persistent, child-visible indicator for the entire active session
* Single-frame streaming (no recording, no persistent storage)
* Hard lifetime bounds (5 minutes default, 1 hour hard cap)
* Immediate, unilateral child stop control

Vista is designed so that the child is **always** aware that a session
is in progress and can revoke it at any moment. The parent never
receives anything other than the current screen frames that the child
has approved.

---

## 2. What Vista Is Not

Vista is **not**:

* A keylogger
* A microphone capture system
* A camera capture system
* A clipboard capture system
* A location tracker
* A notification interceptor
* A browser history harvester
* A password or credential scraper
* A remote control / remote input system
* A covert recording system
* A stealth monitoring system

Any feature that would deliver one of the above capabilities is
**prohibited by design** in Phase 7.

---

## 3. Privacy Invariants

The following invariants are enforced by code, tests, and the audit
log:

### 3.1 The "no silent capture" invariant

* Every screen session requires a fresh, explicit child authorization.
* Trust relationships (Phase 2) are necessary but not sufficient.
* The child UI is expected to show a clearly visible "SCREEN VIEW
  ACTIVE" indicator for the entire session lifetime.
* The child can stop the session at any time.

### 3.2 The "no frame persistence" invariant

* The ``screen_sessions`` and ``screen_authorizations`` database
  tables contain **metadata only**. No frame payload, screenshot,
  pixel data, or image blob is ever persisted.
* The in-memory :class:`FrameStreamBuffer` is bounded and applies
  backpressure. It is cleared on session termination.
* The audit log is redacted by the existing
  :class:`AuditLogger` redaction rules. The list of redacted keys
  is exhaustive and includes every known sensitive key.

### 3.3 The "no remote control" invariant

* The :class:`ScreenMessageType` enum is a strict allowlist of seven
  narrowly-scoped names. No remote-control message type is ever
  exposed.
* The transport-level :class:`MessageType` enum also contains
  narrowly-scoped screen names, no remote-control names.
* :func:`assert_no_remote_control_type` raises
  :class:`ScreenRemoteControlError` for any forbidden name.
* The test suite verifies the absence of every forbidden name.

### 3.4 The "no system bypass" invariant

* The :class:`AndroidScreenProvider` is an abstract integration
  boundary. The shipped :class:`AdapterOnlyScreenProvider` is a
  clearly-marked test adapter that emits synthetic frames.
* No attempt is made to bypass Android's ``MediaProjection`` consent
  flow.
* No root-only tricks. No hidden APIs. No suppression of the system
  screen-capture indicator.

### 3.5 The "no secret material" invariant

* The audit log redacts: passwords, OTPs, private keys, session keys,
  send/recv keys, encryption keys, shared secrets, OTPs, nonces,
  ciphertext, clipboard data, etc.
* The frame payload is opaque to the audit log; the redaction rules
  also scrub ``payload``, ``screenshot``, ``frame_data``, and
  ``raw_pixels`` keys.
* The ``screen_authorizations`` table does not store the
  authorization nonce, the session key, or the OTP.

### 3.6 The "bounded lifetime" invariant

* The default session lifetime is **5 minutes (300 seconds)**.
* The hard cap is **1 hour (3600 seconds)**.
* Inactivity timeouts are enforced.
* The screen authorization expires regardless of whether the parent
  is still connected.

---

## 4. Data Flow and Storage

### 4.1 In transit

* Parent → Child: SCREEN_VIEW_REQUEST, SCREEN_SESSION_START
* Child → Parent: SCREEN_VIEW_APPROVAL, SCREEN_VIEW_DENIAL,
  SCREEN_FRAME
* Bidirectional: SCREEN_SESSION_STOP, SCREEN_SESSION_EXPIRED

All messages are encrypted by the existing Nexus transport. No
plaintext frame data ever leaves the device.

### 4.2 At rest on the parent device

* ``screen_sessions`` table: session metadata only.
* ``screen_authorizations`` table: authorization decision metadata.
* ``audit_events`` table: redacted audit records.
* No frame payload is ever written to disk.

### 4.3 At rest on the child device

* The same tables, populated with metadata only.
* No frame payload is ever written to disk.
* The child-side :class:`ScreenIndicator` is a transient
  in-memory state object. The indicator is not persisted.

---

## 5. Indicator Invariants

The :class:`ScreenIndicator` is the single source of truth for the
child-side visible state. Its invariants:

* The indicator is **always** active while a session is ``ACTIVE``.
* The indicator is **always** deactivated when the session enters a
  terminal state (``STOPPED``, ``DENIED``, ``EXPIRED``, ``REVOKED``).
* No code path in ``screen.*`` can suppress, hide, or alter the
  indicator state without also updating the session lifecycle.
* The indicator render method emits a fixed-width text representation
  that is suitable for any Termux/Linux terminal.

The ``render()`` output explicitly includes the string
``SCREEN VIEW ACTIVE`` whenever the indicator is active. The test
suite verifies this invariant.

---

## 6. Operator-Facing Auditing

The :class:`AuditLogger` records the following Vista events with
metadata only:

* ``SCREEN_VIEW_REQUESTED``
* ``SCREEN_VIEW_APPROVED``
* ``SCREEN_VIEW_DENIED``
* ``SCREEN_SESSION_STARTED``
* ``SCREEN_SESSION_STOPPED``
* ``SCREEN_SESSION_EXPIRED``
* ``SCREEN_SESSION_REVOKED``
* ``SCREEN_FRAME_STREAM_STARTED``
* ``SCREEN_FRAME_STREAM_STOPPED``

The ``details`` field of each event contains only:

* ``session_id``, ``device_id``, ``parent_id``
* ``authorization_id``
* ``width``, ``height``, ``codec``, ``max_fps``
* ``stop_reason``
* ``reason`` (for revocations)

It never contains:

* Frame payloads, screenshots, pixel data
* Passwords, OTPs, private keys, session keys
* Clipboard contents, IME input, audio, video
* Location, contacts, messages, notifications

---

## 7. Operator Controls

A parent can:

* Request a view (after trust is established)
* Approve a view (the child can also approve)
* Deny a view (the child can also deny)
* Stop an active view
* View session metadata (no frame content)

A child can:

* Approve or deny a view request
* Stop an active view at any moment
* See a persistent "SCREEN VIEW ACTIVE" indicator for the entire
  session

A future Android companion component must additionally honor:

* The Android system screen-capture indicator (cannot be hidden)
* The Android ``MediaProjection`` consent dialog (cannot be bypassed)

---

## 8. Verification

The privacy invariants are verified by an explicit test suite
(``tests/test_screen_security.py``) that:

* Iterates the :class:`ScreenMessageType` enum and asserts the
  absence of every remote-control name.
* Iterates the transport :class:`MessageType` enum and asserts the
  absence of every remote-control name.
* Inserts a session with a unique "SECRETx" payload, ingests three
  frames, stops the session, and verifies that the secret bytes do
  not appear in any audit event.
* Inspects the ``screen_sessions`` table schema and asserts the
  absence of every payload-bearing column.
* Asserts that a device without an existing trust relationship
  cannot start a view (trust is necessary but not sufficient).
* Asserts that trust revocation tears down the active session.

A test failure in any of the above cases is treated as a
**critical privacy regression** and must be fixed before the build
is released.
