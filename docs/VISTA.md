# GuardianMesh Vista — Phase 7 (v0.7.0)

**Consent-Based View-Only Screen Sessions**

> **GuardianMesh Vista is NOT a covert monitoring system.**

Vista introduces a privacy-preserving, child-authorized, **view-only** screen
observation subsystem. It is the seventh phase in the GuardianMesh
10-phase roadmap and is the first phase that touches pixel data of any
kind — and it does so with the most restrictive consent model in the
project.

---

## 1. Why Vista Exists

Parents and guardians have a legitimate need to understand what is
happening on a child device in real time. Earlier GuardianMesh phases
already allow authorized, non-covert health, policy, and pairing
information to flow between parent and child devices. Phase 7 extends
that flow to a single, narrow, **view-only** capability:

* The parent may observe the **current screen** of a child device
  **only after** the child has explicitly approved the view.
* The child is shown a **persistent visible indicator** for the entire
  duration of the active session.
* The child can **stop the session at any moment**.
* The parent receives only **view-only frames** — never control, never
  input, never telemetry of any other kind.
* No data is silently recorded. No data is persisted on the parent or
  child beyond the active session lifetime.

Vista is the **only** GuardianMesh feature that can show pixel data, and
its privacy and consent guarantees are intentionally stricter than every
other phase in the project.

---

## 2. Strict Prohibitions

The following are **never** implemented in Vista, in any form, on any
platform:

* Silent screen capture
* Hidden screen sharing
* Stealth recording
* Background covert capture
* Keylogging or keystroke interception
* Keyboard, mouse, touch, gesture, swipe, click, or tap input
* Remote shell or arbitrary command execution
* Microphone capture
* Camera capture
* Clipboard capture
* SMS, MMS, chat, email, or any other message capture
* Contact extraction
* Browser history
* Location tracking
* Notification interception
* Password or credential capture
* Bypassing Android permissions
* Bypassing Android security restrictions
* Disabling or hiding the system screen-capture indicator
* Suppressing or hiding the Vista child-side indicator
* Automatic authorization without child approval

Vista does **not** attempt to circumvent Android's user-visible
``MediaProjection`` consent dialog. It does not use root-only tricks or
hidden APIs. The integration boundary is documented in
``docs/SCREEN_PROTOCOL.md`` and in the source comments of
``guardianmesh/screen/indicator.py``.

---

## 3. Architecture

```
Parent Console
       |
       |  SCREEN_VIEW_REQUEST
       v
Nexus Secure Transport   <-- Phase 6, reused as-is
       |
       v
Child Authorization      <-- child-side explicit decision
       |
       |  APPROVED
       v
Child Screen Session     <-- bounded lifetime, bounded resources
       |
       |  encrypted video frames (TEST codec / future H.264 / VP8 / ...)
       v
Nexus Secure Transport
       |
       v
Parent Viewer            <-- metadata-only status; frames are
                             delivered through the same encrypted
                             transport as every other GuardianMesh
                             payload
```

### 3.1 Module layout

```
guardianmesh/screen/
    __init__.py            # public API
    models.py              # ScreenFrame, ScreenSession, ScreenAuthorization
    authorization.py       # child-side authorization state machine
    session.py             # session lifecycle and bounded buffers
    frames.py              # frame validation, sequence tracking, backpressure
    codec.py               # codec abstraction (TestCodec, future H.264 / VP8 / VP9 / WebP)
    indicator.py           # AndroidScreenProvider boundary + ScreenIndicator
    transport.py           # ScreenMessageType allowlist + ScreenTransportBridge
    controller.py          # high-level orchestrator
    registry.py            # metadata-only database persistence (screen_sessions)
    auth_registry.py       # metadata-only database persistence (screen_authorizations)
    errors.py              # structured exception hierarchy
```

### 3.2 What lives in the database

* The ``screen_sessions`` table: session metadata only.
* The ``screen_authorizations`` table: authorization decision metadata
  only.

The following are **never** stored in the database, in logs, or in
memory beyond a short-lived buffer:

* Frame payloads, screenshots, raw pixel data, image blobs
* Private keys, session keys, shared secrets, OTPs, nonces
* User passwords, clipboard contents, IME input

---

## 4. Child Authorization Lifecycle

```
REQUESTED
   |
   v
PENDING_CHILD_APPROVAL
   |
   +---> DENIED
   |
   v
APPROVED  <-- only after explicit child decision
   |
   +---> EXPIRED
   |
   v
ACTIVE
   |
   +---> STOPPED
   +---> EXPIRED
   +---> REVOKED
```

Key guarantees:

* **Trust is not screen authorization.** A trusted device relationship
  is necessary but not sufficient. Every screen session requires a
  *fresh* child approval.
* **Authorization is single-use.** Once a session is STOPPED,
  EXPIRED, or REVOKED, a new authorization is required.
* **Authorization expires.** The default lifetime is **5 minutes
  (300 seconds)**. The hard cap is **1 hour (3600 seconds)**.
* **Sessions never outlive their lifetime.** The controller and
  CLI tools enforce the lifetime at every transition.
* **Revocation terminates immediately.** Trust revocation (Phase 2)
  tears down any active screen session synchronously.

---

## 5. Child-Side Visible Indicator

The child-side UI must display a clearly visible indicator while a
session is ACTIVE. The :class:`ScreenIndicator` class is the single
source of truth for that state. It cannot be hidden or suppressed by
any other component.

```
┌──────────────────────────────────┐
│ GuardianMesh                     │
│                                  │
│  ● SCREEN VIEW ACTIVE            │
│                                  │
│  Parent: <parent label>          │
│  Session: 02:41 remaining        │
│                                  │
│       [ STOP SHARING ]            │
└──────────────────────────────────┘
```

The indicator is rendered by ``ScreenIndicator.render()``. The CLI
prints the same banner in ``guardian screen view <session_id>``.

---

## 6. Android Boundary

The current GuardianMesh codebase is a **Termux/Linux developer tool**.
It does **not** and **cannot** capture the real Android screen from
Python alone. The :class:`AndroidScreenProvider` abstract base class
defines the integration boundary; the shipped
:class:`AdapterOnlyScreenProvider` is a clearly-marked adapter that
emits deterministic synthetic frames for end-to-end testing.

A future Android companion component (an APK) would implement
``AndroidScreenProvider`` and use Android's ``MediaProjection`` API
with the system consent dialog. The current build never claims that
real screen capture is active unless the provider reports
``is_real_capture = True``.

The :func:`guardian doctor` command explicitly reports:

* ``[✓] Vista module``
* ``[✓] Screen authorization``
* ``[✓] Session manager``
* ``[✓] Frame validation``
* ``[✓] Nexus integration``
* ``[✓] Resource limits``
* ``[✓] Child stop mechanism``
* ``[✓] Visible indicator boundary``
* ``[!] Android screen provider: integration adapter only``

The ``[!]`` notice is a **feature**, not a bug: it is the documented
honest declaration of the current state of the integration.

---

## 7. Frame Protocol

See ``docs/SCREEN_PROTOCOL.md`` for the full wire-level specification.
Highlights:

* All frames are versioned (protocol version ``1.0``).
* Every frame is bound to exactly one ``session_id`` and one
  ``device_id``.
* Frames travel only through the existing Nexus transport and use the
  same AEAD keys as every other message.
* The payload of a frame is opaque to the transport layer; the transport
  enforces authentication, replay protection, and sequence ordering.
* Frames are NEVER persisted on the parent or child disk. The
  in-memory :class:`FrameStreamBuffer` is bounded and applies
  backpressure.
* The default codec is :class:`TestCodec` (deterministic, synthetic).
  Future production codecs (H.264, VP8, VP9, WebP) are wired in
  ``screen/codec.py`` and will be activated by a future Android
  companion component.

---

## 8. Resource Limits

The following defaults are applied by the controller and the
``ScreenSessionConfig``:

| Setting                       | Default | Hard cap |
| ----------------------------- | ------- | -------- |
| ``max_fps``                   | 10      | 30       |
| ``max_width``                 | 1280    | 1920     |
| ``max_height``                | 720     | 1080     |
| ``max_frame_bytes``           | 4 MiB   | 4 MiB    |
| ``max_queue_size``            | 30      | unbounded |
| ``max_duration_seconds``      | 300     | 3600     |
| ``inactivity_timeout_seconds``| 60      | unbounded |

These bounds are enforced in:

* :class:`FrameValidator` (frame size, dimensions, payload size)
* :class:`FrameSequenceTracker` (sequence monotonicity, replay window)
* :class:`BoundedFrameQueue` (queue size, backpressure strategy)
* :class:`ScreenSession.check_lifecycle` (expiration, inactivity)
* :class:`ScreenAuthorizationManager` (max duration)

When the parent is slower than the child, the default backpressure
strategy is ``DROP_OLDEST``: the queue keeps the most recent frames and
drops the oldest. Memory usage is bounded by the queue capacity.

---

## 9. CLI Commands

```
guardian screen status [<device_id>]            [--json]
guardian screen request <device_id>             [--duration SECONDS] [--label LABEL] [--json]
guardian screen approve <session_id>            [--json]
guardian screen deny <session_id>               [--json]
guardian screen start <session_id>              [--json]
guardian screen stop <session_id>               [--json]
guardian screen view <session_id>               [--json]
guardian screen list                            [--json]
guardian screen diagnostics                     [--json]
```

All commands are metadata-only when ``--json`` is set. The ``view``
subcommand prints a live session card (resolution, frame rate, remaining
time, child-side indicator) and **does not** attempt to render decoded
video frames in the terminal — a future Android companion component is
required for that capability.

---

## 10. Security Model

Vista is the most conservative feature in GuardianMesh. The model is
intentionally simple and easy to audit:

* **No new encryption system.** All frames travel through Nexus
  (``TransportSession`` + ``MessageRouter``) with the same AEAD
  keys as every other message.
* **No new transport.** The :class:`ScreenTransportBridge` adapts
  screen envelopes to ``TransportEnvelope`` and reuses the existing
  sequence, replay, and authentication guarantees.
* **No remote control.** The :class:`ScreenMessageType` enum is a
  strict allowlist of seven narrowly-scoped names. Forbidden names
  (``SCREEN_CONTROL``, ``REMOTE_INPUT``, ``EXECUTE``, ``SHELL``,
  ``COMMAND``, ``KEYLOG``, ``KEYSTROKE``, …) are rejected at
  construction time by
  :func:`assert_no_remote_control_type`.
* **No payload persistence.** Frames are only ever held in the
  in-memory :class:`FrameStreamBuffer` and are dropped on session
  termination, transport disconnect, or trust revocation.
* **No redaction gaps.** The audit redaction list in
  ``guardianmesh.storage.audit`` is exhaustive and includes every
  known sensitive key (``payload``, ``screenshot``, ``frame_data``,
  ``raw_pixels``, ``password``, ``private_key``, ``otp``, …).

---

## 11. Privacy Guarantees

The Vista subsystem **never** transmits, stores, or processes:

* Messages, SMS, chat, email content
* Contacts or contact lists
* Photos or media files
* Browser history
* Keyboard input or keystrokes
* Clipboard data
* Microphone audio
* Camera frames
* Location, GPS, geofences
* Notifications
* Passwords, PINs, OTPs, secrets
* Remote control or remote input of any kind

The only payload that ever crosses the wire is the authorized current
screen frame. The only state persisted locally is session metadata.

---

## 12. Limitations (v0.7.0)

* **No real Android capture.** The shipped provider is an adapter
  that emits deterministic synthetic frames. A future Android
  companion component is required for production capture.
* **No terminal video decoder.** The ``view`` subcommand prints
  metadata only.
* **No H.264/VP8/VP9/WebP encoder.** The codec stubs raise
  ``ScreenCodecError`` when invoked. They exist to document the
  integration boundary; a real encoder requires a native dependency
  that is not appropriate for a Termux/Linux CLI tool.
* **No multi-parent shared sessions.** Each session is bound to a
  single parent identity.
* **No session recording.** Vista does not support recording. The
  design is intentionally streaming-only.

These limitations are documented features of Phase 7, not bugs.

---

## 13. Testing

Vista ships with a comprehensive test suite that verifies:

* Authorization state transitions, expiration, revocation
* Frame validation, sequence monotonicity, replay rejection
* Oversized-frame rejection
* Unsupported codec rejection
* Excessive FPS / resolution rejection
* Bounded frame queue and backpressure
* Trust revocation terminates the active session
* No remote-control message type is ever accepted
* No frame payload is ever persisted to the database
* No payload leaks through the audit log
* The full CLI workflow (request → approve → start → stop)

The complete test count is reported in the final phase validation.
