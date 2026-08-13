# GuardianMesh Screen Protocol — Phase 7 (v0.7.0)

This document defines the on-the-wire protocol for consent-based,
view-only screen sessions. The protocol is built on top of the existing
Nexus transport (Phase 6) and reuses its authentication, encryption,
replay defense, and heartbeat machinery.

> GuardianMesh Vista is NOT a covert monitoring system.

---

## 1. Protocol Version

* Protocol version: ``1.0``
* Framing: Nexus ``TransportEnvelope`` over Nexus
  ``EncryptedTransportFrame`` (AES-256-GCM)
* Sequence numbers: per-session, monotonic, with sliding-window replay
  defense

---

## 2. Message Types

The screen protocol adds a strictly allowlisted set of message types
to the Nexus transport:

| Message type           | Direction   | Purpose                                            |
| ---------------------- | ----------- | -------------------------------------------------- |
| ``SCREEN_VIEW_REQUEST``| PARENT → CHILD | Parent requests a view-only screen session.        |
| ``SCREEN_VIEW_APPROVAL``| CHILD → PARENT | Child explicitly approves the view request.        |
| ``SCREEN_VIEW_DENIAL``  | CHILD → PARENT | Child explicitly denies the view request.          |
| ``SCREEN_SESSION_START``| PARENT → CHILD | Parent begins streaming frames for an APPROVED session. |
| ``SCREEN_FRAME``        | CHILD → PARENT | A single screen frame (encrypted, sequence-numbered). |
| ``SCREEN_SESSION_STOP`` | BIDIRECTIONAL | Either side terminates the session.                |
| ``SCREEN_SESSION_EXPIRED``| BIDIRECTIONAL | Authorization/session lifetime has elapsed.        |

### 2.1 Forbidden Names

The following names are **never** accepted on the wire. They are
rejected at construction time by
:func:`assert_no_remote_control_type`:

```
SCREEN_CONTROL
REMOTE_INPUT
REMOTE_CLICK
REMOTE_TAP
REMOTE_SWIPE
REMOTE_GESTURE
EXECUTE
SHELL
COMMAND
KEYLOG
KEYSTROKE
MIC / MICROPHONE
CAMERA
GPS / LOCATION
```

Any attempt to instantiate a screen message with one of these names
raises :class:`ScreenRemoteControlError` and is recorded in the audit
log as a transport rejection.

---

## 3. Screen Envelope

A screen message is wrapped in a :class:`ScreenEnvelope` and then
adapted to a Nexus :class:`TransportEnvelope`. The Nexus envelope
header is the canonical, authenticated, and replay-protected header.
The payload contains screen-specific metadata:

```json
{
  "screen_message_type": "SCREEN_FRAME",
  "screen_session_id": "SCN-1234567890AB",
  "screen_device_id": "GM-C-19A84E72",
  "screen_parent_id": "GM-P-83A1F72C",
  "screen_transport_session_id": "SES-...",
  "screen_payload": {
    "frame_id": "FRM-...",
    "sequence": 1,
    "captured_at": "2026-08-13T12:00:00+00:00",
    "width": 1280,
    "height": 720,
    "pixel_format": "RGB24",
    "codec": "H264",
    "payload_size": 65536,
    "payload_hex": "..."
  }
}
```

The full canonical JSON serialization of a screen envelope is
deterministic (sorted keys, compact separators) so that the same
logical message always produces the same bytes.

---

## 4. Screen Frame

A :class:`ScreenFrame` is a single screen capture. It is a
versioned, session-bound, strictly-validated data structure:

| Field            | Type   | Description                              |
| ---------------- | ------ | ---------------------------------------- |
| ``protocol_version`` | str  | Always ``"1.0"``.                       |
| ``session_id``   | str    | ``SCN-XXXXXXXXXXXX`` screen session ID.  |
| ``device_id``    | str    | Source child device (``GM-C-XXXXXXXX``).|
| ``frame_id``     | str    | ``FRM-XXXXXXXXXXXX`` unique frame ID.    |
| ``sequence``     | int    | Positive, monotonic, per-session.        |
| ``captured_at``  | str    | ISO-8601 UTC timestamp.                  |
| ``width``        | int    | Frame width in pixels (≤ 1920).         |
| ``height``       | int    | Frame height in pixels (≤ 1080).        |
| ``pixel_format`` | str    | One of: ``RGB24``, ``RGBA32``, ``YUV420``, ``BGR24``, ``TEST``. |
| ``codec``        | str    | One of: ``TEST``, ``H264``, ``VP8``, ``VP9``, ``WEBP``. |
| ``payload_size`` | int    | Byte length of the ``payload`` field.    |
| ``payload``      | bytes  | Codec-specific frame payload.            |

### 4.1 Validation

A frame is rejected if any of the following holds:

* ``protocol_version`` is not ``"1.0"``
* ``device_id`` does not match the strict ``GM-(P|C)-XXXXXXXX`` format
* ``session_id`` is empty
* ``sequence`` is non-positive
* ``width`` or ``height`` is non-positive
* ``width`` exceeds ``max_width`` (default 1920)
* ``height`` exceeds ``max_height`` (default 1080)
* ``len(payload)`` exceeds ``max_payload_bytes`` (default 4 MiB)
* ``payload_size`` does not match ``len(payload)``
* ``captured_at`` is not a valid ISO-8601 timestamp

### 4.2 Sequence Tracking

Frames are accepted in strictly monotonic order. The
:class:`FrameSequenceTracker` maintains a sliding window of accepted
sequences and rejects:

* Non-positive sequences
* Duplicate sequences (replays)
* Sequences older than the sliding window boundary

The default window size is ``128``. Memory usage is bounded by the
window size.

---

## 5. Encryption

All screen traffic is encrypted by the existing Nexus transport. The
:class:`ScreenTransportBridge` does not introduce a new encryption
system. The wire-level format is:

```
Nexus TransportEnvelope
  -> AES-256-GCM encryption
  -> EncryptedTransportFrame
  -> Nexus framing (length-prefixed stream)
```

The encryption keys are derived from the same X25519 ECDH shared
secret as every other GuardianMesh message. Replay protection is
enforced at the transport layer; frame-level sequence protection is
enforced at the screen layer. Both layers cooperate.

---

## 6. Codecs

The protocol allows multiple codecs, but only the
:class:`TestCodec` is active in this build. Other codecs are wired in
as integration stubs:

| Codec   | Status     | Notes                                    |
| ------- | ---------- | ---------------------------------------- |
| ``TEST``| ACTIVE     | Deterministic synthetic frames.          |
| ``H264``| STUB       | Future Android companion dependency.     |
| ``VP8`` | STUB       | Future Android companion dependency.     |
| ``VP9`` | STUB       | Future Android companion dependency.     |
| ``WEBP``| STUB       | Future Android companion dependency.     |

The :class:`ScreenCodecRegistry` is the single source of truth. Any
attempt to encode with a stub codec raises
:class:`ScreenCodecError`. Any attempt to register an unknown codec
is rejected.

---

## 7. Authorization

Authorization is bound to a session and recorded in the
``screen_authorizations`` table. The schema is:

| Field                  | Type | Notes                                  |
| ---------------------- | ---- | -------------------------------------- |
| ``authorization_id``   | TEXT | Primary key.                           |
| ``session_id``         | TEXT | UNIQUE. Screen session.                |
| ``device_id``          | TEXT | Child identity.                        |
| ``parent_id``          | TEXT | Parent identity.                       |
| ``decision``           | TEXT | PENDING / APPROVED / DENIED / EXPIRED / REVOKED. |
| ``requested_at``       | TEXT | ISO timestamp.                         |
| ``approved_at``        | TEXT | ISO timestamp or NULL.                 |
| ``denied_at``          | TEXT | ISO timestamp or NULL.                 |
| ``expires_at``         | TEXT | ISO timestamp.                         |
| ``max_duration_seconds``| INT | 30 ≤ N ≤ 3600.                        |
| ``label``              | TEXT | Optional human-readable label.         |
| ``metadata``           | TEXT | JSON (no sensitive keys).              |

The table does **not** store the authorization nonce, the session key,
the OTP, or any other secret. The nonce is generated on the fly for
fresh in-process authorizations and is not persisted.

---

## 8. Session Lifecycle

A :class:`ScreenSession` is a stateful object that ties together the
authorization, the in-memory frame buffer, the visible indicator, the
database record, and the transport session ID. The legal state
transitions are:

```
REQUESTED -> PENDING_CHILD_APPROVAL
PENDING_CHILD_APPROVAL -> APPROVED
PENDING_CHILD_APPROVAL -> DENIED
PENDING_CHILD_APPROVAL -> EXPIRED
APPROVED -> ACTIVE
APPROVED -> EXPIRED
APPROVED -> REVOKED
ACTIVE -> STOPPED
ACTIVE -> EXPIRED
ACTIVE -> REVOKED
```

Any other transition is rejected by
:func:`assert_legal_transition`.

---

## 9. Termination Conditions

A screen session is terminated and the child-side indicator is
deactivated when **any** of the following occurs:

* The child presses ``[ STOP SHARING ]`` (SCREEN_SESSION_STOP from
  child to parent).
* The parent invokes ``guardian screen stop <session_id>``.
* The transport session is closed.
* Trust is revoked for the child device.
* The maximum session lifetime elapses.
* The inactivity timeout elapses.
* The frame buffer or codec raises an unrecoverable error.

In every case, the session transitions to one of ``STOPPED``,
``EXPIRED``, or ``REVOKED``, the child-side indicator is deactivated,
the in-memory frame buffer is cleared, and the database record is
updated.

---

## 10. Threat Model

Vista assumes the following adversary model:

* The parent device is **honest** in following the protocol.
* The child device is **honest-but-cautious**: it may not always
  approve a view, but it never lies about its decision.
* The transport channel is **opaque**: an on-path attacker sees only
  authenticated ciphertext. They cannot forge, replay, or reorder
  frames.
* The OS on each device is **honest** with the user. The
  ``MediaProjection`` consent dialog and the visible indicator
  are user-visible and cannot be suppressed by the application.

The model explicitly **does not** assume the child device is willing
to be silently monitored. Any attempt to implement silent or hidden
monitoring is a violation of the design and is rejected by the
test suite.
