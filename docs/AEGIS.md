# GuardianMesh Aegis — Phase 8 (v0.8.0)

**Production Android Companion & Consent-Gated Screen Capture**

> **Aegis is a consent-based screen-sharing companion, NOT a surveillance engine.**

Aegis turns the Phase 7 Vista Android integration boundary into a
real, production-oriented Android companion architecture using
Android's official ``MediaProjection`` consent flow.

The Termux/Linux GuardianMesh project remains the **control plane**.
The Android companion is the **execution / capture plane**. Aegis is
the contract between them.

---

## 1. The Aegis Equation

```
Child authorization (Vista, Phase 7)
        +
Android system consent (MediaProjection, Phase 8)
        +
Visible indicator (Foreground service notification)
        +
Local stop control (STOP SHARING action)
        +
Time-limited session (5 min default, 1 h hard cap)
        +
Nexus encryption (Phase 6, reused as-is)
        =
Aegis
```

All six are required. Removing any one breaks the safety model.

---

## 2. Three-Key Consent Gate

Capture is forbidden unless all three of the following hold:

1. **Trust** (Phase 2): the device is in the trusted registry.
2. **Authorization** (Phase 7): the child has approved the screen view
   in GuardianMesh.
3. **System consent** (Phase 8): the child has tapped **Allow** in the
   Android ``MediaProjection`` system dialog.

The gate is the enforcement point. There is no shortcut around it. The
control plane refuses to start capture if any one is missing or
expired.

```
REQUESTED
   |
   v
PENDING_CHILD_APPROVAL  (GuardianMesh authorization)
   |
   v
APPROVED
   |
   v
SYSTEM_CONSENT_REQUIRED  (Android MediaProjection dialog)
   |
   v
SYSTEM_CONSENT_GRANTED  (child taps "Allow")
   |
   v
CAPTURING
   |
   +---> STOPPED
   +---> EXPIRED
   +---> REVOKED
```

---

## 3. The Android Companion

The Aegis Android companion lives in ``android/aegis/``. It is a
standard Android Gradle project that:

* Uses only public Android APIs. No root. No hidden APIs. No Magisk.
* Wraps ``android.media.projection.MediaProjection`` with the
  documented consent flow.
* Hosts a foreground service with a persistent ``SCREEN VIEW
  ACTIVE`` notification.
* Exposes a ``STOP SHARING`` action that performs an immediate local
  cancellation — even when the network is unavailable.
* Encodes frames with ``android.media.MediaCodec`` (H.264 hardware
  encoder when available).
* Sends frames over the existing Nexus transport. No new encryption
  protocol.
* Holds frame bytes only in a bounded in-memory queue
  (``BoundedFrameQueue``, max 30 frames, ``DROP_OLDEST`` backpressure).

The companion is documented in detail in ``docs/ANDROID.md``.

---

## 4. Hard Limits

Aegis enforces the following hard limits (both on the control plane
and on the companion):

| Setting | Default | Hard cap |
| --- | --- | --- |
| Frames per second | 10 | 30 |
| Capture width | 1280 | 1920 |
| Capture height | 720 | 1080 |
| Encoded frame size | 4 MiB | 4 MiB |
| Buffered frames | 30 | 30 |
| Maximum session lifetime | 300 s | 3600 s |
| Inactivity timeout | 60 s | unbounded |

These bounds are enforced at every pipeline stage. The frame rate is
enforced by ``FrameLimiter``; the resolution is enforced by
``FrameNormalizer``; the frame size is enforced by
``FrameValidator``; the queue is enforced by ``BoundedFrameQueue``.

When the parent is slower than the child, the default backpressure
strategy is ``DROP_OLDEST``. Memory usage is bounded by the queue
capacity plus the size of one in-flight frame.

---

## 5. Nexus Integration

Aegis does NOT introduce a new encryption protocol. All screen traffic
flows through the existing Nexus transport (Phase 6):

```
Aegis Frame
   ↓
ScreenTransportAdapter (Android)
   ↓
NexusClient (X25519 + HKDF + AES-256-GCM)
   ↓
Socket (loopback / LAN)
   ↓
TransportEnvelope (Phase 6)
   ↓
TransportSession.encrypt_envelope (Phase 6)
   ↓
EncryptedTransportFrame (Phase 6)
   ↓
Nexus framing (Phase 6)
```

The same AEAD keys, the same replay defense, and the same
authentication guarantees protect every screen frame as every other
GuardianMesh message. The ``ScreenMessageType`` allowlist contains
zero remote-control names; the production transport ``MessageType``
enum has been extended with seven narrow screen names (``SCREEN_*``)
and no other additions.

---

## 6. Privacy Guarantees

Aegis never transmits, stores, or processes:

* Messages, SMS, chat, email
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
screen frame. The only state persisted locally is session metadata in
the ``aegis_sessions`` table (Phase 8 Migration).

---

## 7. Test Suite

Aegis ships with a comprehensive test suite that verifies:

* Capture is forbidden without explicit authorization
* Capture is forbidden without explicit system consent
* Capture is forbidden on a non-Android platform
* Frame bytes never reach the database
* Frame bytes never reach the audit log
* Frame bytes never reach the in-memory logs
* No remote-control message type is ever accepted
* The visible indicator is active for the entire capture session
* Trust revocation tears down the active session
* Authorization expiry tears down the active session
* System consent revocation tears down the active session
* Local stop works without contacting the parent
* Bounded queue with ``DROP_OLDEST`` backpressure

The full test count and coverage are reported in the Phase 8 final
validation.

---

## 8. CLI Commands

Aegis extends the Phase 7 ``guardian screen`` commands:

```
guardian screen status [<device_id>]            # existing (Vista)
guardian screen request <device_id>             # existing (Vista)
guardian screen approve <session_id>            # existing (Vista)
guardian screen deny <session_id>               # existing (Vista)
guardian screen start <session_id>              # existing (Vista)
guardian screen stop <session_id>               # existing (Vista)
guardian screen view <session_id>               # existing (Vista)
guardian screen list                            # existing (Vista)
guardian screen diagnostics                     # extended (Aegis)
guardian screen providers                       # new (Aegis)
guardian screen limits                          # new (Aegis)
```

``guardian screen providers`` lists the available Android capture
providers (metadata only). On Linux it reports the
``AdapterOnlyMediaProjectionProvider``; on Android it would report
the production ``MediaProjection`` provider.

``guardian screen limits`` reports the documented Aegis hard limits
as a JSON or text table.

---

## 9. Doctor

``guardian doctor`` extends with Aegis-specific checks:

* ``Aegis module`` - Aegis classes import and expose the documented API.
* ``System consent gate`` - The gate refuses capture on Linux.
* ``Aegis privacy redaction`` - ``AegisSessionInfo`` does not contain
  any payload-bearing fields.
* ``Android provider boundary`` - The adapter reports
  ``is_real_capture = False`` on Linux.
* (existing) ``Visible indicator`` - The Vista child-side indicator
  displays the documented banner.

On Linux the doctor honestly reports:

> ``Android screen provider: integration adapter only``

The doctor never claims real Android capture is active unless the
provider reports ``is_real_capture = True``.

---

## 10. Limitations

Aegis Phase 8 has the following documented limitations:

1. **No real Android capture on Linux/Termux.** The shipped provider
   is the ``AdapterOnlyMediaProjectionProvider`` test adapter. A
   future Android companion (APK) is required for production capture.
2. **No terminal video decoder.** The ``view`` subcommand prints
   metadata only. Real video decoding happens in a future viewer.
3. **MediaCodec stub on the control plane.** The
   ``AndroidMediaCodecEncoder`` class is wired in but raises
   ``AegisEncoderError`` when invoked from the Python control plane.
4. **The companion must be built and installed on a physical Android
   device.** The companion is documented reference architecture
   that requires a real Android build environment.

These limitations are documented features of Phase 8, not bugs.
