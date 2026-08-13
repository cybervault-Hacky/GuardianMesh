# GuardianMesh Android Companion — Aegis

> The Aegis Android companion is the **execution / capture plane** of
> GuardianMesh Phase 8. The Python control plane (Termux / Linux)
> drives the companion through the existing Nexus transport; the
> companion performs the actual ``MediaProjection`` capture on the
> child device.

This document describes the production Android companion. The
companion is implemented in Kotlin and lives in
``android/aegis/`` at the repository root.

## Status legend

| Category | Status |
| --- | --- |
| Architecture | **Implemented** (Kotlin reference) |
| Module structure | **Implemented** (Kotlin reference) |
| JVM unit tests | **Implemented** (15 tests) |
| Android build | **Requires physical Android build environment** |
| Real device validation | **Requires physical Android validation** |
| Real MediaProjection | **Requires physical Android companion (APK)** |

> The companion is **not executable** on the Linux/Termux development
> host. It is documented reference architecture that requires a real
> Android build environment (``./gradlew assembleDebug``) and a
> physical Android device to validate.

## Module structure

```
android/aegis/
├── README.md                                    # Companion overview
├── build.gradle.kts                             # Android build
├── settings.gradle.kts                          # Gradle settings
└── app/
    ├── src/
    │   ├── main/
    │   │   ├── AndroidManifest.xml              # Permissions, services
    │   │   ├── res/values/strings.xml           # Notification copy
    │   │   └── java/com/guardianmesh/aegis/
    │   │       ├── app/
    │   │       │   ├── AegisApplication.kt      # Process-wide setup
    │   │       │   └── AegisForegroundService.kt# Foreground indicator
    │   │       ├── core/
    │   │       │   ├── AegisConstants.kt        # Hard limits
    │   │       │   ├── AegisError.kt            # Typed errors
    │   │       │   ├── AegisLogger.kt           # Metadata-only logger
    │   │       │   └── AegisMetrics.kt           # Bounded counters
    │   │       ├── screen/
    │   │       │   ├── MediaProjectionProvider.kt  # Real capture boundary
    │   │       │   ├── ImageReaderFrameSource.kt    # Virtual display reader
    │   │       │   ├── FrameNormalizer.kt           # Resolution guard
    │   │       │   ├── FrameLimiter.kt              # FPS guard
    │   │       │   ├── AndroidMediaCodecEncoder.kt  # Production encoder
    │   │       │   └── BoundedFrameQueue.kt        # Bounded buffer
    │   │       ├── transport/
    │   │       │   ├── NexusClient.kt              # Reuses Phase 6
    │   │       │   └── ScreenTransportAdapter.kt  # Frame -> Nexus
    │   │       ├── authorization/
    │   │       │   ├── SystemConsentGate.kt        # MediaProjection gate
    │   │       │   └── ConsentTokenStore.kt       # Encrypted prefs
    │   │       └── security/
    │   │           ├── PrivacyGuard.kt             # Defensive guards
    │   │           └── RedactionRules.kt           # Reuse Python list
    │   └── test/
    │       └── java/com/guardianmesh/aegis/
    │           ├── FrameLimiterTest.kt
    │           ├── BoundedFrameQueueTest.kt
    │           ├── RedactionRulesTest.kt
    │           ├── PrivacyGuardTest.kt
    │           └── AegisConstantsTest.kt
    └── gradle/
```

## Permissions (minimum required)

The manifest declares only the permissions that are genuinely
required for the documented behaviour. **No** of the following
permissions are declared:

* ``INTERNET`` (the companion talks to the parent over the existing
  Nexus loopback or LAN; no direct internet access is required).
* ``RECORD_AUDIO`` (no microphone).
* ``CAMERA`` (no camera).
* ``ACCESS_FINE_LOCATION`` (no location).
* ``READ_CONTACTS`` (no contacts).
* ``READ_SMS`` (no SMS).
* ``BIND_ACCESSIBILITY_SERVICE`` (no accessibility).
* ``SYSTEM_ALERT_WINDOW`` (no overlay tricks).
* ``MANAGE_EXTERNAL_STORAGE`` (no file scraping).
* ``READ_CALL_LOG`` (no call log).
* ``QUERY_ALL_PACKAGES``.

The permissions that **are** declared are:

* ``android.permission.FOREGROUND_SERVICE`` - required for the
  indicator notification.
* ``android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION`` -
  required by Android 14+ for the foreground service that hosts the
  projection.
* ``android.permission.POST_NOTIFICATIONS`` - required to display
  the indicator on Android 13+.

## Architectural rules

The companion implements the same contracts as the Python control
plane. The following rules are non-negotiable:

1. **No silent capture.** The companion MUST receive an Android
   ``MediaProjection`` token issued by the system consent dialog
   before any frame is delivered to the pipeline.
2. **Foreground service indicator is always visible.** The
   companion MUST start a foreground service with the documented
   notification before delivering frames and MUST stop the service
   the moment the session ends.
3. **Child stop is local and immediate.** The companion MUST honour
   the ``STOP SHARING`` notification action locally — even if the
   network is unavailable — by tearing down the projection, the
   foreground service, the buffer, and the in-memory state.
4. **No remote control.** The companion has no SCREEN_CONTROL,
   REMOTE_INPUT, EXECUTE, SHELL, or COMMAND surface. It only emits
   ``SCREEN_FRAME`` and metadata over the existing Nexus transport.
5. **No frame persistence.** The companion never writes frame bytes
   to disk. Frames exist only in the in-memory ``BoundedFrameQueue``
   for the duration of one frame processing cycle.
6. **Bounded resources.** Maximum 10 FPS, 1280x720, 4 MiB encoded
   frame, 30 queued frames, ``DROP_OLDEST`` backpressure.
7. **No hidden APIs.** The companion uses only public Android APIs.
   No root. No Magisk. No system-level bypass.
8. **Encryption reuse.** The companion never invents a new
   encryption protocol. All payloads flow through ``NexusClient``
   which uses the same X25519 + HKDF + AES-256-GCM primitives as
   every other GuardianMesh message.

## Building

The companion is a standard Android Gradle project. To build:

```bash
cd android/aegis
./gradlew assembleDebug
```

The resulting APK is installed on the child device and runs the
``AegisForegroundService`` whenever the parent requests a view.

## Testing

The companion ships with a JVM unit test suite that exercises the
core frame pipeline and consent logic without requiring a physical
Android device. The unit tests use ``JUnit 4`` and run on the JVM.

To run the unit tests:

```bash
cd android/aegis
./gradlew test
```

The unit tests cover:

* ``FrameLimiter`` - first-frame-allowed, second-frame-too-quick
  rejection, reset behaviour, invalid FPS rejection.
* ``BoundedFrameQueue`` - queue fills, ``DROP_OLDEST`` strategy,
  drain behaviour, invalid max-size rejection.
* ``RedactionRules`` - the forbidden-key set contains the documented
  sensitive keys and does not contain any remote-control keys.
* ``PrivacyGuard`` - payload-bearing field names are rejected;
  metadata field names are accepted.
* ``AegisConstants`` - the documented hard limits are stable.

## Lifecycle handling

The companion handles every Android lifecycle event:

* Activity recreation
* process death and restart
* screen lock
* display rotation
* orientation changes
* network loss and recovery
* ``MediaProjection`` termination
* permission denial
* encoder failure
* ``ImageReader`` failure

The companion never silently restarts capture after authorization
becomes invalid. A new capture session requires a fresh
authorization and a fresh system consent grant.

## What the companion is NOT

The companion is **not**:

* a keylogger
* a microphone capture service
* a camera capture service
* a clipboard reader
* a location tracker
* a notification interceptor
* a stealth monitoring system
* a remote-control system

These prohibitions are enforced by:

* the absence of the relevant permissions in the manifest;
* the absence of remote-control code paths in the production code;
* the narrow ``SCREEN_FRAME``-only message surface;
* the unit test suite that verifies the redaction rules;
* the absence of any audio, camera, location, clipboard, or contact
  APIs in the production code.

## How to validate on a real device

To validate the companion on a physical Android device:

1. Build the APK: ``cd android/aegis && ./gradlew assembleDebug``.
2. Install on the child device: ``adb install app/build/outputs/apk/debug/app-debug.apk``.
3. Pair the child device with the parent via ``guardian pair`` (Phase 2).
4. Approve a screen view via ``guardian screen request`` (Phase 7).
5. Watch the foreground notification appear on the child device
   after the system consent dialog is granted.
6. Tap ``STOP SHARING`` on the child device to verify local stop
   works without the network.
7. Inspect the ``aegis_sessions`` table on the parent to confirm
   metadata persistence.

> The companion **cannot** be validated on the Linux/Termux
> development host. The Phase 8 final validation explicitly
> separates the categories "implemented", "unit-tested", and
> "requires physical Android validation".

## Cross-references

* ``docs/AEGIS.md`` - the Aegis operational guide.
* ``docs/SCREEN_PROTOCOL.md`` - the wire-level screen protocol.
* ``docs/SCREEN_PRIVACY.md`` - the privacy guarantees.
* ``android/aegis/README.md`` - the companion overview.
