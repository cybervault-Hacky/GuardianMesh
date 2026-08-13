# Aegis Android Companion

> **Aegis is a consent-based screen-sharing companion, NOT a surveillance engine.**

The Aegis Android companion is the **execution / capture plane** of the
GuardianMesh Phase 8 architecture. The Python control plane (Termux /
Linux) drives the companion through the Nexus transport; the companion
performs the actual ``MediaProjection`` capture on the child device.

## Module structure

```
android/aegis/
├── README.md
├── app/
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml
│       │   ├── java/com/guardianmesh/aegis/
│       │   │   ├── app/
│       │   │   │   ├── AegisApplication.kt
│       │   │   │   ├── AegisForegroundService.kt
│       │   │   │   └── NotificationFactory.kt
│       │   │   ├── core/
│       │   │   │   ├── AegisConstants.kt
│       │   │   │   ├── AegisLogger.kt
│       │   │   │   └── AegisMetrics.kt
│       │   │   ├── screen/
│       │   │   │   ├── MediaProjectionProvider.kt
│       │   │   │   ├── ImageReaderFrameSource.kt
│       │   │   │   ├── FrameNormalizer.kt
│       │   │   │   ├── FrameLimiter.kt
│       │   │   │   ├── AndroidMediaCodecEncoder.kt
│       │   │   │   └── BoundedFrameQueue.kt
│       │   │   ├── transport/
│       │   │   │   ├── NexusClient.kt
│       │   │   │   └── ScreenTransportAdapter.kt
│       │   │   ├── authorization/
│       │   │   │   ├── SystemConsentGate.kt
│       │   │   │   └── ConsentTokenStore.kt
│       │   │   └── security/
│       │   │       ├── PrivacyGuard.kt
│       │   │       └── RedactionRules.kt
│       │   └── res/values/strings.xml
│       └── test/
│           └── java/com/guardianmesh/aegis/
│               ├── MediaProjectionProviderTest.kt
│               ├── FrameLimiterTest.kt
│               ├── BoundedFrameQueueTest.kt
│               └── SystemConsentGateTest.kt
└── gradle/
    └── build.gradle.kts
```

## Architectural rules

The companion implements the same contracts as the Python control
plane. The following rules are non-negotiable:

1. **No silent capture.** The companion MUST receive an Android
   ``MediaProjection`` token issued by the system consent dialog before
   any frame is delivered to the pipeline.
2. **Foreground service indicator is always visible.** The companion
   MUST start a foreground service with the documented notification
   before delivering frames and MUST stop the service the moment the
   session ends.
3. **Child stop is local and immediate.** The companion MUST honour the
   ``STOP SHARING`` notification action locally — even if the network
   is unavailable — by tearing down the projection, the foreground
   service, the buffer, and the in-memory state.
4. **No remote control.** The companion has no SCREEN_CONTROL,
   REMOTE_INPUT, EXECUTE, SHELL, or COMMAND surface. It only emits
   ``SCREEN_FRAME`` and metadata over the existing Nexus transport.
5. **No frame persistence.** The companion never writes frame bytes
   to disk. Frames exist only in the in-memory ``BoundedFrameQueue`` for
   the duration of one frame processing cycle.
6. **Bounded resources.** Maximum 10 FPS, 1280x720, 4 MiB encoded
   frame, 30 queued frames, ``DROP_OLDEST`` backpressure.
7. **No hidden APIs.** The companion uses only public Android APIs.
   No root. No Magisk. No system-level bypass.
8. **Encryption reuse.** The companion never invents a new encryption
   protocol. All payloads flow through ``NexusClient`` which uses the
   same X25519 + HKDF + AES-256-GCM primitives as every other
   GuardianMesh message.

## Permissions

The Android manifest declares only the minimum permissions required
for the documented behaviour:

* ``android.permission.FOREGROUND_SERVICE`` - required for the
  indicator notification.
* ``android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION`` -
  required by Android 14+ for the foreground service that hosts the
  projection.
* ``android.permission.POST_NOTIFICATIONS`` - required to display
  the indicator on Android 13+.

**No** of the following permissions are declared:

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

## Lifecycle

The companion implements the documented Android lifecycle:

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
Android device. The unit tests use ``Robolectric`` and a small set of
in-process fakes. Run with:

```bash
cd android/aegis
./gradlew test
```

## Limitations

The companion requires:

* Android 7.0 (API 24) or later.
* ``MediaProjection`` support, which is standard on all modern Android
  devices.
* A foreground service capable of running ``MEDIA_PROJECTION``
  (Android 14+).

Devices that do not meet these requirements are not supported by
Aegis. The control plane reports this honestly through the doctor
and the screen CLI commands.

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

These prohibitions are enforced by the absence of the relevant
permissions, the absence of remote-control code paths, the narrow
``SCREEN_FRAME``-only message surface, and the test suite.
