# GuardianMesh Screen Capture — Aegis Pipeline

This document describes the Aegis frame capture pipeline, end to
end. The pipeline is the **execution / capture plane**; the
authorization state machine is the **control plane**; the two
coordinate through the ``AegisController``.

## 1. Pipeline overview

```
MediaProjectionProvider
      ↓
ImageReaderFrameSource
      ↓
FrameNormalizer
      ↓
FrameLimiter
      ↓
AndroidMediaCodecEncoder (production) or TestScreenEncoder (tests)
      ↓
BoundedFrameQueue  (max 30 frames, DROP_OLDEST backpressure)
      ↓
ScreenTransportAdapter
      ↓
NexusClient (Phase 6, reused)
      ↓
Nexus TransportEnvelope (Phase 6)
      ↓
AES-256-GCM encryption
      ↓
Socket (loopback / LAN)
```

The pipeline is implemented identically on the Python control plane
(via the ``AegisFramePipeline``) and on the Android companion (via
the ``ScreenTransportAdapter`` + ``AndroidMediaCodecEncoder``). The
two implementations share the same contract, the same hard limits,
and the same backpressure behaviour.

## 2. Hard limits

Aegis enforces the following hard limits at every stage:

| Setting | Default | Hard cap | Enforcement point |
| --- | --- | --- | --- |
| Maximum FPS | 10 | 30 | ``FrameLimiter`` |
| Maximum width | 1280 | 1920 | ``FrameNormalizer``, ``FrameValidator`` |
| Maximum height | 720 | 1080 | ``FrameNormalizer``, ``FrameValidator`` |
| Maximum encoded frame size | 4 MiB | 4 MiB | ``FrameValidator`` |
| Maximum queued frames | 30 | 30 | ``BoundedFrameQueue`` |
| Maximum session lifetime | 300 s | 3600 s | ``ScreenAuthorization`` + ``AegisSessionInfo`` |
| Inactivity timeout | 60 s | unbounded | ``ScreenSession.check_lifecycle`` |
| Maximum payload sequence window | 128 | 128 | ``FrameSequenceTracker`` |

These limits are enforced both on the Android companion and on the
Python control plane. The Android constants are defined in
``android/aegis/app/src/main/java/com/guardianmesh/aegis/core/AegisConstants.kt``;
the Python constants are defined in
``guardianmesh/core/config.py``.

## 3. Backpressure

When the parent is slower than the child, the default backpressure
strategy is ``DROP_OLDEST``:

* The ``BoundedFrameQueue`` holds at most 30 frames.
* When a new frame arrives and the queue is full, the oldest frame
  is dropped.
* The drop count is recorded in ``AegisMetrics`` and exposed through
  the parent-side diagnostics.

The queue is the only place where frame bytes exist in memory
outside of the encoder and transport. When the queue is dropped,
the memory is reclaimed. The system never grows memory without
bound.

## 4. Lifecycle

The pipeline is started and stopped through the ``AegisController``:

* **Start**: ``AegisController.start_capture(aegis_session_id)``
  builds a pipeline, starts the foreground service, and verifies
  that the system consent is GRANTED.
* **Stop**: ``AegisController.stop_capture(aegis_session_id, reason)``
  tears down the pipeline, stops the foreground service, clears the
  in-memory buffer, and revokes the system consent.

The pipeline is also stopped automatically when:

* the authorization expires (``AegisController.expire_due()``);
* the trust is revoked (the parent-side controller observes the
  transport revocation and tears down the screen session);
* the transport session is closed;
* the child presses ``STOP SHARING`` (the foreground service
  action fires and tears the pipeline down locally);
* the ``MediaProjection`` token is revoked by the system.

In every case, the in-memory buffer is cleared, the foreground
service is stopped, and the database record is updated. Frame
bytes are never persisted.

## 5. Metrics

The pipeline records bounded metrics:

* ``frames_captured`` - frames received from the provider
* ``frames_normalized`` - frames that passed the normalizer
* ``frames_encoded`` - frames successfully encoded
* ``frames_queued`` - frames accepted by the bounded queue
* ``frames_transmitted`` - frames sent over the transport
* ``frames_dropped`` - frames dropped by the queue
* ``queue_depth`` - current depth of the queue
* ``queue_capacity`` - maximum capacity of the queue
* ``average_encode_latency_ms`` - mean encode latency
* ``transport_failures`` - transport send failures
* ``encoder_failures`` - encoder failures
* ``projection_failures`` - projection failures
* ``last_frame_sequence`` - the last sequence number accepted

These metrics are metadata only. They never contain frame bytes,
screenshot blobs, or any captured screen content. They are exposed
through ``AegisController.diagnostics()`` and through the CLI
``guardian screen diagnostics``.

## 6. Failure modes

| Failure | Behaviour |
| --- | --- |
| Provider returns ``captured=False`` | The frame is dropped; the metric records a projection failure. |
| ``MediaProjection`` is revoked by the system | The companion tears down the pipeline and stops the foreground service. |
| Encoder fails | The frame is dropped; the metric records an encoder failure. |
| Transport send fails | The frame is dropped; the metric records a transport failure. |
| Queue is full | The oldest frame is dropped; the metric records a drop. |
| ImageReader fails | The companion tears down the pipeline. |
| Network drops | The pipeline continues to capture; the queue fills; frames are dropped with ``DROP_OLDEST``. |
| Process death | The companion is restarted by the OS; the foreground service is rebuilt but capture is NOT restarted without fresh authorization. |

In every case, the in-memory state is bounded and the system
recovers deterministically.

## 7. Reuse of Nexus

The pipeline never invents a new encryption protocol. Every frame
is wrapped in a ``TransportEnvelope`` and encrypted by the existing
``TransportSession`` from Phase 6. The same X25519 + HKDF +
AES-256-GCM primitives protect every screen frame as every other
GuardianMesh message. The same replay defense and authentication
guarantees apply.

The ``ScreenMessageType`` enum (Python control plane) is mirrored
in the ``TransportEnvelope.message_type`` field. The Android
companion's ``ScreenTransportAdapter`` builds the envelope and
hands it to the ``NexusClient``, which sends it over the existing
socket. The Python control plane's ``TransportEnvelope`` validates
the message type and routes it to the ``MessageRouter``.

## 8. Test fixtures

The unit suite uses the following test fixtures to exercise the
pipeline:

* ``AdapterOnlyMediaProjectionProvider`` - the Linux/Termux
  adapter that emits deterministic synthetic frames.
* ``FakeMediaProjectionProvider`` - an in-process fake that
  simulates a real Android projection. Used in the
  ``test_aegis_controller.py`` and ``test_aegis_pipeline.py``
  tests.
* ``TestScreenEncoder`` - a deterministic encoder that emits a
  64-byte synthetic payload derived from SHA-256. The companion's
  ``AndroidMediaCodecEncoder`` is a separate production class
  that is invoked at runtime on Android.

The test fixtures are not used in production. They are clearly
marked and cannot be confused with the production code paths.

## 9. References

* ``docs/AEGIS.md`` - operational guide.
* ``docs/ANDROID.md`` - Android companion architecture.
* ``docs/SCREEN_PROTOCOL.md`` - wire-level protocol.
* ``docs/SCREEN_PRIVACY.md`` - privacy guarantees.
* ``guardianmesh/aegis/pipeline.py`` - Python control-plane pipeline.
* ``android/aegis/.../screen/`` - Android companion pipeline.
