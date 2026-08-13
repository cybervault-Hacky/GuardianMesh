# GuardianMesh Development Guide

## 1. Prerequisites

- **Python**: Version 3.11, 3.12, or 3.13
- **Git**: For source control
- **Operating System**: Linux or Termux on Android

---

## 2. Environment Setup

### Linux Setup

```bash
# Clone repository
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh

# Editable install with dev dependencies
pip install --break-system-packages -e ".[dev]"
```

### Termux on Android Setup

```bash
pkg update -y
pkg install -y python git libffi clang make
cd GuardianMesh
pip install -e ".[dev]"
```

---

## 3. Running Tests & Coverage

GuardianMesh uses `pytest` with `pytest-cov`:

```bash
# Run complete test suite
pytest

# Run tests with verbose output
pytest -v

# Run Transport tests
pytest tests/test_transport_*.py

# Run Console tests
pytest tests/test_console_cli.py tests/test_devices_cli.py tests/test_console_services.py

# Run Orion tests
pytest tests/test_orion_*.py tests/test_migration_v9.py

# Run Atlas tests
pytest tests/test_atlas_*.py tests/test_migration_v10.py
```

---

## 4. Linting, Formatting & Type Checking

GuardianMesh enforces strict code quality via `ruff` and `mypy`:

```bash
# Check code style & linter rules
ruff check guardianmesh tests

# Auto-format codebase
ruff format guardianmesh tests

# Run static type checks
mypy guardianmesh
```

---

## 5. Adding Database Migrations

When extending the SQLite schema:
1. Open `guardianmesh/storage/migrations.py`.
2. Add a new `Migration` instance to the `MIGRATIONS` sequence with incremented `version`.
3. Provide clean, idempotent `CREATE` or `ALTER` SQL statements.
4. Add corresponding tests in `tests/test_database.py` or new migration test files.

---

## 6. Security Testing Guidelines

Any PR touching security, identity, pairing, telemetry, policy, console, transport, or screen-view code must:
1. Verify that `ALLOWED_HEALTH_FIELDS` is strictly enforced and personal content keys are rejected.
2. Ensure Sentinel evaluates only explicit technical conditions without behavioral inferences.
3. Ensure no private keys, OTPs, session keys, or passwords leak into JSON exports or terminal outputs.
4. Ensure child authorization is strictly mandatory and challenge nonces cannot be replayed.
5. Ensure monotonic sequence numbers and sliding windows prevent envelope replay.
6. Ensure mutual Ed25519 authentication and X25519 forward secrecy for transport channels.
7. Validate that file permissions remain `0700` for directories and `0600` for keys/databases.
8. Pass 100% of existing tests without regressions.

Any PR touching the Vista screen subsystem (Phase 7) must additionally:
1. Verify that no remote-control message type is ever added to
   `ScreenMessageType` or `transport.models.MessageType`.
2. Verify that the `screen_sessions` and `screen_authorizations`
   schemas contain no payload-bearing columns.
3. Verify that frame payloads are never written to the database, the
   audit log, or any log file.
4. Verify that the visible `SCREEN VIEW ACTIVE` indicator is
   rendered for every ACTIVE session and only for ACTIVE sessions.
5. Verify that trust revocation tears down the active session.
6. Verify that bounded session lifetime, inactivity timeout, and
   transport disconnect all terminate the session.
7. Verify that the `AndroidScreenProvider` is the only entry point
   for screen capture and that it never claims
   `is_real_capture = True` unless an actual native capture is
   wired in.

Any PR touching the Aegis screen-capture subsystem (Phase 8) must
additionally:

1. Verify that the `MediaProjection` system consent is **GRANTED**
   before any frame is delivered to the pipeline.
2. Verify that the foreground service notification is visible for
   the entire active session and exposes the `STOP SHARING` action.
3. Verify that local stop works without contacting the parent
   (the companion must tear the pipeline down locally).
4. Verify that the companion's Android manifest declares only the
   documented minimum permissions and adds none of the following:
   `INTERNET` (not required for the loopback Nexus path), `RECORD_AUDIO`,
   `CAMERA`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`, `READ_SMS`,
   `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`,
   `MANAGE_EXTERNAL_STORAGE`, `READ_CALL_LOG`.
5. Verify that frame bytes never appear in the `aegis_sessions`
   database table, in the audit log, in any log file, or in any
   exception message.
6. Verify that the `AegisSessionInfo` model exposes no
   payload-bearing field.
7. Verify that the `FrameMetrics` snapshot contains no frame bytes
   and is exposed through `AegisController.diagnostics()` only.
8. Verify that the `BoundedFrameQueue` applies `DROP_OLDEST`
   backpressure and never grows beyond the documented queue size.
9. Verify that bounded resources (10 FPS, 1280x720, 4 MiB encoded
   frame, 30 queued frames) are enforced at every pipeline stage.
10. Verify that the `ScreenMessageType` allowlist remains at seven
    narrowly-scoped names. No `SCREEN_CONTROL`, `REMOTE_INPUT`,
    `EXECUTE`, `SHELL`, `COMMAND` additions.
11. Verify that the companion never invokes the production
    `AndroidMediaCodecEncoder` from the Python control plane
    (it must raise `AegisEncoderError`).
12. Verify that `guardian doctor` reports the Aegis platform
    honestly on Linux: it must show
    `Android screen provider: integration adapter only` as a Notice,
    not a failure, and must never falsely report real Android
    capture as operational.
13. Pass the new Aegis unit tests in `tests/test_aegis_*.py` and
    the new migration test in `tests/test_migration_v8.py` without
    regression.

Any PR touching the Orion orchestration subsystem (Phase 9) must
additionally:

1. Verify that the `OrionEventType`, `OrionActionType`, and
   `OrionCapability` allowlists are strict. Adding a forbidden name
   to any of these enums must raise at construction time.
2. Verify that the `FORBIDDEN_PAYLOAD_KEYS` and
   `FORBIDDEN_ACTION_PARAM_KEYS` sets reject every form of sensitive
   content (frame, screenshot, keylog, message, clipboard,
   microphone, audio, camera, video, location, gps,
   browser_history, contacts, photos, files, command, shell, exec,
   execute, remote_input, password, private_key, secret, token,
   otp).
3. Verify that the four Orion database tables (`orion_events`,
   `orion_actions`, `orion_capabilities`, `orion_reconciliation`)
   contain no column for frame bytes, command strings, private
   keys, session keys, passwords, OTPs, or any other sensitive
   content. Use `PRAGMA table_info(...)` to inspect.
4. Verify that the 11 `ORION_*` audit event types record only
   metadata. Inspect `details` for any forbidden key.
5. Verify that the `OrionConsentValidator` delegates to
   `TrustManager`, `ScreenAuthorizationManager`, and
   `SystemConsentGate`. It must never invent consent.
6. Verify that the `OrionCapabilityRegistry` refuses to enable
   any negative default. Adding `AUDIO_CAPTURE: True` to a
   capabilities record must raise `OrionCapabilityError`.
7. Verify that the action queue enforces idempotency. Two
   enqueues with the same `idempotency_key` must result in a
   single persisted action.
8. Verify that the action queue is bounded. Enqueuing past the
   `max_size` must raise `OrionQueueError`.
9. Verify that expired actions are never executed. An action with
   `expires_at` in the past is marked `EXPIRED` at sweep time.
10. Verify that the `OrionReconciliationReport` is metadata-only.
    It must contain no `frame`, `screenshot`, `command`, or
    `password` keys.
11. Verify that the `OrionActionHandlers` register only safe
    handler entries. No `EXECUTE`, `SHELL`, `REMOTE_INPUT`,
    `HIDDEN_SCREENSHOT` actions are dispatched.
12. Verify that `guardian doctor` reports the Orion subsystem
    honestly. All 11 Orion doctor checks must pass on a healthy
    install.
13. Pass the new Orion unit tests in `tests/test_orion_*.py` and
    the new migration test in `tests/test_migration_v9.py`
    without regression.

Any PR touching the Atlas production-hardening subsystem
(Phase 10) must additionally:

1. Verify that the `AtlasCapabilityRegistry` pre-populated set
   includes only the documented subsystem names. Adding
   surveillance-style capability names is forbidden.
2. Verify that the `BACKUP_ALLOWED_TABLES` set explicitly
   excludes `transport_messages` and any other sensitive
   table. The `BACKUP_FORBIDDEN_COLUMNS` map must strip
   `private_key_pem` from `identities`.
3. Verify that the five Atlas database tables
   (`atlas_backups`, `atlas_health`, `atlas_recovery`,
   `atlas_capability_versions`, `atlas_retention`) have no
   column for frame bytes, command strings, private keys,
   session keys, passwords, OTPs, or any other sensitive
   content. Use `PRAGMA table_info(...)` to inspect.
4. Verify that `AtlasRecoveryManager` never resurrects
   revoked trust, expired authorization, or expired Aegis
   consent. Recovery marks expired state as `EXPIRED`; it
   never re-queues or re-executes.
5. Verify that the `AtlasReleaseValidator` checks the Android
   manifest against the documented forbidden permission set.
   Adding `RECORD_AUDIO`, `CAMERA`, `READ_SMS`, etc. is
   forbidden.
6. Verify that the `AtlasObservability` collector never
   includes secrets, frame bytes, or private user content. The
   output is metadata-only.
7. Verify that `guardian doctor` reports 9 new Atlas-specific
   checks: `Atlas module`, `Atlas database schema`,
   `Atlas capability registry`, `Atlas migration state`,
   `Atlas backup subsystem`, `Atlas recovery subsystem`,
   `Atlas integrity verifier`, `Atlas observability`,
   `Atlas release validation`. All 9 must pass on a healthy
   install.
8. Verify that `guardian release` reports `READY` only when
   every documented gate passes. The release must not claim
   readiness when checks fail.
9. Pass the new Atlas unit tests in `tests/test_atlas_*.py`
   and the new migration test in `tests/test_migration_v10.py`
   without regression.
