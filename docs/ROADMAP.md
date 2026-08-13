# GuardianMesh 10-Phase Roadmap

GuardianMesh is structured across 10 progressive phases to deliver a transparent, consent-based supervision ecosystem.

---

```
  Phase 1: Genesis (v0.1.0)
     ↓
  Phase 2: Link / Pairing (v0.2.0)
     ↓
  Phase 3: Pulse / Device Health (v0.3.0)
     ↓
  Phase 4: Sentinel / Policies & Alerts (v0.4.0)
     ↓
  Phase 5: Console / Parent Dashboard (v0.5.0)
     ↓
  Phase 6: Nexus / Secure Transport (v0.6.0)
     ↓
  Phase 7: Vista / Consent-Based Screen Sessions (v0.7.0)
     ↓
  Phase 8: Aegis / Production Android Companion (v0.8.0)
     ↓
  Phase 9: Orion / Consent-Aware Orchestration (v0.9.0)
     ↓
  Phase 10: Atlas / Production Hardening (v1.0.0)  <-- [Current Phase]
```

---

---

## Phase 1: Genesis (v0.1.0) — *Complete*
- **Objective**: Establish the secure local foundation.
- **Deliverables**:
  - `guardian` CLI developer tool.
  - Asymmetric cryptographic identities (`GM-P-XXXXXXXX` & `GM-C-XXXXXXXX`).
  - Ed25519 keypair generation and secure `0600`/`0700` storage.
  - SQLite database engine with automated migration runner.
  - Privacy-preserving audit logging with automatic secret scrubbing.
  - System diagnostics via `guardian doctor` and `guardian status`.
  - Termux and Linux platform user space compatibility.

---

## Phase 2: Link / Pairing (v0.2.0) — *Complete*
- **Objective**: Mutual, consent-driven device pairing & trust establishment.
- **Deliverables**:
  - Pairing state machine (`CREATED` → `VERIFICATION_PENDING` → `VERIFIED` → `CHILD_AUTHORIZATION_PENDING` → `AUTHORIZED` → `TRUST_ESTABLISHED` → `PAIRED`).
  - `DeliveryProvider` abstraction (Email SMTP, SMS optional, Demo mode).
  - Hardened OTP security (salted SHA-256 verifiers, single-use, rate limits, attempt limits).
  - Mandatory child authorization protocol with replay-resistant challenge nonces.
  - Cryptographic trust registry in `trusted_devices` with instant revocation support.
  - CLI commands (`guardian pair`, `pair status`, `pair verify`, `pair authorize`, `pair list`, `pair revoke`, `pair cancel`, `pair rename`).

---

## Phase 3: Pulse / Device Health (v0.3.0) — *Complete*
- **Objective**: Privacy-bounded device health telemetry.
- **Deliverables**:
  - Strict privacy allowlist (`ALLOWED_HEALTH_FIELDS`) and rejection of surveillance fields.
  - Technical collectors (Battery, Storage, Uptime, Connectivity).
  - Authenticated `TelemetryEnvelope` with canonical JSON serialization and Ed25519 signing.
  - Monotonic sequence tracking and replay protection (`device_sequences`).
  - Real-time health state derivation (`ONLINE`, `DEGRADED`, `OFFLINE`, `UNKNOWN`).
  - Controlled telemetry emitter scheduler with bounded exponential backoff.
  - Transactional retention cleanup.
  - CLI commands (`guardian telemetry`, `status`, `history`, `refresh`, `pause`, `resume`).

---

## Phase 4: Sentinel / Policies & Alerts (v0.4.0) — *Complete*
- **Objective**: Privacy-bounded policy engine, deterministic rule evaluation, and alert lifecycle management.
- **Deliverables**:
  - Technical health rules (`LOW_BATTERY`, `LOW_STORAGE`, `OFFLINE`, `DEGRADED_CONNECTION`, `HEARTBEAT_DELAYED`, `HEALTH_UNKNOWN`).
  - Policy CRUD and default health policies per trusted device.
  - Alert deduplication, automatic resolution when conditions clear, parental acknowledgements, and dismissals.
  - Transactional alert retention cleanup.
  - CLI commands (`guardian policy`, `guardian alerts`).

---

## Phase 5: Console / Parent Dashboard (v0.5.0) — *Complete*
- **Objective**: Unified parent console, device management suite, adaptive terminal typography, and JSON export.
- **Deliverables**:
  - Unified dashboard (`guardian console dashboard`) aggregating devices, health, alerts, and audit history.
  - Dedicated device management suite (`guardian devices list`, `show`, `health`, `rename`, `revoke`).
  - Dynamic terminal renderer adapting from narrow mobile Termux screens (40/60 cols) to wide desktop widths (80/120 cols).
  - Non-interactive and machine-readable JSON exports (`--json`).
  - Continuous dashboard watch mode (`--watch`).
  - Strict NO_COLOR and accessibility compliance.

---

## Phase 6: Nexus / Secure Transport (v0.6.0) — *Complete*
- **Objective**: End-to-end encrypted, authenticated transport and multi-device synchronization.
- **Deliverables**:
  - Ephemeral X25519 Diffie-Hellman key agreement for forward secrecy.
  - Mutual Ed25519 authentication verifying signatures against `TrustManager`.
  - HKDF-SHA256 symmetric key derivation and AES-256-GCM authenticated payload encryption.
  - Per-session monotonic sequence tracking with bounded sliding-window replay protection.
  - Background periodic heartbeats, latency probe frames (Ping/Pong), and timeout detection.
  - Exponential reconnection backoffs with jitter and retry bounds.
  - Memory, local socket (UNIX domain and loopback TCP), and zero-knowledge relay interfaces.
  - CLI commands (`guardian transport status`, `peers`, `sessions`, `connect`, `disconnect`, `reconnect`).
  - Database Migration 6 (`006_nexus_transport`).

---

## Phase 7: Vista / Consent-Based Screen Sessions (v0.7.0) — *Complete*
- **Objective**: Consent-based, view-only screen observation with the strictest possible privacy guarantees. **NOT** a covert monitoring system.
- **Mandatory Safety Rules**:
  1. **Trust != Screen Authorization**. Every screen session requires a fresh, explicit child-side authorization, even between trusted devices.
  2. **No Remote Control**. No SCREEN_CONTROL, REMOTE_INPUT, EXECUTE, SHELL, COMMAND, KEYLOG, or remote tap/swipe/click/gesture message type is ever exposed. The protocol message-type allowlist is verified by an automated test.
  3. **Prominent Child-Side Indicator**. A persistent `SCREEN VIEW ACTIVE` banner is rendered on the child side for the entire session lifetime. The child can stop the session at any moment.
  4. **Bounded Session Lifetime**. Default 5 minutes, hard cap 1 hour. Inactivity timeout and trust revocation terminate the session immediately.
  5. **No Frame Persistence**. The `screen_sessions` and `screen_authorizations` tables store metadata only. Frames are held only in a bounded in-memory buffer with `DROP_OLDEST` backpressure.
  6. **No Bypass of OS Consent**. The shipped `AndroidScreenProvider` is a documented integration boundary; production capture requires a future Android companion component that uses `MediaProjection` with the system consent dialog. The current build never claims real capture is active.
- **Deliverables**:
  - Isolated `guardianmesh/screen/` module with `models`, `authorization`, `session`, `frames`, `codec`, `indicator`, `transport`, `controller`, `registry`, `errors`.
  - Strict allowlist of 7 screen message types: `SCREEN_VIEW_REQUEST`, `SCREEN_VIEW_APPROVAL`, `SCREEN_VIEW_DENIAL`, `SCREEN_SESSION_START`, `SCREEN_FRAME`, `SCREEN_SESSION_STOP`, `SCREEN_SESSION_EXPIRED`.
  - Versioned `ScreenFrame` model with strict validation (resolution, codec, payload size, sequence).
  - Bounded `FrameStreamBuffer` with monotonic sequence tracking and explicit backpressure strategy.
  - Deterministic `TestCodec` plus documented integration stubs for `H264`, `VP8`, `VP9`, `WEBP` (production encoders require a future Android companion component).
  - `ScreenController` orchestrator that reuses the existing Nexus transport; no new encryption system.
  - `ScreenIndicator` model for the child-side visible UI banner.
  - 9 new audit event types with strict redaction (no payload, no credentials, no keys).
  - CLI commands (`guardian screen status`, `request`, `approve`, `deny`, `start`, `stop`, `view`, `list`, `diagnostics`).
  - Dashboard `SCREEN VIEW` block on the unified console.
  - Database Migration 7 (`007_vista_screen_sessions`) — metadata only, no frame columns.
  - 8 new doctor checks covering the full Vista subsystem.
  - Documentation: `docs/VISTA.md`, `docs/SCREEN_PROTOCOL.md`, `docs/SCREEN_PRIVACY.md`.

---

## Phase 8: Aegis / Production Android Companion (v0.8.0) — *Complete*
- **Objective**: Production Android companion architecture using Android's official `MediaProjection` consent flow.
- **Mandatory Safety Rules**:
  1. **Three-Key Consent Gate**: Trust (Phase 2) + Authorization (Phase 7) + System Consent (Phase 8) — all three are required.
  2. **No Remote Control**: The screen message type allowlist remains at seven narrowly-scoped names. No `SCREEN_CONTROL`, `REMOTE_INPUT`, `EXECUTE`, `SHELL`, `COMMAND`.
  3. **Visible Foreground Service Indicator**: A persistent notification is displayed for the entire capture session. The child can stop locally via a `STOP SHARING` action.
  4. **Local Stop Control**: The child can stop the session immediately, even when the network is unavailable.
  5. **No Frame Persistence**: Frames exist only in the in-memory `BoundedFrameQueue` for one frame processing cycle.
  6. **Bounded Resources**: 10 FPS, 1280x720, 4 MiB encoded frame, 30 queued frames, `DROP_OLDEST` backpressure.
  7. **Encryption Reuse**: All screen traffic flows through the existing Nexus transport. The companion's `NexusClient` reuses Phase 6 primitives.
  8. **No New Permissions**: Only `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_MEDIA_PROJECTION`, and `POST_NOTIFICATIONS` are declared. No microphone, camera, location, contacts, SMS, accessibility, or storage permissions.
- **Deliverables**:
  - Isolated `guardianmesh/aegis/` module with `errors`, `models`, `consent`, `media_projection`, `encoder`, `indicator_service`, `pipeline`, `controller`, `registry`, `metrics`.
  - `MediaProjectionProvider` abstract class with `AdapterOnlyMediaProjectionProvider` and `FakeMediaProjectionProvider` implementations.
  - `ScreenEncoder` abstract class with `TestScreenEncoder` and `AndroidMediaCodecEncoder` (production stub).
  - `SystemConsentGate` state machine with `NOT_REQUESTED`, `REQUESTED`, `GRANTED`, `DENIED`, `REVOKED`, `EXPIRED`.
  - `ForegroundServiceIndicator` model with STOP SHARING action and deterministic notification copy.
  - `AegisFramePipeline` orchestration: `MediaProjection` → `ImageReader` → `FrameNormalizer` → `FrameLimiter` → `ScreenEncoder` → `BoundedFrameQueue` → transport.
  - `FrameMetrics` with bounded counters, latencies, and queue stats. Metadata only.
  - `AegisController` high-level orchestrator: `create_session`, `request_system_consent`, `grant_system_consent`, `deny_system_consent`, `start_capture`, `stop_capture`, `expire_due`, `diagnostics`, `list_providers`, `list_limits`.
  - 12 new audit event types for the full consent-gated capture lifecycle.
  - Database Migration 8 (`008_aegis_screen_capture`) — `aegis_sessions` table (metadata only).
  - CLI extensions: `guardian screen providers`, `guardian screen limits`.
  - 4 new doctor checks (`Aegis module`, `System consent gate`, `Aegis privacy redaction`, `Android provider boundary`).
  - Documentation: `docs/AEGIS.md`, `docs/ANDROID.md`, `docs/SCREEN_CAPTURE.md`.
  - Android Kotlin reference companion in `android/aegis/` with JVM unit tests.

---

## Phase 9: Orion / Consent-Aware Orchestration (v0.9.0) — *Complete*
- **Objective**: Deterministic, event-driven orchestration of all eight existing subsystems (Pulse, Sentinel, Console, Nexus, Vista, Aegis, Trust, Link) — without introducing any new covert monitoring, remote control, shell execution, hidden screen capture, microphone/camera activation, location tracking, clipboard collection, message collection, browser-history collection, or bypass of existing consent mechanisms.
- **Mandatory Safety Rules**:
  1. **Orion is orchestration, NOT surveillance.** The `OrionActionType` and `OrionEventType` allowlists are strict. `EXECUTE`, `SHELL`, `REMOTE_INPUT`, `TYPE_TEXT`, `ENABLE_MICROPHONE`, `ENABLE_CAMERA`, `READ_SMS`, `READ_FILES`, `HIDDEN_SCREENSHOT`, `KEYSTROKE`, `MESSAGE`, `MICROPHONE`, `CAMERA`, `LOCATION`, `BROWSER_HISTORY`, etc. are all forbidden at construction time.
  2. **No payload capture.** The `FORBIDDEN_PAYLOAD_KEYS` and `FORBIDDEN_ACTION_PARAM_KEYS` sets reject every form of sensitive content (frame, screenshot, keylog, password, private_key, secret, token, command, shell, exec, code, script).
  3. **No secrets in audit logs.** The 11 new `ORION_*` audit event types record only metadata.
  4. **No sensitive columns.** Migration 9's four Orion tables have no column for frame bytes, command strings, or secrets.
  5. **Consent is delegated, not invented.** `OrionConsentValidator` is a thin wrapper that delegates to `TrustManager`, `ScreenAuthorizationManager`, and `SystemConsentGate`.
  6. **Capabilities are explicit.** `OrionCapabilityRegistry` pre-populates the control-plane profile. Negative defaults (AUDIO_CAPTURE, REMOTE_INPUT, KEYLOGGING, etc.) are always False and the registry refuses to set them to True.
  7. **Bounded queue.** The action queue has a configurable maximum size (default 10,000) to prevent unbounded growth.
  8. **Bounded retry.** Each action has a `max_retries` cap. The executor respects it.
  9. **Idempotency.** Duplicate `idempotency_key` values are silently rejected.
  10. **Action expiry.** Actions past their `expires_at` are marked EXPIRED at sweep time and never executed.
  11. **Reconciliation is metadata-only.** The `OrionReconciliationReport` never contains frame bytes, commands, or secrets.
- **Deliverables**:
  - Isolated `guardianmesh/orion/` package with 15 modules: `__init__`, `errors`, `models`, `events`, `bus`, `capabilities`, `consent`, `actions`, `handlers`, `queue`, `executor`, `reconciliation`, `registry`, `scheduler`, `coordinator`.
  - `OrionEventBus` with sync (deterministic) and async (worker thread) modes, three backpressure strategies, per-device sequence ordering, handler-failure isolation, bounded retry.
  - `OrionActionQueue` — persistent, idempotent, with UNIQUE INDEX on `idempotency_key`. Bounded size, expiration sweep, status transitions.
  - `OrionExecutor` — sequential, bounded by `max_consecutive_failures`. Bounded retry.
  - `OrionActionHandlers` — 12 SAFE handlers. Each delegates to an existing subsystem. No `EXECUTE`, no `SHELL`, no `REMOTE_INPUT`, no hidden capture.
  - `OrionConsentValidator` — delegates to existing subsystems. Never invents consent.
  - `OrionStateReconciler` — applies the documented reconciliation rules. Idempotent. Produces metadata-only reports.
  - `OrionCapabilityRegistry` — pre-populated control-plane profile. Negative defaults are always False.
  - `OrionRegistry` — persistent capabilities, events, and reports.
  - `OrionScheduler` — composes bus, queue, executor, handlers.
  - `OrionCoordinator` — high-level entry point with `publish`, `submit`, `reconcile`, `metrics`.
  - 11 new audit event types (`ORION_*`).
  - Database Migration 9 (`009_orion_schema`) — `orion_events`, `orion_actions`, `orion_capabilities`, `orion_reconciliation` with 12 indexes. No columns for frame bytes, command strings, or secrets.
  - CLI extensions: `guardian orchestrate status|events|actions|action|retry|cancel|reconcile|capabilities` and `guardian capabilities <device_id>`. All support `--json` and work at 40/60/80/120 column terminals.
  - 11 new doctor checks covering the full Orion subsystem.
  - 380+ new tests covering event/action/bus/queue/handler/reconciliation/capability/registry/scheduler/coordinator/security/privacy/CLI/deep-coverage.
  - Documentation: `docs/ORION.md`, `docs/ORCHESTRATION.md`, `docs/RECONCILIATION.md`, `docs/ACTIONS.md`.

---

## Phase 10: Atlas / Production Hardening (v1.0.0) — *Current Phase*
- **Objective**: Production hardening, reliability, and release platform. Make the existing v0.9 system more secure, more reliable, more observable, more recoverable, more maintainable, more auditable, and more release-ready. **NOT** a new surveillance subsystem.
- **Mandatory Safety Rules**:
  1. **No new surveillance capability.** Atlas never implements covert monitoring, remote input, shell execution, hidden screen capture, microphone/camera activation, location tracking, clipboard collection, message collection, browser-history collection, or bypass around existing consent mechanisms.
  2. **Metadata-only persistence.** Atlas never stores frame bytes, command strings, private keys, session keys, passwords, OTPs, or private user content. The five new Atlas database tables (`atlas_backups`, `atlas_health`, `atlas_recovery`, `atlas_capability_versions`, `atlas_retention`) have no column for sensitive content.
  3. **Backups are metadata-only.** The `BACKUP_ALLOWED_TABLES` set explicitly excludes `transport_messages` and other sensitive tables. The `BACKUP_FORBIDDEN_COLUMNS` map strips `private_key_pem` from the `identities` table. Every backup is integrity-protected by a SHA-256 digest.
  4. **Restore is fail-closed.** Restore rejects unknown backups, rejects incompatible schema versions, and refuses to silently overwrite active state. Dry-run is the default.
  5. **Recovery is fail-closed.** Recovery never resurrects revoked trust, expired authorization, or expired Aegis consent. Recovery marks expired state as EXPIRED; it never re-queues or re-executes.
  6. **Capabilities are explicit.** Every documented subsystem gets a versioned `AtlasCapabilityVersion` with risk classification (LOW/MEDIUM/HIGH/CRITICAL) and explicit consent requirements. Unknown capabilities are rejected.
  7. **Retention is bounded.** Retention policies bound the growth of existing metadata tables. They never collect new categories of personal data.
  8. **Observability is metadata-only.** Every metric is a count or a timestamp. Metrics never include secrets, frame bytes, or private content.
  9. **Doctor is honest.** `guardian doctor` reports 9 new Atlas-specific checks. On Linux it shows `Android screen provider: integration adapter only` as a Notice. It never falsely reports real Android capture as operational.
- **Deliverables**:
  - Isolated `guardianmesh/atlas/` package with 18 modules: `__init__`, `errors`, `models`, `integrity`, `lifecycle`, `health`, `diagnostics`, `backup`, `restore`, `recovery`, `compatibility`, `capabilities`, `observability`, `metrics`, `retention`, `release`, `controller`.
  - `AtlasIntegrityVerifier` — SQLite integrity, schema presence, migration state, foreign keys, forbidden columns, audit presence, audit redaction, identity presence.
  - `AtlasLifecycleValidator` — no-expired-active-identity, no-revoked-device-in-active, no-expired-transport-sessions, no-orphaned-screen-authorizations, no-expired-orion-actions, no-stale-sequences.
  - `AtlasBackupManager` — metadata-only backups with SHA-256 integrity digest, schema-version compatibility check, allowed-table whitelist, forbidden-column redaction.
  - `AtlasRestoreManager` — dry-run by default, schema-version check, integrity verification, atomic restore.
  - `AtlasRecoveryManager` — deterministic recovery for expired Orion actions, expired screen authorizations, expired Aegis sessions. Never resurrects revoked state.
  - `AtlasHealthMonitor` — per-subsystem health check (OK/DEGRADED/WARNING/FAILED/UNAVAILABLE), persisted snapshots, latest-records query.
  - `AtlasObservability` — bounded metrics for every subsystem.
  - `AtlasMetrics` — aggregated metrics with failed/degraded subsystem counts.
  - `AtlasCapabilityRegistry` — versioned capability descriptors for every documented subsystem.
  - `AtlasRetentionManager` — bounded metadata-only retention policies.
  - `AtlasReleaseValidator` — release-readiness checks including the Android manifest permission verification.
  - `AtlasDiagnostics` — standard and deep diagnostic suites.
  - `AtlasController` — high-level entry point.
  - `010_atlas` migration creates 5 tables: `atlas_backups`, `atlas_health`, `atlas_recovery`, `atlas_capability_versions`, `atlas_retention`.
  - CLI extensions: `guardian atlas status|backup|restore|recover|retention|health|capabilities|version`, `guardian diagnostics [--full]`, `guardian release`. All support `--json`.
  - 9 new doctor checks: `Atlas module`, `Atlas database schema`, `Atlas capability registry`, `Atlas migration state`, `Atlas backup subsystem`, `Atlas recovery subsystem`, `Atlas integrity verifier`, `Atlas observability`, `Atlas release validation`.
  - 200+ new tests covering: normal operation, malformed input, invalid state, expired state, revoked state, corruption, interruption, duplicate operations, concurrent operations, retry limits, recovery, migration compatibility, backup integrity, restore integrity, JSON output, narrow terminal output, NO_COLOR, security boundaries, privacy boundaries.
  - Documentation: `docs/ATLAS.md`, `docs/RELEASE.md`, `docs/OPERATIONS.md`, `docs/UPGRADING.md`, `docs/RECOVERY.md`, `docs/OBSERVABILITY.md`.

---
