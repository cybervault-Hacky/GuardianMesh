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
  Phase 7: Vista / Consent-Based Screen Sessions (v0.7.0)  <-- [Current Phase]
     ↓
  Phase 8: Dashboard / Reporting (v0.8.0)
     ↓
  Phase 9: Security Hardening (v0.9.0)
     ↓
  Phase 10: Production Release (v1.0.0)
```

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

## Phase 7: Vista / Consent-Based Screen Sessions (v0.7.0) — *Current Phase*
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

## Phase 8: Dashboard & Reporting (v0.8.0)
- **Objective**: Consolidated parental dashboard and weekly family summary views.

---

## Phase 9: Security Hardening (v0.9.0)
- **Objective**: Independent penetration testing, formal verification, threat model review, and strict memory safety audits.

---

## Phase 10: Production Release (v1.0.0)
- **Objective**: General availability across Linux distributions and Termux Android.
