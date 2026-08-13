# GuardianMesh

[![Phase](https://img.shields.io/badge/Phase-9%20Orion-blue.svg)](docs/ROADMAP.md)
[![Version](https://img.shields.io/badge/Version-0.9.0-green.svg)](pyproject.toml)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-orange.svg)](#supported-platforms)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**GuardianMesh** is a developer-grade, consent-based parental device supervision system designed to run on Termux (Android) and Linux.

---

## Safety & Architectural Boundary

> **IMPORTANT ARCHITECTURAL MANDATE:**
> GuardianMesh is built on the principle of **explicit mutual consent**. It must **never** implement covert or silent monitoring.

### Prohibited Surveillance Features
GuardianMesh will **never** include:
- Hidden screen capture or silent background monitoring
- Keyloggers or keystroke interception
- Microphone or camera capture
- Message interception (SMS/chat/email reading)
- Browser history or bookmark harvesting
- Clipboard data collection
- Password or credential scraping
- Remote control / remote input injection
- Bypassing Android OS permissions or child consent

---

## Phase 6: Nexus (v0.6.0)

Phase 6 introduces **secure transport, authenticated channels, and multi-device synchronization**:
- **End-to-End Encrypted Transport**: Ephemeral X25519 Diffie-Hellman key exchange, HKDF-SHA256 key derivation, and AES-256-GCM AEAD encryption.
- **Mutual Ed25519 Authentication**: Integrated with the Phase 2 cryptographic trust registry (`trusted_devices`).
- **Replay Protection & Sequence Monotonicity**: Per-session sequence numbering with bounded sliding-window replay caching.
- **Liveness Monitoring & Heartbeats**: Background periodic heartbeats, latency probes (Ping/Pong), and timeout derivation.
- **Bounded Reconnection Management**: Exponential retry backoffs with jitter and retry count bounds.
- **Dedicated CLI Commands (`guardian transport`)**: Manage peers, sessions, connections, and status with machine-readable `--json` support.
- **Zero-Knowledge Relay Boundary**: Secure relay abstraction enforcing payload confidentiality without plaintext exposure.

## Phase 7: Vista (v0.7.0)

Phase 7 introduces **consent-based view-only screen sessions**:
- **Child-Authorized Screen View**: Every session requires an explicit, fresh child approval. Trust relationships (Phase 2) are necessary but not sufficient.
- **Visible Child-Side Indicator**: A persistent "SCREEN VIEW ACTIVE" banner is rendered for the entire session lifetime. The child can stop the session at any moment.
- **Bounded Session Lifetime**: Default 5 minutes, hard cap 1 hour. Inactivity timeouts and trust revocation terminate the session immediately.
- **Versioned Frame Protocol**: Strict validation, monotonic sequences, bounded replay window, and explicit oversize / sequence / codec rejection.
- **Resource Limits**: Default 10 FPS, 1280x720 resolution, 4 MiB max frame payload, bounded buffer with `DROP_OLDEST` backpressure.
- **Android Boundary**: `AndroidScreenProvider` is a clearly-marked integration boundary. A future Android companion component is required for real capture; the current build ships a deterministic test adapter.
- **No Remote Control**: The protocol message type allowlist contains zero remote-control names. `SCREEN_CONTROL`, `REMOTE_INPUT`, `EXECUTE`, `SHELL`, `COMMAND`, `KEYLOG`, `KEYSTROKE`, etc. are explicitly rejected.
- **No Frame Persistence**: Frames are never written to disk. The `screen_sessions` and `screen_authorizations` tables store metadata only.
- **Dedicated CLI Commands (`guardian screen`)**: Request, approve, deny, start, stop, view, list, and inspect diagnostics with machine-readable `--json` support.

## Phase 8: Aegis (v0.8.0)

Phase 8 turns the Phase 7 Vista Android integration boundary into a real, production-oriented Android companion architecture using Android's official `MediaProjection` consent flow.

- **Three-Key Consent Gate**: Trust (Phase 2) + Authorization (Phase 7) + System consent (Phase 8) — all three are required.
- **`MediaProjection` Provider**: `MediaProjectionProvider` is the production boundary. The shipped `AdapterOnlyMediaProjectionProvider` is a deterministic test fixture for Linux/Termux.
- **Foreground Service Indicator**: An Android foreground service notification is visible for the entire capture session. The child can stop the session locally via a `STOP SHARING` action.
- **System Consent State Machine**: A new `SYSTEM_CONSENT_REQUIRED` / `SYSTEM_CONSENT_GRANTED` state pair ensures the Android system dialog is honoured.
- **Frame Pipeline**: `MediaProjection` → `ImageReader` → `FrameNormalizer` → `FrameLimiter` → `AndroidMediaCodecEncoder` (production) / `TestScreenEncoder` (tests) → `BoundedFrameQueue` → `ScreenTransportAdapter` → `NexusClient`.
- **Bounded Metrics**: `frames_captured`, `frames_encoded`, `frames_dropped`, `queue_depth`, `transport_failures`, `projection_failures`, `encoder_failures`, `last_frame_sequence`. Metadata only — never frame bytes.
- **No New Encryption**: All screen traffic flows through the existing Nexus transport (Phase 6). The companion's `NexusClient` reuses the same X25519 + HKDF + AES-256-GCM primitives.
- **No Remote Control**: The `ScreenMessageType` allowlist remains at seven narrowly-scoped names. No `SCREEN_CONTROL`, `REMOTE_INPUT`, `EXECUTE`, `SHELL`, `COMMAND` etc.
- **No Frame Persistence**: Frames exist only in the in-memory `BoundedFrameQueue` for the duration of one frame processing cycle.
- **Android Companion**: A production Kotlin reference implementation lives in `android/aegis/`. It is documented architecture that requires a real Android build environment to execute.
- **CLI Extensions**: `guardian screen providers` and `guardian screen limits` expose Aegis metadata.
- **Doctor Extensions**: 4 new Aegis-specific checks (`Aegis module`, `System consent gate`, `Aegis privacy redaction`, `Android provider boundary`).

## Phase 9: Orion (v0.9.0)

Phase 9 introduces **Consent-Aware Orchestration & State Reconciliation**. Orion is the event-driven orchestration layer that ties the existing subsystems (Pulse, Sentinel, Console, Nexus, Vista, Aegis, Trust) together — without introducing any new surveillance or remote-control capability.

- **Event Bus**: A bounded, thread-safe `OrionEventBus` with deterministic and async modes, three backpressure strategies (`DROP_OLDEST`, `DROP_NEWEST`, `REJECT`), per-device sequence ordering, handler-failure isolation, and bounded retry.
- **Action Queue**: A persistent, idempotent `OrionActionQueue` backed by SQLite (Migration 9). Idempotency via UNIQUE INDEX on `idempotency_key`. Bounded size (default 10,000). Status transitions: `PENDING → RUNNING → SUCCEEDED/FAILED/EXPIRED/CANCELLED`.
- **State Reconciler**: A deterministic `OrionStateReconciler` that runs after reconnect, applying the documented rules (trust revocation wins, expired authorization wins, expired sessions stopped, stale events discarded, etc.). The report is metadata-only.
- **Capability Registry**: A pre-populated control-plane profile plus explicit per-device records. Negative defaults (`AUDIO_CAPTURE`, `REMOTE_INPUT`, `KEYLOGGING`, etc.) are **always False** and the registry refuses to set them to True.
- **Consent Validator**: A thin wrapper that delegates to `TrustManager`, `ScreenAuthorizationManager`, and `SystemConsentGate`. Orion never invents consent.
- **12 Safe Handlers**: `REFRESH_HEALTH`, `ACKNOWLEDGE_ALERT`, `RESOLVE_ALERT`, `RECONNECT_TRANSPORT`, `REQUEST_SCREEN_SESSION`, `STOP_SCREEN_SESSION`, `REQUEST_AEGIS_CONSENT`, `STOP_AEGIS_CAPTURE`, `RECONCILE_STATE`, `REQUEST_CAPABILITIES`, etc. No `EXECUTE`, no `SHELL`, no `REMOTE_INPUT`, no hidden capture.
- **Forbidden Payload Keys**: Frame, screenshot, keylog, message, clipboard, microphone, audio, camera, video, location, gps, browser_history, contacts, photos, files, command, shell, exec, execute, remote_input, remote_tap, remote_click, password, private_key, secret, token, otp — all rejected at construction time.
- **Migration 9**: `009_orion_schema` creates `orion_events`, `orion_actions`, `orion_capabilities`, `orion_reconciliation` with 12 indexes. No columns for frame bytes, command strings, or secrets.
- **11 New Audit Events**: `ORION_EVENT_ACCEPTED`, `ORION_EVENT_REJECTED`, `ORION_ACTION_CREATED`, `ORION_ACTION_STARTED`, `ORION_ACTION_COMPLETED`, `ORION_ACTION_FAILED`, `ORION_ACTION_EXPIRED`, `ORION_RECONCILIATION_STARTED`, `ORION_RECONCILIATION_COMPLETED`, `ORION_CONFLICT_RESOLVED`, `ORION_CAPABILITY_CHANGED`. Metadata only.
- **CLI Extensions**: `guardian orchestrate status|events|actions|action|retry|cancel|reconcile|capabilities` and `guardian capabilities <device_id>`. All support `--json` and work at 40/60/80/120 column terminals.
- **Doctor Extensions**: 11 new Orion-specific checks (`Orion module`, `Orion event bus`, `Orion action queue`, `Orion idempotency`, `Orion reconciliation`, `Orion capability registry`, `Orion database schema`, `Orion audit integration`, `Orion consent integration`, `Orion offline queue`, `Orion handler registry`).

See [docs/ORION.md](docs/ORION.md), [docs/ORCHESTRATION.md](docs/ORCHESTRATION.md), [docs/RECONCILIATION.md](docs/RECONCILIATION.md), and [docs/ACTIONS.md](docs/ACTIONS.md).

---

## Supported Platforms

- **Termux on Android** (ARM64, ARMv7, x86_64)
- **Linux** (Debian, Ubuntu, Arch, Fedora, Alpine)
- **Python 3.11+ / Python 3.12+**

---

## Installation

### Standard Linux / Development Installation

```bash
# Clone the repository
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh

# Install package and dependencies in user space
pip install --break-system-packages -e ".[dev]"
```

### Termux on Android Installation

```bash
# Update Termux packages
pkg update -y
pkg install -y python git libffi

# Clone and install
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh
pip install -e .
```

---

## CLI Usage & Commands

```bash
guardian --help
```

### 1. View Unified Parent Dashboard (`guardian console`)
```bash
guardian console dashboard
```

Output:
```
GuardianMesh
═══════════════════════════════════════
Console v0.6.0 (Nexus)

DEVICES
───────────────────────────────────────
Trusted       2
Online        1
Degraded      0
Offline       1

HEALTH
───────────────────────────────────────
Battery       82%
Storage       45.0% free
Connectivity  ONLINE

ALERTS
───────────────────────────────────────
Critical      0
Warning       1
Active        1

RECENT ACTIVITY
───────────────────────────────────────
01:54  Device heartbeat received
01:52  Health alert resolved
01:48  Device paired successfully
───────────────────────────────────────
```

### 2. Device Management (`guardian devices`)
```bash
# List all trusted child devices
guardian devices list

# Show full device details (identity, trust, telemetry, alerts, policy, transport)
guardian devices show GM-C-19A84E72

# Inspect focused technical health metrics
guardian devices health GM-C-19A84E72

# Rename device
guardian devices rename GM-C-19A84E72 "Kid Smart Tablet"

# Revoke trust
guardian devices revoke GM-C-19A84E72
```

### 3. Secure Transport & Multi-Device Sync (`guardian transport`)
```bash
# Check transport subsystem status
guardian transport status

# List transport peers and connection states
guardian transport peers

# Connect to a trusted device
guardian transport connect GM-C-19A84E72

# Reconnect using exponential backoff
guardian transport reconnect GM-C-19A84E72

# Terminate transport channel
guardian transport disconnect GM-C-19A84E72
```

### 4. Sentinel Health Alerts (`guardian alerts`)
```bash
# View active alerts
guardian alerts active

# Acknowledge alert
guardian alerts acknowledge ALT-8F2A1C

# Dismiss alert
guardian alerts dismiss ALT-8F2A1C
```

### 5. Surveillance Policies (`guardian policy`)
```bash
# List policies
guardian policy list

# Inspect policy rules
guardian policy show POL-7A3B1C
```

### 6. Consent-Based Screen Sessions (`guardian screen`)
```bash
# Parent requests a view-only screen session
guardian screen request GM-C-19A84E72

# Child explicitly approves the view
guardian screen approve SCN-1234567890AB

# Parent begins streaming
guardian screen start SCN-1234567890AB

# Stop a session (parent or child)
guardian screen stop SCN-1234567890AB

# Inspect aggregate Vista diagnostics
guardian screen diagnostics

# List available Android capture providers (Aegis)
guardian screen providers

# Show the documented Aegis hard limits
guardian screen limits
```

### 7. Pair with a Child Device (`guardian pair`)
```bash
guardian pair --method demo
```

---

## Roadmap

GuardianMesh is structured across 10 progressive phases:

1. **Phase 1: Genesis (v0.1.0)** — Secure local foundation, identities, key storage, SQLite database, CLI diagnostics. *(Complete)*
2. **Phase 2: Link (v0.2.0)** — Reciprocal pairing protocol, DeliveryProvider abstraction, OTP verification, mandatory child authorization, trust management. *(Complete)*
3. **Phase 3: Pulse (v0.3.0)** — Privacy-bounded device health telemetry, allowlisted metrics, monotonic sequence tracking, health state evaluation. *(Complete)*
4. **Phase 4: Sentinel (v0.4.0)** — Privacy-bounded policy engine, deterministic rule evaluation, alert deduplication, auto-resolution. *(Complete)*
5. **Phase 5: Console (v0.5.0)** — Unified parent console, device management suite, adaptive terminal typography, JSON export. *(Complete)*
6. **Phase 6: Nexus (v0.6.0)** — End-to-end encrypted transport, mutual Ed25519 authentication, X25519 Diffie-Hellman key exchange, AES-256-GCM framing, heartbeat monitoring. *(Current)*
7. **Phase 7: View-Only Screen Sharing (v0.7.0)** — View-only screen sharing with explicit child authorization, persistent active indicator, and no remote control.
8. **Phase 8: Aegis (v0.8.0)** — Android companion with `MediaProjection` consent flow, foreground service indicator, and frame pipeline.
9. **Phase 9: Orion (v0.9.0)** — Consent-aware orchestration & state reconciliation. Event bus, persistent action queue, capability registry, deterministic reconciler, safe handler set.
10. **Phase 10: Production Release (v1.0.0)** — Production-grade multi-platform release.

---

## Documentation

- [Vista Screen Sessions Guide](docs/VISTA.md)
- [Screen Protocol Specification](docs/SCREEN_PROTOCOL.md)
- [Screen Privacy Guarantees](docs/SCREEN_PRIVACY.md)
- [Aegis Companion Guide](docs/AEGIS.md)
- [Orion Orchestration Guide](docs/ORION.md)
- [Orchestration Internals](docs/ORCHESTRATION.md)
- [Reconciliation Guide](docs/RECONCILIATION.md)
- [Actions Guide](docs/ACTIONS.md)
- [Android Companion Architecture](docs/ANDROID.md)
- [Screen Capture Pipeline](docs/SCREEN_CAPTURE.md)
- [Privacy Guarantees](docs/PRIVACY.md)
- [Nexus Transport Guide](docs/NEXUS.md)
- [Transport Architecture](docs/TRANSPORT.md)
- [Protocol Specification](docs/PROTOCOL.md)
- [Console & Dashboard Guide](docs/CONSOLE.md)
- [Policies Specification Guide](docs/POLICIES.md)
- [Alerts Lifecycle Guide](docs/ALERTS.md)
- [Telemetry Specification Guide](docs/TELEMETRY.md)
- [Pairing & Trust Protocol Guide](docs/PAIRING.md)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Security Model & Boundaries](docs/SECURITY.md)
- [10-Phase Roadmap](docs/ROADMAP.md)
- [Development & Testing Guide](docs/DEVELOPMENT.md)

---

## Testing & Quality

Run the complete test suite:

```bash
pytest
```

Run linter and type checks:

```bash
ruff check guardianmesh tests
mypy guardianmesh
```

---

## License

GuardianMesh is licensed under the [MIT License](LICENSE).
