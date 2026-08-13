# GuardianMesh Architecture

## 1. Overview & Architectural Principles

GuardianMesh is architected as a modular, consent-based parental supervision platform built for POSIX user spaces (Linux and Termux on Android).

```
┌─────────────────────────────────────────────────────────────┐
│                       guardian CLI                          │
│               (main.py, commands.py)                        │
└──┬─────────┬─────────┬─────────┬─────────┬───────────┬─────┴───┐
   │         │         │         │         │           │         │
┌──▼──────┐┌─▼──────┐┌─▼──────┐┌─▼──────┐┌─▼───────┐┌─▼─────┐┌──▼──────┐
│ console ││  view-  ││trans-  ││ policy ││ tele-  ││ Aegis ││ pairing │
│ Engine  ││  only   ││ port   ││ Engine ││ metry  ││(Phase ││ Engine  │
│         ││ screen  ││(Nexus) ││        ││ Engine ││  8)   ││         │
│         ││ (Vista) ││        ││        ││        ││Andoird││         │
│         ││(Phase7) ││        ││        ││        ││compa- ││         │
│         ││        ││        ││        ││        ││nion   ││         │
└──┬──────┘└──┬──────┘└──┬─────┘└──┬─────┘└──┬─────┘└──┬─────┘└──┬──────┘
   │         │         │         │         │         │         │
└──┴─────────┴─────────┴────┬────┴────┬────┴────┬────┴────────┴────────┘
                            │         │         │
┌───────────────────────────▼─────────▼─────────▼───────────────┐
│                       storage Engine                         │
│       (database, migrations, audit.py, aegis_sessions)       │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│                       security Engine                         │
│                   (crypto.py, secrets.py)                     │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│                        core & device                          │
│        (config, paths, logging, collectors, platform)         │
└───────────────────────────────────────────────────────────────┘
```

---

## 2. Package Structure & Module Responsibilities

```
guardianmesh/
├── __init__.py           # Package version (v0.5.0) and phase constants (Console)
├── cli/
│   ├── __init__.py       # CLI exports
│   ├── commands.py       # Command implementations (console, devices, policy, alerts, etc.)
│   └── main.py           # Argument parsing, exit code handling, formatted routing
├── console/
│   ├── __init__.py       # Console exports
│   ├── dashboard.py      # DashboardController: single-shot, watch mode, JSON export
│   ├── formatters.py     # TerminalFormatter: adaptive width (40-120 cols), NO_COLOR, tables
│   ├── models.py         # DashboardSnapshot, DeviceView
│   ├── navigation.py     # ConsoleNavigator: interactive text menu router
│   ├── renderer.py       # ConsoleRenderer: terminal typography and JSON views
│   └── services.py       # ConsoleService: unified facade over domain subsystems
├── core/
│   ├── __init__.py       # Core module exports
│   ├── config.py         # GuardianConfig dataclass, JSON persistence, env overrides
│   ├── errors.py         # Domain exception hierarchy (PolicyError, TelemetryError, etc.)
│   ├── logging.py        # Redacting logger, PEM/secret scrubbers
│   └── paths.py          # Platform detection, permission helpers, home resolution
├── device/
│   ├── __init__.py       # Device exports
│   ├── collectors.py     # Technical health collectors (battery, storage, uptime, connectivity)
│   └── platform.py       # Host environment inspection (Linux, Termux, Android)
├── identity/
│   ├── __init__.py       # Identity exports
│   ├── manager.py        # Identity lifecycle, creation, validation, activation
│   └── models.py         # Identity dataclass, IdentityRole enum, format validator
├── pairing/
│   ├── __init__.py       # Pairing exports
│   ├── authorization.py  # Challenge-nonce generation, Ed25519 verification, adapters
│   ├── manager.py        # PairingManager: full pairing session lifecycle orchestration
│   ├── models.py         # PairingSession, PairingState, TrustedDevice dataclasses
│   ├── otp.py            # CSPRNG OTP generation, salted verifier hashing, validation
│   ├── providers.py      # DeliveryProvider, EmailDeliveryProvider, Sms, Demo
│   └── trust.py          # TrustManager: trusted device registry, revocation
├── policy/
│   ├── __init__.py       # Policy exports
│   ├── alerts.py         # AlertManager: deduplication, auto-resolution, acknowledgements
│   ├── engine.py         # PolicyEngine: policy CRUD and device health evaluation
│   ├── evaluator.py      # RuleEvaluator: deterministic technical rule evaluation
│   └── models.py         # Policy, PolicyRule, Alert, RuleType, AlertSeverity
├── security/
│   ├── __init__.py       # Security exports
│   ├── crypto.py         # Ed25519 asymmetric cryptography & SHA-256 digests
│   ├── fingerprints.py   # Public key fingerprint generation (SHA256:...)
│   └── secrets.py        # KeyStorageManager, secure file permissions, redaction
├── storage/
│   ├── __init__.py       # Storage exports
│   ├── audit.py          # AuditLogger, sensitive data scrubber, event queries
│   ├── database.py       # SQLite wrapper, WAL mode, foreign keys, integrity checks
│   └── migrations.py     # Schema versioning and migration engine
├── telemetry/
│   ├── __init__.py       # Telemetry exports
│   ├── models.py         # TelemetryEnvelope, HealthSnapshot, ALLOWED_HEALTH_FIELDS
│   ├── processor.py      # TelemetryProcessor: validation, trust, health state derivation
│   ├── scheduler.py      # TelemetryScheduler: controlled background worker
│   ├── sequence.py       # SequenceManager: monotonic tracking & replay prevention
│   └── transport.py      # Legacy transport abstractions (LocalTransport, TestTransport)
└── transport/
    ├── __init__.py       # Transport subsystem exports
    ├── client.py         # TransportClient, MemoryTransportClient, LocalSocketClient, FutureNetwork
    ├── crypto.py         # Ephemeral X25519, HKDF-SHA256, AES-256-GCM authenticated encryption
    ├── errors.py         # Transport exception hierarchy
    ├── framing.py        # 4-byte length-prefixed stream framing
    ├── heartbeat.py      # HeartbeatManager: liveness, ping/pong, and timeout derivation
    ├── models.py         # TransportEnvelope, EncryptedTransportFrame, PeerInfo, SessionInfo
    ├── reconnect.py      # ReconnectManager: bounded exponential backoff & jitter
    ├── registry.py       # TransportRegistry: persistent sessions, peers, sequence numbers
    ├── router.py         # MessageRouter: dispatch to Telemetry, Policy, and Alert subsystems
    ├── server.py         # TransportServer, MemoryTransportServer, LocalSocketServer
    └── session.py        # TransportSession: active session keys, monotonic sequences, replay window
├── aegis/
│   ├── __init__.py       # Aegis public API
│   ├── errors.py         # Aegis exception hierarchy
│   ├── models.py         # AegisSessionInfo, AegisSessionState, SystemConsentState
│   ├── consent.py        # SystemConsentGate, capability detection
│   ├── media_projection.py  # MediaProjectionProvider (integration boundary)
│   ├── encoder.py        # ScreenEncoder, AndroidMediaCodecEncoder
│   ├── indicator_service.py  # ForegroundServiceIndicator
│   ├── pipeline.py       # AegisFramePipeline
│   ├── controller.py     # AegisController
│   ├── registry.py       # AegisSessionRegistry
│   └── metrics.py        # FrameMetrics
├── orion/
│   ├── __init__.py       # Orion public API re-exports
│   ├── errors.py         # OrionError hierarchy
│   ├── models.py         # OrionCapability, OrionDeviceCapabilities, OrionReconciliationReport
│   ├── events.py         # OrionEvent, OrionEventType, forbidden event/payload keys
│   ├── actions.py        # OrionAction, OrionActionType, ACTION_CONSENT_REQUIREMENTS, forbidden names
│   ├── bus.py            # OrionEventBus, BackpressureStrategy
│   ├── capabilities.py   # OrionCapabilityRegistry (in-memory, control-plane pre-populated)
│   ├── consent.py        # OrionConsentValidator (delegates to existing subsystems)
│   ├── handlers.py       # OrionActionHandlers (12 safe handlers)
│   ├── queue.py          # OrionActionQueue (persistent, idempotent)
│   ├── executor.py       # OrionExecutor (drain + bounded retry)
│   ├── reconciliation.py # OrionStateReconciler (deterministic rules)
│   ├── registry.py       # OrionRegistry (persistence)
│   ├── scheduler.py      # OrionScheduler (composition)
│   └── coordinator.py    # OrionCoordinator (high-level entry point)
├── atlas/
│   ├── __init__.py       # Atlas public API re-exports
│   ├── errors.py         # 14 Atlas exception classes
│   ├── models.py         # AtlasCapabilityVersion, AtlasBackupInfo, etc.
│   ├── integrity.py      # AtlasIntegrityVerifier (read-only checks)
│   ├── lifecycle.py      # AtlasLifecycleValidator (key/session lifecycle)
│   ├── health.py         # AtlasHealthMonitor (per-subsystem health)
│   ├── diagnostics.py    # AtlasDiagnostics (standard and deep suites)
│   ├── backup.py         # AtlasBackupManager (metadata-only backups)
│   ├── restore.py        # AtlasRestoreManager (dry-run-first restore)
│   ├── recovery.py       # AtlasRecoveryManager (crash recovery)
│   ├── compatibility.py  # AtlasCompatibilityChecker
│   ├── capabilities.py   # AtlasCapabilityRegistry (versioned capabilities)
│   ├── observability.py  # AtlasObservability (bounded metrics)
│   ├── metrics.py        # AtlasMetrics (aggregated metrics)
│   ├── retention.py      # AtlasRetentionManager (bounded retention)
│   ├── release.py        # AtlasReleaseValidator (release-readiness)
│   └── controller.py     # AtlasController (high-level entry point)
```

---

## 3. Database Schema Overview

GuardianMesh maintains an idempotent SQLite database across schema migrations:
- **Migration 1 (`001_initial_schema`)**: `identities`, `config_entries`, `audit_events`.
- **Migration 2 (`002_pairing_schema`)**: `pairing_sessions`, `pairing_nonces`, `trusted_devices`.
- **Migration 3 (`003_telemetry_schema`)**: `device_health`, `telemetry_events`, `device_sequences`.
- **Migration 4 (`004_sentinel_schema`)**: `policies`, `policy_rules`, `alerts`.
- **Phase 5 (Console)**: Presentation and facade layer.
- **Migration 6 (`006_nexus_transport`)**: `transport_sessions`, `transport_peers`, `transport_messages`, `transport_sequences`.
- **Phase 7 (Vista)**: Consent-based view-only screen sessions.
  - **Migration 7 (`007_vista_screen_sessions`)**: `screen_sessions`, `screen_authorizations` (metadata only).
- **Phase 8 (Aegis)**: Production Android companion with `MediaProjection` consent.
  - **Migration 8 (`008_aegis_screen_capture`)**: `aegis_sessions` (metadata only).
- **Phase 9 (Orion)**: Consent-aware orchestration & state reconciliation.
  - **Migration 9 (`009_orion_schema`)**: `orion_events`, `orion_actions` (with UNIQUE INDEX on `idempotency_key`), `orion_capabilities`, `orion_reconciliation` — all metadata only. No columns for frame bytes, command strings, or secrets.
- **Phase 10 (Atlas)**: Production hardening, reliability, and release platform.
  - **Migration 10 (`010_atlas`)**: `atlas_backups`, `atlas_health`, `atlas_recovery`, `atlas_capability_versions`, `atlas_retention` — all metadata only. No columns for frame bytes, command strings, or secrets.
