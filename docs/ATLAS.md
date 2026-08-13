# GuardianMesh Atlas — Phase 10 (v1.0.0)

**Production Hardening, Reliability & Release Platform**

> **Atlas is production hardening, NOT a new surveillance layer.**

Atlas is the final production layer in the GuardianMesh 10-phase
roadmap. It exists to make the existing v0.9 system more secure,
more reliable, more observable, more recoverable, more
maintainable, more auditable, and more release-ready.

Atlas does **not** introduce any new surveillance capability. It
hardens the existing system through:

* Integrity verification for the database, identity, trust, and
  audit subsystems.
* Lifecycle validation for keys, sessions, sequences, and stale
  state.
* Health and observability metrics for every GuardianMesh
  subsystem.
* Bounded backup and restore of metadata-only state.
* Crash recovery for interrupted operations.
* Capability versioning with explicit risk classification.
* Retention policies for bounded metadata growth.
* Release validation that does not claim readiness when checks
  fail.
* Diagnostics that report honestly on Linux/Termux without faking
  Android validation.

Atlas never bypasses Trust, Vista authorization, or Aegis system
consent. It never stores frame bytes, command strings, secrets, or
private user content.

---

## 1. Why Atlas Exists

After Phase 9, GuardianMesh had nine independent subsystems, each
excellent in isolation. To make the system production-ready,
Atlas adds:

* **Reliability** — integrity verification, lifecycle validation,
  crash recovery, bounded retry, and bounded queues.
* **Security hardening** — explicit authorization gates, audit
  redaction verification, forbidden-column checks, and Android
  manifest permission verification.
* **Lifecycle management** — recovery for interrupted operations
  without resurrecting revoked or expired state.
* **Data integrity** — SQLite integrity check, foreign-key check,
  forbidden-column check, and audit-chain redaction verification.
* **Observability** — bounded metrics for every documented
  subsystem.
* **Diagnostics** — standard and deep diagnostic suites that report
  honestly.
* **Backup/recovery** — metadata-only backup with integrity digests
  and dry-run restore.
* **Migration resilience** — compatibility checks and metadata
  preservation.
* **Capability compatibility** — versioned capability descriptors
  with risk classification.
* **Concurrency** — concurrent tests for the queue, bus, and
  observers.
* **Release engineering** — release validation that does not
  claim readiness when mandatory checks fail.
* **CI validation** — manifest permission checks, package build
  verification, and Android JVM suite.
* **Android release preparation** — debug/release separation,
  manifest verification, dependency validation.

---

## 2. Strict Prohibitions

The following are **never** implemented in Atlas, in any form, on
any platform:

* Covert monitoring.
* Hidden or unauthorized screen capture.
* Microphone or camera activation.
* Location tracking.
* Clipboard collection.
* Message collection (SMS, chat, email).
* Browser-history collection.
* Bypass of Trust, Vista authorization, or Aegis system consent.
* Persistence of frame bytes, command strings, private keys,
  session keys, passwords, OTPs, or any other sensitive content.
* Resurrecting revoked trust relationships.
* Resurrecting expired authorization.
* Resurrecting expired Aegis consent.
* Restarting stopped screen sessions without explicit authorization.
* Faking Android validation on Linux/Termux.

---

## 3. Module Layout

```
guardianmesh/atlas/
├── __init__.py            # Public API re-exports
├── errors.py              # 14 exception classes
├── models.py              # Strongly-typed data models
├── integrity.py           # Read-only integrity verifier
├── lifecycle.py           # Read-only lifecycle validator
├── health.py              # Per-subsystem health monitor
├── diagnostics.py         # Standard and deep diagnostic suites
├── backup.py              # Metadata-only backup manager
├── restore.py             # Dry-run-first restore manager
├── recovery.py            # Crash-recovery manager
├── compatibility.py       # Schema and version compatibility
├── capabilities.py        # Versioned capability registry
├── observability.py       # Bounded observability metrics
├── metrics.py             # Aggregated metrics
├── retention.py           # Bounded retention policies
├── release.py             # Release-readiness validator
└── controller.py          # High-level controller
```

---

## 4. Security Model

### Bounded trust

Atlas never grants consent. The existing
`OrionConsentValidator` and the underlying `TrustManager`,
`ScreenAuthorizationManager`, and `SystemConsentGate` remain the
authoritative sources. Atlas only records what each capability
requires.

### Audit redaction

Every audit record created by an Atlas subsystem carries only
metadata. The `OrionAuditRedactionCheck` (in
`guardianmesh.atlas.integrity`) verifies that no audit event
contains a forbidden key (private_key, password, secret, frame,
screenshot, keylog, command, shell, etc.).

### Forbidden columns

Migration 10 creates five new tables. None of them include
columns for sensitive content. The
`AtlasIntegrityVerifier.check_forbidden_columns` method
verifies this on every doctor run.

### Android manifest

The `AtlasReleaseValidator.check_aegis_manifest_permissions` method
verifies that the Android companion's manifest declares only
allowed permissions. The forbidden set includes
`RECORD_AUDIO`, `CAMERA`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`,
`READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`, and others.

---

## 5. Reliability

### Crash recovery

The `AtlasRecoveryManager` performs deterministic recovery for
interrupted operations:

* Expired `PENDING` or `RUNNING` Orion actions are marked EXPIRED.
* Expired `APPROVED` screen authorizations are marked EXPIRED.
* Expired `INITIALIZED`, `CONSENT_GRANTED`, or `CAPTURING` Aegis
  sessions are marked EXPIRED.

Recovery never resurrects revoked trust, expired authorization,
or expired Aegis consent. Recovery is fail-closed.

### Backup and restore

The `AtlasBackupManager` produces metadata-only backups with a
SHA-256 integrity digest. The `AtlasRestoreManager` verifies
integrity, schema compatibility, and dry-run validity before
applying any change.

The `BACKUP_ALLOWED_TABLES` set explicitly excludes
`transport_messages` and any other sensitive table. The
`BACKUP_FORBIDDEN_COLUMNS` map strips `private_key_pem` from the
`identities` table.

---

## 6. Observability

The `AtlasObservability` collects bounded metrics for every
documented subsystem:

* `genesis` — identity count, audit event count.
* `link` — trusted device count, by status.
* `pulse` — device health count.
* `sentinel` — policy count, alert count, by status.
* `nexus` — transport session count, by state, peer count.
* `vista` — screen session count, authorization count.
* `aegis` — aegis session count, by state.
* `orion` — event count, action count, by status, capability count,
  reconciliation count.
* `atlas` — backup count, health count, recovery count, capability
  version count, retention count.

Metrics are metadata-only. They never include secrets, frame
bytes, or private content.

---

## 7. Diagnostics

* `guardian doctor` — fast standard suite. Reports all 49
  pre-existing and new checks (Genesis through Atlas).
* `guardian doctor --full` — deep suite. Adds release-readiness
  checks and the Android manifest permission verification.
* `guardian diagnostics` — Atlas-specific diagnostic suite. Does
  not require an Android environment.

Diagnostics report honestly. On Linux/Termux, the Android
provider boundary is reported as a Notice, not a failure.

---

## 8. Release Validation

The `AtlasReleaseValidator` performs the following checks:

* Version consistency (stored config vs runtime).
* Migration state (must be v10).
* Audit event classes (every documented ORION_* event must exist).
* Android manifest permissions (only the documented minimum set).

`guardian release` runs these checks. It does not claim readiness
when any check fails.

---

## 9. CLI Reference

### `guardian atlas`

```
guardian atlas status                # Subsystem status
guardian atlas backup                # Create metadata-only backup
guardian atlas restore <id>          # Restore (dry-run by default)
guardian atlas recover               # Run crash recovery
guardian atlas retention             # Apply retention (dry-run by default)
guardian atlas health                # Record a health snapshot
guardian atlas capabilities          # List versioned capabilities
guardian atlas version                # Show release information
```

All commands support `--json` for machine-readable output. All
work at 40/60/80/120 column terminals and respect `NO_COLOR`.

### `guardian diagnostics`

```
guardian diagnostics                  # Standard suite
guardian diagnostics --full           # Deep suite
guardian diagnostics --json           # JSON output
```

### `guardian release`

```
guardian release                       # Check release-readiness
guardian release --json                # JSON output
```

---

## 10. Migration 10

`010_atlas` creates five new tables:

* `atlas_backups` — metadata-only backup manifest.
* `atlas_health` — per-subsystem health snapshots.
* `atlas_recovery` — crash-recovery records.
* `atlas_capability_versions` — versioned capability descriptors.
* `atlas_retention` — bounded retention policies.

The migration adds the necessary indexes and UNIQUE constraints
and is fully idempotent.

---

## 11. Doctor Coverage

`guardian doctor` includes 9 new Atlas-specific checks:

* `Atlas module` — every documented public symbol is present.
* `Atlas database schema` — all five tables exist.
* `Atlas capability registry` — the registry is non-empty.
* `Atlas migration state` — schema is at v10.
* `Atlas backup subsystem` — backup creation and verification work.
* `Atlas recovery subsystem` — recovery returns SUCCEEDED for
  empty state.
* `Atlas integrity verifier` — all integrity checks pass.
* `Atlas observability` — observability collection returns sane
  values.
* `Atlas release validation` — basic release checks pass.

All 9 checks pass on a healthy install.

---

## 12. Known Limitations

* **Android physical-device validation cannot be performed in
  this sandbox.** The Aegis Android Kotlin companion cannot be
  built or executed here. The companion code is documented
  architecture only. The Python control plane uses
  `AdapterOnlyMediaProjectionProvider` and `TestScreenEncoder`
  for Linux/Termux.
* **Real `MediaProjection` capture is not performed from the
  Python control plane.** This is by design. The Aegis subsystem
  is the production boundary, and it requires a real Android
  build environment. Atlas does not change this.
