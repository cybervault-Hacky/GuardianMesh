# GuardianMesh Orion — Phase 9 (v0.9.0)

**Consent-Aware Orchestration & State Reconciliation**

> **Orion is orchestration, NOT surveillance.**

Orion is the ninth phase in the GuardianMesh 10-phase roadmap. It
introduces a deterministic, event-driven orchestration layer that
coordinates the existing subsystems — Pulse health telemetry, Sentinel
policies and alerts, Console state, Nexus transport, Vista screen
sessions, Aegis Android companion state, and Trust/revocation state —
**without** introducing any new covert monitoring, remote input, shell
execution, hidden screen capture, microphone/camera activation, location
tracking, clipboard collection, message collection, browser-history
collection, or bypass around the existing consent mechanisms.

---

## 1. Why Orion Exists

By Phase 8, GuardianMesh had eight independent subsystems, each
excellent in isolation. After reconnecting a child device through Nexus
(Phase 6), a parent needed a way to:

* Ask the device to refresh its health snapshot.
* Acknowledge or resolve a stale alert.
* Reconcile local state with the device's view of the world.
* Inspect the device's declared capabilities.
* Stop an in-progress screen session.
* Surface consent-aware events in a unified stream.

Earlier phases handled each of these through independent code paths.
Orion unifies them under a single, deterministic, idempotent
orchestration plane with the same privacy guarantees as the rest of
GuardianMesh.

Orion does **not**:

* Implement a keylogger, a microphone activator, a camera activator,
  a clipboard collector, a message collector, a browser-history
  collector, a location tracker, a hidden screen capture, a remote
  shell, or any other form of covert monitoring.
* Weaken, bypass, or replace any existing consent mechanism. Orion
  *only* delegates to existing subsystems (TrustManager, Vista
  authorization, Aegis SystemConsentGate) and never invents new
  consent.
* Persist private keys, session keys, passwords, OTPs, plaintext
  screen frames, frame bytes, command strings, or private user
  content. Migration 9's schema is column-restricted to metadata.

---

## 2. Strict Prohibitions

The following are **never** implemented in Orion, in any form, on any
platform:

* Covert monitoring of any kind
* Remote control or remote input
* Shell execution or arbitrary command execution
* Microphone or camera activation
* Hidden or unauthorized screen capture
* Location tracking
* Clipboard collection
* Message collection (SMS, email, chat)
* Browser-history collection
* Bypass of Vista, Aegis, or TrustManager consent
* Persistence of sensitive payloads in any Orion table
* Persistence of secrets in any Orion audit log

The forbidden-name allowlists in `events.py`, `actions.py`, and
`models.py` are enforced at construction time. An event type,
action type, or capability that appears in the forbidden set cannot be
created at all.

---

## 3. Event Model

Orion events are strongly typed, deterministic, and contain only
metadata — never frame bytes, never secrets, never private user
content.

Every `OrionEvent` carries:

* `event_id` — a unique identifier (e.g. `OEV-...`).
* `event_type` — one of the strict allowlist values (e.g.
  `DEVICE_CONNECTED`, `TRUST_REVOKED`, `RECONCILIATION_COMPLETED`).
* `source` — the subsystem that produced the event.
* `device_id` — the target device, validated as a GuardianMesh
  identity id (or the `SYSTEM` / `BUS` / `ORION` sentinel).
* `created_at` — ISO-8601 timestamp.
* `correlation_id` — for correlating related events.
* `schema_version` — `"1.0"`.
* `payload` — a metadata-only dict. Forbidden keys (frame, screenshot,
  command, shell, password, etc.) are rejected at construction time.
* `priority` — `LOW`, `NORMAL`, `HIGH`, or `CRITICAL`.
* `sequence` — per-device monotonic sequence number, assigned by the
  bus.

Forbidden event types (`KEYSTROKE`, `MESSAGE`, `MICROPHONE`, `CAMERA`,
`LOCATION`, `SHELL_COMMAND`, `REMOTE_INPUT`, `BROWSER_HISTORY`, etc.)
are rejected at construction time by `assert_safe_event_type_name`.

---

## 4. Action Model

Orion actions are safe, allowlisted, and persistent. The action
allowlist is intentionally narrow:

* `REFRESH_HEALTH`, `REQUEST_HEALTH_SYNC`
* `ACKNOWLEDGE_ALERT`, `RESOLVE_ALERT`
* `RECONNECT_TRANSPORT`, `REQUEST_STATUS_SYNC`
* `REQUEST_SCREEN_SESSION`, `STOP_SCREEN_SESSION`
* `REQUEST_AEGIS_CONSENT`, `STOP_AEGIS_CAPTURE`
* `RECONCILE_STATE`, `REQUEST_CAPABILITIES`

Forbidden action types (`EXECUTE`, `SHELL`, `REMOTE_INPUT`, `TYPE_TEXT`,
`ENABLE_MICROPHONE`, `READ_SMS`, `READ_FILES`, `HIDDEN_SCREENSHOT`,
etc.) are rejected at construction time by `assert_safe_action_type_name`.

Each action has:

* Explicit consent requirements, declared in
  `ACTION_CONSENT_REQUIREMENTS`.
* Explicit expiration (`expires_at`).
* Deterministic id (`OAC-...`) and correlation id.
* Status that flows through the persistent queue: `PENDING` →
  `RUNNING` → `SUCCEEDED` / `FAILED` / `EXPIRED` / `CANCELLED`.
* Optional `idempotency_key` for at-most-once execution.
* Metadata-only `parameters`. Forbidden parameter keys (command, shell,
  exec, code, script, frame, screenshot, keylog, password, private_key,
  secret, token) are rejected at construction time.

---

## 5. Consent Requirements

Each action type declares its consent requirements explicitly:

| Action Type             | Required Consent                                                          |
| ----------------------- | ------------------------------------------------------------------------- |
| `REFRESH_HEALTH`        | `TRUST_REQUIRED`                                                          |
| `REQUEST_HEALTH_SYNC`   | `TRUST_REQUIRED`                                                          |
| `ACKNOWLEDGE_ALERT`     | (none)                                                                    |
| `RESOLVE_ALERT`         | (none)                                                                    |
| `RECONNECT_TRANSPORT`   | (none)                                                                    |
| `REQUEST_STATUS_SYNC`   | `TRUST_REQUIRED`                                                          |
| `REQUEST_SCREEN_SESSION`| `TRUST_REQUIRED` + `VISTA_AUTHORIZATION_REQUIRED` + `AEGIS_SYSTEM_CONSENT_REQUIRED` + `CHILD_AUTHORIZATION_REQUIRED` |
| `STOP_SCREEN_SESSION`   | `TRUST_REQUIRED` + `EXISTING_ACTIVE_SESSION`                              |
| `REQUEST_AEGIS_CONSENT` | `TRUST_REQUIRED` + `VISTA_AUTHORIZATION_REQUIRED` + `AEGIS_SYSTEM_CONSENT_REQUIRED` + `CHILD_AUTHORIZATION_REQUIRED` |
| `STOP_AEGIS_CAPTURE`    | `TRUST_REQUIRED` + `EXISTING_ACTIVE_SESSION`                              |
| `RECONCILE_STATE`       | `TRUST_REQUIRED`                                                          |
| `REQUEST_CAPABILITIES`  | (none)                                                                    |

Orion's `OrionConsentValidator` is the single place where Orion makes
consent decisions. It never short-circuits; it only delegates to the
existing subsystems and surfaces their verdicts.

---

## 6. State Reconciliation

After a device reconnects through Nexus, Orion runs a deterministic
state reconciliation cycle. The reconciler applies the documented
rules:

1. **Trust revocation always wins.** A revoked trust relationship
   tears down all transport, Vista, and Aegis state for the device.
2. **Expired authorization always wins.** An expired Vista or Aegis
   authorization marks the affected session as EXPIRED.
3. **Expired sessions must be stopped.** Any session whose
   `expires_at` has elapsed is marked EXPIRED.
4. **Stale events must be safely recorded.** Events older than the
   staleness threshold (default 600 seconds / 10 minutes) are recorded
   in the report but not applied to state.
5. **Duplicate events are ignored.** The bus enforces this; the
   reconciler only runs after the bus has deduplicated.
6. **No sensitive payload replay.** The reconciler never replays
   screen frames, command payloads, or any other private content.
7. **Idempotency.** Running reconciliation twice in a row produces
   the same final state.

The reconciler produces a metadata-only `OrionReconciliationReport`
describing the cycle. The report is persisted through
`OrionRegistry` for later inspection.

---

## 7. Capability Discovery

Capabilities are documented, allowlisted, and explicit:

* **Positive capabilities** (the device CAN do these):
  `HEALTH_TELEMETRY`, `POLICIES`, `ALERTS`, `SECURE_TRANSPORT`,
  `SCREEN_SESSION`, `SYSTEM_CONSENT`, `ORCHESTRATION`.
* **Negative defaults** (the device CANNOT do these — always False):
  `AUDIO_CAPTURE`, `CAMERA_CAPTURE`, `REMOTE_INPUT`, `REMOTE_SHELL`,
  `KEYLOGGING`, `LOCATION_TRACKING`, `CLIPBOARD_ACCESS`,
  `MESSAGE_COLLECTION`, `BROWSER_HISTORY`, `HIDDEN_SCREEN_CAPTURE`.

Orion **never** infers a capability from the platform. Every
capability is enabled only if the caller passes `True` explicitly.
A device that does not declare a capability is assumed to NOT support
it.

The `OrionCapabilityRegistry` is pre-populated with a control-plane
profile (`ORION`) that records what the meta-device (the parent host)
can do, without claiming any device-side capture capabilities.

---

## 8. Privacy Guarantees

Orion is the only subsystem in GuardianMesh whose name was chosen to
remind developers that the privacy model is the entire point:

1. **No covert monitoring.** The event and action type allowlists
   forbid any surveillance-style event or action.
2. **No payload capture.** Forbidden payload and parameter keys
   include every form of sensitive content.
3. **No secrets in audit logs.** The 11 new audit event types
   (`ORION_*`) record only metadata.
4. **No sensitive columns.** The `orion_events`, `orion_actions`,
   `orion_capabilities`, and `orion_reconciliation` tables have no
   column for frame bytes, command strings, or secrets.
5. **Bounded queue.** The action queue has a configurable maximum
   size (default 10,000) to prevent unbounded growth.
6. **Bounded retry.** Each action has a `max_retries` cap; the
   executor respects it.
7. **Action expiry.** Actions past their `expires_at` are marked
   EXPIRED at sweep time and never executed.
8. **Idempotency.** Duplicate `idempotency_key` values are silently
   rejected.
9. **Metadata-only reports.** Reconciliation reports never contain
   frame bytes, commands, or secrets.

---

## 9. Command Line

Orion exposes its functionality through two new top-level commands:

* `guardian orchestrate <status|events|actions|action|retry|cancel|reconcile|capabilities>`
* `guardian capabilities <device_id>`

Both support `--json` for machine-readable output.

### Example: status

```
$ guardian orchestrate status
GuardianMesh Orion
────────────────────────────────
Running        no

Event Bus:
  Queue size     0
  Processed      0
  Dropped        0
  Failed         0

Action Queue:
  Total          3
  CANCELLED      3

Capabilities:
  Devices        1

Registry:
  events                 0
  actions                3
  capabilities_records   0
  reconciliations        1
```

### Example: reconciliation

```
$ guardian orchestrate reconcile GM-C-19A84E72
Orion Reconciliation: ORC-41F3D6C11390
────────────────────────────────
Device         GM-C-19A84E72
Started        2026-08-13T07:12:46.883064+00:00
Completed      2026-08-13T07:12:46.883086+00:00
Final state    SYNCED
Events         0
Conflicts      0 / 0 resolved
Stale          0
Failed         0
```

### Example: capabilities

```
$ guardian orchestrate capabilities ORION
Orion Capabilities: ORION
────────────────────────────────
Source         default-control-plane
Discovered     2026-08-13T07:12:49.205366+00:00

Positive (allowed):
  • HEALTH_TELEMETRY
  • POLICIES
  • ALERTS
  • SECURE_TRANSPORT
  • ORCHESTRATION

Negative (always False):
  • AUDIO_CAPTURE
  • BROWSER_HISTORY
  • CAMERA_CAPTURE
  • CLIPBOARD_ACCESS
  • HIDDEN_SCREEN_CAPTURE
  • KEYLOGGING
  • LOCATION_TRACKING
  • MESSAGE_COLLECTION
  • REMOTE_INPUT
  • REMOTE_SHELL
```

---

## 10. Migration 9

`009_orion_schema` creates four tables:

* `orion_events` — metadata-only event log.
* `orion_actions` — persistent, idempotent action queue with a
  UNIQUE INDEX on `idempotency_key`.
* `orion_capabilities` — per-device capability records.
* `orion_reconciliation` — metadata-only reconciliation reports.

The migration adds 12 indexes for efficient lookups by device, event
type, status, correlation id, and timestamp. None of the tables
include columns for frame bytes, command strings, or secrets.

---

## 11. Module Layout

```
guardianmesh/orion/
├── __init__.py        # Public API re-exports
├── errors.py          # 10 exception classes
├── models.py          # OrionCapability, OrionDeviceCapabilities,
│                      # OrionReconciliationReport
├── events.py          # OrionEvent, OrionEventType, OrionEventPriority,
│                      # FORBIDDEN_EVENT_NAMES, FORBIDDEN_PAYLOAD_KEYS
├── actions.py         # OrionAction, OrionActionType, OrionActionStatus,
│                      # ACTION_CONSENT_REQUIREMENTS, FORBIDDEN_ACTION_*
├── bus.py             # OrionEventBus, BackpressureStrategy
├── queue.py           # OrionActionQueue (persistent, idempotent)
├── executor.py        # OrionExecutor (drain + bounded retry)
├── handlers.py        # OrionActionHandlers (12 safe handlers)
├── consent.py         # OrionConsentValidator (delegates to existing)
├── reconciliation.py  # OrionStateReconciler
├── capabilities.py    # OrionCapabilityRegistry
├── registry.py        # OrionRegistry (persistence)
├── scheduler.py       # OrionScheduler (composes bus+queue+executor)
└── coordinator.py     # OrionCoordinator (high-level entry point)
```

The modules are small, strongly typed, and individually testable. The
package is the smallest possible unit of orchestration — it does not
duplicate or replace any prior subsystem.

---

## 12. Doctor Checks

`guardian doctor` includes 11 new Orion-specific checks:

* Orion module — all 15 documented public symbols are present.
* Orion event bus — initial state and configuration.
* Orion action queue — round-trip and persistence.
* Orion idempotency — duplicate `idempotency_key` is rejected.
* Orion reconciliation — `report_id` format and `completed_at` is set.
* Orion capability registry — control-plane profile and negative
  defaults are all False.
* Orion database schema — all four tables are present.
* Orion audit integration — all 11 ORION_* audit event types exist.
* Orion consent integration — safe actions validate without
  configured subsystems.
* Orion offline queue — actions persist across queue reopens.
* Orion handler registry — handler dispatch map is populated.

All 11 checks pass on a healthy install.
