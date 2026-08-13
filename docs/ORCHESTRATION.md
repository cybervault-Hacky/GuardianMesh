# GuardianMesh Orchestration Guide

This document is a high-level overview of how the GuardianMesh subsystems
interact under Orion (Phase 9). For the privacy model, see
[ORION.md](ORION.md). For reconciliation rules, see
[RECONCILIATION.md](RECONCILIATION.md). For the action lifecycle, see
[ACTIONS.md](ACTIONS.md).

---

## Subsystem Map

| Phase | Subsystem | Responsibility                                            |
| ----- | --------- | --------------------------------------------------------- |
| 1     | Core      | Identities, configuration, paths, errors.                |
| 2     | Link      | TrustManager, pairing, OTP, child authorization.         |
| 3     | Pulse     | Health telemetry, device health, sequence manager.       |
| 4     | Sentinel  | Policies, alerts, evaluators.                             |
| 5     | Console   | Dashboard, formatter, services, navigation.              |
| 6     | Nexus     | Encrypted transport, sessions, peers, framing.            |
| 7     | Vista     | View-only screen sessions, indicator, frames.            |
| 8     | Aegis     | Android companion, system consent, encoder.              |
| 9     | Orion     | Event bus, action queue, reconciliation, capabilities.   |

Orion is the orchestration layer that ties them all together. It
**does not** replace any subsystem — it composes them.

---

## The Orion Coordinator

The `OrionCoordinator` is the high-level entry point. It owns:

* The event bus (`OrionEventBus`).
* The action queue (`OrionActionQueue`).
* The executor (`OrionExecutor`).
* The scheduler (`OrionScheduler`).
* The action handlers (`OrionActionHandlers`).
* The state reconciler (`OrionStateReconciler`).
* The consent validator (`OrionConsentValidator`).
* The capability registry (`OrionCapabilityRegistry`).
* The persistent registry (`OrionRegistry`).

```python
from guardianmesh.orion.coordinator import OrionCoordinator

coord = OrionCoordinator(db=db)
coord.start()

# Publish an event
coord.publish(some_event)

# Submit an action (built and enqueued in one call)
coord.submit(
    action_type=OrionActionType.REQUEST_CAPABILITIES,
    device_id="GM-C-19A84E72",
    requested_by="GM-P-83A1F72C",
)

# Run reconciliation
report = coord.reconcile("GM-C-19A84E72")
```

The coordinator never invents new logic. It only composes the
existing components and exposes a small, well-documented surface.

---

## Event-Driven Flow

```
subsystem  ──▶  OrionEvent  ──▶  OrionEventBus  ──▶  handler(s)
```

1. A subsystem (Pulse, Sentinel, Vista, Aegis, TrustManager) emits an
   `OrionEvent`.
2. The bus enforces dedup, ordering, and bounded retry.
3. Handlers are explicit, allowlisted, and SAFE. They never execute
   arbitrary code.

## Action-Driven Flow

```
caller  ──▶  OrionAction  ──▶  OrionActionQueue  ──▶  OrionExecutor
                                                            │
                                                            ▼
                                                      handler
                                                            │
                                                            ▼
                                              status (SUCCEEDED/FAILED)
```

1. A caller (CLI, REST API, internal subsystem) builds an
   `OrionAction`.
2. The action is persisted in the queue with an optional
   `idempotency_key`.
3. The executor pulls PENDING actions and dispatches them to handlers.
4. Handlers delegate to existing subsystems (Pulse, Sentinel,
   Nexus, Vista, Aegis).
5. Status transitions are recorded in the queue.

---

## Consent Chain

```
OrionAction  ──▶  OrionConsentValidator  ──▶  TrustManager
                                          ──▶  ScreenAuthorizationManager
                                          ──▶  SystemConsentGate (Aegis)
```

The `OrionConsentValidator` declares what each action needs; it does
not invent new consent. The existing subsystems decide whether the
required consent is in place. Orion only propagates the decision.

---

## Reconciliation Flow

```
device reconnect  ──▶  OrionStateReconciler.reconcile(device_id)
                              │
                              ├── trust revocation rule
                              ├── screen session expiry rule
                              ├── aegis session expiry rule
                              ├── transport state rule
                              ├── event staleness rule
                              └── action deduplication rule
                              │
                              ▼
                    OrionReconciliationReport (metadata-only)
```

The report is persisted through `OrionRegistry.list_reports()` and
returned to the caller. It never contains frame bytes, commands, or
secrets.

---

## Capability Flow

```
device declares  ──▶  OrionDeviceCapabilities.discover(...)
                              │
                              ▼
                  OrionCapabilityRegistry  ──▶  handler inspection
                              │
                              ▼
                  audit log (ORION_CAPABILITY_CHANGED)
```

Capabilities are explicit, allowlisted, and never inferred from the
platform. Negative defaults are always False.

---

## Failure Isolation

* A handler exception in the bus is caught, recorded, and surfaces as
  a metric. The bus continues to deliver subsequent events.
* A handler exception in the executor is caught, marked FAILED, and
  triggers bounded retry (or terminal failure if max_retries is
  exhausted).
* A reconciliation rule that throws is caught and recorded as
  `failed_actions += 1`. The remaining rules still run.

---

## Audit Integration

Orion records 11 new audit event types:

* `ORION_EVENT_ACCEPTED` — event admitted by the bus.
* `ORION_EVENT_REJECTED` — event rejected (forbidden type, etc.).
* `ORION_ACTION_CREATED` — action enqueued.
* `ORION_ACTION_STARTED` — handler invoked.
* `ORION_ACTION_COMPLETED` — handler returned success.
* `ORION_ACTION_FAILED` — handler raised.
* `ORION_ACTION_EXPIRED` — sweep marked it EXPIRED.
* `ORION_RECONCILIATION_STARTED` — reconcile() entered.
* `ORION_RECONCILIATION_COMPLETED` — reconcile() returned.
* `ORION_CONFLICT_RESOLVED` — a reconciliation rule resolved a
  conflict.
* `ORION_CAPABILITY_CHANGED` — capability was enabled or disabled.

Audit records carry only metadata. Forbidden keys (password, private
key, secret, frame, command, shell) are never recorded.

---

## Threading Model

* The bus worker thread drains the in-memory queue and dispatches to
  handlers. Handlers are called serially per bus instance.
* The executor thread drains the persistent queue and dispatches to
  handlers. Handlers are called serially per executor instance.
* The reconciler is not threaded; it is invoked explicitly by the
  caller.

All shared state is protected by `threading.RLock`.

---

## Lifecycle

```python
coord = OrionCoordinator(db=db)
coord.start()  # Spawns bus + executor threads
try:
    coord.publish(event)
    coord.submit(action_type, device_id, requested_by)
    report = coord.reconcile(device_id)
finally:
    coord.stop()  # Stops threads gracefully
```

`start()` and `stop()` are idempotent. `is_running()` returns the
current state. The coordinator never blocks indefinitely on shutdown.
