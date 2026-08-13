# GuardianMesh Reconciliation Guide

This document describes how Orion's `OrionStateReconciler` brings a
reconnected device back into a known-good state.

---

## When Reconciliation Runs

The reconciler is invoked explicitly:

```python
from guardianmesh.orion.reconciliation import OrionStateReconciler

recon = OrionStateReconciler(registry=registry)
report = recon.reconcile("GM-C-19A84E72")
```

In a production deployment, the parent host calls `reconcile()` after
the device reconnects through Nexus. The call is idempotent — running
it twice in a row produces the same final state.

---

## Reconciliation Rules

The reconciler applies the documented rules in order:

### Rule 1 — Trust revocation always wins

If a device's trust relationship is revoked, the reconciler tears
down all transport, Vista, and Aegis state for the device. The
existing `TrustManager` is the authoritative source for trust state;
Orion never modifies it directly.

### Rule 2 — Expired authorization always wins

A Vista authorization whose lifetime has elapsed marks the affected
session as EXPIRED. The `ScreenAuthorizationManager` is the
authoritative source.

### Rule 3 — Expired sessions must be stopped

Any session (Vista or Aegis) whose `expires_at` has elapsed is
stopped. The `ScreenController` and `AegisController` are the
authoritative sources for session lifetime.

### Rule 4 — Transport state must be reconciled

The transport registry records per-peer connection state. If a peer
is in a terminal state (FAILED, EXPIRED), the reconciler flags it
as a conflict to be addressed at the next reconnect attempt.

### Rule 5 — Stale events must be safely discarded or marked stale

Events older than the staleness threshold (default 600 seconds / 10
minutes) are recorded in the reconciliation report as stale. They
are not applied to local state. The threshold is configurable via
the `staleness_seconds` parameter.

### Rule 6 — Duplicate events must be ignored

The event bus enforces this at the source; the reconciler only runs
after the bus has deduplicated.

### Rule 7 — No sensitive payload replay

The reconciler never replays screen frames, command payloads, or any
other private content. It only records that an event was processed.

### Rule 8 — Idempotency

Running reconciliation twice in a row produces the same final state.
The report's `report_id` is unique per call, but the resulting
`final_state` is stable.

---

## The Report

The reconciler returns a metadata-only `OrionReconciliationReport`:

```python
@dataclass
class OrionReconciliationReport:
    report_id: str
    device_id: str
    started_at: str
    completed_at: str | None
    events_processed: int = 0
    conflicts_detected: int = 0
    conflicts_resolved: int = 0
    stale_events: int = 0
    failed_actions: int = 0
    final_state: str = "SYNCED"
    notes: str = ""
```

`final_state` is one of:

* `SYNCED` — reconciliation completed without conflicts.
* `RESYNC_REQUIRED` — at least one rule detected a conflict.
* `FAILED` — at least one rule threw an unrecoverable error.

The report is persisted to the `orion_reconciliation` table through
`OrionRegistry.upsert_report()`.

---

## Staleness Threshold

The default `DEFAULT_STALENESS_SECONDS` is 600 (10 minutes). It is
documented in `guardianmesh.orion.reconciliation`.

You can override it per call:

```python
report = recon.reconcile(
    "GM-C-19A84E72",
    events=stale_events,
    staleness_seconds=60,
)
```

A lower threshold treats more events as stale; a higher threshold
treats more events as fresh.

---

## Edge Cases

### Empty event list

A reconciliation call with no events is a valid no-op. The report
records `events_processed = 0` and `stale_events = 0`.

### Device mismatch

Events whose `device_id` does not match the target device are
silently ignored. They are not counted as processed or stale.

### Invalid timestamps

Events with unparseable `created_at` timestamps are recorded as
stale. The reconciler never crashes on malformed input.

### Corrupted registry

The reconciler delegates persistence to `OrionRegistry`, which
handles corrupted JSON records gracefully (skipping them rather
than crashing).

### Handler failure during a rule

A rule that throws an exception is caught and recorded as
`failed_actions += 1`. The remaining rules still run.

---

## Test Coverage

The reconciler is covered by 16 unit tests in
`tests/test_orion_reconciliation.py`:

* ID generation.
* Empty device id rejection.
* Basic reconciliation.
* Report persistence.
* Idempotency.
* Fresh event processing.
* Stale event marking.
* Custom staleness threshold.
* Sequence-ordered processing.
* Per-device filtering.
* Invalid timestamp handling.
* Empty event list.
* Optional events parameter.
* Metadata-only report.
* Default staleness constant.
* No-external-subsystems mode.

---

## Failure Modes

The reconciler raises `OrionReconciliationError` only when:

* `device_id` is empty or None.

All other failures are caught and recorded in the report. The
reconciler is intentionally permissive: it should not block
reconnection on a single bad event.
