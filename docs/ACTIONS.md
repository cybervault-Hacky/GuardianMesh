# GuardianMesh Actions Guide

This document describes Orion's action model, the persistent queue,
and the lifecycle of an `OrionAction`.

---

## The Action Type Allowlist

Orion actions are SAFE by construction. The strict allowlist of
`OrionActionType` values is:

| Type                       | Purpose                                            |
| -------------------------- | -------------------------------------------------- |
| `REFRESH_HEALTH`           | Ask Pulse to refresh health snapshot.              |
| `REQUEST_HEALTH_SYNC`      | Request a health-state synchronization.            |
| `ACKNOWLEDGE_ALERT`        | Acknowledge a Sentinel alert.                      |
| `RESOLVE_ALERT`            | Resolve a Sentinel alert.                          |
| `RECONNECT_TRANSPORT`      | Reconnect a Nexus transport channel.               |
| `REQUEST_STATUS_SYNC`      | Request a status synchronization.                  |
| `REQUEST_SCREEN_SESSION`   | Request a Vista view-only screen session.          |
| `STOP_SCREEN_SESSION`      | Stop an in-progress Vista screen session.          |
| `REQUEST_AEGIS_CONSENT`    | Request Aegis system consent.                      |
| `STOP_AEGIS_CAPTURE`       | Stop an in-progress Aegis capture.                 |
| `RECONCILE_STATE`          | Trigger a state reconciliation.                    |
| `REQUEST_CAPABILITIES`     | Request a device's capability record.              |

Forbidden action types include `EXECUTE`, `SHELL`, `REMOTE_INPUT`,
`TYPE_TEXT`, `ENABLE_MICROPHONE`, `READ_SMS`, `HIDDEN_SCREENSHOT`,
and many more. They are rejected at construction time by
`assert_safe_action_type_name`.

---

## Action Lifecycle

```
PENDING ──▶ RUNNING ──▶ SUCCEEDED
       │         │
       │         └────▶ FAILED ─(retry)──▶ PENDING
       │
       └──────────────▶ EXPIRED  (sweep_expired)
       │
       └──────────────▶ CANCELLED (cancel command)
```

### Status Transitions

* `PENDING` — initial state, awaiting execution.
* `RUNNING` — executor has dispatched the action to a handler.
* `SUCCEEDED` — handler returned successfully.
* `FAILED` — handler raised and `max_retries` is exhausted.
* `EXPIRED` — sweep marked the action as past `expires_at`.
* `CANCELLED` — operator explicitly cancelled the action.

---

## Idempotency

Every action can carry an optional `idempotency_key`. Duplicate keys
are silently rejected at `enqueue` time. The queue enforces a UNIQUE
INDEX on `idempotency_key` in the `orion_actions` table.

```python
action = OrionAction(
    action_id="OAC-001",
    action_type=OrionActionType.REQUEST_CAPABILITIES,
    device_id="GM-C-19A84E72",
    ...
    idempotency_key="client-req-12345",
)
queue.enqueue(action)  # True
queue.enqueue(action_with_same_key)  # False (idempotent)
```

This is the at-most-once guarantee: a logical action is executed at
most once even if the operator submits it multiple times.

---

## Bounded Retry

Each action has a `retry_count` and a `max_retries`. When a handler
raises, the queue's `mark_failed(retry=True)` increments
`retry_count` and schedules a `next_attempt_at` with exponential
backoff (2^retry_count seconds).

When `retry_count` reaches `max_retries`, the action is marked
`FAILED` and is not retried again.

The executor also has a `max_consecutive_failures` cap. If the
executor hits this cap, it stops processing new actions until the
operator intervenes.

---

## Bounded Queue Size

The queue has a configurable maximum size (default 10,000). When
the queue is at capacity, `enqueue` raises `OrionQueueError`. This
prevents unbounded growth from buggy or malicious producers.

---

## Expiration Sweep

The queue's `sweep_expired(now=None)` method marks all PENDING or
RUNNING actions whose `expires_at` is in the past as `EXPIRED`. The
executor calls this at the start of every drain cycle.

```python
expired_ids = queue.sweep_expired()
# Returns: ['OAC-1', 'OAC-2', ...]
```

Expired actions never run.

---

## Building an Action

The `OrionScheduler.build_action()` method constructs a well-formed
action from a request:

```python
scheduler.build_action(
    action_type=OrionActionType.REQUEST_CAPABILITIES,
    device_id="GM-C-19A84E72",
    requested_by="GM-P-83A1F72C",
    parameters={"alert_id": "ALT-001"},
    idempotency_key="client-12345",
    ttl_seconds=300,
)
```

The action's consent requirements are derived from the documented
map. The action's expiration is set to `now + ttl_seconds`. The
action's id and correlation id are auto-generated.

For a one-shot build-and-enqueue, use `scheduler.submit()`:

```python
scheduler.submit(
    action_type=OrionActionType.REQUEST_CAPABILITIES,
    device_id="GM-C-19A84E72",
    requested_by="GM-P-83A1F72C",
)
```

---

## Consent Validation

Before execution, the `OrionConsentValidator` consults:

* `TrustManager` for `TRUST_REQUIRED`.
* `ScreenAuthorizationManager` for `VISTA_AUTHORIZATION_REQUIRED`.
* `SystemConsentGate` for `AEGIS_SYSTEM_CONSENT_REQUIRED`.
* The active session registry for `EXISTING_ACTIVE_SESSION`.

If any required consent is missing or expired, the validator raises
`OrionConsentViolationError`. The action is then marked FAILED.

Orion never invents consent. It only delegates.

---

## Audit Integration

Every action lifecycle event is recorded in the audit log:

* `ORION_ACTION_CREATED` — at enqueue time.
* `ORION_ACTION_STARTED` — when the handler is invoked.
* `ORION_ACTION_COMPLETED` — when the handler returns successfully.
* `ORION_ACTION_FAILED` — when the handler raises.
* `ORION_ACTION_EXPIRED` — when sweep marks it EXPIRED.

Audit records carry only metadata. Forbidden keys (password, private
key, secret, frame, command, shell) are never recorded.

---

## Database Schema

The `orion_actions` table includes:

```sql
CREATE TABLE orion_actions (
    action_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    parameters TEXT,  -- JSON
    idempotency_key TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    next_attempt_at TEXT,
    last_error TEXT,
    updated_at TEXT,
    result TEXT  -- JSON
);

CREATE UNIQUE INDEX idx_orion_actions_idempotency_unique
    ON orion_actions (idempotency_key)
    WHERE idempotency_key IS NOT NULL;
```

None of the columns store frame bytes, command strings, or secrets.

---

## Action Handlers

`OrionActionHandlers` is the SAFE handler registry. Each handler
delegates to an existing subsystem:

| Action Type                       | Handler Delegation                                |
| --------------------------------- | ------------------------------------------------- |
| `REFRESH_HEALTH`                  | `TelemetryProcessor` (metadata only)              |
| `REQUEST_HEALTH_SYNC`             | `TelemetryProcessor` (metadata only)              |
| `ACKNOWLEDGE_ALERT`               | `AlertManager.acknowledge_alert`                  |
| `RESOLVE_ALERT`                   | `AlertManager.resolve_alert`                      |
| `RECONNECT_TRANSPORT`             | `TransportClient.reconnect`                       |
| `REQUEST_STATUS_SYNC`             | (metadata only)                                   |
| `REQUEST_SCREEN_SESSION`          | `ScreenController.request_view`                   |
| `STOP_SCREEN_SESSION`             | `ScreenController.stop_session`                   |
| `REQUEST_AEGIS_CONSENT`           | `AegisController.request_system_consent`          |
| `STOP_AEGIS_CAPTURE`              | `AegisController.stop_capture`                    |
| `RECONCILE_STATE`                 | `OrionStateReconciler.reconcile`                  |
| `REQUEST_CAPABILITIES`            | `OrionCapabilityRegistry.get`                     |

Handlers never execute arbitrary code. They only delegate.

---

## CLI

The CLI exposes the action lifecycle through:

```bash
$ guardian orchestrate actions                # List all actions
$ guardian orchestrate actions --status pending
$ guardian orchestrate action OAC-001         # Show one action
$ guardian orchestrate retry OAC-001          # Re-queue a failed action
$ guardian orchestrate cancel OAC-001         # Cancel a pending action
```

All commands support `--json` for machine-readable output.
