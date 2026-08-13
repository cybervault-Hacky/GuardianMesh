# GuardianMesh Recovery Guide (Atlas v1.0.0)

This document describes how to recover from interrupted or
inconsistent state in GuardianMesh.

---

## 1. Recovery Philosophy

Atlas recovery is **deterministic** and **fail-closed**. It
never resurrects revoked trust, expired authorization, or
expired Aegis consent. It never restarts a stopped screen
session without explicit authorization.

Recovery is not a substitute for backup. It is a last-resort
operation that brings a database into a known-consistent state.

---

## 2. What Recovery Does

The `AtlasRecoveryManager` performs three deterministic
operations:

### 2.1. Mark expired Orion actions as `EXPIRED`

Any `PENDING` or `RUNNING` Orion action whose `expires_at` is in
the past is marked `EXPIRED`. The action is never re-executed.

### 2.2. Mark expired screen authorizations as `EXPIRED`

Any `APPROVED` screen authorization whose `expires_at` is in
the past is marked `EXPIRED`. The authorization is never
re-activated. The associated screen session is not automatically
stopped; that requires an explicit `STOP` action.

### 2.3. Mark expired Aegis sessions as `EXPIRED`

Any `INITIALIZED`, `CONSENT_GRANTED`, or `CAPTURING` Aegis
session whose `expires_at` is in the past is marked `EXPIRED`.
The session is never re-activated.

---

## 3. What Recovery Does NOT Do

* It does NOT resurrect revoked trust. A `REVOKED` device remains
  `REVOKED`.
* It does NOT re-queue or re-execute any action. Expired actions
  are marked `EXPIRED` and never re-attempted.
* It does NOT re-activate any consent. Expired consent is
  marked `EXPIRED` and never re-granted.
* It does NOT restart any screen session. A stopped screen
  session remains stopped.
* It does NOT modify any audit log entry. Audit logs are
  append-only.
* It does NOT delete any data. It only marks state as
  `EXPIRED`.

---

## 4. Recovery Procedure

### 4.1. Standard recovery

```bash
guardian atlas recover
```

This runs all three recovery operations. The output lists the
number of actions taken for each operation.

### 4.2. Programmatic recovery

```python
from guardianmesh.storage.database import Database
from guardianmesh.atlas.recovery import AtlasRecoveryManager

db = Database("/path/to/guardian.db")
records = AtlasRecoveryManager(db).recover_all()
for record in records:
    print(f"{record.operation}: {record.actions_taken} actions taken")
```

### 4.3. Recovery from a corrupted database

If the database is corrupted (SQLite integrity check fails),
recovery is not sufficient. You must:

1. Restore the database from a backup using
   `guardian atlas restore <backup_id> --apply`.
2. If no backup is available, recreate the database from scratch
   using `guardian init --force`.
3. Re-pair with all trusted devices.
4. Re-create all policies, screen authorizations, and Aegis
   sessions.

The `init --force` operation is destructive. It deletes the
existing database and creates a new one. It does NOT delete
the keys directory.

---

## 5. Recovery Verification

After running recovery, verify the result:

```bash
guardian doctor
guardian diagnostics
```

Both should report zero failures on a healthy install. If
recovery introduced inconsistencies, the doctor will report
the specific check that failed.

---

## 6. Recovery Failure Modes

Recovery itself can fail in three documented ways:

### 6.1. Database unavailable

If the database is unavailable, recovery raises
`AtlasRecoveryError`. Resolve the database issue first
(e.g. restore from backup), then run recovery.

### 6.2. Corrupted table

If a table is corrupted, recovery's query may fail. The
exception is caught and recorded in the recovery record. The
remaining recovery operations still run.

### 6.3. Recovery overflow

If the recovery action count exceeds the documented maximum
(currently unbounded; bounded by the actual number of expired
records), recovery completes successfully but the action count
may be very large. The recovery record's `actions_taken` field
records the actual count.

---

## 7. Recovery and Privacy

Recovery never reveals private user content. The recovery
records are metadata-only. They include:

* `recovery_id` — unique identifier.
* `operation` — the recovery operation name.
* `started_at` — ISO-8601 timestamp.
* `completed_at` — ISO-8601 timestamp (set on success).
* `device_id` — the device the recovery applied to (if any).
* `status` — `PENDING`, `RUNNING`, `SUCCEEDED`, `FAILED`, or
  `CANCELLED`.
* `actions_taken` — the number of actions performed.
* `notes` — free-text notes.

Recovery records are persisted to the `atlas_recovery` table.
They are NOT written to the audit log.

---

## 8. Recovery Limitations

* Recovery cannot recover from a deleted database. Use a
  backup.
* Recovery cannot recover from a corrupted key file. Use a
  backup.
* Recovery cannot recover from a network partition. The
  transport layer is responsible for handling network issues.
* Recovery cannot recover from a faulty Android companion.
  The companion's own recovery procedures are out of scope for
  the Python control plane.
