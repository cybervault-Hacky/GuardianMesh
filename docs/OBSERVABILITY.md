# GuardianMesh Observability Guide (Atlas v1.0.0)

This document describes the observability model for GuardianMesh.

---

## 1. Observability Philosophy

Atlas observability is **bounded** and **metadata-only**. Every
metric is a count or a timestamp. Metrics never include secrets,
frame bytes, or private user content.

Observability is read-only. It never modifies the database or
the audit log. It is safe to run at any frequency.

---

## 2. Subsystem Metrics

The `AtlasObservability` collector gathers metrics for every
documented subsystem:

### 2.1. `genesis` — Core identity

* `identity_count` — number of identities in the database.
* `audit_event_count` — number of audit events in the database.

### 2.2. `link` — Pairing and trust

* `trusted_device_count` — number of trusted devices.
* `trusted_device_by_status` — distribution by status (ACTIVE,
  REVOKED, etc.).

### 2.3. `pulse` — Health telemetry

* `device_health_count` — number of health records.

### 2.4. `sentinel` — Policies and alerts

* `policy_count` — number of policies.
* `alert_count` — number of alerts.
* `alert_by_status` — distribution by status.

### 2.5. `nexus` — Secure transport

* `transport_session_count` — number of transport sessions.
* `transport_session_by_state` — distribution by state.
* `transport_peer_count` — number of transport peers.

### 2.6. `vista` — Screen sessions

* `screen_session_count` — number of screen sessions.
* `screen_authorization_count` — number of screen authorizations.

### 2.7. `aegis` — Android companion

* `aegis_session_count` — number of Aegis sessions.
* `aegis_session_by_state` — distribution by state.

### 2.8. `orion` — Orchestration

* `event_count` — number of Orion events.
* `action_count` — number of Orion actions.
* `action_by_status` — distribution by status.
* `capability_count` — number of capability records.
* `reconciliation_count` — number of reconciliation reports.

### 2.9. `atlas` — Production platform

* `backup_count` — number of backup records.
* `health_count` — number of health snapshots.
* `recovery_count` — number of recovery records.
* `capability_version_count` — number of capability version
  records.
* `retention_count` — number of retention policies.

---

## 3. Programmatic Access

### 3.1. Observability collection

```python
from guardianmesh.storage.database import Database
from guardianmesh.atlas.observability import AtlasObservability

db = Database("/path/to/guardian.db")
metrics = AtlasObservability(db).collect()
```

The `metrics` dict contains the per-subsystem metrics described
above plus a `generated_at` timestamp.

### 3.2. Metrics aggregation

```python
from guardianmesh.storage.database import Database
from guardianmesh.atlas.metrics import AtlasMetrics

db = Database("/path/to/guardian.db")
result = AtlasMetrics(db).collect()
```

The `result` dict contains:

* `health` — per-subsystem health (status, summary,
  remediation).
* `observability` — per-subsystem metrics.
* `summary` — failed and degraded subsystem lists.

### 3.3. Health monitoring

```python
from guardianmesh.storage.database import Database
from guardianmesh.atlas.health import AtlasHealthMonitor

db = Database("/path/to/guardian.db")
monitor = AtlasHealthMonitor(db)
snapshot = monitor.record_health()
```

`record_health()` writes one row per subsystem to the
`atlas_health` table and returns the snapshot. The snapshot
includes the per-subsystem status, summary, and remediation
hint.

### 3.4. Latest health

```python
records = monitor.latest_health(limit=50)
```

Returns the most recent `atlas_health` records, newest first.

---

## 4. CLI Access

### 4.1. Status

```bash
guardian atlas status               # Per-subsystem metrics
guardian atlas --json status        # JSON output
```

### 4.2. Health

```bash
guardian atlas health               # Record a health snapshot
guardian atlas --json health        # JSON output
```

### 4.3. Capabilities

```bash
guardian atlas capabilities         # List versioned capabilities
guardian atlas --json capabilities  # JSON output
```

### 4.4. Version

```bash
guardian atlas version              # Show release information
guardian atlas --json version       # JSON output
```

---

## 5. Output Format

The human-readable output is bounded to the current terminal
width. It uses ASCII characters only. The output respects
`NO_COLOR` and `GUARDIANMESH_NO_COLOR` environment variables.

The JSON output is a single, valid JSON document. It contains no
ANSI codes, no secrets, and no private payloads. It is suitable
for machine parsing.

---

## 6. Privacy Guarantees

The `AtlasObservability` collector:

* Returns only counts, statuses, and timestamps.
* Never includes secrets, frame bytes, or private user content.
* Respects the existing audit redaction rules. The audit log
  is sanitized at write time; observability reads the
  sanitized data.

The `AtlasMetrics` aggregator:

* Returns a summary of failed and degraded subsystems. The
  summary is a list of subsystem names; it does not include
  any payload.
* The full metrics payload is bounded to a small number of
  fields per subsystem. It is safe to log.

---

## 7. Limits

The observability model is bounded:

* Every metric is an integer count or a string status.
* No metric includes a payload, a frame, or a private user
  content.
* The output of `collect()` is bounded by the number of
  documented subsystems (currently 10).
* The output of `latest_health(limit=N)` is bounded by `N`.

The observability model is not a substitute for application
logs. Application logs include the full audit log, which is
sanitized at write time. Observability is for quick checks,
not for forensics.

---

## 8. Integration with External Systems

The JSON output of `guardian atlas --json status` is suitable
for ingestion by external monitoring systems. The schema is
documented above. The output is stable across patch and minor
releases.

A typical integration:

```bash
guardian atlas --json status | \
    jq '.observability.orion.action_by_status.PENDING' | \
    curl -X POST https://monitoring.example.com/metrics
```

This sends the number of pending Orion actions to an external
monitoring system.
