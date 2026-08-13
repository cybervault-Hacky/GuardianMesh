# GuardianMesh Sentinel Alerts Specification (Phase 4)

## 1. Alert Lifecycle & State Machine

Alerts are raised automatically by Sentinel when policy rules trigger on authenticated Pulse health snapshots.

```
       [Rule Triggered]
              │
              ▼
           ACTIVE ◄──────── (Deduplication: updates last_seen_at)
              │
      ┌───────┼───────┐
      │       │       │
      ▼       ▼       ▼
 [Acknowledge][Dismiss][Condition Cleared]
      │       │       │
      ▼       │       ▼
 ACKNOWLEDGED │    RESOLVED
      │       │
      ├───────┘
      │
      ▼
  DISMISSED
```

---

## 2. Alert Model & Fields

- `id`: Unique alert identifier (`ALT-XXXXXXXX`).
- `device_id`: Monitored child device (`GM-C-XXXXXXXX`).
- `policy_id`: Triggering policy (`POL-XXXXXXXX`).
- `rule_type`: Evaluated rule (`LOW_BATTERY`, `OFFLINE`, etc.).
- `severity`: `INFO`, `WARNING`, `CRITICAL`.
- `message`: Human-readable technical notification.
- `status`: `ACTIVE`, `ACKNOWLEDGED`, `RESOLVED`, `DISMISSED`.
- `dedup_key`: Deduplication composite index (`<device_id>:<policy_id>:<rule_type>`).
- `trigger_value`: Value at trigger time (e.g. `14%`, `Offline for 180s`).
- `created_at`: Initial trigger ISO timestamp.
- `last_seen_at`: Timestamp of most recent triggered evaluation.
- `acknowledged_at`: Timestamp of parental acknowledgement.
- `resolved_at`: Timestamp of automatic or manual resolution.
- `dismissed_at`: Timestamp of dismissal.

---

## 3. Deduplication & Auto-Resolution

### A. Deduplication
When consecutive telemetry envelopes continue to trigger the same condition (e.g. device remains offline for 10 minutes), Sentinel does **not** create duplicate alerts. It updates the existing active alert's `last_seen_at` and current trigger value.

### B. Auto-Resolution
When the underlying technical condition clears (e.g. device comes back online or battery charges above threshold), Sentinel automatically transitions the alert status from `ACTIVE` or `ACKNOWLEDGED` to `RESOLVED`, setting `resolved_at` and emitting an `ALERT_RESOLVED` audit event.

---

## 4. Retention Policy & Transactional Cleanup

Historical alerts with status `RESOLVED` or `DISMISSED` are pruned automatically according to `alert_retention_days` (default: 30 days). Active and acknowledged alerts are strictly preserved.

---

## 5. Alert CLI Commands

### View Active Alerts (Sentinel Overview)
```bash
guardian alerts
guardian alerts active
```

Output:
```
GuardianMesh Sentinel
─────────────────────────────
Active Alerts: 1

! GM-C-19A84E72
  Battery level is low: 14% (threshold: <20%)
  Severity: WARNING
  Alert ID: ALT-8F2A1C
  Recorded: 2026-08-12 19:35:00
```

### List Alerts History
```bash
guardian alerts list --today
guardian alerts list --severity critical
```

### Acknowledge Alert
```bash
guardian alerts acknowledge ALT-8F2A1C
```

### Dismiss Alert
```bash
guardian alerts dismiss ALT-8F2A1C
```

### Manually Resolve Alert
```bash
guardian alerts resolve ALT-8F2A1C
```
