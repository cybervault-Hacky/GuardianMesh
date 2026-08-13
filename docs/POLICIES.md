# GuardianMesh Sentinel Policies Specification (Phase 4)

## 1. Overview & Architectural Boundaries

GuardianMesh Sentinel is a **privacy-bounded policy engine** that evaluates technical device health metrics to detect resource exhaustion and connectivity disruptions.

> **STRICT PRIVACY MANDATE:**
> Sentinel operates **only** on allowlisted technical metrics gathered by Pulse. It is strictly prohibited from evaluating, storing, or inferring personal user behavior, messaging, browsing, location, or application usage.

```
┌─────────────────────────────────────────────────────────────┐
│                      ALLOWED RULE TYPES                     │
├──────────────────────┬──────────────────────────────────────┤
│ Rule Type            │ Evaluated Condition                  │
├──────────────────────┼──────────────────────────────────────┤
│ LOW_BATTERY          │ battery_percent < threshold (e.g. 20)│
│ LOW_STORAGE          │ storage_free_percent < threshold (%) │
│ OFFLINE              │ health_state == OFFLINE              │
│ DEGRADED_CONNECTION  │ health_state == DEGRADED             │
│ HEARTBEAT_DELAYED    │ last_seen_seconds > duration         │
│ HEALTH_UNKNOWN       │ health_state == UNKNOWN              │
└──────────────────────┴──────────────────────────────────────┘
```

---

## 2. Policy Model & Schema

Each policy is associated with a verified `device_id` (`GM-C-XXXXXXXX`) and contains a list of `PolicyRule` configurations:

```json
{
  "id": "POL-7A3B1C",
  "device_id": "GM-C-19A84E72",
  "name": "Default Health Policy",
  "enabled": true,
  "rules": [
    {
      "rule_type": "LOW_BATTERY",
      "threshold": 20.0,
      "severity": "WARNING",
      "enabled": true
    },
    {
      "rule_type": "LOW_STORAGE",
      "threshold": 10.0,
      "severity": "WARNING",
      "enabled": true
    },
    {
      "rule_type": "HEARTBEAT_DELAYED",
      "duration_seconds": 60,
      "severity": "WARNING",
      "enabled": true
    },
    {
      "rule_type": "OFFLINE",
      "duration_seconds": 120,
      "severity": "CRITICAL",
      "enabled": true
    },
    {
      "rule_type": "DEGRADED_CONNECTION",
      "severity": "WARNING",
      "enabled": true
    }
  ]
}
```

---

## 3. Policy Evaluation Semantics

1. **Deterministic Evaluation**: Given the same health snapshot and policy configuration, `RuleEvaluator` produces identical results.
2. **Missing Telemetry Handling**: If a technical metric is unavailable (e.g. `battery_percent is None` on a system without a battery), Sentinel does **not** fabricate a violation.
3. **Trust Verification**: If a device's trust is revoked, Sentinel immediately ceases evaluation for that device.

---

## 4. Policy CLI Commands

### List Policies
```bash
guardian policy list
```

### Inspect Policy Rules
```bash
guardian policy show POL-7A3B1C
```

### Enable / Disable Policy
```bash
guardian policy enable POL-7A3B1C
guardian policy disable POL-7A3B1C
```

### Create Custom Policy
```bash
guardian policy create --device GM-C-19A84E72 --name "Tablet Health Policy"
```

### Delete Policy
```bash
guardian policy delete POL-7A3B1C
```
