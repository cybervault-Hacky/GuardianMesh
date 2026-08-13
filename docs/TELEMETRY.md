# GuardianMesh Privacy-Bounded Device Health Telemetry (Phase 3: Pulse)

## 1. Overview & Privacy Principle

GuardianMesh Pulse provides **privacy-bounded device health telemetry**. Its purpose is to answer a single fundamental operational question:

> **"Is the paired child device healthy and online?"**

### Strict Privacy Guarantee
Pulse collects **strictly technical resource metrics**. It is mathematically and architecturally incapable of collecting personal content, browsing history, or surveillance feeds.

```
┌──────────────────────────────────────────────┐
│        ALLOWED TECHNICAL HEALTH FIELDS       │
├──────────────────────────────────────────────┤
│  • battery_percent    (0–100 integer)        │
│  • charging           (boolean)              │
│  • storage_total_bytes (aggregate int)       │
│  • storage_free_bytes  (aggregate int)       │
│  • uptime_seconds     (monotonic int)        │
│  • connectivity       (ONLINE/DEGRADED/...)  │
│  • platform           (OS descriptor)        │
│  • agent_version      (software version)     │
└──────────────────────────────────────────────┘

                       VS

┌──────────────────────────────────────────────┐
│        STRICTLY PROHIBITED FIELDS            │
├──────────────────────────────────────────────┤
│  ✗ Screen capture / Screen mirroring         │
│  ✗ Keystrokes / Keyboard input / Passwords   │
│  ✗ Messages / SMS / Chat text                │
│  ✗ Contacts / Call contents                  │
│  ✗ Files / Photos / Videos / Directories     │
│  ✗ Browser history / Visited URLs / DNS      │
│  ✗ Clipboard contents                        │
│  ✗ Microphone audio / Camera video           │
│  ✗ GPS / Geolocation tracking                │
│  ✗ App usage statistics / App names          │
│  ✗ Notification body contents                │
└──────────────────────────────────────────────┘
```

---

## 2. Telemetry Architecture

```
  Child Device (Emitter)                        Parent Device (Receiver)
  ──────────────────────                        ────────────────────────
         │                                                 │
  [Device Collectors]                                      │
  (Battery, Storage, Uptime, Conn)                         │
         │                                                 │
         ▼                                                 │
  [HealthSnapshot]                                         │
  (Validated against allowlist)                            │
         │                                                 │
         ▼                                                 │
  [Monotonic Sequence + Timestamp]                         │
         │                                                 │
         ▼                                                 │
  [TelemetryEnvelope]                                      │
  (Canonical JSON + Ed25519 Signature)                     │
         │                                                 │
         ▼                                                 │
   [Transport] ───────────────────────────────────────────►│
   (Local / Test / Relay Pipe)                             ▼
                                                [TelemetryProcessor]
                                                ├── 1. Check Allowlist
                                                ├── 2. Verify Trust (Phase 2)
                                                ├── 3. Verify Ed25519 Signature
                                                ├── 4. Validate Monotonic Sequence
                                                ├── 5. Check Timestamp / Clock Skew
                                                └── 6. Check Paused Status
                                                           │
                                                           ▼
                                                [Derive Health State]
                                                (ONLINE / DEGRADED / OFFLINE)
                                                           │
                                                           ▼
                                                [Persist Health & History]
                                                (device_health, telemetry_events)
```

---

## 3. Telemetry Envelope & Canonical Signing

Every telemetry packet is transmitted inside a signed `TelemetryEnvelope`:

```json
{
  "protocol_version": "1.0",
  "device_id": "GM-C-19A84E72",
  "sequence": 42,
  "captured_at": "2026-08-12T19:30:00+00:00",
  "payload": {
    "battery_percent": 82,
    "charging": true,
    "storage_total_bytes": 64000000000,
    "storage_free_bytes": 28000000000,
    "uptime_seconds": 18420,
    "connectivity": "ONLINE",
    "platform": "Linux",
    "agent_version": "0.3.0"
  },
  "signature": "3a8f1b2c..."
}
```

### Deterministic Canonical Serialization
To guarantee reproducible signature verification across diverse platforms and architectures, the envelope computes canonical bytes using strict lexicographical key sorting and compact JSON delimiters (`separators=(',', ':')`):
```python
canonical_struct = {
    "captured_at": self.captured_at,
    "device_id": self.device_id,
    "payload": self.payload,
    "protocol_version": self.protocol_version,
    "sequence": self.sequence,
}
json.dumps(canonical_struct, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

---

## 4. Authentication & Replay Protection

### A. Trust Integration
Telemetry envelopes are authenticated against the Phase 2 `TrustManager`. Envelopes from unknown or revoked device IDs are rejected immediately with `TelemetryAuthenticationError`.

### B. Monotonic Sequence Verification
Each emitting device maintains an atomically incremented outgoing sequence number (`1, 2, 3, ...`). The receiver tracks the highest accepted sequence number in `device_sequences`.
- Any envelope where `sequence <= last_accepted_sequence` is rejected with `TelemetryReplayError`.

### C. Timestamp & Clock Skew Validation
- Envelopes with timestamps exceeding future clock skew tolerance (`120s` default) are rejected with `TelemetryTimestampError`.
- Historical envelopes older than the retention window (`7 days` default) are rejected.

---

## 5. Health State Derivation

Device health states are evaluated deterministically:

| Health State | Condition |
|---|---|
| **`ONLINE`** | Heartbeat received within degraded threshold (default: ≤ 60s). |
| **`DEGRADED`** | Heartbeat delayed between degraded threshold and offline threshold (60s – 120s). |
| **`OFFLINE`** | Heartbeat older than offline threshold (> 120s) or connectivity explicitly `OFFLINE`. |
| **`UNKNOWN`** | No telemetry recorded yet or corrupted timestamp. |

---

## 6. Retention Policy & Transactional Cleanup

Historical health snapshots in `telemetry_events` are purged automatically according to `telemetry_retention_days` (default: 7 days).
Cleanup is transactional and emits a `TELEMETRY_CLEANUP` audit record.

```bash
# Programmatic cleanup
processor.cleanup_retention(retention_days=7)
```

---

## 7. Transport Abstractions

| Transport | Purpose | Security Context |
|---|---|---|
| **`LocalTransport`** | Inter-thread queue for local testing. | Local sandbox only. |
| **`TestTransport`** | Mock transport for deterministic test harnesses. | Unit/Integration testing. |
| **`FutureNetworkTransport`** | Interface contract for Phase 6 end-to-end encrypted relay. | Scheduled for Phase 6. |

---

## 8. CLI Usage

### View Telemetry Overview
```bash
guardian telemetry
```

### Inspect Device Health Status
```bash
guardian telemetry status GM-C-19A84E72
```

Output:
```
GuardianMesh Pulse
─────────────────────────
Device:          GM-C-19A84E72
Health:          ONLINE
Battery:         82% / Charging
Storage:         26.1 GB free
Uptime:          5h 7m
Connectivity:    ONLINE
Last heartbeat:  14 seconds ago
```

### Inspect Telemetry History
```bash
guardian telemetry history GM-C-19A84E72 --today
```

### Trigger On-Demand Refresh
```bash
guardian telemetry refresh GM-C-19A84E72
```

### Pause / Resume Telemetry
```bash
guardian telemetry pause GM-C-19A84E72
guardian telemetry resume GM-C-19A84E72
```
