# GuardianMesh Parent Console & Unified Dashboard (Phase 5)

## 1. Overview & Architectural Principles

The GuardianMesh Console provides a **unified, privacy-bounded management dashboard** for parents to supervise device health, configure surveillance policies, inspect active incidents, and review audit records.

> **STRICT LOCAL & PRIVACY BOUNDARY:**
> The Console operates **entirely locally in unprivileged user space** (Linux and Termux on Android). It displays strictly technical health and security metrics. It is mathematically and architecturally incapable of displaying personal content, messaging, browser history, keystrokes, or location.

```
┌─────────────────────────────────────────────────────────────┐
│                 GUARDIANMESH PARENT CONSOLE                 │
├─────────────────────────────────────────────────────────────┤
│  • Unified Dashboard (Devices, Health, Alerts, Activity)    │
│  • Device Management (List, Detail, Health, Rename, Revoke) │
│  • Sentinel Incident Center (Active, Acknowledge, Resolve)  │
│  • Surveillance Policies (CRUD, Thresholds, Rules)          │
│  • Out-of-Band Pairing Management                           │
│  • Immutable Security Audit Log                             │
│  • Automation-Friendly Machine-Readable JSON Export         │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Unified Dashboard

```bash
guardian console dashboard
```

Output:
```
GuardianMesh
═══════════════════════════════════════
Console v0.5.0 (Console)

DEVICES
───────────────────────────────────────
Trusted       2
Online        1
Degraded      0
Offline       1

HEALTH
───────────────────────────────────────
Battery       82%
Storage       45.0% free
Connectivity  ONLINE

ALERTS
───────────────────────────────────────
Critical      0
Warning       1
Active        1

RECENT ACTIVITY
───────────────────────────────────────
01:54  Device heartbeat received
01:52  Health alert resolved
01:48  Device paired successfully
───────────────────────────────────────
```

### Non-Interactive and JSON Modes
- **Non-Interactive Mode**: `guardian console --non-interactive` or `guardian console dashboard` disables all interactive prompts, suitable for automated scripts and cron jobs.
- **Machine-Readable JSON Mode**: `guardian console dashboard --json` outputs valid JSON without ANSI styling or secrets.

---

## 3. Device Management

The `guardian devices` command suite provides comprehensive device inspection and lifecycle management:

### List All Trusted Devices
```bash
guardian devices list
```

Output:
```
GuardianMesh Devices
ID             LABEL           ROLE   HEALTH   TRUST
────────────────────────────────────────────────────────
GM-C-19A84E72  Kid Galaxy Tab  CHILD  ONLINE   TRUSTED
GM-C-83A1F72C  Kid Phone       CHILD  OFFLINE  TRUSTED
```

### Inspect Single Device Details
```bash
guardian devices show GM-C-19A84E72
```

Output:
```
Device Details
────────────────────────────────
ID:              GM-C-19A84E72
Label:           Kid Galaxy Tab
Role:            CHILD
Trust:           ACTIVE
Fingerprint:     SHA256:YYc/5lJ8WNF5NJEWdUmY6B3jEemuevN+P/zHzdV7w+I

Health Status
────────────────────────────────
State:           ONLINE
Battery:         82% (Charging)
Storage:         26.1 GB free
Uptime:          5h 7m
Connectivity:    ONLINE
Last heartbeat:  14s ago

Active Alerts:
  ! [WARNING] Battery level is low: 14% (threshold: <20%)
```

### Focused Health Telemetry View
```bash
guardian devices health GM-C-19A84E72
```

### Device Renaming & Revocation
```bash
# Rename device
guardian devices rename GM-C-19A84E72 "Kid Smart Tablet"

# Revoke device trust immediately
guardian devices revoke GM-C-19A84E72
```

---

## 4. Console Subcommands & Shortcuts

| Command | Description |
|---|---|
| `guardian console` | Launch interactive menu (in TTY) or print dashboard. |
| `guardian console dashboard [--watch]` | Render dashboard snapshot (or continuously refresh). |
| `guardian console devices [--json]` | Monitored devices summary. |
| `guardian console alerts [--json]` | Active Sentinel alerts view. |
| `guardian console policies [--json]` | Device policies overview. |
| `guardian console pairing [--json]` | Pairing sessions and trusted devices summary. |
| `guardian console audit [--json]` | Recent security and system activity. |
| `guardian console status [--json]` | Subsystem readiness verification. |

---

## 5. Terminal Typography, Narrow Screen & Color Support

1. **Adaptive Width Layout**: The `TerminalFormatter` dynamically adjusts tables and card layouts to fit widths from `40` columns (mobile Termux) up to `120` columns (desktop terminals).
2. **Color & NO_COLOR Support**:
   - ANSI color formatting is enabled by default in TTY environments.
   - Automatically disabled when piped, redirected, or when `NO_COLOR=1` is set.
   - Can be explicitly disabled with `--no-color`.
   - Colors are supplementary: meaning is **never** conveyed solely through color.
3. **Unicode & ASCII Fallbacks**: Supports both clean Unicode line drawing (`─`, `═`, `│`) and ASCII borders (`-`, `=`, `|`).

---

## 6. Security Review & Privacy Assurance

- **Zero Private Keys in JSON**: Dashboard and device JSON exports contain only public identifiers, fingerprints, and technical metrics.
- **Zero Plaintext Secrets**: No OTPs, passwords, or SMTP credentials are rendered.
- **Strict Revocation Enforcement**: Revoked devices are immediately flagged as `REVOKED` and blocked from generating active telemetry or alerts.
