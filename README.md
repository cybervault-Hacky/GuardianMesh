# GuardianMesh

[![Phase](https://img.shields.io/badge/Phase-6%20Nexus-blue.svg)](docs/ROADMAP.md)
[![Version](https://img.shields.io/badge/Version-0.6.0-green.svg)](pyproject.toml)
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux-orange.svg)](#supported-platforms)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**GuardianMesh** is a developer-grade, consent-based parental device supervision system designed to run on Termux (Android) and Linux.

---

## Safety & Architectural Boundary

> **IMPORTANT ARCHITECTURAL MANDATE:**
> GuardianMesh is built on the principle of **explicit mutual consent**. It must **never** implement covert or silent monitoring.

### Prohibited Surveillance Features
GuardianMesh will **never** include:
- Hidden screen capture or silent background monitoring
- Keyloggers or keystroke interception
- Microphone or camera capture
- Message interception (SMS/chat/email reading)
- Browser history or bookmark harvesting
- Clipboard data collection
- Password or credential scraping
- Remote control / remote input injection
- Bypassing Android OS permissions or child consent

---

## Phase 6: Nexus (v0.6.0)

Phase 6 introduces **secure transport, authenticated channels, and multi-device synchronization**:
- **End-to-End Encrypted Transport**: Ephemeral X25519 Diffie-Hellman key exchange, HKDF-SHA256 key derivation, and AES-256-GCM AEAD encryption.
- **Mutual Ed25519 Authentication**: Integrated with the Phase 2 cryptographic trust registry (`trusted_devices`).
- **Replay Protection & Sequence Monotonicity**: Per-session sequence numbering with bounded sliding-window replay caching.
- **Liveness Monitoring & Heartbeats**: Background periodic heartbeats, latency probes (Ping/Pong), and timeout derivation.
- **Bounded Reconnection Management**: Exponential retry backoffs with jitter and retry count bounds.
- **Dedicated CLI Commands (`guardian transport`)**: Manage peers, sessions, connections, and status with machine-readable `--json` support.
- **Zero-Knowledge Relay Boundary**: Secure relay abstraction enforcing payload confidentiality without plaintext exposure.

---

## Supported Platforms

- **Termux on Android** (ARM64, ARMv7, x86_64)
- **Linux** (Debian, Ubuntu, Arch, Fedora, Alpine)
- **Python 3.11+ / Python 3.12+**

---

## Installation

### Standard Linux / Development Installation

```bash
# Clone the repository
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh

# Install package and dependencies in user space
pip install --break-system-packages -e ".[dev]"
```

### Termux on Android Installation

```bash
# Update Termux packages
pkg update -y
pkg install -y python git libffi

# Clone and install
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh
pip install -e .
```

---

## CLI Usage & Commands

```bash
guardian --help
```

### 1. View Unified Parent Dashboard (`guardian console`)
```bash
guardian console dashboard
```

Output:
```
GuardianMesh
═══════════════════════════════════════
Console v0.6.0 (Nexus)

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

### 2. Device Management (`guardian devices`)
```bash
# List all trusted child devices
guardian devices list

# Show full device details (identity, trust, telemetry, alerts, policy, transport)
guardian devices show GM-C-19A84E72

# Inspect focused technical health metrics
guardian devices health GM-C-19A84E72

# Rename device
guardian devices rename GM-C-19A84E72 "Kid Smart Tablet"

# Revoke trust
guardian devices revoke GM-C-19A84E72
```

### 3. Secure Transport & Multi-Device Sync (`guardian transport`)
```bash
# Check transport subsystem status
guardian transport status

# List transport peers and connection states
guardian transport peers

# Connect to a trusted device
guardian transport connect GM-C-19A84E72

# Reconnect using exponential backoff
guardian transport reconnect GM-C-19A84E72

# Terminate transport channel
guardian transport disconnect GM-C-19A84E72
```

### 4. Sentinel Health Alerts (`guardian alerts`)
```bash
# View active alerts
guardian alerts active

# Acknowledge alert
guardian alerts acknowledge ALT-8F2A1C

# Dismiss alert
guardian alerts dismiss ALT-8F2A1C
```

### 5. Surveillance Policies (`guardian policy`)
```bash
# List policies
guardian policy list

# Inspect policy rules
guardian policy show POL-7A3B1C
```

### 6. Pair with a Child Device (`guardian pair`)
```bash
guardian pair --method demo
```

---

## Roadmap

GuardianMesh is structured across 10 progressive phases:

1. **Phase 1: Genesis (v0.1.0)** — Secure local foundation, identities, key storage, SQLite database, CLI diagnostics. *(Complete)*
2. **Phase 2: Link (v0.2.0)** — Reciprocal pairing protocol, DeliveryProvider abstraction, OTP verification, mandatory child authorization, trust management. *(Complete)*
3. **Phase 3: Pulse (v0.3.0)** — Privacy-bounded device health telemetry, allowlisted metrics, monotonic sequence tracking, health state evaluation. *(Complete)*
4. **Phase 4: Sentinel (v0.4.0)** — Privacy-bounded policy engine, deterministic rule evaluation, alert deduplication, auto-resolution. *(Complete)*
5. **Phase 5: Console (v0.5.0)** — Unified parent console, device management suite, adaptive terminal typography, JSON export. *(Complete)*
6. **Phase 6: Nexus (v0.6.0)** — End-to-end encrypted transport, mutual Ed25519 authentication, X25519 Diffie-Hellman key exchange, AES-256-GCM framing, heartbeat monitoring. *(Current)*
7. **Phase 7: View-Only Screen Sharing (v0.7.0)** — View-only screen sharing with explicit child authorization, persistent active indicator, and no remote control.
8. **Phase 8: Dashboard & Reporting (v0.8.0)** — Consolidated parental reporting.
9. **Phase 9: Security Hardening (v0.9.0)** — Formal cryptographic audit and penetration hardening.
10. **Phase 10: Production Release (v1.0.0)** — Production-grade multi-platform release.

---

## Documentation

- [Nexus Transport Guide](docs/NEXUS.md)
- [Transport Architecture](docs/TRANSPORT.md)
- [Protocol Specification](docs/PROTOCOL.md)
- [Console & Dashboard Guide](docs/CONSOLE.md)
- [Policies Specification Guide](docs/POLICIES.md)
- [Alerts Lifecycle Guide](docs/ALERTS.md)
- [Telemetry Specification Guide](docs/TELEMETRY.md)
- [Pairing & Trust Protocol Guide](docs/PAIRING.md)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Security Model & Boundaries](docs/SECURITY.md)
- [10-Phase Roadmap](docs/ROADMAP.md)
- [Development & Testing Guide](docs/DEVELOPMENT.md)

---

## Testing & Quality

Run the complete test suite:

```bash
pytest
```

Run linter and type checks:

```bash
ruff check guardianmesh tests
mypy guardianmesh
```

---

## License

GuardianMesh is licensed under the [MIT License](LICENSE).
