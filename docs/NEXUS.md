# GuardianMesh Nexus (Phase 6) — Developer Guide & CLI Reference

## 1. Introduction

**Nexus** (Phase 6) transforms GuardianMesh into a synchronized, authenticated parent ↔ child device system. It manages encrypted channels, session persistence, heartbeat monitoring, and automated reconnection backoffs.

---

## 2. CLI Commands Reference

### Transport Status (`guardian transport status`)
Inspect the operational state of the transport subsystem:

```bash
guardian transport status
```

Output:
```
GuardianMesh Transport Status
────────────────────────────────
Subsystem:        READY
Listen Endpoint:  0.0.0.0:8443
Active Sessions:  1
Connected Peers:  1 / 1
Default Mode:     LOCAL
```

Machine-readable JSON export:
```bash
guardian transport status --json
```

```json
{
  "status": "READY",
  "transport_enabled": true,
  "listen_host": "0.0.0.0",
  "listen_port": 8443,
  "active_sessions": 1,
  "total_peers": 1,
  "connected_peers": 1,
  "mode": "LOCAL",
  "active_identity": "GM-P-83A1F72C"
}
```

---

### Registered Transport Peers (`guardian transport peers`)
List all paired devices and their current channel states:

```bash
guardian transport peers
```

JSON output:
```bash
guardian transport peers --json
```

---

### Transport Sessions (`guardian transport sessions`)
List active and historical encrypted transport sessions:

```bash
guardian transport sessions
guardian transport sessions --device GM-C-19A84E72 --json
```

---

### Connect to Device (`guardian transport connect`)
Initiate mutual cryptographic handshake and establish an active session:

```bash
guardian transport connect GM-C-19A84E72
```

---

### Disconnect Device (`guardian transport disconnect`)
Terminate active transport session:

```bash
guardian transport disconnect GM-C-19A84E72
```

---

### Reconnect Device (`guardian transport reconnect`)
Reconnect using bounded exponential backoff:

```bash
guardian transport reconnect GM-C-19A84E72
```

---

## 3. Diagnostics via `guardian doctor`

`guardian doctor` now verifies all Nexus components:
- `[✓] Transport module`
- `[✓] Cryptographic backend`
- `[✓] Trust registry`
- `[✓] Session database`
- `[✓] Replay protection`
- `[✓] Local transport`
- `[✓] Message router`
