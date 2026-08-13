# GuardianMesh Protocol Specification (Phase 6: Nexus)

## 1. Protocol Overview

The GuardianMesh Nexus protocol operates over binary length-prefixed stream frames using canonical JSON serialization and AES-256-GCM AEAD encryption.

---

## 2. Framing Layer

Streaming sockets (TCP and UNIX domain sockets) use a 4-byte big-endian unsigned length prefix:

```
┌───────────────────────────────┬───────────────────────────────────────────┐
│ Length (4 bytes, Big-Endian)  │ Payload (Length bytes)                    │
└───────────────────────────────┴───────────────────────────────────────────┘
```

- **Maximum Frame Size**: Default `65,536` bytes (64 KB).
- Frames exceeding the maximum limit are immediately dropped with `TransportOversizedMessageError`.

---

## 3. Message Envelope Format

### Canonical Plaintext Envelope (`TransportEnvelope`)

```json
{
  "protocol_version": "1.0",
  "message_id": "MSG-A1B2C3D4E5F6",
  "session_id": "SES-112233445566",
  "sender_id": "GM-P-83A1F72C",
  "recipient_id": "GM-C-19A84E72",
  "message_type": "TELEMETRY",
  "sequence": 1,
  "created_at": "2026-08-13T02:00:00+00:00",
  "expires_at": "2026-08-13T02:05:00+00:00",
  "payload": {
    "battery_percent": 85,
    "charging": true,
    "connectivity": "ONLINE"
  },
  "authentication": {
    "signature_hex": "..."
  }
}
```

### Encrypted Wire Frame (`EncryptedTransportFrame`)

```json
{
  "protocol_version": "1.0",
  "session_id": "SES-112233445566",
  "sequence": 1,
  "sender_id": "GM-P-83A1F72C",
  "recipient_id": "GM-C-19A84E72",
  "message_type": "TELEMETRY",
  "nonce_hex": "e75b32b30000000000000001",
  "ciphertext_hex": "3a8f9c2d... (AES-GCM Ciphertext + 16-byte Tag)",
  "created_at": "2026-08-13T02:00:00+00:00",
  "expires_at": "2026-08-13T02:05:00+00:00"
}
```

---

## 4. Authorized Message Types

| Message Type | Direction | Subsystem | Description |
| :--- | :--- | :--- | :--- |
| `HELLO` | Client ↔ Server | Transport | Initial protocol discovery and version negotiation. |
| `SESSION_INIT` | Initiator → Responder | Security | Ephemeral X25519 public key + signed Ed25519 proof. |
| `SESSION_ACK` | Responder → Initiator | Security | Ephemeral X25519 public key + session ID + signed proof. |
| `HEARTBEAT` | Both directions | Transport | Periodic liveness verification. |
| `TELEMETRY` | Child → Parent | Pulse | Device health metrics (battery, storage, uptime, connectivity). |
| `ALERT` | Child → Parent | Sentinel | Technical health condition alerts (e.g. low battery). |
| `POLICY_SYNC` | Parent → Child | Sentinel | Supervision policy distribution. |
| `DEVICE_STATUS` | Both directions | Console | High-level device state updates. |
| `PING` | Both directions | Transport | Latency round-trip probe. |
| `PONG` | Both directions | Transport | Response to `PING`. |
| `REKEY` | Both directions | Security | Session renewal and key ratcheting. |
| `GOODBYE` | Both directions | Transport | Graceful session termination. |
| `ERROR` | Both directions | Core | Protocol error notifications. |

---

## 5. Handshake Flow

```
Initiator (Client)                              Responder (Server)
─────────────────                              ──────────────────
1. Generate X25519 (c_priv, c_pub)
2. Generate client_nonce
3. Sign GM-INIT proof with Ed25519
4. Send SESSION_INIT ─────────────────────────► 5. Verify Ed25519 signature via TrustManager
                                                6. Generate X25519 (s_priv, s_pub)
                                                7. Generate server_nonce & session_id
                                                8. Sign GM-ACK proof with Ed25519
                                                9. Derive keys via HKDF-SHA256
                                          ◄──── 10. Send SESSION_ACK
11. Verify Ed25519 signature via TrustManager
12. Derive keys via HKDF-SHA256
13. Session Established (CONNECTED) ◄═════════► 13. Session Established (CONNECTED)
```
