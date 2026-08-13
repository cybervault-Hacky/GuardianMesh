# GuardianMesh Transport Architecture (Phase 6: Nexus)

## 1. Overview

**GuardianMesh Nexus (Phase 6)** establishes the authenticated, end-to-end encrypted transport subsystem connecting parent and child devices.

```
Parent Device (GM-P-XXXXXXXX)                      Child Device (GM-C-XXXXXXXX)
┌───────────────────────────┐                      ┌───────────────────────────┐
│     Console / Policy      │                      │    Collectors / Agent     │
└─────────────┬─────────────┘                      └─────────────▲─────────────┘
              │                                                  │
┌─────────────▼─────────────┐                      ┌─────────────┴─────────────┐
│    TransportClient        │                      │    TransportServer        │
│   (Memory/LocalSocket)    │                      │   (Memory/LocalSocket)    │
└─────────────┬─────────────┘                      └─────────────▲─────────────┘
              │                                                  │
              │         SESSION_INIT (Ed25519 Signed)            │
              ├─────────────────────────────────────────────────►│
              │                                                  │
              │         SESSION_ACK  (Ed25519 Signed)            │
              │◄─────────────────────────────────────────────────┤
              │                                                  │
              │  ═══ AES-256-GCM Ephemeral Encrypted Channel ═══  │
              │◄────────────────────────────────────────────────►│
```

---

## 2. Secure Channel Architecture

Nexus provides a forward-secret, mutually authenticated communication channel:

1. **Mutual Device Authentication**:
   - Uses long-term Ed25519 device identities (`GM-P-XXXXXXXX` and `GM-C-XXXXXXXX`).
   - Handshake initiation (`SESSION_INIT`) and acknowledgement (`SESSION_ACK`) are cryptographically signed using Ed25519 private keys.
   - Public keys are verified strictly against the existing Phase 2 `TrustManager` registry (`trusted_devices`).

2. **Ephemeral Key Agreement (X25519)**:
   - Each connection generates ephemeral X25519 keypairs.
   - Diffie-Hellman exchange produces an ephemeral shared secret.
   - Private ephemeral keys are held strictly in memory and wiped immediately on session termination.

3. **Key Derivation (HKDF-SHA256)**:
   - Derives two distinct 32-byte symmetric keys: `client_to_server_key` and `server_to_client_key`.
   - Incorporates combined CSPRNG challenge nonces (`client_nonce` + `server_nonce`) as salt.
   - Contextual info parameter: `GuardianMesh-Nexus-v0.6-AES-GCM-256`.

4. **Authenticated Encryption (AES-256-GCM)**:
   - All message payloads are encrypted with AES-256-GCM.
   - Nonce construction: Deterministic 12-byte nonce combining 4-byte session salt prefix + 8-byte uint64 sequence number.
   - Associated Data (AD): Canonical JSON header (protocol version, session ID, sequence, sender ID, recipient ID, message type, created_at, expires_at). Any wire tampering with header fields triggers immediate authentication failure (`InvalidTag` / `TransportAuthenticationError`).

5. **Replay & Sequence Defense**:
   - Monotonically increasing per-session sequence numbers.
   - Sliding window buffer (default 128 sequences) preventing sequence replay, duplicate injection, and sequence rollback.
   - Expiration validation against UTC ISO-8601 timestamps.

---

## 3. Transport Implementations

| Implementation | Type | Scope | Description |
| :--- | :--- | :--- | :--- |
| `MemoryTransportClient` / `Server` | In-Memory | Local / Testing | Zero-copy thread-safe queue transport for component tests and integration harnesses. |
| `LocalSocketTransportClient` / `Server` | Socket / IPC | Linux / Termux | Local UNIX domain socket (`0600` permissions) or localhost TCP for inter-process communication. |
| `FutureNetworkTransport` | Interface | Production Boundary | Clean interface specification for future production encrypted relay transport. |
| `RelayTransport` | Interface | Zero-Knowledge Relay | Interface enforcing end-to-end encrypted packet forwarding without plaintext visibility. |

---

## 4. Relay Boundary & Confidentiality

GuardianMesh defines a strict zero-knowledge boundary for future network relays:
- **Zero Plaintext Payload Visibility**: The relay operates exclusively on `EncryptedTransportFrame` wire packets.
- **Relay Observable Metadata**: A network relay may observe packet size, timing, and device endpoint metadata. It cannot observe payload contents or decrypt telemetry metrics.
- **No Anonymity Network**: GuardianMesh transport does not claim anonymity or onion routing.

---

## 5. Explicit Safety Boundaries

> **MANDATORY SAFETY BOUNDARY:**
> Phase 6 (Nexus) implements secure transport infrastructure **ONLY**.
> - It does **NOT** implement screen viewing, screen mirroring, or screen capture.
> - It does **NOT** allow arbitrary command execution or remote shell access.
> - All messages are restricted to the strict `MessageType` allowlist.
