# GuardianMesh Secure Pairing & Trust Protocol (Phase 2: Link)

## 1. Overview & Security Philosophy

GuardianMesh's pairing protocol establishes an authenticated, cryptographic trust relationship between a Parent device (`GM-P-XXXXXXXX`) and a Child device (`GM-C-XXXXXXXX`).

> **CRITICAL SECURITY BOUNDARY:**
> Successful OTP verification **never** automatically grants supervisory authority. **Explicit child authorization on the child device is strictly mandatory.** If the child denies authorization, no trust relationship can be established.

```
                    PAIRING PROTOCOL FLOW

  Parent Device                                 Child Device
  ─────────────                                 ────────────
        │                                             │
        │ 1. Initiate Pairing Session                 │
        │    (Email / SMS / Demo)                     │
        ▼                                             │
  [OTP Generated & Dispatched]                        │
        │                                             │
        │ 2. Submit OTP Verification                  │
        ▼                                             │
  [OTP Verified & Single-Use Invalidation]            │
        │                                             │
        │ 3. Request Child Authorization              │
        │    (Sends Fresh Challenge Nonce)            │
        ├────────────────────────────────────────────►│
        │                                             │ 4. Child Approves / Denies
        │                                             │    (Signs Nonce with Ed25519)
        │ 5. Transmit Signed Decision                 │
        │◄────────────────────────────────────────────┤
        │                                             │
  [Verify Ed25519 Signature & Fresh Nonce]            │
        │                                             │
   ┌────┴───────────────────────────┐                 │
   │                                │                 │
[APPROVE]                        [DENY]               │
   │                                │                 │
   ▼                                ▼                 │
[Trust Established]         [Session Terminated]      │
[Device Status: ACTIVE]     [Status: DENIED]          │
```

---

## 2. Pairing State Machine

All pairing sessions strictly adhere to a deterministic state machine that prevents out-of-order or unauthorized transitions:

```
               CREATED
                  │
                  ▼
         VERIFICATION_PENDING
                  │
                  ▼
               VERIFIED
                  │
                  ▼
     CHILD_AUTHORIZATION_PENDING
                  │
         ┌────────┴────────┐
         │                 │
      [DENIED]        [AUTHORIZED]
         │                 │
         ▼                 ▼
      DENIED       TRUST_ESTABLISHED
                           │
                           ▼
                         PAIRED
                           │
                           ▼
                        REVOKED
```

### State Definitions
- `CREATED`: Session registered, awaiting initial OTP dispatch.
- `VERIFICATION_PENDING`: OTP dispatched out-of-band; awaiting parent entry.
- `VERIFIED`: OTP correctly verified; verifier hash invalidated (single-use).
- `CHILD_AUTHORIZATION_PENDING`: Fresh challenge nonce generated; awaiting explicit child authorization.
- `AUTHORIZED`: Child device cryptographically signed and approved pairing.
- `TRUST_ESTABLISHED`: Remote public key and fingerprint registered in local trusted devices table.
- `PAIRED`: Pairing session completed successfully.
- `DENIED`: Child device rejected pairing request. (Terminal state)
- `EXPIRED`: Session or OTP lifetime expired. (Terminal state)
- `CANCELLED`: Session manually cancelled by parent. (Terminal state)
- `REVOKED`: Established trust revoked. (Terminal state)

---

## 3. Verification Providers

GuardianMesh supports three verification delivery conduits:

### A. Email OTP (Preferred Development Method)
- Uses standard SMTP over TLS/STARTTLS.
- Configurable via `config.json` (`smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `smtp_use_tls`, `smtp_from_address`) or environment variables (`GUARDIANMESH_SMTP_*`).
- If unconfigured, reports `○ CONFIGURE SMTP` and rejects dispatch with a clean error.
- Recipient email address is validated against standard format rules.

### B. SMS OTP (Optional)
- Architected as an optional abstraction for future SMS gateways.
- Marked as optional and unconfigured by default.

### C. Demo Mode (Development / Testing)
- Explicitly gated: requires `--method demo` or selection in interactive wizard.
- Generates genuine cryptographic OTPs, enforces all attempt limits, single-use invalidation, cooldowns, and child authorization rules.

---

## 4. OTP Security Lifecycle

1. **CSPRNG Generation**: 6-digit numeric codes generated via `secrets.randbelow(1_000_000)`.
2. **Zero Plaintext Storage**: Plaintext OTPs are **never** stored in the database. Only a salted SHA-256 verifier hash (`SHA256(salt:session_id:code)`) is persisted.
3. **Zero Plaintext Logging**: OTPs are scrubbed automatically by `RedactingFormatter` and never written to logs or audit tables.
4. **Single-Use Invalidation**: Once verified or upon attempt exhaustion, the verifier hash is cleared immediately from database storage.
5. **Attempt Limiting**: Maximum 5 attempts per session (configurable). Exceeding max attempts immediately invalidates the session (`EXPIRED`).
6. **Resend Cooldown**: 30-second cooldown between resend requests prevents flooding and abuse.
7. **Short Expiration**: 5-minute OTP lifetime and 10-minute session lifetime.

---

## 5. Mandatory Child Authorization Boundary

Parent OTP verification **only** verifies parental possession of the out-of-band communication channel. It **does not** authorize pairing.

### Challenge-Response Nonce Specification
1. When entering `CHILD_AUTHORIZATION_PENDING`, the parent generates a 256-bit cryptographically secure random challenge nonce.
2. The nonce is registered in `pairing_nonces` with a 5-minute expiration timestamp.
3. The child device signs the deterministic payload:
   ```
   GM-AUTH-V1:<session_id>:<parent_id>:<child_id>:<nonce>:<decision>
   ```
   using its Ed25519 private key.
4. The parent verifies the signature using the child's public key.
5. **Replay Protection**: The nonce is marked as `used = 1` atomically. Any attempt to reuse or replay a previously consumed nonce is rejected with `ReplayedNonceError`.

---

## 6. Trust Establishment & Revocation

### Trust Record (`trusted_devices`)
Upon successful authorization, a cryptographic trust record is created:
- `local_identity_id`: Local identity (`GM-P-XXXXXXXX`).
- `remote_identity_id`: Remote identity (`GM-C-XXXXXXXX`).
- `remote_role`: Remote role (`CHILD`).
- `remote_public_key_fingerprint`: SHA-256 fingerprint (`SHA256:...`).
- `remote_public_key_pem`: Ed25519 public key in standard SPKI PEM format.
- `status`: `ACTIVE`.
- `trust_version`: Integer version tracking.

### Revocation (`guardian pair revoke <device_id>`)
- Immediately changes device status to `REVOKED`.
- Automatically invalidates any pending or active pairing sessions associated with the device.
- Rejects future authentication attempts with `TrustRevokedError`.
- Records a `TRUST_REVOKED` audit event.

---

## 7. Privacy Guarantees

- **Decoupled Identity**: Email addresses and phone numbers are verification conduits only. They **never** become the device identity.
- **Auditing**: Audit events (`PAIRING_CREATED`, `OTP_VERIFIED`, `CHILD_APPROVED`, `TRUST_ESTABLISHED`, `TRUST_REVOKED`) record operational timestamps without logging sensitive data.
