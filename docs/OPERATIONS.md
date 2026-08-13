# GuardianMesh Operations Guide (Atlas v1.0.0)

This document describes the operational aspects of running
GuardianMesh in production.

---

## 1. Installation

```bash
# Clone the repository
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh

# Install with development dependencies
pip install --break-system-packages -e ".[dev]"

# Initialize the local repository
guardian init --role=parent
```

The first run creates the local home directory at
`$GUARDIANMESH_HOME` (default `~/.guardianmesh/`), generates an
Ed25519 keypair, applies all migrations through v10, and creates
the local identity.

---

## 2. Daily Operations

### Status

```bash
guardian status                # Show operational status
guardian doctor                # Run fast diagnostic suite
guardian doctor --full         # Run deep diagnostic suite
guardian diagnostics            # Run Atlas diagnostic suite
```

### Audit

```bash
guardian audit list             # List recent audit events
```

### Pairing

```bash
guardian pair start            # Start a pairing session
guardian pair status            # Show pairing status
guardian pair list              # List trusted devices
guardian pair revoke <id>       # Revoke a trusted device
```

### Transport

```bash
guardian transport status       # Show transport status
guardian transport peers        # List transport peers
guardian transport connect <id> # Connect to a peer
guardian transport disconnect <id>
guardian transport reconnect <id>
```

### Screen

```bash
guardian screen request <id>    # Request a view-only session
guardian screen approve <sid>   # Approve a session
guardian screen deny <sid>      # Deny a session
guardian screen list            # List all sessions
guardian screen status          # Show active sessions
```

### Orchestration

```bash
guardian orchestrate status      # Show Orion status
guardian orchestrate events      # List recent events
guardian orchestrate actions      # List queued actions
guardian orchestrate reconcile <device_id>
```

### Atlas

```bash
guardian atlas status            # Show Atlas subsystem status
guardian atlas backup            # Create a metadata-only backup
guardian atlas restore <id>      # Restore (dry-run by default)
guardian atlas recover           # Run crash recovery
guardian atlas retention         # Apply retention (dry-run by default)
guardian atlas health            # Record a health snapshot
guardian atlas capabilities      # List versioned capabilities
guardian atlas version           # Show release information
```

---

## 3. Backup and Restore

### Create a backup

```bash
guardian atlas backup
```

The backup is written to `${GUARDIANMESH_HOME}/data/atlas_backups/`.
The backup manifest is recorded in the `atlas_backups` table.
The backup is integrity-protected by a SHA-256 digest.

The backup is **metadata only**. It never contains:

* Private keys
* Session keys
* Plaintext screen frames
* Command strings
* Passwords, OTPs, tokens
* Surveillance data

### List backups

```bash
ls ${GUARDIANMESH_HOME}/data/atlas_backups/
```

Or query the database:

```bash
sqlite3 ${GUARDIANMESH_HOME}/data/guardian.db \
    "SELECT backup_id, created_at, status, size_bytes FROM atlas_backups;"
```

### Verify a backup

The `AtlasBackupManager.verify_backup(backup_id)` method verifies
the integrity of a backup against its recorded digest. A backup
with a mismatched digest is reported as invalid.

### Restore a backup

```bash
# Dry-run (default)
guardian atlas restore <backup_id>

# Apply
guardian atlas restore <backup_id> --apply
```

Restore is atomic: it executes within a single SQLite transaction.
Restore refuses to silently overwrite active state.

---

## 4. Crash Recovery

```bash
guardian atlas recover
```

Recovery performs three deterministic operations:

1. Mark expired `PENDING` or `RUNNING` Orion actions as `EXPIRED`.
2. Mark expired `APPROVED` screen authorizations as `EXPIRED`.
3. Mark expired `INITIALIZED`, `CONSENT_GRANTED`, or `CAPTURING`
   Aegis sessions as `EXPIRED`.

Recovery never resurrects revoked trust, expired authorization,
or expired Aegis consent. Recovery is fail-closed.

---

## 5. Retention

```bash
# Dry-run (default)
guardian atlas retention

# Apply
guardian atlas retention --apply
```

Retention policies are documented in
`guardianmesh.atlas.retention.DEFAULT_RETENTION_DAYS`. They bound
the growth of metadata tables. They never collect new categories
of personal data.

---

## 6. Diagnostics and Doctor

```bash
guardian doctor                  # Fast standard suite
guardian doctor --full           # Deep suite
guardian diagnostics              # Atlas-specific suite
```

The doctor reports the status of every documented check. On a
healthy install, all checks pass. The Android provider boundary
is reported as a Notice on Linux/Termux, not a failure.

---

## 7. Release Validation

```bash
guardian release                  # Check release-readiness
```

Release validation does not claim readiness when any mandatory
check fails. The release is `READY` only when:

* Version consistency passes.
* Migration state is at v10.
* Audit event classes are present.
* Android manifest declares only allowed permissions.

---

## 8. Logs and Audit

* Audit log: `${GUARDIANMESH_HOME}/data/guardian.db::audit_events`.
* Application log: `${GUARDIANMESH_HOME}/logs/guardianmesh.log`.
* Backup directory: `${GUARDIANMESH_HOME}/data/atlas_backups/`.

The audit log is sanitized at write time. The redaction rules
strip private keys, session keys, passwords, OTPs, and other
sensitive material.

---

## 9. Troubleshooting

### `guardian doctor` reports failures

1. Read the `Reason:` line for each failed check.
2. Run `guardian doctor --full` for the deep diagnostic suite.
3. Consult `docs/RECOVERY.md` for recovery procedures.
4. If the failure persists, file an issue with the failure
   output.

### `guardian release` reports NOT READY

1. Read the `Reason:` line for each failed check.
2. Run `pytest tests/test_migration_v10.py` to verify the
   migration.
3. Run `pytest tests/test_atlas_release.py` to verify the
   release checks.
4. Consult `docs/UPGRADING.md` for upgrade procedures.

### Backup verification fails

1. Run `guardian atlas backup` to create a new backup.
2. Run `guardian atlas restore <new_id> --dry-run` to verify
   dry-run works.
3. If the verification of an old backup fails, the backup file
   may have been corrupted on disk. The database still contains
   the old manifest row. You can delete the old manifest row
   manually after creating a fresh backup.

---

## 10. Production Checklist

Before declaring a GuardianMesh install production-ready:

* [ ] `guardian doctor --full` reports zero failures.
* [ ] `guardian release` reports `READY`.
* [ ] At least one `guardian atlas backup` has been created.
* [ ] The Android companion has been built and tested on a real
  device (out of scope for the Python control plane).
* [ ] The local home directory has permissions `0700`.
* [ ] The local keys directory has permissions `0700`.
* [ ] The local database has permissions `0600`.
* [ ] The local backups directory has permissions `0700`.
* [ ] `NO_COLOR=1` and `GUARDIANMESH_NO_COLOR=1` are honored
  (verified by automated tests).
