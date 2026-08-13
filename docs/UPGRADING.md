# GuardianMesh Upgrading Guide (Atlas v1.0.0)

This document describes how to upgrade GuardianMesh from one
version to the next.

---

## 1. Compatibility Policy

GuardianMesh follows [Semantic Versioning](https://semver.org/):

* **Patch** releases (e.g. 1.0.0 → 1.0.1) are bug fixes only. They
  never change the public API, the database schema, or the
  on-disk format.
* **Minor** releases (e.g. 1.0.0 → 1.1.0) add new features. They
  may add database tables or columns. They never break the public
  API.
* **Major** releases (e.g. 1.0.0 → 2.0.0) may break the public
  API. Migration tooling is provided.

GuardianMesh never breaks the database schema in a patch or
minor release. Schema changes are documented in the migration
chain.

---

## 2. Upgrading from v0.9.x to v1.0.0 (Atlas)

The Atlas release adds Migration 10 (`010_atlas`). The migration
creates five new tables:

* `atlas_backups`
* `atlas_health`
* `atlas_recovery`
* `atlas_capability_versions`
* `atlas_retention`

The migration is fully idempotent. Reapplying it is a no-op.

### Step 1: Update the package

```bash
pip install --break-system-packages --upgrade "guardianmesh>=1.0.0"
```

### Step 2: Verify the migration

```bash
guardian doctor
```

If the doctor reports `Atlas migration state: ✓`, the migration
has been applied successfully. If it reports a failure, run:

```bash
python -c "
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
db = Database('/path/to/guardian.db')
MigrationManager().apply_migrations(db)
print('Schema is at version', MigrationManager().get_current_version(db))
"
```

The expected output is:

```
Schema is at version 10
```

### Step 3: Run the new doctor checks

```bash
guardian doctor --full
```

The full suite includes 9 new Atlas-specific checks. All 9 should
pass on a healthy install.

### Step 4: Create a backup

```bash
guardian atlas backup
```

This creates a metadata-only backup of the current state. The
backup is integrity-protected by a SHA-256 digest.

### Step 5: Verify release readiness

```bash
guardian release
```

The release is `READY` when every documented gate passes. If the
release is `NOT READY`, the output lists the failed gates.

### Step 6: Verify CLI

```bash
guardian atlas status
guardian atlas capabilities
guardian atlas version
```

All three commands should return clean output. The `capabilities`
command should list 10 documented subsystems.

### Step 7: Verify observability

```bash
guardian atlas --json status
```

The output should be valid JSON containing per-subsystem metrics.

---

## 3. Upgrading from Earlier Versions

Earlier versions of GuardianMesh used different migration
chains. To upgrade from v0.8.x or earlier:

1. Back up the existing database.
2. Update the package.
3. Run `guardian doctor`. The doctor will report any missing
   migrations.
4. If migrations are pending, run
   `python -c "from guardianmesh.storage.migrations import MigrationManager; from guardianmesh.storage.database import Database; MigrationManager().apply_migrations(Database('/path/to/guardian.db'))"`.
5. Run `guardian doctor --full` to verify the upgrade.

The migration chain is sequential. Migrations are applied in
order: v1, v2, v3, v4, v6, v7, v8, v9, v10. Version 5 is reserved
and unused.

---

## 4. Rolling Back

GuardianMesh does not provide a built-in rollback. The recommended
approach for rolling back is:

1. Stop the GuardianMesh daemon (if any).
2. Restore the database from a pre-upgrade backup using
   `guardian atlas restore <backup_id> --apply`.
3. Downgrade the package to the previous version.
4. Restart the daemon.

`guardian atlas restore` is atomic. The restore executes within
a single SQLite transaction. If the transaction fails, the
database is left in its previous state.

---

## 5. Multi-Node Upgrades

GuardianMesh is a single-node control plane. The parent host
runs the Python control plane; child devices run the Android
companion. The upgrade procedure is:

1. Upgrade the parent host (Python control plane).
2. Run `guardian doctor --full` on the parent host.
3. Run `guardian release` on the parent host.
4. Distribute the new Android companion build to child devices.
5. The companion does not auto-upgrade. The user must install
   the new companion on each child device.

The CI cannot validate the Android companion upgrade. Manual
validation on a real Android device is required.
