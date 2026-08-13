# GuardianMesh Release Process (Atlas v1.0.0)

This document describes the GuardianMesh release process. Atlas
introduces a release-readiness gate that does not claim readiness
when any mandatory check fails.

---

## 1. Release Gates

A GuardianMesh release is **READY** only when every documented
gate passes:

* **Version consistency** — the stored `config_entries.version`
  matches the runtime `__version__`.
* **Migration state** — the database is at the documented schema
  version (currently v10).
* **Audit event classes** — every documented `ORION_*` and
  `ATLAS_*` audit event type exists in
  `guardianmesh.storage.audit.AuditEventType`.
* **Ruff** — `ruff check .` reports zero errors.
* **Mypy** — `mypy guardianmesh` reports zero issues.
* **Pytest** — `pytest` reports 100% pass.
* **Coverage** — every new module reports >= 90% coverage.
* **Migration tests** — `pytest tests/test_migration_v*.py`
  reports 100% pass.
* **Security tests** — `pytest tests/test_*_security.py` reports
  100% pass.
* **Privacy tests** — `pytest tests/test_*_privacy.py` reports
  100% pass.
* **Android manifest** — only the documented minimum permissions
  are declared.
* **No secrets in repository** — `grep -rE "private_key_pem|...`
  reports no real secrets.
* **No forbidden surveillance APIs** — the documented
  surveillance-style event types, action types, and capabilities
  are rejected at construction time.

---

## 2. Release Validation

The `AtlasReleaseValidator` performs the following checks:

* `release_version` — stored version matches runtime version.
* `release_migration` — schema is at v10.
* `release_audit_classes` — every documented ORION_* audit event
  type exists.
* `release_aegis_manifest` — Android manifest declares only
  allowed permissions.

`guardian release` runs these checks. It does not claim readiness
when any check fails.

---

## 3. CI Pipeline

The CI pipeline runs, in order:

1. `ruff check .`
2. `mypy guardianmesh`
3. `pytest tests/test_migration_v*.py`
4. `pytest tests/test_*_security.py`
5. `pytest tests/test_*_privacy.py`
6. `pytest --cov=guardianmesh --cov-report=term-missing`
7. `pytest tests/test_atlas_release.py::test_check_aegis_manifest_clean`
8. `pytest tests/test_atlas_cli.py`

The CI does NOT include:

* `pytest tests/test_orion_cli.py` — the CLI tests run on a
  fresh temp home; they are part of the local test suite.
* `pytest tests/test_screen_cli.py` — same as above.
* Android physical-device validation — this requires a real
  Android device, which is not available in the CI sandbox.

---

## 4. Android Release Preparation

The Android companion is documented architecture. It cannot be
built or executed in the CI sandbox. The release process for the
Android companion is:

* `cd android/aegis/`
* `./gradlew assembleDebug` (development)
* `./gradlew test` (JVM unit tests)
* `./gradlew assembleRelease` (production, requires signing
  configuration)
* `./gradlew bundleRelease` (Android App Bundle, requires signing
  configuration)

The CI does not sign the companion or upload it to the Play
Store. Those steps are out of scope for GuardianMesh.

---

## 5. Versioning Policy

* `__version__` follows [Semantic Versioning](https://semver.org/).
* `__phase__` is the documented phase name.
* `MigrationManager.version` is the database schema version.
* `AtlasCapabilityVersion.version` is the capability descriptor
  version.

A release increments:

* `__version__` — major, minor, or patch.
* `__phase__` — when the phase name changes.
* `MigrationManager.version` — when the database schema changes.
* `AtlasCapabilityVersion.version` — when a capability descriptor
  changes.

---

## 6. Commit Message Policy

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/)
format:

```
<type>(<scope>): <subject>
```

Where `<type>` is one of:

* `feat` — a new feature.
* `fix` — a bug fix.
* `docs` — documentation only.
* `style` — formatting only.
* `refactor` — code change that neither fixes a bug nor adds a
  feature.
* `test` — adding or correcting tests.
* `chore` — build or auxiliary tool changes.

Example:

```
feat: implement GuardianMesh Atlas production platform
```

---

## 7. Branching Policy

* `main` — the stable branch. Every commit on `main` is a
  release.
* `arena/<session-id>-<phase>` — a development branch for a single
  session. The session ID is documented in the branch name.

Pull requests target `main`. The CI must pass before a PR can be
merged.

---

## 8. Android Release Checklist

Before declaring the Android companion ready for production:

* [ ] Manifest declares only allowed permissions.
* [ ] No keystores, signing passwords, or API keys in the
  repository.
* [ ] `compileSdk` and `targetSdk` are current.
* [ ] `minSdk` is documented.
* [ ] JVM unit tests pass.
* [ ] Foreground service notification text is current.
* [ ] Visible `STOP SHARING` action works without network.
* [ ] `MediaProjection` consent dialog is honored.
* [ ] No background capture.

The CI cannot validate the above against a real Android device.
Manual validation is required for production release.
