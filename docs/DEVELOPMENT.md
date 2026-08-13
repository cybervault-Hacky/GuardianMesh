# GuardianMesh Development Guide

## 1. Prerequisites

- **Python**: Version 3.11, 3.12, or 3.13
- **Git**: For source control
- **Operating System**: Linux or Termux on Android

---

## 2. Environment Setup

### Linux Setup

```bash
# Clone repository
git clone https://github.com/cybervault-Hacky/GuardianMesh.git
cd GuardianMesh

# Editable install with dev dependencies
pip install --break-system-packages -e ".[dev]"
```

### Termux on Android Setup

```bash
pkg update -y
pkg install -y python git libffi clang make
cd GuardianMesh
pip install -e ".[dev]"
```

---

## 3. Running Tests & Coverage

GuardianMesh uses `pytest` with `pytest-cov`:

```bash
# Run complete test suite
pytest

# Run tests with verbose output
pytest -v

# Run Transport tests
pytest tests/test_transport_*.py

# Run Console tests
pytest tests/test_console_cli.py tests/test_devices_cli.py tests/test_console_services.py
```

---

## 4. Linting, Formatting & Type Checking

GuardianMesh enforces strict code quality via `ruff` and `mypy`:

```bash
# Check code style & linter rules
ruff check guardianmesh tests

# Auto-format codebase
ruff format guardianmesh tests

# Run static type checks
mypy guardianmesh
```

---

## 5. Adding Database Migrations

When extending the SQLite schema:
1. Open `guardianmesh/storage/migrations.py`.
2. Add a new `Migration` instance to the `MIGRATIONS` sequence with incremented `version`.
3. Provide clean, idempotent `CREATE` or `ALTER` SQL statements.
4. Add corresponding tests in `tests/test_database.py` or new migration test files.

---

## 6. Security Testing Guidelines

Any PR touching security, identity, pairing, telemetry, policy, console, transport, or screen-view code must:
1. Verify that `ALLOWED_HEALTH_FIELDS` is strictly enforced and personal content keys are rejected.
2. Ensure Sentinel evaluates only explicit technical conditions without behavioral inferences.
3. Ensure no private keys, OTPs, session keys, or passwords leak into JSON exports or terminal outputs.
4. Ensure child authorization is strictly mandatory and challenge nonces cannot be replayed.
5. Ensure monotonic sequence numbers and sliding windows prevent envelope replay.
6. Ensure mutual Ed25519 authentication and X25519 forward secrecy for transport channels.
7. Validate that file permissions remain `0700` for directories and `0600` for keys/databases.
8. Pass 100% of existing tests without regressions.

Any PR touching the Vista screen subsystem (Phase 7) must additionally:
1. Verify that no remote-control message type is ever added to
   `ScreenMessageType` or `transport.models.MessageType`.
2. Verify that the `screen_sessions` and `screen_authorizations`
   schemas contain no payload-bearing columns.
3. Verify that frame payloads are never written to the database, the
   audit log, or any log file.
4. Verify that the visible `SCREEN VIEW ACTIVE` indicator is
   rendered for every ACTIVE session and only for ACTIVE sessions.
5. Verify that trust revocation tears down the active session.
6. Verify that bounded session lifetime, inactivity timeout, and
   transport disconnect all terminate the session.
7. Verify that the `AndroidScreenProvider` is the only entry point
   for screen capture and that it never claims
   `is_real_capture = True` unless an actual native capture is
   wired in.
