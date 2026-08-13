"""Tests for SQLite database wrapper, pragmas, migrations, integrity, and idempotency."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_database_connection_and_pragmas(tmp_path: Path) -> None:
    """Test database connection, foreign keys, and WAL pragmas."""
    db_path = tmp_path / "test.db"
    db = Database(db_path)

    with db.connect() as conn:
        fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        assert fk == 1

        busy = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        assert busy == 5000


def test_database_crud_and_transactions(tmp_path: Path) -> None:
    """Test execute, fetchone, fetchall, and transaction rollbacks."""
    db_path = tmp_path / "test.db"
    db = Database(db_path)

    db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")
    db.execute("INSERT INTO items (name) VALUES (?);", ("item1",))
    db.executemany("INSERT INTO items (name) VALUES (?);", [("item2",), ("item3",)])

    row = db.fetchone("SELECT name FROM items WHERE id = ?;", (1,))
    assert row is not None
    assert row["name"] == "item1"

    all_rows = db.fetchall("SELECT * FROM items ORDER BY id ASC;")
    assert len(all_rows) == 3
    assert [r["name"] for r in all_rows] == ["item1", "item2", "item3"]

    # Test transaction rollback on error
    with pytest.raises(RuntimeError), db.transaction() as conn:
        conn.execute("INSERT INTO items (name) VALUES (?);", ("item4",))
        raise RuntimeError("Forced abort")

    # item4 should not be in the database
    row4 = db.fetchone("SELECT * FROM items WHERE name = ?;", ("item4",))
    assert row4 is None


def test_migrations_application_and_idempotency(tmp_path: Path) -> None:
    """Test applying migrations and verifying idempotency when run repeatedly."""
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    mgr = MigrationManager()

    # First run: applies all current schema migrations
    newly_applied = mgr.apply_migrations(db)
    assert len(newly_applied) >= 1
    assert "001_initial_schema" in newly_applied
    assert mgr.get_current_version(db) >= 1

    # Second run: nothing to apply (idempotent)
    second_applied = mgr.apply_migrations(db)
    assert len(second_applied) == 0

    # Check tables exist
    tables = [r[0] for r in db.fetchall("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")]
    assert "schema_migrations" in tables
    assert "identities" in tables
    assert "config_entries" in tables
    assert "audit_events" in tables


def test_database_integrity_check(tmp_path: Path) -> None:
    """Test integrity check passes on valid DB and detects corruption."""
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    MigrationManager().apply_migrations(db)

    healthy, msg = db.check_integrity()
    assert healthy is True
    assert msg == "ok"
    db.verify_or_raise()

    # Test non-existent file
    db_missing = Database(tmp_path / "missing.db")
    healthy, _ = db_missing.check_integrity()
    assert healthy is False
