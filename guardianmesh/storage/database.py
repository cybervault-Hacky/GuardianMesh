"""SQLite database abstraction with connection management, WAL mode, and integrity verification."""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Generator, Sequence
from pathlib import Path
from typing import Any, cast

from guardianmesh.core.errors import DatabaseIntegrityError, StorageError
from guardianmesh.core.paths import ensure_directory


class Database:
    """Production-grade SQLite database wrapper with strict safety pragmas."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path).expanduser().resolve()
        self._is_closed = False

    def ensure_storage(self) -> None:
        """Ensure database parent directory exists with 0700 permissions."""
        ensure_directory(self.db_path.parent, mode=0o700)

    def _configure_connection(self, conn: sqlite3.Connection) -> None:
        """Apply security and performance pragmas to SQLite connection."""
        conn.row_factory = sqlite3.Row
        # Enforce foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON;")
        # Set busy timeout to 5000ms
        conn.execute("PRAGMA busy_timeout = 5000;")
        # Try WAL mode; fallback to DELETE if WAL is unsupported by filesystem
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
        except sqlite3.OperationalError:
            conn.execute("PRAGMA journal_mode = DELETE;")

    @contextlib.contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding an active SQLite connection."""
        self.ensure_storage()
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            self._configure_connection(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextlib.contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager executing multiple operations within a single transaction."""
        self.ensure_storage()
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            self._configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> int:
        """Execute a parameterized SQL statement and return affected row count."""
        try:
            with self.connect() as conn:
                cursor = conn.execute(sql, params)
                return cursor.rowcount
        except sqlite3.Error as e:
            raise StorageError(f"Database execute error: {e}") from e

    def executemany(self, sql: str, seq_of_params: Sequence[Sequence[Any] | dict[str, Any]]) -> int:
        """Execute a parameterized SQL statement against multiple parameter sets."""
        try:
            with self.connect() as conn:
                cursor = conn.executemany(sql, seq_of_params)
                return cursor.rowcount
        except sqlite3.Error as e:
            raise StorageError(f"Database executemany error: {e}") from e

    def fetchone(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> sqlite3.Row | None:
        """Execute query and fetch a single row."""
        try:
            with self.connect() as conn:
                cursor = conn.execute(sql, params)
                row = cursor.fetchone()
                return cast(sqlite3.Row | None, row)
        except sqlite3.Error as e:
            raise StorageError(f"Database fetchone error: {e}") from e

    def fetchall(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[sqlite3.Row]:
        """Execute query and fetch all matching rows."""
        try:
            with self.connect() as conn:
                cursor = conn.execute(sql, params)
                return cursor.fetchall()
        except sqlite3.Error as e:
            raise StorageError(f"Database fetchall error: {e}") from e

    def check_integrity(self) -> tuple[bool, str]:
        """Run SQLite integrity check to verify database health.

        Returns:
            Tuple of (is_healthy, status_message).
        """
        if not self.db_path.is_file():
            return False, "Database file does not exist."

        try:
            with self.connect() as conn:
                cursor = conn.execute("PRAGMA integrity_check;")
                rows = cursor.fetchall()
                results = [row[0] for row in rows]
                if len(results) == 1 and results[0] == "ok":
                    return True, "ok"
                return False, "; ".join(results)
        except Exception as e:
            return False, str(e)

    def verify_or_raise(self) -> None:
        """Verify database integrity or raise DatabaseIntegrityError."""
        healthy, msg = self.check_integrity()
        if not healthy:
            raise DatabaseIntegrityError(f"Database integrity check failed: {msg}")
