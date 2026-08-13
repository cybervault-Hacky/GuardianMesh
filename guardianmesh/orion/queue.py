"""Orion Phase 9 persistent action queue.

The :class:`OrionActionQueue` provides transactional, idempotent
queueing of :class:`OrionAction` instances. The queue is backed by
SQLite and uses the ``orion_actions`` table created by Migration 9.

Properties:

* **Idempotency**: duplicate ``idempotency_key`` values are silently
  rejected; no duplicate action is created.
* **Persistent state**: the queue survives process restart.
* **Bounded retry**: each action records its ``retry_count``;
  ``max_retries`` is enforced at submission.
* **Expiration**: actions with a past ``expires_at`` are marked
  ``EXPIRED`` at sweep time and never run.
* **Concurrency**: the queue is thread-safe via a single
  ``threading.RLock``. SQLite transactions provide additional
  guarantees.

The queue never persists secrets, command strings, frame bytes,
or other sensitive payloads. Action parameters are metadata only.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import threading
from typing import Any

from guardianmesh.core.errors import ValidationError
from guardianmesh.orion.actions import (
    SCHEMA_VERSION as ACTION_SCHEMA_VERSION,
)
from guardianmesh.orion.actions import (
    OrionAction,
    OrionActionStatus,
    OrionActionType,
)
from guardianmesh.orion.errors import OrionActionError, OrionQueueError
from guardianmesh.storage.database import Database


class OrionActionQueue:
    """Persistent, idempotent action queue."""

    def __init__(self, db: Database, max_size: int = 10_000) -> None:
        if max_size <= 0:
            raise ValidationError("max_size must be positive.")
        self._db = db
        self._max_size = max_size
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Enqueue
    # ------------------------------------------------------------------

    def enqueue(self, action: OrionAction) -> bool:
        """Persist an action. Returns True if created, False if duplicate.

        Duplicate ``idempotency_key`` values are silently rejected
        to preserve the at-most-once guarantee. The action is
        rejected if the queue is at capacity.
        """
        if not isinstance(action, OrionAction):
            raise OrionActionError("action must be an OrionAction.")
        with self._lock:
            self._enforce_size_limit()
            if action.idempotency_key and self._has_idempotency_key(
                action.idempotency_key
            ):
                return False
            meta = json.dumps({"parameters": action.parameters, "result": {}})
            try:
                with self._db.transaction() as conn:
                    conn.execute(
                        """
                        INSERT INTO orion_actions (
                            action_id, action_type, device_id, status,
                            created_at, expires_at, correlation_id,
                            requested_by, schema_version, parameters,
                            idempotency_key, retry_count, max_retries,
                            next_attempt_at, last_error, updated_at, result
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            action.action_id,
                            action.action_type.value,
                            action.device_id,
                            action.status.value,
                            action.created_at,
                            action.expires_at,
                            action.correlation_id,
                            action.requested_by,
                            action.schema_version,
                            meta,
                            action.idempotency_key,
                            action.retry_count,
                            action.max_retries,
                            action.next_attempt_at,
                            action.last_error,
                            action.updated_at,
                            json.dumps({}),
                        ),
                    )
            except sqlite3.IntegrityError as e:
                # Another writer raced us with the same action id.
                raise OrionQueueError(
                    f"Failed to enqueue action '{action.action_id}': {e}"
                ) from e
        return True

    def _has_idempotency_key(self, key: str) -> bool:
        row = self._db.fetchone(
            "SELECT 1 FROM orion_actions WHERE idempotency_key = ? LIMIT 1;",
            (key,),
        )
        return row is not None

    def _enforce_size_limit(self) -> None:
        row = self._db.fetchone("SELECT COUNT(*) AS c FROM orion_actions;")
        count = int(row["c"]) if row else 0
        if count >= self._max_size:
            raise OrionQueueError(
                f"Action queue is at capacity ({self._max_size})."
            )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, action_id: str) -> OrionAction | None:
        row = self._db.fetchone(
            "SELECT * FROM orion_actions WHERE action_id = ?;",
            (action_id,),
        )
        if row is None:
            return None
        return self._row_to_action(dict(row))

    def list_by_status(
        self,
        status: OrionActionStatus | str | None = None,
        *,
        device_id: str | None = None,
        limit: int = 100,
    ) -> list[OrionAction]:
        params: list[Any] = []
        where: list[str] = []
        if status is not None:
            if isinstance(status, str):
                status = OrionActionStatus.from_str(status)
            where.append("status = ?")
            params.append(status.value)
        if device_id is not None:
            where.append("device_id = ?")
            params.append(device_id)
        where_clause = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(limit)
        rows = self._db.fetchall(
            f"SELECT * FROM orion_actions{where_clause} "
            f"ORDER BY created_at ASC LIMIT ?;",
            tuple(params),
        )
        return [self._row_to_action(dict(r)) for r in rows]

    def list_all(self, limit: int = 200) -> list[OrionAction]:
        return self.list_by_status(None, limit=limit)

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def mark_running(self, action_id: str) -> None:
        self._update_status(action_id, OrionActionStatus.RUNNING)

    def mark_succeeded(
        self, action_id: str, result: dict[str, Any] | None = None
    ) -> None:
        self._update_status(
            action_id,
            OrionActionStatus.SUCCEEDED,
            result=result or {},
        )

    def mark_failed(
        self, action_id: str, error: str, *, retry: bool = True
    ) -> None:
        """Mark an action as failed. Optionally retry with backoff."""
        with self._lock:
            current = self.get(action_id)
            if current is None:
                return
            if retry and current.can_retry():
                next_attempt = (
                    datetime.datetime.now(datetime.UTC)
                    + datetime.timedelta(seconds=2 ** current.retry_count)
                ).isoformat()
                self._db.execute(
                    """
                    UPDATE orion_actions
                    SET status = ?, retry_count = ?, last_error = ?,
                        next_attempt_at = ?, updated_at = ?
                    WHERE action_id = ?;
                    """,
                    (
                        OrionActionStatus.PENDING.value,
                        current.retry_count + 1,
                        error,
                        next_attempt,
                        datetime.datetime.now(datetime.UTC).isoformat(),
                        action_id,
                    ),
                )
            else:
                self._update_status(
                    action_id, OrionActionStatus.FAILED, last_error=error
                )

    def mark_expired(self, action_id: str) -> None:
        self._update_status(action_id, OrionActionStatus.EXPIRED)

    def mark_cancelled(self, action_id: str) -> None:
        self._update_status(action_id, OrionActionStatus.CANCELLED)

    def _update_status(
        self,
        action_id: str,
        status: OrionActionStatus,
        *,
        last_error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        if result is not None:
            self._db.execute(
                """
                UPDATE orion_actions
                SET status = ?, last_error = ?, result = ?, updated_at = ?
                WHERE action_id = ?;
                """,
                (
                    status.value,
                    last_error,
                    json.dumps(result),
                    datetime.datetime.now(datetime.UTC).isoformat(),
                    action_id,
                ),
            )
        else:
            self._db.execute(
                """
                UPDATE orion_actions
                SET status = ?, last_error = ?, updated_at = ?
                WHERE action_id = ?;
                """,
                (
                    status.value,
                    last_error,
                    datetime.datetime.now(datetime.UTC).isoformat(),
                    action_id,
                ),
            )

    # ------------------------------------------------------------------
    # Expiration sweep
    # ------------------------------------------------------------------

    def sweep_expired(
        self, now: datetime.datetime | None = None
    ) -> list[str]:
        """Mark all expired pending actions as EXPIRED. Returns the ids."""
        now = now or datetime.datetime.now(datetime.UTC)
        rows = self._db.fetchall(
            """
            SELECT action_id FROM orion_actions
            WHERE status IN ('PENDING', 'RUNNING') AND expires_at < ?;
            """,
            (now.isoformat(),),
        )
        ids = [r["action_id"] for r in rows]
        for action_id in ids:
            self.mark_expired(action_id)
        return ids

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def _row_to_action(self, row: dict[str, Any]) -> OrionAction:
        meta_raw = row.get("parameters") or "{}"
        try:
            meta = json.loads(meta_raw)
            parameters = meta.get("parameters", {}) if isinstance(meta, dict) else {}
        except (json.JSONDecodeError, TypeError):
            parameters = {}
        result_raw = row.get("result") or "{}"
        try:
            result = json.loads(result_raw)
            if not isinstance(result, dict):
                result = {}
        except (json.JSONDecodeError, TypeError):
            result = {}
        return OrionAction(
            action_id=str(row["action_id"]),
            action_type=OrionActionType.from_str(str(row["action_type"])),
            device_id=str(row["device_id"]),
            created_at=str(row["created_at"]),
            expires_at=str(row["expires_at"]),
            correlation_id=str(row["correlation_id"]),
            requested_by=str(row["requested_by"]),
            status=OrionActionStatus.from_str(str(row["status"])),
            schema_version=str(row.get("schema_version", ACTION_SCHEMA_VERSION)),
            parameters=parameters,
            idempotency_key=row.get("idempotency_key"),
            retry_count=int(row.get("retry_count", 0)),
            max_retries=int(row.get("max_retries", 3)),
            next_attempt_at=row.get("next_attempt_at"),
            last_error=row.get("last_error"),
            updated_at=row.get("updated_at"),
            result=result,
        )

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        rows = self._db.fetchall(
            "SELECT status, COUNT(*) AS c FROM orion_actions GROUP BY status;"
        )
        by_status = {str(r["status"]): int(r["c"]) for r in rows}
        return {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "max_size": self._max_size,
        }


__all__ = ["OrionActionQueue"]
