"""Orion Phase 9 persistent registry.

The :class:`OrionRegistry` persists :class:`OrionDeviceCapabilities`,
:class:`OrionEvent` (for audit and reconciliation), and
:class:`OrionReconciliationReport` records.

The registry NEVER stores:

* private keys
* session keys
* passwords
* OTPs
* plaintext screen frames
* screen frame bytes
* arbitrary command strings
* private message content

The schema is created by Migration 9.
"""

from __future__ import annotations

import json
from typing import Any

from guardianmesh.orion.errors import OrionError
from guardianmesh.orion.events import SCHEMA_VERSION as EVENT_SCHEMA_VERSION
from guardianmesh.orion.events import OrionEvent, OrionEventType
from guardianmesh.orion.models import (
    OrionDeviceCapabilities,
    OrionReconciliationReport,
)
from guardianmesh.storage.database import Database


class OrionRegistry:
    """Persistent registry for Orion capabilities, events, and reports."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def upsert_capabilities(self, caps: OrionDeviceCapabilities) -> None:
        if not isinstance(caps, OrionDeviceCapabilities):
            raise OrionError("caps must be an OrionDeviceCapabilities.")
        caps_json = json.dumps(caps.to_dict(), sort_keys=True)
        self.db.execute(
            """
            INSERT INTO orion_capabilities (
                capability_id, device_id, capabilities_json,
                schema_version, discovered_at, updated_at, source, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                capabilities_json = excluded.capabilities_json,
                schema_version = excluded.schema_version,
                updated_at = excluded.updated_at,
                source = excluded.source,
                notes = excluded.notes;
            """,
            (
                caps.device_id,
                caps.device_id,
                caps_json,
                caps.schema_version,
                caps.discovered_at,
                caps.updated_at or caps.discovered_at,
                caps.source,
                caps.notes,
            ),
        )

    def get_capabilities(self, device_id: str) -> OrionDeviceCapabilities | None:
        row = self.db.fetchone(
            "SELECT * FROM orion_capabilities WHERE device_id = ?;",
            (device_id,),
        )
        if row is None:
            return None
        try:
            data = json.loads(row["capabilities_json"])
        except (json.JSONDecodeError, TypeError):
            return None
        return OrionDeviceCapabilities.from_dict(data)

    def list_capabilities(self) -> list[OrionDeviceCapabilities]:
        rows = self.db.fetchall(
            "SELECT * FROM orion_capabilities ORDER BY device_id;"
        )
        result: list[OrionDeviceCapabilities] = []
        for row in rows:
            try:
                data = json.loads(row["capabilities_json"])
                result.append(OrionDeviceCapabilities.from_dict(data))
            except (json.JSONDecodeError, TypeError):
                continue
        return result

    # ------------------------------------------------------------------
    # Events (audit + reconciliation log)
    # ------------------------------------------------------------------

    def record_event(self, event: OrionEvent) -> None:
        if not isinstance(event, OrionEvent):
            raise OrionError("event must be an OrionEvent.")
        payload_json = json.dumps(event.payload or {}, sort_keys=True)
        self.db.execute(
            """
            INSERT INTO orion_events (
                event_id, event_type, source, device_id, created_at,
                correlation_id, schema_version, payload_json, priority,
                sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                event.event_id,
                event.event_type.value,
                event.source,
                event.device_id,
                event.created_at,
                event.correlation_id,
                event.schema_version,
                payload_json,
                event.priority.value,
                event.sequence,
            ),
        )

    def list_events(
        self,
        device_id: str | None = None,
        *,
        limit: int = 100,
    ) -> list[OrionEvent]:
        if device_id is not None:
            rows = self.db.fetchall(
                "SELECT * FROM orion_events WHERE device_id = ? "
                "ORDER BY sequence ASC LIMIT ?;",
                (device_id, limit),
            )
        else:
            rows = self.db.fetchall(
                "SELECT * FROM orion_events ORDER BY created_at ASC LIMIT ?;",
                (limit,),
            )
        result: list[OrionEvent] = []
        for row in rows:
            row_dict = dict(row)
            try:
                payload = json.loads(row_dict.get("payload_json") or "{}")
            except (json.JSONDecodeError, TypeError):
                payload = {}
            try:
                event_type = OrionEventType.from_str(str(row_dict.get("event_type", "")))
            except Exception:
                continue
            result.append(
                OrionEvent(
                    event_id=str(row_dict.get("event_id", "")),
                    event_type=event_type,
                    source=str(row_dict.get("source", "")),
                    device_id=str(row_dict.get("device_id", "")),
                    created_at=str(row_dict.get("created_at", "")),
                    correlation_id=str(row_dict.get("correlation_id", "")),
                    schema_version=str(
                        row_dict.get("schema_version", EVENT_SCHEMA_VERSION)
                    ),
                    payload=payload,
                    sequence=int(row_dict.get("sequence", 0)),
                )
            )
        return result

    # ------------------------------------------------------------------
    # Reconciliation reports
    # ------------------------------------------------------------------

    def upsert_report(self, report: OrionReconciliationReport) -> None:
        if not isinstance(report, OrionReconciliationReport):
            raise OrionError("report must be an OrionReconciliationReport.")
        self.db.execute(
            """
            INSERT INTO orion_reconciliation (
                report_id, device_id, started_at, completed_at,
                events_processed, conflicts_detected, conflicts_resolved,
                stale_events, failed_actions, final_state, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                report.report_id,
                report.device_id,
                report.started_at,
                report.completed_at,
                report.events_processed,
                report.conflicts_detected,
                report.conflicts_resolved,
                report.stale_events,
                report.failed_actions,
                report.final_state,
                report.notes,
            ),
        )

    def list_reports(
        self, device_id: str | None = None, *, limit: int = 50
    ) -> list[OrionReconciliationReport]:
        if device_id is not None:
            rows = self.db.fetchall(
                "SELECT * FROM orion_reconciliation WHERE device_id = ? "
                "ORDER BY started_at DESC LIMIT ?;",
                (device_id, limit),
            )
        else:
            rows = self.db.fetchall(
                "SELECT * FROM orion_reconciliation "
                "ORDER BY started_at DESC LIMIT ?;",
                (limit,),
            )
        return [self._row_to_report(dict(r)) for r in rows]

    def _row_to_report(self, row: dict[str, Any]) -> OrionReconciliationReport:
        row_dict = dict(row) if not isinstance(row, dict) else row
        return OrionReconciliationReport(
            report_id=str(row_dict.get("report_id", "")),
            device_id=str(row_dict.get("device_id", "")),
            started_at=str(row_dict.get("started_at", "")),
            completed_at=row_dict.get("completed_at"),
            events_processed=int(row_dict.get("events_processed", 0)),
            conflicts_detected=int(row_dict.get("conflicts_detected", 0)),
            conflicts_resolved=int(row_dict.get("conflicts_resolved", 0)),
            stale_events=int(row_dict.get("stale_events", 0)),
            failed_actions=int(row_dict.get("failed_actions", 0)),
            final_state=str(row_dict.get("final_state", "SYNCED")),
            notes=str(row_dict.get("notes", "")),
        )

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def metrics(self) -> dict[str, Any]:
        rows = self.db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name LIKE 'orion_%';"
        )
        tables = sorted(r["name"] for r in rows)
        out: dict[str, Any] = {"tables": tables}
        for table in tables:
            row = self.db.fetchone(f"SELECT COUNT(*) AS c FROM {table};")
            if row:
                out[f"{table}.count"] = int(row["c"])
        return out


__all__ = ["OrionRegistry"]
