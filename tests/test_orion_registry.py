"""Tests for the Orion Phase 9 persistent registry.

Covers capabilities upsert/get/list, event record/listing, and
reconciliation report upsert/listing. The registry must NEVER
persist private keys, frame bytes, command strings, or other
sensitive payloads.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.orion.errors import OrionError
from guardianmesh.orion.events import OrionEvent, OrionEventType
from guardianmesh.orion.models import (
    OrionDeviceCapabilities,
    OrionReconciliationReport,
)
from guardianmesh.orion.registry import OrionRegistry
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "orion_registry.db"


@pytest.fixture
def db(db_path: Path) -> Database:
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def _event(event_id: str = "OEV-00000001", device_id: str = "GM-C-19A84E72") -> OrionEvent:
    return OrionEvent(
        event_id=event_id,
        event_type=OrionEventType.DEVICE_CONNECTED,
        source="test",
        device_id=device_id,
        created_at=datetime.datetime.now(datetime.UTC).isoformat(),
        correlation_id=f"OCR-{event_id}",
    )


def _caps(device_id: str = "GM-C-19A84E72") -> OrionDeviceCapabilities:
    return OrionDeviceCapabilities.discover(
        device_id, health_telemetry=True, alerts=True
    )


def _report(device_id: str = "GM-C-19A84E72") -> OrionReconciliationReport:
    now = datetime.datetime.now(datetime.UTC)
    return OrionReconciliationReport(
        report_id="ORC-12345678",
        device_id=device_id,
        started_at=now.isoformat(),
        completed_at=(now + datetime.timedelta(seconds=1)).isoformat(),
        events_processed=10,
        conflicts_detected=2,
        conflicts_resolved=2,
    )


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


def test_upsert_capabilities(db: Database) -> None:
    reg = OrionRegistry(db)
    caps = _caps()
    reg.upsert_capabilities(caps)
    fetched = reg.get_capabilities("GM-C-19A84E72")
    assert fetched is not None
    assert fetched.device_id == "GM-C-19A84E72"


def test_upsert_capabilities_replaces_existing(db: Database) -> None:
    reg = OrionRegistry(db)
    caps = _caps()
    reg.upsert_capabilities(caps)
    # Second upsert with different note should update the row.
    caps.notes = "Updated note"
    reg.upsert_capabilities(caps)
    fetched = reg.get_capabilities("GM-C-19A84E72")
    assert fetched.notes == "Updated note"


def test_upsert_capabilities_validates_type(db: Database) -> None:
    reg = OrionRegistry(db)
    with pytest.raises(OrionError):
        reg.upsert_capabilities("not caps")  # type: ignore[arg-type]


def test_get_capabilities_returns_none_for_unknown(db: Database) -> None:
    reg = OrionRegistry(db)
    assert reg.get_capabilities("DOES-NOT-EXIST") is None


def test_get_capabilities_handles_corrupted_json(db: Database) -> None:
    reg = OrionRegistry(db)
    db.execute(
        """
        INSERT INTO orion_capabilities (
            capability_id, device_id, capabilities_json, schema_version,
            discovered_at, updated_at, source, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "GM-C-CORRUPT",
            "GM-C-CORRUPT",
            "not valid json {{",
            "1.0",
            "2026-08-13T00:00:00+00:00",
            "2026-08-13T00:00:00+00:00",
            "test",
            "",
        ),
    )
    assert reg.get_capabilities("GM-C-CORRUPT") is None


def test_list_capabilities(db: Database) -> None:
    reg = OrionRegistry(db)
    reg.upsert_capabilities(_caps("GM-C-11111111"))
    reg.upsert_capabilities(_caps("GM-C-22222222"))
    all_caps = reg.list_capabilities()
    assert len(all_caps) == 2
    ids = [c.device_id for c in all_caps]
    assert "GM-C-11111111" in ids
    assert "GM-C-22222222" in ids


def test_list_capabilities_skips_corrupted(db: Database) -> None:
    reg = OrionRegistry(db)
    reg.upsert_capabilities(_caps("GM-C-19A84E72"))
    db.execute(
        """
        INSERT INTO orion_capabilities (
            capability_id, device_id, capabilities_json, schema_version,
            discovered_at, updated_at, source, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "GM-C-CORRUPT",
            "GM-C-CORRUPT",
            "{not json",
            "1.0",
            "2026-08-13T00:00:00+00:00",
            "2026-08-13T00:00:00+00:00",
            "test",
            "",
        ),
    )
    caps = reg.list_capabilities()
    ids = [c.device_id for c in caps]
    assert "GM-C-19A84E72" in ids
    # Corrupted row should be skipped.
    assert "GM-C-CORRUPT" not in ids


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_record_event(db: Database) -> None:
    reg = OrionRegistry(db)
    ev = _event()
    reg.record_event(ev)
    out = reg.list_events(device_id="GM-C-19A84E72")
    assert len(out) == 1
    assert out[0].event_id == "OEV-00000001"


def test_record_event_rejects_non_event(db: Database) -> None:
    reg = OrionRegistry(db)
    with pytest.raises(OrionError):
        reg.record_event("not an event")  # type: ignore[arg-type]


def test_list_events_filters_by_device(db: Database) -> None:
    reg = OrionRegistry(db)
    reg.record_event(_event("OEV-A1", "GM-C-11111111"))
    reg.record_event(_event("OEV-B1", "GM-C-22222222"))
    out = reg.list_events(device_id="GM-C-11111111")
    assert len(out) == 1
    assert out[0].device_id == "GM-C-11111111"


def test_list_events_respects_limit(db: Database) -> None:
    reg = OrionRegistry(db)
    for i in range(5):
        reg.record_event(_event(f"OEV-{i:08d}"))
    out = reg.list_events(limit=3)
    assert len(out) == 3


def test_list_events_handles_corrupted_payload(db: Database) -> None:
    reg = OrionRegistry(db)
    db.execute(
        """
        INSERT INTO orion_events (
            event_id, event_type, source, device_id, created_at,
            correlation_id, schema_version, payload_json, priority, sequence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "OEV-CORRUPT",
            "DEVICE_CONNECTED",
            "test",
            "GM-C-19A84E72",
            "2026-08-13T00:00:00+00:00",
            "OCR-CORRUPT",
            "1.0",
            "{not json",
            "NORMAL",
            1,
        ),
    )
    out = reg.list_events()
    # Corrupted payload should still return a record (with empty payload).
    assert len(out) == 1
    assert out[0].payload == {}


def test_list_events_skips_unknown_event_type(db: Database) -> None:
    reg = OrionRegistry(db)
    db.execute(
        """
        INSERT INTO orion_events (
            event_id, event_type, source, device_id, created_at,
            correlation_id, schema_version, payload_json, priority, sequence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "OEV-UNKNOWN",
            "UNKNOWN_TYPE",
            "test",
            "GM-C-19A84E72",
            "2026-08-13T00:00:00+00:00",
            "OCR-UNKNOWN",
            "1.0",
            "{}",
            "NORMAL",
            1,
        ),
    )
    out = reg.list_events()
    assert out == []  # Unknown event type is silently skipped


# ---------------------------------------------------------------------------
# Reconciliation reports
# ---------------------------------------------------------------------------


def test_upsert_report(db: Database) -> None:
    reg = OrionRegistry(db)
    report = _report()
    reg.upsert_report(report)
    reports = reg.list_reports(device_id="GM-C-19A84E72")
    assert len(reports) == 1
    assert reports[0].report_id == "ORC-12345678"


def test_upsert_report_validates_type(db: Database) -> None:
    reg = OrionRegistry(db)
    with pytest.raises(OrionError):
        reg.upsert_report("not a report")  # type: ignore[arg-type]


def test_list_reports_filters_by_device(db: Database) -> None:
    reg = OrionRegistry(db)
    reg.upsert_report(_report("GM-C-11111111"))
    report2 = _report("GM-C-22222222")
    report2.report_id = "ORC-99999999"
    reg.upsert_report(report2)
    out = reg.list_reports(device_id="GM-C-11111111")
    assert len(out) == 1
    assert out[0].device_id == "GM-C-11111111"


def test_list_reports_respects_limit(db: Database) -> None:
    reg = OrionRegistry(db)
    for i in range(5):
        report = OrionReconciliationReport(
            report_id=f"ORC-{i:08d}",
            device_id="GM-C-19A84E72",
            started_at="2026-08-13T00:00:00+00:00",
            completed_at=None,
        )
        reg.upsert_report(report)
    out = reg.list_reports(limit=3)
    assert len(out) == 3


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_registry_metrics_lists_orion_tables(db: Database) -> None:
    reg = OrionRegistry(db)
    m = reg.metrics()
    assert "orion_events.count" in m
    assert "orion_actions.count" in m
    assert "orion_capabilities.count" in m
    assert "orion_reconciliation.count" in m
