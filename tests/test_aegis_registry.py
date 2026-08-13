"""Tests for the Aegis database registry (Phase 8)."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.aegis.models import (
    AegisPlatform,
    AegisSessionInfo,
    AegisSessionState,
    EncoderBackend,
    SystemConsentState,
)
from guardianmesh.aegis.registry import AegisSessionRegistry
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "aegis_registry.db"


@pytest.fixture
def db(db_path: Path) -> Database:
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def _make_info(
    aegis_id: str = "AEG-12345678",
    screen_id: str = "SCN-12345678",
    state: AegisSessionState = AegisSessionState.INITIALIZED,
) -> AegisSessionInfo:
    now = datetime.datetime.now(datetime.UTC)
    return AegisSessionInfo(
        aegis_session_id=aegis_id,
        screen_session_id=screen_id,
        device_id="GM-C-19A84E72",
        parent_id="GM-P-83A1F72C",
        consent_state=SystemConsentState.NOT_REQUESTED,
        platform=AegisPlatform.ANDROID,
        backend=EncoderBackend.MEDIA_CODEC,
        state=state.value,
        created_at=now.isoformat(),
        expires_at=(now + datetime.timedelta(seconds=300)).isoformat(),
    )


def test_registry_upsert_and_get(db: Database) -> None:
    """Insert and read back an Aegis session record."""
    reg = AegisSessionRegistry(db)
    info = _make_info()
    reg.upsert(info)
    fetched = reg.get("AEG-12345678")
    assert fetched is not None
    assert fetched.aegis_session_id == "AEG-12345678"
    assert fetched.consent_state == SystemConsentState.NOT_REQUESTED
    assert fetched.platform == AegisPlatform.ANDROID
    assert fetched.backend == EncoderBackend.MEDIA_CODEC


def test_registry_upsert_is_idempotent(db: Database) -> None:
    """Re-inserting a record updates fields rather than duplicating rows."""
    reg = AegisSessionRegistry(db)
    info = _make_info()
    reg.upsert(info)
    info.consent_state = SystemConsentState.GRANTED
    info.state = AegisSessionState.CAPTURING.value
    reg.upsert(info)
    fetched = reg.get("AEG-12345678")
    assert fetched is not None
    assert fetched.consent_state == SystemConsentState.GRANTED
    assert fetched.state == AegisSessionState.CAPTURING.value
    rows = db.fetchall("SELECT * FROM aegis_sessions;")
    assert len(rows) == 1


def test_registry_list_for_device(db: Database) -> None:
    """list_for_device returns only sessions for the requested device."""
    reg = AegisSessionRegistry(db)
    reg.upsert(_make_info(aegis_id="AEG-A", screen_id="SCN-A"))
    reg.upsert(_make_info(aegis_id="AEG-B", screen_id="SCN-B"))
    # Manually mutate the device_id of the second record.
    info2 = _make_info(aegis_id="AEG-C", screen_id="SCN-C")
    info2.device_id = "GM-C-OTHERDEVICE"
    reg.upsert(info2)
    rows = reg.list_for_device("GM-C-19A84E72")
    assert len(rows) == 2
    assert {r.aegis_session_id for r in rows} == {"AEG-A", "AEG-B"}


def test_registry_list_all(db: Database) -> None:
    """list_all returns every Aegis session."""
    reg = AegisSessionRegistry(db)
    reg.upsert(_make_info(aegis_id="AEG-A", screen_id="SCN-A"))
    reg.upsert(_make_info(aegis_id="AEG-B", screen_id="SCN-B"))
    rows = reg.list_all()
    assert len(rows) == 2


def test_registry_delete(db: Database) -> None:
    """delete removes a row and returns True iff a row was removed."""
    reg = AegisSessionRegistry(db)
    reg.upsert(_make_info())
    assert reg.delete("AEG-12345678") is True
    assert reg.get("AEG-12345678") is None
    assert reg.delete("AEG-NOT_THERE") is False


def test_registry_never_persists_payload(db: Database) -> None:
    """The registry must NEVER persist frame payload bytes."""
    reg = AegisSessionRegistry(db)
    reg.upsert(_make_info())
    cols = [row["name"] for row in db.fetchall("PRAGMA table_info(aegis_sessions);")]
    forbidden = {
        "payload",
        "payload_hex",
        "screenshot",
        "frame_data",
        "image",
        "raw_pixels",
        "encoded_video",
    }
    assert forbidden.isdisjoint(set(cols))


def test_registry_consent_state_check_constraint(db: Database) -> None:
    """Invalid consent_state values are rejected by the CHECK constraint."""
    from guardianmesh.core.errors import StorageError

    reg = AegisSessionRegistry(db)
    reg.upsert(_make_info())
    # Manually try to update with an invalid consent_state.
    with pytest.raises(StorageError):
        db.execute(
            "UPDATE aegis_sessions SET consent_state = ? WHERE aegis_session_id = ?;",
            ("NONSENSE", "AEG-12345678"),
        )


def test_registry_corrupt_metadata_falls_back_to_empty(db: Database) -> None:
    """If metadata JSON is malformed, the registry falls back to {} safely."""
    reg = AegisSessionRegistry(db)
    reg.upsert(_make_info())
    db.execute(
        "UPDATE aegis_sessions SET metadata = ? WHERE aegis_session_id = ?;",
        ("{not valid json", "AEG-12345678"),
    )
    fetched = reg.get("AEG-12345678")
    assert fetched is not None
    assert fetched.metadata == {}


def test_registry_round_trip_preserves_all_fields(db: Database) -> None:
    """All metadata fields round-trip through the database."""
    reg = AegisSessionRegistry(db)
    info = _make_info()
    info.consent_state = SystemConsentState.GRANTED
    info.state = AegisSessionState.CAPTURING.value
    info.started_at = "2026-08-13T00:01:00+00:00"
    info.consent_granted_at = "2026-08-13T00:00:30+00:00"
    info.last_frame_sequence = 42
    info.stop_reason = "USER_STOPPED"
    reg.upsert(info)
    fetched = reg.get("AEG-12345678")
    assert fetched is not None
    assert fetched.started_at == "2026-08-13T00:01:00+00:00"
    assert fetched.consent_granted_at == "2026-08-13T00:00:30+00:00"
    assert fetched.last_frame_sequence == 42
    assert fetched.stop_reason == "USER_STOPPED"
