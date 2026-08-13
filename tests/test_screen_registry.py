"""Tests for the screen session database registry (Phase 7: Vista)."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.screen.models import (
    ScreenCodec,
    ScreenSessionInfo,
    ScreenSessionState,
    StopReason,
)
from guardianmesh.screen.registry import ScreenSessionRegistry
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "screen_registry.db"


@pytest.fixture
def db(db_path: Path) -> Database:
    database = Database(db_path)
    MigrationManager().apply_migrations(database)
    return database


def _make_info(
    session_id: str = "SCN-12345678",
    device_id: str = "GM-C-19A84E72",
    parent_id: str = "GM-P-83A1F72C",
    state: ScreenSessionState = ScreenSessionState.ACTIVE,
) -> ScreenSessionInfo:
    now = datetime.datetime.now(datetime.UTC)
    return ScreenSessionInfo(
        session_id=session_id,
        device_id=device_id,
        parent_id=parent_id,
        state=state,
        requested_at=now.isoformat(),
        expires_at=(now + datetime.timedelta(seconds=300)).isoformat(),
        width=1280,
        height=720,
        codec=ScreenCodec.TEST,
        max_fps=10,
        frame_count=0,
        bytes_sent=0,
        bytes_received=0,
    )


def test_registry_upsert_and_get(db: Database) -> None:
    """Insert and read back a screen session record."""
    reg = ScreenSessionRegistry(db)
    info = _make_info()
    reg.upsert(info)

    fetched = reg.get("SCN-12345678")
    assert fetched is not None
    assert fetched.session_id == info.session_id
    assert fetched.state == ScreenSessionState.ACTIVE
    assert fetched.width == 1280
    assert fetched.height == 720
    assert fetched.codec == ScreenCodec.TEST


def test_registry_upsert_is_idempotent(db: Database) -> None:
    """Re-inserting a record updates fields rather than duplicating rows."""
    reg = ScreenSessionRegistry(db)
    info = _make_info()
    reg.upsert(info)
    info.frame_count = 42
    reg.upsert(info)

    fetched = reg.get("SCN-12345678")
    assert fetched is not None
    assert fetched.frame_count == 42

    rows = db.fetchall("SELECT * FROM screen_sessions;")
    assert len(rows) == 1


def test_registry_list_for_device(db: Database) -> None:
    """list_for_device returns only sessions for the requested device."""
    reg = ScreenSessionRegistry(db)
    reg.upsert(_make_info(session_id="SCN-A", device_id="GM-C-DEVICEA"))
    reg.upsert(_make_info(session_id="SCN-B", device_id="GM-C-DEVICEA"))
    reg.upsert(_make_info(session_id="SCN-C", device_id="GM-C-DEVICEB"))

    devs = reg.list_for_device("GM-C-DEVICEA")
    assert len(devs) == 2
    assert {d.session_id for d in devs} == {"SCN-A", "SCN-B"}


def test_registry_list_for_parent(db: Database) -> None:
    """list_for_parent returns sessions for the requested parent."""
    reg = ScreenSessionRegistry(db)
    reg.upsert(_make_info(session_id="SCN-A", parent_id="GM-P-PARENTA"))
    reg.upsert(_make_info(session_id="SCN-B", parent_id="GM-P-PARENTB"))

    parents = reg.list_for_parent("GM-P-PARENTA")
    assert len(parents) == 1
    assert parents[0].parent_id == "GM-P-PARENTA"


def test_registry_list_active_filters_state(db: Database) -> None:
    """list_active returns only ACTIVE sessions."""
    reg = ScreenSessionRegistry(db)
    reg.upsert(_make_info(session_id="SCN-ACT", state=ScreenSessionState.ACTIVE))
    reg.upsert(_make_info(session_id="SCN-STOP", state=ScreenSessionState.STOPPED))
    reg.upsert(_make_info(session_id="SCN-EXP", state=ScreenSessionState.EXPIRED))

    active = reg.list_active()
    assert len(active) == 1
    assert active[0].session_id == "SCN-ACT"


def test_registry_delete(db: Database) -> None:
    """delete removes a row and returns True iff a row was deleted."""
    reg = ScreenSessionRegistry(db)
    reg.upsert(_make_info())
    assert reg.delete("SCN-12345678") is True
    assert reg.get("SCN-12345678") is None
    assert reg.delete("SCN-NOT_THERE") is False


def test_registry_never_persists_payload(db: Database) -> None:
    """The registry must NEVER persist frame payload bytes."""
    reg = ScreenSessionRegistry(db)
    reg.upsert(_make_info())
    # Look at the raw columns: payload must not exist.
    cols = [
        row["name"]
        for row in db.fetchall("PRAGMA table_info(screen_sessions);")
    ]
    forbidden = {"payload", "payload_hex", "screenshot", "frame_data", "image"}
    assert not (forbidden & set(cols)), f"Forbidden columns present: {forbidden & set(cols)}"


def test_registry_round_trip_preserves_stop_reason(db: Database) -> None:
    """Stop reasons round-trip through the database."""
    reg = ScreenSessionRegistry(db)
    info = _make_info(state=ScreenSessionState.STOPPED)
    info.stop_reason = StopReason.CHILD_STOPPED
    reg.upsert(info)
    fetched = reg.get("SCN-12345678")
    assert fetched is not None
    assert fetched.stop_reason == StopReason.CHILD_STOPPED


def test_registry_corrupt_metadata_falls_back_to_empty(db: Database) -> None:
    """If metadata JSON is malformed, the registry falls back to {} safely."""
    reg = ScreenSessionRegistry(db)
    reg.upsert(_make_info())
    # Overwrite metadata with invalid JSON.
    db.execute(
        "UPDATE screen_sessions SET metadata = ? WHERE session_id = ?;",
        ("{not valid json", "SCN-12345678"),
    )
    fetched = reg.get("SCN-12345678")
    assert fetched is not None
    assert fetched.metadata == {}
