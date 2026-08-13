"""Tests for TelemetryScheduler background worker, bounded backoff, and lifecycle."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import TelemetryTransportError
from guardianmesh.device.collectors import DeviceCollector
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.scheduler import TelemetryScheduler
from guardianmesh.telemetry.sequence import SequenceManager
from guardianmesh.telemetry.transport import TestTransport


def test_telemetry_scheduler_emission_and_lifecycle(tmp_path: Path) -> None:
    """Test scheduler emits signed envelopes, starts, pauses, resumes, and stops."""
    db = Database(tmp_path / "sched_test.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path, heartbeat_interval_seconds=1)
    key_storage = KeyStorageManager(tmp_path / "keys")
    identity_mgr = IdentityManager(db, key_storage)

    child, _ = identity_mgr.create_identity(role=IdentityRole.CHILD)
    seq_mgr = SequenceManager(db)
    transport = TestTransport()
    collector = DeviceCollector(target_path=tmp_path)

    scheduler = TelemetryScheduler(
        device_id=child.id,
        key_storage=key_storage,
        sequence_manager=seq_mgr,
        transport=transport,
        collector=collector,
        config=config,
    )

    # 1. Single emission tick
    envelope = scheduler.tick()
    assert envelope is not None
    assert envelope.device_id == child.id
    assert envelope.sequence == 1
    assert len(transport.sent_envelopes) == 1

    # 2. Pause and tick returns None
    scheduler.pause()
    assert scheduler.is_paused() is True
    assert scheduler.tick() is None

    # 3. Resume and tick produces sequence 2
    scheduler.resume()
    assert scheduler.is_paused() is False
    env2 = scheduler.tick()
    assert env2 is not None
    assert env2.sequence == 2

    # 4. Background thread start and stop
    scheduler.start()
    assert scheduler.is_running() is True
    scheduler.stop(timeout=1.0)
    assert scheduler.is_running() is False


def test_telemetry_scheduler_bounded_backoff_on_transport_failure(tmp_path: Path) -> None:
    """Test scheduler handles transport failure with bounded backoff and raises TelemetryTransportError."""
    db = Database(tmp_path / "sched_fail.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path, telemetry_max_retries=1)
    key_storage = KeyStorageManager(tmp_path / "keys")
    child, _ = IdentityManager(db, key_storage).create_identity(role=IdentityRole.CHILD)

    transport_failing = TestTransport(should_fail=True)
    scheduler = TelemetryScheduler(
        device_id=child.id,
        key_storage=key_storage,
        sequence_manager=SequenceManager(db),
        transport=transport_failing,
        config=config,
    )

    with pytest.raises(TelemetryTransportError):
        scheduler.tick()
