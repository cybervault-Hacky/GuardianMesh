"""Deep coverage tests for Telemetry CLI commands, config validation, and model deserialization."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from guardianmesh.cli.main import main
from guardianmesh.core.config import GuardianConfig
from guardianmesh.core.errors import ConfigError
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager
from guardianmesh.telemetry.models import (
    ConnectivityState,
    DeviceHealthState,
    HealthSnapshot,
    TelemetryEnvelope,
)
from guardianmesh.telemetry.processor import TelemetryProcessor


def test_config_telemetry_validations(tmp_path: Path) -> None:
    """Test config bounds checking for telemetry settings."""
    with pytest.raises(ConfigError):
        GuardianConfig(home_dir=tmp_path, heartbeat_interval_seconds=0)

    with pytest.raises(ConfigError):
        GuardianConfig(home_dir=tmp_path, health_sampling_interval_seconds=-5)

    with pytest.raises(ConfigError):
        GuardianConfig(home_dir=tmp_path, telemetry_retention_days=0)

    with pytest.raises(ConfigError):
        GuardianConfig(home_dir=tmp_path, timestamp_skew_tolerance_seconds=-1)


def test_telemetry_models_deserialization_and_states() -> None:
    """Test enum from_str fallbacks and model deserialization methods."""
    assert ConnectivityState.from_str("ONLINE") == ConnectivityState.ONLINE
    assert ConnectivityState.from_str("unknown_state") == ConnectivityState.UNKNOWN

    assert DeviceHealthState.from_str("ONLINE") == DeviceHealthState.ONLINE
    assert DeviceHealthState.from_str("invalid_health") == DeviceHealthState.UNKNOWN

    # HealthSnapshot from_payload_dict
    payload = {
        "battery_percent": 95,
        "charging": True,
        "connectivity": "ONLINE",
        "agent_version": "0.3.0",
    }
    snap = HealthSnapshot.from_payload_dict("GM-C-19A84E72", payload)
    assert snap.device_id == "GM-C-19A84E72"
    assert snap.battery_percent == 95

    # TelemetryEnvelope from_dict
    env_dict = {
        "protocol_version": "1.0",
        "device_id": "GM-C-19A84E72",
        "sequence": 4,
        "captured_at": "2026-08-12T19:00:00+00:00",
        "payload": payload,
        "signature": "abcd",
    }
    envelope = TelemetryEnvelope.from_dict(env_dict)
    assert envelope.sequence == 4
    assert envelope.signature == "abcd"

    # Verify signature on missing signature returns False
    envelope_nosig = TelemetryEnvelope(
        device_id="GM-C-19A84E72",
        sequence=1,
        payload=payload,
    )
    assert envelope_nosig.verify_signature("...") is False


def test_telemetry_processor_health_derivation(tmp_path: Path) -> None:
    """Test derive_health_state returns ONLINE, DEGRADED, OFFLINE, UNKNOWN appropriately."""
    db = Database(tmp_path / "proc_deriv.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(
        home_dir=tmp_path,
        health_degraded_threshold_seconds=60,
        health_offline_threshold_seconds=120,
    )
    trust_mgr = TrustManager(db)
    processor = TelemetryProcessor(db, config, trust_mgr)

    now = datetime.datetime.now(datetime.UTC)

    # 1. Heartbeat 10s ago -> ONLINE
    recent = (now - datetime.timedelta(seconds=10)).isoformat()
    assert processor.derive_health_state(recent, "ONLINE") == DeviceHealthState.ONLINE

    # 2. Heartbeat 80s ago -> DEGRADED
    degraded = (now - datetime.timedelta(seconds=80)).isoformat()
    assert processor.derive_health_state(degraded, "ONLINE") == DeviceHealthState.DEGRADED

    # 3. Heartbeat 200s ago -> OFFLINE
    offline = (now - datetime.timedelta(seconds=200)).isoformat()
    assert processor.derive_health_state(offline, "ONLINE") == DeviceHealthState.OFFLINE

    # 4. Connectivity reported OFFLINE -> OFFLINE
    assert processor.derive_health_state(recent, "OFFLINE") == DeviceHealthState.OFFLINE

    # 5. Corrupted timestamp -> UNKNOWN
    assert processor.derive_health_state("NOT_ISO_DATE") == DeviceHealthState.UNKNOWN


def test_cli_telemetry_edge_cases(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI telemetry commands error branches and missing devices."""
    home_dir = str(tmp_path / "gm_tel_edges")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # Overview with no trusted devices
    code_ov = main(["--home-dir", home_dir, "telemetry"])
    assert code_ov == 0
    assert "No active trusted devices" in capsys.readouterr().out

    # Status with no trusted devices
    code_st = main(["--home-dir", home_dir, "telemetry", "status"])
    assert code_st == 1
    assert "Device ID required" in capsys.readouterr().out

    # History with no devices
    code_h = main(["--home-dir", home_dir, "telemetry", "history"])
    assert code_h == 1
    assert "Device ID required" in capsys.readouterr().out

    # Refresh non-existent device
    code_r = main(["--home-dir", home_dir, "telemetry", "refresh", "GM-C-99999999"])
    assert code_r == 1
    assert "not an active trusted device" in capsys.readouterr().out

    # Pause missing device
    with pytest.raises(SystemExit) as excinfo:
        main(["--home-dir", home_dir, "telemetry", "pause"])
    assert excinfo.value.code == 2

    # Resume missing device
    with pytest.raises(SystemExit) as excinfo:
        main(["--home-dir", home_dir, "telemetry", "resume"])
    assert excinfo.value.code == 2
