"""Tests for platform-aware technical health collectors: battery, storage, uptime, connectivity."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from guardianmesh.device.collectors import (
    BatteryCollector,
    ConnectivityCollector,
    DeviceCollector,
    StorageCollector,
    UptimeCollector,
)


def test_battery_collector_sysfs(tmp_path: Path) -> None:
    """Test BatteryCollector reading from Linux/Android sysfs power_supply files."""
    bat_dir = tmp_path / "sys_class_power" / "BAT0"
    bat_dir.mkdir(parents=True)
    (bat_dir / "capacity").write_text("85\n")
    (bat_dir / "status").write_text("Charging\n")

    with patch("guardianmesh.device.collectors.Path") as mock_path:

        def path_side_effect(arg):
            if "/sys/class/power_supply/BAT0" in str(arg):
                return bat_dir
            return Path(arg)

        mock_path.side_effect = path_side_effect
        percent, charging = BatteryCollector.collect()
        assert percent == 85
        assert charging is True


def test_battery_collector_unavailable() -> None:
    """Test BatteryCollector degrades gracefully when no battery files exist."""
    with patch("guardianmesh.device.collectors.Path") as mock_path:
        mock_obj = MagicMock()
        mock_obj.is_dir.return_value = False
        mock_path.return_value = mock_obj
        percent, charging = BatteryCollector.collect()
        assert percent is None
        assert charging is None


def test_storage_collector(tmp_path: Path) -> None:
    """Test StorageCollector returns aggregate byte values without inspecting files."""
    mock_usage = MagicMock(total=100_000_000_000, free=40_000_000_000)
    with patch("shutil.disk_usage", return_value=mock_usage):
        total, free = StorageCollector.collect(tmp_path)
        assert total == 100_000_000_000
        assert free == 40_000_000_000


def test_uptime_collector_proc(tmp_path: Path) -> None:
    """Test UptimeCollector reading /proc/uptime."""
    uptime_file = tmp_path / "uptime"
    uptime_file.write_text("3600.50 14200.20\n")

    with patch("guardianmesh.device.collectors.Path") as mock_path:

        def side_effect(arg):
            if str(arg) == "/proc/uptime":
                return uptime_file
            return Path(arg)

        mock_path.side_effect = side_effect
        secs = UptimeCollector.collect()
        assert secs == 3600


def test_connectivity_collector_sysfs(tmp_path: Path) -> None:
    """Test ConnectivityCollector inspecting network operstate."""
    net_dir = tmp_path / "sys_net"
    eth0 = net_dir / "eth0"
    eth0.mkdir(parents=True)
    (eth0 / "operstate").write_text("up\n")

    with patch("guardianmesh.device.collectors.Path") as mock_path:

        def side_effect(arg):
            if str(arg) == "/sys/class/net":
                return net_dir
            return Path(arg)

        mock_path.side_effect = side_effect
        state = ConnectivityCollector.collect()
        assert state == "ONLINE"


def test_device_collector_aggregator(tmp_path: Path) -> None:
    """Test DeviceCollector aggregates strictly allowlisted technical metrics."""
    collector = DeviceCollector(target_path=tmp_path)
    data = collector.collect_health_data()

    assert "agent_version" in data
    assert "connectivity" in data
    assert "platform" in data
    assert "battery_percent" in data
    assert "storage_free_bytes" in data

    # Verify no personal data keys exist
    for forbidden in ["messages", "contacts", "photos", "files", "browser_history", "location", "screen"]:
        assert forbidden not in data
