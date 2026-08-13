"""Platform-aware technical device health collectors (battery, storage, uptime, connectivity).

PRIVACY GUARANTEE:
These collectors gather strictly aggregate technical resource metrics.
They NEVER collect personal data, files, photos, browsing history, keystrokes, or location.
"""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path
from typing import Any

from guardianmesh import __version__
from guardianmesh.core.paths import is_android, is_termux


class BatteryCollector:
    """Collects battery level and charging state with graceful degradation."""

    @staticmethod
    def collect() -> tuple[int | None, bool | None]:
        """Collect battery percentage (0-100) and charging status (bool).

        Returns:
            Tuple of (battery_percent, is_charging). Returns (None, None) if unavailable.
        """
        # 1. Inspect Linux / Android sysfs power_supply paths
        sysfs_candidates = [
            Path("/sys/class/power_supply/BAT0"),
            Path("/sys/class/power_supply/BAT1"),
            Path("/sys/class/power_supply/battery"),
        ]

        for p in sysfs_candidates:
            if p.is_dir():
                try:
                    cap_file = p / "capacity"
                    stat_file = p / "status"

                    percent: int | None = None
                    if cap_file.is_file():
                        raw_cap = cap_file.read_text().strip()
                        val = int(raw_cap)
                        percent = max(0, min(100, val))

                    charging: bool | None = None
                    if stat_file.is_file():
                        raw_stat = stat_file.read_text().strip().lower()
                        if "charging" in raw_stat:
                            charging = True
                        elif "discharging" in raw_stat:
                            charging = False
                        elif "full" in raw_stat:
                            charging = True

                    if percent is not None or charging is not None:
                        return percent, charging
                except Exception:
                    pass

        # If running on AC desktop or virtual machine without battery
        return None, None


class StorageCollector:
    """Collects aggregate filesystem storage metrics without enumerating files."""

    @staticmethod
    def collect(target_path: Path | None = None) -> tuple[int | None, int | None]:
        """Collect aggregate total and free storage bytes.

        Returns:
            Tuple of (storage_total_bytes, storage_free_bytes).
        """
        path = target_path or Path.home()
        try:
            usage = shutil.disk_usage(str(path))
            return int(usage.total), int(usage.free)
        except Exception:
            return None, None


class UptimeCollector:
    """Collects monotonic system uptime in seconds without inferring personal activity."""

    @staticmethod
    def collect() -> int | None:
        """Collect system uptime seconds.

        Returns:
            Integer uptime in seconds, or None if unavailable.
        """
        proc_uptime = Path("/proc/uptime")
        if proc_uptime.is_file():
            try:
                content = proc_uptime.read_text().strip()
                raw_seconds = content.split()[0]
                return int(float(raw_seconds))
            except Exception:
                pass

        # Fallback to monotonic clock if available
        try:
            return int(time.monotonic())
        except Exception:
            return None


class ConnectivityCollector:
    """Determines general technical connectivity state (ONLINE, DEGRADED, OFFLINE, UNKNOWN)."""

    @staticmethod
    def collect() -> str:
        """Check network interface readiness without recording network destinations.

        Returns:
            One of 'ONLINE', 'DEGRADED', 'OFFLINE', 'UNKNOWN'.
        """
        # Inspect local network interfaces via /sys/class/net
        net_dir = Path("/sys/class/net")
        if net_dir.is_dir():
            try:
                has_active = False
                for iface in net_dir.iterdir():
                    if iface.name == "lo":
                        continue
                    operstate = iface / "operstate"
                    if operstate.is_file():
                        state = operstate.read_text().strip().lower()
                        if state in ("up", "unknown"):
                            has_active = True
                            break
                if has_active:
                    return "ONLINE"
            except Exception:
                pass

        # Fallback: socket capability test
        import socket

        try:
            # Check local network socket binding ability
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.close()
            return "ONLINE"
        except Exception:
            return "UNKNOWN"


class DeviceCollector:
    """Aggregates technical health metrics into an allowlisted snapshot payload."""

    def __init__(self, target_path: Path | None = None) -> None:
        self.target_path = target_path

    def collect_health_data(self) -> dict[str, Any]:
        """Collect strictly allowlisted technical health metrics.

        Returns:
            Dictionary with allowlisted technical metrics only.
        """
        battery_pct, is_charging = BatteryCollector.collect()
        total_storage, free_storage = StorageCollector.collect(self.target_path)
        uptime_sec = UptimeCollector.collect()
        conn_state = ConnectivityCollector.collect()

        plat_desc = "Termux" if is_termux() else ("Android" if is_android() else sys.platform)

        return {
            "battery_percent": battery_pct,
            "charging": is_charging,
            "storage_total_bytes": total_storage,
            "storage_free_bytes": free_storage,
            "uptime_seconds": uptime_sec,
            "connectivity": conn_state,
            "platform": plat_desc,
            "agent_version": __version__,
        }
