"""Device and platform detection for Termux and Linux environments."""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass

from guardianmesh.core.paths import is_android, is_linux, is_root, is_termux


@dataclass
class PlatformInfo:
    """Detailed information about the runtime host environment."""

    system: str
    release: str
    machine: str
    python_version: str
    is_termux: bool
    is_android: bool
    is_linux: bool
    is_root: bool
    termux_prefix: str | None = None
    termux_version: str | None = None

    @property
    def platform_name(self) -> str:
        """User-friendly platform identification."""
        if self.is_termux:
            return "Termux on Android"
        elif self.is_android:
            return "Android (User space)"
        elif self.is_linux:
            return f"Linux ({self.machine})"
        return f"{self.system} ({self.machine})"

    def to_dict(self) -> dict[str, str | bool | None]:
        """Convert platform details to dictionary."""
        return {
            "platform_name": self.platform_name,
            "system": self.system,
            "release": self.release,
            "machine": self.machine,
            "python_version": self.python_version,
            "is_termux": self.is_termux,
            "is_android": self.is_android,
            "is_linux": self.is_linux,
            "is_root": self.is_root,
            "termux_prefix": self.termux_prefix,
            "termux_version": self.termux_version,
        }


def get_platform_info() -> PlatformInfo:
    """Detect current system architecture, Termux status, and Python environment."""
    termux = is_termux()
    android = is_android()
    linux = is_linux()
    root = is_root()

    return PlatformInfo(
        system=platform.system(),
        release=platform.release(),
        machine=platform.machine(),
        python_version=f"{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}",
        is_termux=termux,
        is_android=android,
        is_linux=linux,
        is_root=root,
        termux_prefix=os.environ.get("PREFIX") if termux else None,
        termux_version=os.environ.get("TERMUX_VERSION") if termux else None,
    )
