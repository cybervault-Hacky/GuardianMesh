"""Parent console and unified dashboard subsystem for GuardianMesh (Phase 5: Console)."""

from __future__ import annotations

from guardianmesh.console.dashboard import DashboardController
from guardianmesh.console.formatters import TerminalFormatter
from guardianmesh.console.models import DashboardSnapshot, DeviceView
from guardianmesh.console.navigation import ConsoleNavigator
from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.console.services import ConsoleService

__all__ = [
    "ConsoleNavigator",
    "ConsoleRenderer",
    "ConsoleService",
    "DashboardController",
    "DashboardSnapshot",
    "DeviceView",
    "TerminalFormatter",
]
