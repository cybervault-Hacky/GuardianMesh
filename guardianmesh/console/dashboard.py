"""Dashboard controller supporting single-shot inspection, JSON export, and watch mode."""

from __future__ import annotations

import sys
import time

from guardianmesh.console.models import DashboardSnapshot
from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.console.services import ConsoleService
from guardianmesh.core.config import GuardianConfig


class DashboardController:
    """Controls dashboard data acquisition, rendering, and watch mode refreshes."""

    def __init__(
        self,
        service: ConsoleService,
        renderer: ConsoleRenderer | None = None,
        config: GuardianConfig | None = None,
    ) -> None:
        self.service = service
        self.renderer = renderer or ConsoleRenderer()
        self.config = config or GuardianConfig()

    def get_snapshot(self) -> DashboardSnapshot:
        """Fetch fresh dashboard snapshot from domain services."""
        return self.service.get_dashboard_snapshot()

    def render(self, format_json: bool = False) -> str:
        """Fetch and render the dashboard snapshot."""
        snapshot = self.get_snapshot()
        return self.renderer.render_dashboard(snapshot, format_json=format_json)

    def watch(
        self,
        interval_seconds: int | None = None,
        format_json: bool = False,
        max_iterations: int | None = None,
    ) -> None:
        """Continuously refresh dashboard at configured interval until interrupted."""
        interval = max(1, interval_seconds or self.config.console_refresh_interval_seconds)
        iterations = 0

        try:
            while True:
                if not format_json and sys.stdout.isatty():
                    # Clear terminal screen cleanly (ANSI escape)
                    print("\033[2J\033[H", end="")

                output = self.render(format_json=format_json)
                print(output)

                iterations += 1
                if max_iterations and iterations >= max_iterations:
                    break

                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nDashboard watch exited.")
