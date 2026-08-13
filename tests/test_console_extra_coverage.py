"""Extra coverage tests for Console navigation, dashboard watch loop, and renderers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from guardianmesh.cli.main import main
from guardianmesh.console.dashboard import DashboardController
from guardianmesh.console.formatters import TerminalFormatter
from guardianmesh.console.navigation import ConsoleNavigator
from guardianmesh.console.renderer import ConsoleRenderer
from guardianmesh.console.services import ConsoleService
from guardianmesh.core.config import GuardianConfig
from guardianmesh.storage.database import Database
from guardianmesh.storage.migrations import MigrationManager


def test_console_navigation_all_options(tmp_path: Path) -> None:
    """Test ConsoleNavigator routes all menu options 1 through 8 and invalid choice."""
    db = Database(tmp_path / "nav.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    service = ConsoleService(db, config)
    renderer = ConsoleRenderer(TerminalFormatter(color_enabled=False))
    navigator = ConsoleNavigator(service, renderer)

    # Sequence of user selections: 1, 2, 3, 4, 5, 6, 7, 99 (invalid), 8 (exit)
    with patch("builtins.input", side_effect=["1", "2", "3", "4", "5", "6", "7", "99", "8"]):
        code = navigator.run_interactive_menu()
        assert code == 0


def test_dashboard_watch_loop(tmp_path: Path) -> None:
    """Test DashboardController.watch runs max_iterations and exits cleanly."""
    db = Database(tmp_path / "watch.db")
    MigrationManager().apply_migrations(db)
    config = GuardianConfig(home_dir=tmp_path)
    service = ConsoleService(db, config)
    controller = DashboardController(service, config=config)

    # Run 2 iterations in watch mode
    controller.watch(interval_seconds=1, max_iterations=2)


def test_renderer_views_coverage() -> None:
    """Test ConsoleRenderer methods with colored and uncolored outputs."""
    fmt = TerminalFormatter(color_enabled=True, explicit_width=80)
    renderer = ConsoleRenderer(fmt)

    # Render empty states
    assert "No trusted devices" in renderer.render_device_list([])
    assert "No alerts found" in renderer.render_alerts([])
    assert "No policies configured" in renderer.render_policies([])
    assert "No recent activity" in renderer.render_audit([])

    # Render status
    stat_out = renderer.render_status({"Identity": "READY", "Pairing": "DISABLED", "Storage": "ERROR"})
    assert "Identity" in stat_out
    assert "READY" in stat_out

    # Render device detail without health
    from guardianmesh.console.models import DeviceView

    view_no_health = DeviceView(
        device_id="GM-C-19A84E72",
        label=None,
        role="CHILD",
        trust_status="ACTIVE",
        fingerprint="SHA256:abcd",
        created_at="2026-08-13T01:00:00Z",
    )
    detail_str = renderer.render_device_detail(view_no_health)
    assert "No health telemetry" in detail_str


def test_cli_console_and_devices_json_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Test CLI commands in --json mode."""
    home_dir = str(tmp_path / "gm_json_cli")
    main(["--home-dir", home_dir, "init", "--role", "parent"])
    capsys.readouterr()

    # console pairing --json
    assert main(["--home-dir", home_dir, "console", "pairing", "--json"]) == 0
    assert "pairing" in capsys.readouterr().out

    # console audit --json
    assert main(["--home-dir", home_dir, "console", "audit", "--json"]) == 0
    assert "audit_events" in capsys.readouterr().out

    # console status --json
    assert main(["--home-dir", home_dir, "console", "status", "--json"]) == 0
    assert "subsystems" in capsys.readouterr().out

    # config --json
    assert main(["--home-dir", home_dir, "config", "--json"]) == 0
    assert "version" in capsys.readouterr().out
