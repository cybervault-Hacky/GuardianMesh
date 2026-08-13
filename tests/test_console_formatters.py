"""Tests for TerminalFormatter width bounds, color handling, tables, and relative time."""

from __future__ import annotations

import datetime

import pytest

from guardianmesh.console.formatters import TerminalFormatter


def test_terminal_formatter_widths() -> None:
    """Test explicit and bounded terminal widths."""
    fmt_40 = TerminalFormatter(explicit_width=40)
    assert fmt_40.get_width() == 40

    fmt_60 = TerminalFormatter(explicit_width=60)
    assert fmt_60.get_width() == 60

    fmt_120 = TerminalFormatter(explicit_width=120)
    assert fmt_120.get_width() == 120

    # Bounds clamp
    fmt_too_small = TerminalFormatter(explicit_width=20)
    assert fmt_too_small.get_width() == 40

    fmt_too_large = TerminalFormatter(explicit_width=200)
    assert fmt_too_large.get_width() == 120


def test_terminal_formatter_colors_and_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test ANSI colorization and NO_COLOR compliance."""
    # When color enabled
    fmt_col = TerminalFormatter(color_enabled=True, explicit_width=80)
    fmt_col.color_enabled = True
    colored = fmt_col.colorize("Status OK", "green", bold=True)
    assert "\033[" in colored
    assert "Status OK" in colored

    # When color disabled
    fmt_no_col = TerminalFormatter(color_enabled=False)
    assert fmt_no_col.colorize("Status OK", "green", bold=True) == "Status OK"

    # NO_COLOR environment variable support
    monkeypatch.setenv("NO_COLOR", "1")
    fmt_env = TerminalFormatter()
    assert fmt_env.color_enabled is False


def test_table_formatting_and_narrow_adaptation() -> None:
    """Test adaptive table generation on narrow vs wide widths."""
    headers = ["ID", "LABEL", "STATUS"]
    rows = [
        ["GM-C-83A1F72C", "Very Long Child Device Phone Label", "ONLINE"],
        ["GM-C-19A84E72", "Tablet", "OFFLINE"],
    ]

    fmt_80 = TerminalFormatter(explicit_width=80, color_enabled=False)
    tbl_80 = fmt_80.format_table(headers, rows)
    assert "GM-C-83A1F72C" in tbl_80
    assert "ONLINE" in tbl_80

    # Narrow 40-column adaptation
    fmt_40 = TerminalFormatter(explicit_width=40, color_enabled=False)
    tbl_40 = fmt_40.format_table(headers, rows)
    assert "GM-C-" in tbl_40
    # Every line should be <= 40 chars
    for line in tbl_40.splitlines():
        assert len(line) <= 45


def test_relative_time_formatting() -> None:
    """Test relative duration formatting."""
    now = datetime.datetime.now(datetime.UTC)

    t_10s = (now - datetime.timedelta(seconds=10)).isoformat()
    assert "s ago" in TerminalFormatter.format_relative_time(t_10s)

    t_5m = (now - datetime.timedelta(minutes=5)).isoformat()
    assert "5m ago" == TerminalFormatter.format_relative_time(t_5m)

    t_3h = (now - datetime.timedelta(hours=3)).isoformat()
    assert "3h ago" == TerminalFormatter.format_relative_time(t_3h)

    assert TerminalFormatter.format_relative_time(None) == "never"
