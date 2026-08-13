"""Terminal typography, dynamic width adaptation, table generation, and color formatting."""

from __future__ import annotations

import datetime
import os
import shutil
import sys
from collections.abc import Sequence
from typing import Any


class TerminalFormatter:
    """Handles adaptive terminal layout, color styling, and table formatting across diverse column widths."""

    def __init__(
        self,
        color_enabled: bool = True,
        ascii_borders: bool = False,
        explicit_width: int | None = None,
    ) -> None:
        self.explicit_width = explicit_width
        self.ascii_borders = ascii_borders

        # Check NO_COLOR specification (https://no-color.org) and TTY status
        if "NO_COLOR" in os.environ or "GUARDIANMESH_NO_COLOR" in os.environ:
            self.color_enabled = False
        elif not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
            self.color_enabled = False
        else:
            self.color_enabled = color_enabled

    def get_width(self) -> int:
        """Resolve current terminal width with safe bounds (40 to 120 columns)."""
        if self.explicit_width:
            return max(40, min(self.explicit_width, 120))
        try:
            w = shutil.get_terminal_size(fallback=(80, 24)).columns
            return max(40, min(w, 120))
        except Exception:
            return 80

    def colorize(self, text: str, color: str = "", bold: bool = False, dim: bool = False) -> str:
        """Apply ANSI color styling if enabled."""
        if not self.color_enabled:
            return text

        codes: list[str] = []
        if bold:
            codes.append("1")
        if dim:
            codes.append("2")

        color_map = {
            "red": "31",
            "green": "32",
            "yellow": "33",
            "blue": "34",
            "magenta": "35",
            "cyan": "36",
            "white": "37",
        }
        if color.lower() in color_map:
            codes.append(color_map[color.lower()])

        if not codes:
            return text

        prefix = f"\033[{';'.join(codes)}m"
        suffix = "\033[0m"
        return f"{prefix}{text}{suffix}"

    def rule(self, char: str | None = None, width: int | None = None) -> str:
        """Generate a horizontal divider rule."""
        w = width or self.get_width()
        if not char:
            char = "-" if self.ascii_borders else "─"
        return char * w

    def double_rule(self, width: int | None = None) -> str:
        """Generate a double horizontal divider rule."""
        w = width or self.get_width()
        char = "=" if self.ascii_borders else "═"
        return char * w

    def format_table(
        self,
        headers: Sequence[str],
        rows: Sequence[Sequence[Any]],
        alignments: Sequence[str] | None = None,
        max_col_widths: Sequence[int] | None = None,
    ) -> str:
        """Render an adaptive table fitting terminal width.

        Args:
            headers: List of column header titles.
            rows: Matrix of row values.
            alignments: List of alignment chars ('<' for left, '>' for right, '^' for center).
            max_col_widths: Optional list of explicit column width caps.

        Returns:
            Formatted string representation of table.
        """
        if not headers:
            return ""

        term_width = self.get_width()
        col_count = len(headers)
        aligns = list(alignments) if alignments else ["<"] * col_count

        # Compute initial content widths
        col_widths: list[int] = [len(str(h)) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                if i < col_count:
                    col_widths[i] = max(col_widths[i], len(str(val)))

        if max_col_widths:
            for i, cap in enumerate(max_col_widths):
                if i < col_count and cap > 0:
                    col_widths[i] = min(col_widths[i], cap)

        # Scale down if total width exceeds terminal width
        total_width = sum(col_widths) + (col_count - 1) * 2
        if total_width > term_width:
            excess = total_width - term_width
            # Reduce largest columns proportionally
            for _ in range(excess):
                max_idx = col_widths.index(max(col_widths))
                if col_widths[max_idx] > 8:
                    col_widths[max_idx] -= 1

        lines: list[str] = []

        # Header line
        header_cells: list[str] = []
        for i, h in enumerate(headers):
            w = col_widths[i]
            val_str = str(h)[:w]
            align = aligns[i] if i < len(aligns) else "<"
            header_cells.append(f"{val_str:{align}{w}}")

        lines.append("  ".join(header_cells))
        lines.append(self.rule(width=min(term_width, sum(col_widths) + (col_count - 1) * 2)))

        # Data rows
        for row in rows:
            row_cells: list[str] = []
            for i, _h in enumerate(headers):
                w = col_widths[i]
                val = str(row[i]) if i < len(row) else ""
                if len(val) > w:
                    val = val[: max(1, w - 3)] + "..."
                align = aligns[i] if i < len(aligns) else "<"
                row_cells.append(f"{val:{align}{w}}")
            lines.append("  ".join(row_cells))

        return "\n".join(lines)

    @staticmethod
    def format_relative_time(iso_str: str | None) -> str:
        """Format an ISO timestamp into compact relative duration (e.g. 14s ago, 5m ago)."""
        if not iso_str:
            return "never"
        try:
            dt = datetime.datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                now = datetime.datetime.now()
            else:
                now = datetime.datetime.now(dt.tzinfo)

            seconds = int((now - dt).total_seconds())

            if seconds < 0:
                return "just now"
            if seconds < 60:
                return f"{seconds}s ago"
            minutes = round(seconds / 60)
            if minutes < 60:
                return f"{minutes}m ago"
            hours = round(minutes / 60)
            if hours < 24:
                return f"{hours}h ago"
            days = round(hours / 24)
            return f"{days}d ago"
        except Exception:
            return iso_str[:19].replace("T", " ")
