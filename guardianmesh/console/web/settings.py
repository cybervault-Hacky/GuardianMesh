"""Local, privacy-safe preferences for the Parent Console web UI."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from guardianmesh.core.config import GuardianConfig

VALID_LANGUAGES = {"en", "hi", "hinglish", "pt", "fr", "zh", "ko", "es"}
VALID_THEMES = {"system", "light", "dark"}


@dataclass(frozen=True)
class ConsoleUISettings:
    """User-facing preferences stored locally in the GuardianMesh home."""

    language: str = "en"
    theme: str = "system"
    notifications: bool = True
    open_browser: bool = True
    startup_page: str = "home"
    data_retention_days: int = 30
    session_timeout_minutes: int = 30

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConsoleUISettings:
        language = str(data.get("language", "en"))
        theme = str(data.get("theme", "system"))
        if language not in VALID_LANGUAGES:
            language = "en"
        if theme not in VALID_THEMES:
            theme = "system"
        retention = int(data.get("data_retention_days", 30))
        timeout = int(data.get("session_timeout_minutes", 30))
        startup_page = str(data.get("startup_page", "home"))
        if startup_page not in {"home", "devices", "screen", "alerts", "activity", "settings"}:
            startup_page = "home"
        return cls(
            language=language,
            theme=theme,
            notifications=bool(data.get("notifications", True)),
            open_browser=bool(data.get("open_browser", True)),
            startup_page=startup_page,
            data_retention_days=max(1, min(retention, 3650)),
            session_timeout_minutes=max(5, min(timeout, 480)),
        )


class ConsoleUISettingsStore:
    """Persist only local UI preferences; never store secrets or device content."""

    def __init__(self, config: GuardianConfig) -> None:
        self._path = Path(config.data_dir) / "console_ui_settings.json"

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> ConsoleUISettings:
        if not self._path.is_file():
            return ConsoleUISettings()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ConsoleUISettings()
        if not isinstance(data, dict):
            return ConsoleUISettings()
        return ConsoleUISettings.from_dict(data)

    def save(self, settings: ConsoleUISettings) -> Path:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._path.parent.chmod(0o700)
        except OSError:
            pass
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(settings), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self._path)
        try:
            self._path.chmod(0o600)
        except OSError:
            pass
        return self._path

    def update(self, changes: dict[str, Any]) -> ConsoleUISettings:
        current = asdict(self.load())
        safe_changes = {
            key: value
            for key, value in changes.items()
            if key
            in {
                "language",
                "theme",
                "notifications",
                "open_browser",
                "startup_page",
                "data_retention_days",
                "session_timeout_minutes",
            }
        }
        current.update(safe_changes)
        merged = ConsoleUISettings.from_dict(current)
        self.save(merged)
        return merged
