"""Configuration management for GuardianMesh with safe defaults and environment overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardianmesh.core.errors import ConfigError
from guardianmesh.core.paths import ensure_directory, get_default_home_dir

VALID_ROLES = {"PARENT", "CHILD"}
VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL"}


@dataclass
class GuardianConfig:
    """GuardianMesh runtime configuration."""

    version: str = "0.7.0"
    phase: str = "Vista"
    home_dir: Path = field(default_factory=get_default_home_dir)
    data_dir: Path = field(default=Path())
    database_path: Path = field(default=Path())
    keys_dir: Path = field(default=Path())
    log_dir: Path = field(default=Path())
    log_level: str = "INFO"
    default_role: str = "PARENT"
    auto_migrate: bool = True
    pairing_enabled: bool = True
    telemetry_enabled: bool = True

    # SMTP / Email Configuration (Phase 2)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    smtp_from_address: str | None = None

    # Pairing & OTP Security Limits (Phase 2)
    otp_expiration_seconds: int = 300
    session_expiration_seconds: int = 600
    otp_resend_cooldown_seconds: int = 30
    max_otp_attempts: int = 5
    nonce_expiration_seconds: int = 300

    # Telemetry & Device Health Configuration (Phase 3: Pulse)
    heartbeat_interval_seconds: int = 30
    health_sampling_interval_seconds: int = 30
    health_degraded_threshold_seconds: int = 60
    health_offline_threshold_seconds: int = 120
    timestamp_skew_tolerance_seconds: int = 120
    telemetry_retention_days: int = 7
    telemetry_max_retries: int = 3
    telemetry_backoff_base_seconds: float = 2.0
    telemetry_backoff_max_seconds: float = 30.0

    # Policy & Alert Engine Configuration (Phase 4: Sentinel)
    alert_dedup_cooldown_seconds: int = 300
    alert_retention_days: int = 30
    default_battery_threshold: int = 20
    default_storage_threshold: int = 10
    default_offline_duration_seconds: int = 120
    default_degraded_duration_seconds: int = 60
    policy_evaluation_enabled: bool = True

    # Parent Console & Dashboard Configuration (Phase 5: Console)
    console_refresh_interval_seconds: int = 5
    console_max_activity_entries: int = 5
    console_color_enabled: bool = True
    console_ascii_borders: bool = False

    # Secure Transport Configuration (Phase 6: Nexus)
    transport_enabled: bool = True
    transport_listen_host: str = "0.0.0.0"
    transport_listen_port: int = 8443
    transport_session_ttl_seconds: int = 3600
    transport_heartbeat_interval_seconds: int = 15
    transport_heartbeat_timeout_seconds: int = 45
    transport_max_reconnect_attempts: int = 5
    transport_reconnect_initial_delay_seconds: float = 1.0
    transport_reconnect_max_delay_seconds: float = 30.0
    transport_max_message_size_bytes: int = 65536
    transport_replay_window_size: int = 128

    # Screen View Configuration (Phase 7: Vista)
    screen_view_enabled: bool = True
    screen_view_default_max_duration_seconds: int = 300  # 5 minutes
    screen_view_max_duration_seconds: int = 3600  # 1 hour hard cap
    screen_view_default_fps: int = 10
    screen_view_max_fps: int = 30
    screen_view_default_width: int = 1280
    screen_view_default_height: int = 720
    screen_view_max_width: int = 1920
    screen_view_max_height: int = 1080
    screen_view_max_frame_bytes: int = 4 * 1024 * 1024
    screen_view_max_queue_size: int = 30
    screen_view_inactivity_timeout_seconds: int = 60

    def __post_init__(self) -> None:
        """Resolve dependent directory paths and validate configuration boundaries."""
        self.home_dir = Path(self.home_dir).expanduser().resolve()

        if not self.data_dir or self.data_dir == Path():
            self.data_dir = self.home_dir / "data"
        else:
            self.data_dir = Path(self.data_dir).expanduser().resolve()

        if not self.database_path or self.database_path == Path():
            self.database_path = self.data_dir / "guardian.db"
        else:
            self.database_path = Path(self.database_path).expanduser().resolve()

        if not self.keys_dir or self.keys_dir == Path():
            self.keys_dir = self.home_dir / "keys"
        else:
            self.keys_dir = Path(self.keys_dir).expanduser().resolve()

        if not self.log_dir or self.log_dir == Path():
            self.log_dir = self.home_dir / "logs"
        else:
            self.log_dir = Path(self.log_dir).expanduser().resolve()

        self.default_role = self.default_role.upper()
        if self.default_role not in VALID_ROLES:
            raise ConfigError(f"Invalid default_role '{self.default_role}'. Must be PARENT or CHILD.")

        self.log_level = self.log_level.upper()
        if self.log_level not in VALID_LOG_LEVELS:
            raise ConfigError(f"Invalid log_level '{self.log_level}'. Must be one of {VALID_LOG_LEVELS}.")

        # Telemetry bounds validation
        if self.heartbeat_interval_seconds <= 0:
            raise ConfigError("heartbeat_interval_seconds must be positive.")
        if self.health_sampling_interval_seconds <= 0:
            raise ConfigError("health_sampling_interval_seconds must be positive.")
        if self.telemetry_retention_days <= 0:
            raise ConfigError("telemetry_retention_days must be at least 1 day.")
        if self.timestamp_skew_tolerance_seconds < 0:
            raise ConfigError("timestamp_skew_tolerance_seconds cannot be negative.")

        # Policy & Alert bounds validation
        if self.alert_dedup_cooldown_seconds < 0:
            raise ConfigError("alert_dedup_cooldown_seconds cannot be negative.")
        if self.alert_retention_days <= 0:
            raise ConfigError("alert_retention_days must be at least 1 day.")
        if not (1 <= self.default_battery_threshold <= 99):
            raise ConfigError("default_battery_threshold must be between 1 and 99.")
        if not (1 <= self.default_storage_threshold <= 99):
            raise ConfigError("default_storage_threshold must be between 1 and 99.")

        # Console bounds validation
        if self.console_refresh_interval_seconds <= 0:
            raise ConfigError("console_refresh_interval_seconds must be positive.")
        if self.console_max_activity_entries <= 0:
            raise ConfigError("console_max_activity_entries must be positive.")

        # Transport bounds validation (Phase 6: Nexus)
        if self.transport_session_ttl_seconds <= 0:
            raise ConfigError("transport_session_ttl_seconds must be positive.")
        if self.transport_heartbeat_interval_seconds <= 0:
            raise ConfigError("transport_heartbeat_interval_seconds must be positive.")
        if self.transport_heartbeat_timeout_seconds <= 0:
            raise ConfigError("transport_heartbeat_timeout_seconds must be positive.")
        if self.transport_max_reconnect_attempts < 0:
            raise ConfigError("transport_max_reconnect_attempts cannot be negative.")
        if self.transport_reconnect_initial_delay_seconds <= 0:
            raise ConfigError("transport_reconnect_initial_delay_seconds must be positive.")
        if self.transport_reconnect_max_delay_seconds < self.transport_reconnect_initial_delay_seconds:
            raise ConfigError("transport_reconnect_max_delay_seconds cannot be less than initial delay.")
        if self.transport_max_message_size_bytes <= 0:
            raise ConfigError("transport_max_message_size_bytes must be positive.")
        if self.transport_replay_window_size <= 0:
            raise ConfigError("transport_replay_window_size must be positive.")
        if not (1 <= self.transport_listen_port <= 65535):
            raise ConfigError("transport_listen_port must be between 1 and 65535.")

        # Screen view bounds validation (Phase 7: Vista)
        if self.screen_view_default_max_duration_seconds <= 0:
            raise ConfigError("screen_view_default_max_duration_seconds must be positive.")
        if self.screen_view_max_duration_seconds < self.screen_view_default_max_duration_seconds:
            raise ConfigError(
                "screen_view_max_duration_seconds must be >= screen_view_default_max_duration_seconds."
            )
        if self.screen_view_default_fps <= 0:
            raise ConfigError("screen_view_default_fps must be positive.")
        if self.screen_view_max_fps < self.screen_view_default_fps:
            raise ConfigError(
                "screen_view_max_fps must be >= screen_view_default_fps."
            )
        if self.screen_view_max_width <= 0 or self.screen_view_max_height <= 0:
            raise ConfigError("screen_view_max_width and max_height must be positive.")
        if self.screen_view_max_frame_bytes <= 0:
            raise ConfigError("screen_view_max_frame_bytes must be positive.")
        if self.screen_view_max_queue_size <= 0:
            raise ConfigError("screen_view_max_queue_size must be positive.")
        if self.screen_view_inactivity_timeout_seconds <= 0:
            raise ConfigError("screen_view_inactivity_timeout_seconds must be positive.")

    @property
    def config_file_path(self) -> Path:
        """Path to the config.json file."""
        return self.home_dir / "config.json"

    @property
    def log_file_path(self) -> Path:
        """Path to the main log file."""
        return self.log_dir / "guardian.log"

    def ensure_directories(self) -> None:
        """Create all required directories with secure 0700 permissions."""
        ensure_directory(self.home_dir, mode=0o700)
        ensure_directory(self.data_dir, mode=0o700)
        ensure_directory(self.keys_dir, mode=0o700)
        ensure_directory(self.log_dir, mode=0o700)

    def to_dict(self, redact_secrets: bool = False) -> dict[str, Any]:
        """Serialize configuration to a JSON-compatible dictionary."""
        smtp_pass = self.smtp_password
        if redact_secrets and smtp_pass:
            smtp_pass = "[CONFIGURED]"

        return {
            "version": self.version,
            "phase": self.phase,
            "home_dir": str(self.home_dir),
            "data_dir": str(self.data_dir),
            "database_path": str(self.database_path),
            "keys_dir": str(self.keys_dir),
            "log_dir": str(self.log_dir),
            "log_level": self.log_level,
            "default_role": self.default_role,
            "auto_migrate": self.auto_migrate,
            "pairing_enabled": self.pairing_enabled,
            "telemetry_enabled": self.telemetry_enabled,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_username": self.smtp_username,
            "smtp_password": smtp_pass,
            "smtp_use_tls": self.smtp_use_tls,
            "smtp_from_address": self.smtp_from_address,
            "otp_expiration_seconds": self.otp_expiration_seconds,
            "session_expiration_seconds": self.session_expiration_seconds,
            "otp_resend_cooldown_seconds": self.otp_resend_cooldown_seconds,
            "max_otp_attempts": self.max_otp_attempts,
            "nonce_expiration_seconds": self.nonce_expiration_seconds,
            "heartbeat_interval_seconds": self.heartbeat_interval_seconds,
            "health_sampling_interval_seconds": self.health_sampling_interval_seconds,
            "health_degraded_threshold_seconds": self.health_degraded_threshold_seconds,
            "health_offline_threshold_seconds": self.health_offline_threshold_seconds,
            "timestamp_skew_tolerance_seconds": self.timestamp_skew_tolerance_seconds,
            "telemetry_retention_days": self.telemetry_retention_days,
            "telemetry_max_retries": self.telemetry_max_retries,
            "telemetry_backoff_base_seconds": self.telemetry_backoff_base_seconds,
            "telemetry_backoff_max_seconds": self.telemetry_backoff_max_seconds,
            "alert_dedup_cooldown_seconds": self.alert_dedup_cooldown_seconds,
            "alert_retention_days": self.alert_retention_days,
            "default_battery_threshold": self.default_battery_threshold,
            "default_storage_threshold": self.default_storage_threshold,
            "default_offline_duration_seconds": self.default_offline_duration_seconds,
            "default_degraded_duration_seconds": self.default_degraded_duration_seconds,
            "policy_evaluation_enabled": self.policy_evaluation_enabled,
            "console_refresh_interval_seconds": self.console_refresh_interval_seconds,
            "console_max_activity_entries": self.console_max_activity_entries,
            "console_color_enabled": self.console_color_enabled,
            "console_ascii_borders": self.console_ascii_borders,
            "transport_enabled": self.transport_enabled,
            "transport_listen_host": self.transport_listen_host,
            "transport_listen_port": self.transport_listen_port,
            "transport_session_ttl_seconds": self.transport_session_ttl_seconds,
            "transport_heartbeat_interval_seconds": self.transport_heartbeat_interval_seconds,
            "transport_heartbeat_timeout_seconds": self.transport_heartbeat_timeout_seconds,
            "transport_max_reconnect_attempts": self.transport_max_reconnect_attempts,
            "transport_reconnect_initial_delay_seconds": self.transport_reconnect_initial_delay_seconds,
            "transport_reconnect_max_delay_seconds": self.transport_reconnect_max_delay_seconds,
            "transport_max_message_size_bytes": self.transport_max_message_size_bytes,
            "transport_replay_window_size": self.transport_replay_window_size,
            "screen_view_enabled": self.screen_view_enabled,
            "screen_view_default_max_duration_seconds": self.screen_view_default_max_duration_seconds,
            "screen_view_max_duration_seconds": self.screen_view_max_duration_seconds,
            "screen_view_default_fps": self.screen_view_default_fps,
            "screen_view_max_fps": self.screen_view_max_fps,
            "screen_view_default_width": self.screen_view_default_width,
            "screen_view_default_height": self.screen_view_default_height,
            "screen_view_max_width": self.screen_view_max_width,
            "screen_view_max_height": self.screen_view_max_height,
            "screen_view_max_frame_bytes": self.screen_view_max_frame_bytes,
            "screen_view_max_queue_size": self.screen_view_max_queue_size,
            "screen_view_inactivity_timeout_seconds": self.screen_view_inactivity_timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], home_dir: Path | None = None) -> GuardianConfig:
        """Build GuardianConfig from a dictionary with validation."""
        raw_home = data.get("home_dir")
        h_dir = Path(str(raw_home)) if raw_home else (home_dir or get_default_home_dir())
        return cls(
            version=data.get("version", "0.7.0"),
            phase=data.get("phase", "Vista"),
            home_dir=h_dir,
            data_dir=Path(data["data_dir"]) if "data_dir" in data else Path(),
            database_path=Path(data["database_path"]) if "database_path" in data else Path(),
            keys_dir=Path(data["keys_dir"]) if "keys_dir" in data else Path(),
            log_dir=Path(data["log_dir"]) if "log_dir" in data else Path(),
            log_level=data.get("log_level", "INFO"),
            default_role=data.get("default_role", "PARENT"),
            auto_migrate=data.get("auto_migrate", True),
            pairing_enabled=data.get("pairing_enabled", True),
            telemetry_enabled=data.get("telemetry_enabled", True),
            smtp_host=data.get("smtp_host"),
            smtp_port=int(data.get("smtp_port", 587)),
            smtp_username=data.get("smtp_username"),
            smtp_password=data.get("smtp_password"),
            smtp_use_tls=bool(data.get("smtp_use_tls", True)),
            smtp_from_address=data.get("smtp_from_address"),
            otp_expiration_seconds=int(data.get("otp_expiration_seconds", 300)),
            session_expiration_seconds=int(data.get("session_expiration_seconds", 600)),
            otp_resend_cooldown_seconds=int(data.get("otp_resend_cooldown_seconds", 30)),
            max_otp_attempts=int(data.get("max_otp_attempts", 5)),
            nonce_expiration_seconds=int(data.get("nonce_expiration_seconds", 300)),
            heartbeat_interval_seconds=int(data.get("heartbeat_interval_seconds", 30)),
            health_sampling_interval_seconds=int(data.get("health_sampling_interval_seconds", 30)),
            health_degraded_threshold_seconds=int(data.get("health_degraded_threshold_seconds", 60)),
            health_offline_threshold_seconds=int(data.get("health_offline_threshold_seconds", 120)),
            timestamp_skew_tolerance_seconds=int(data.get("timestamp_skew_tolerance_seconds", 120)),
            telemetry_retention_days=int(data.get("telemetry_retention_days", 7)),
            telemetry_max_retries=int(data.get("telemetry_max_retries", 3)),
            telemetry_backoff_base_seconds=float(data.get("telemetry_backoff_base_seconds", 2.0)),
            telemetry_backoff_max_seconds=float(data.get("telemetry_backoff_max_seconds", 30.0)),
            alert_dedup_cooldown_seconds=int(data.get("alert_dedup_cooldown_seconds", 300)),
            alert_retention_days=int(data.get("alert_retention_days", 30)),
            default_battery_threshold=int(data.get("default_battery_threshold", 20)),
            default_storage_threshold=int(data.get("default_storage_threshold", 10)),
            default_offline_duration_seconds=int(data.get("default_offline_duration_seconds", 120)),
            default_degraded_duration_seconds=int(data.get("default_degraded_duration_seconds", 60)),
            policy_evaluation_enabled=bool(data.get("policy_evaluation_enabled", True)),
            console_refresh_interval_seconds=int(data.get("console_refresh_interval_seconds", 5)),
            console_max_activity_entries=int(data.get("console_max_activity_entries", 5)),
            console_color_enabled=bool(data.get("console_color_enabled", True)),
            console_ascii_borders=bool(data.get("console_ascii_borders", False)),
            transport_enabled=bool(data.get("transport_enabled", True)),
            transport_listen_host=str(data.get("transport_listen_host", "0.0.0.0")),
            transport_listen_port=int(data.get("transport_listen_port", 8443)),
            transport_session_ttl_seconds=int(data.get("transport_session_ttl_seconds", 3600)),
            transport_heartbeat_interval_seconds=int(data.get("transport_heartbeat_interval_seconds", 15)),
            transport_heartbeat_timeout_seconds=int(data.get("transport_heartbeat_timeout_seconds", 45)),
            transport_max_reconnect_attempts=int(data.get("transport_max_reconnect_attempts", 5)),
            transport_reconnect_initial_delay_seconds=float(
                data.get("transport_reconnect_initial_delay_seconds", 1.0)
            ),
            transport_reconnect_max_delay_seconds=float(
                data.get("transport_reconnect_max_delay_seconds", 30.0)
            ),
            transport_max_message_size_bytes=int(data.get("transport_max_message_size_bytes", 65536)),
            transport_replay_window_size=int(data.get("transport_replay_window_size", 128)),
            screen_view_enabled=bool(data.get("screen_view_enabled", True)),
            screen_view_default_max_duration_seconds=int(
                data.get("screen_view_default_max_duration_seconds", 300)
            ),
            screen_view_max_duration_seconds=int(
                data.get("screen_view_max_duration_seconds", 3600)
            ),
            screen_view_default_fps=int(data.get("screen_view_default_fps", 10)),
            screen_view_max_fps=int(data.get("screen_view_max_fps", 30)),
            screen_view_default_width=int(data.get("screen_view_default_width", 1280)),
            screen_view_default_height=int(data.get("screen_view_default_height", 720)),
            screen_view_max_width=int(data.get("screen_view_max_width", 1920)),
            screen_view_max_height=int(data.get("screen_view_max_height", 1080)),
            screen_view_max_frame_bytes=int(
                data.get("screen_view_max_frame_bytes", 4 * 1024 * 1024)
            ),
            screen_view_max_queue_size=int(data.get("screen_view_max_queue_size", 30)),
            screen_view_inactivity_timeout_seconds=int(
                data.get("screen_view_inactivity_timeout_seconds", 60)
            ),
        )


def load_config(home_dir: Path | None = None) -> GuardianConfig:
    """Load configuration from disk with environment variable overrides."""
    resolved_home = home_dir or get_default_home_dir()
    config_path = resolved_home / "config.json"

    data: dict[str, Any] = {}
    if config_path.is_file():
        try:
            with open(config_path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            raise ConfigError(f"Failed to read configuration file at {config_path}: {e}") from e

    # Environment variable overrides
    if "GUARDIANMESH_HOME" in os.environ:
        data["home_dir"] = os.environ["GUARDIANMESH_HOME"]
    elif home_dir:
        data["home_dir"] = str(home_dir)

    if "GUARDIANMESH_DATA_DIR" in os.environ:
        data["data_dir"] = os.environ["GUARDIANMESH_DATA_DIR"]

    if "GUARDIANMESH_DB_PATH" in os.environ:
        data["database_path"] = os.environ["GUARDIANMESH_DB_PATH"]

    if "GUARDIANMESH_KEYS_DIR" in os.environ:
        data["keys_dir"] = os.environ["GUARDIANMESH_KEYS_DIR"]

    if "GUARDIANMESH_LOG_DIR" in os.environ:
        data["log_dir"] = os.environ["GUARDIANMESH_LOG_DIR"]

    if "GUARDIANMESH_LOG_LEVEL" in os.environ:
        data["log_level"] = os.environ["GUARDIANMESH_LOG_LEVEL"]

    if "GUARDIANMESH_DEFAULT_ROLE" in os.environ:
        data["default_role"] = os.environ["GUARDIANMESH_DEFAULT_ROLE"]

    if "GUARDIANMESH_SMTP_HOST" in os.environ:
        data["smtp_host"] = os.environ["GUARDIANMESH_SMTP_HOST"]

    if "GUARDIANMESH_SMTP_PORT" in os.environ:
        try:
            data["smtp_port"] = int(os.environ["GUARDIANMESH_SMTP_PORT"])
        except ValueError:
            pass

    if "GUARDIANMESH_SMTP_USERNAME" in os.environ:
        data["smtp_username"] = os.environ["GUARDIANMESH_SMTP_USERNAME"]
    elif "GUARDIANMESH_SMTP_USER" in os.environ:
        data["smtp_username"] = os.environ["GUARDIANMESH_SMTP_USER"]

    if "GUARDIANMESH_SMTP_PASSWORD" in os.environ:
        data["smtp_password"] = os.environ["GUARDIANMESH_SMTP_PASSWORD"]
    elif "GUARDIANMESH_SMTP_PASS" in os.environ:
        data["smtp_password"] = os.environ["GUARDIANMESH_SMTP_PASS"]

    if "GUARDIANMESH_SMTP_FROM" in os.environ:
        data["smtp_from_address"] = os.environ["GUARDIANMESH_SMTP_FROM"]

    if "GUARDIANMESH_HEARTBEAT_INTERVAL" in os.environ:
        try:
            data["heartbeat_interval_seconds"] = int(os.environ["GUARDIANMESH_HEARTBEAT_INTERVAL"])
        except ValueError:
            pass

    if "GUARDIANMESH_TELEMETRY_RETENTION" in os.environ:
        try:
            data["telemetry_retention_days"] = int(os.environ["GUARDIANMESH_TELEMETRY_RETENTION"])
        except ValueError:
            pass

    if "GUARDIANMESH_TIMESTAMP_SKEW" in os.environ:
        try:
            data["timestamp_skew_tolerance_seconds"] = int(os.environ["GUARDIANMESH_TIMESTAMP_SKEW"])
        except ValueError:
            pass

    if "GUARDIANMESH_ALERT_RETENTION" in os.environ:
        try:
            data["alert_retention_days"] = int(os.environ["GUARDIANMESH_ALERT_RETENTION"])
        except ValueError:
            pass

    if "GUARDIANMESH_ALERT_DEDUP_COOLDOWN" in os.environ:
        try:
            data["alert_dedup_cooldown_seconds"] = int(os.environ["GUARDIANMESH_ALERT_DEDUP_COOLDOWN"])
        except ValueError:
            pass

    if "GUARDIANMESH_CONSOLE_REFRESH" in os.environ:
        try:
            data["console_refresh_interval_seconds"] = int(os.environ["GUARDIANMESH_CONSOLE_REFRESH"])
        except ValueError:
            pass

    if "GUARDIANMESH_TRANSPORT_PORT" in os.environ:
        try:
            data["transport_listen_port"] = int(os.environ["GUARDIANMESH_TRANSPORT_PORT"])
        except ValueError:
            pass

    if "GUARDIANMESH_TRANSPORT_HOST" in os.environ:
        data["transport_listen_host"] = os.environ["GUARDIANMESH_TRANSPORT_HOST"]

    if "NO_COLOR" in os.environ or "GUARDIANMESH_NO_COLOR" in os.environ:
        data["console_color_enabled"] = False

    return GuardianConfig.from_dict(data, home_dir=resolved_home)


def save_config(config: GuardianConfig) -> Path:
    """Persist GuardianConfig to config.json with 0600 permissions."""
    config.ensure_directories()
    config_path = config.config_file_path

    try:
        tmp_path = config_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config.to_dict(redact_secrets=False), f, indent=2)
            f.write("\n")
        tmp_path.replace(config_path)
        try:
            config_path.chmod(0o600)
        except OSError:
            pass
        return config_path
    except OSError as e:
        raise ConfigError(f"Failed to save configuration to {config_path}: {e}") from e
