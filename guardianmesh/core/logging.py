"""Privacy-conscious, structured logging for GuardianMesh."""

from __future__ import annotations

import logging
import re
from pathlib import Path

# Patterns to redact from logs
_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]*PRIVATE KEY-----",
    re.IGNORECASE,
)
_SENSITIVE_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|secret|token|private_key|key_material|otp|auth_code)\b\s*[:=]\s*['\"]?([^\s'\",]+)['\"]?"
)
_OTP_CODE_PATTERN = re.compile(r"\b(otp|code|pin)\s*[:=]?\s*\b\d{4,8}\b", re.IGNORECASE)


def redact_sensitive_data(text: str) -> str:
    """Scrub sensitive cryptographic secrets, tokens, passwords, and OTPs from log text."""
    if not isinstance(text, str):
        return text

    # Redact private key PEM blocks
    scrubbed = _PEM_PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)

    # Redact sensitive key-value pairs
    scrubbed = _SENSITIVE_KEY_VALUE_PATTERN.sub(r"\1=[REDACTED]", scrubbed)

    # Redact raw OTP / PIN patterns
    scrubbed = _OTP_CODE_PATTERN.sub(r"\1=[REDACTED_CODE]", scrubbed)

    return scrubbed


class RedactingFormatter(logging.Formatter):
    """Logging formatter that automatically scrubs sensitive key material and tokens."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_sensitive_data(original)


_INITIALIZED = False


def setup_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    console_output: bool = False,
) -> logging.Logger:
    """Configure GuardianMesh logging with privacy protections.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to write log output.
        console_output: Whether to attach a console log handler (default False for CLI cleanliness).

    Returns:
        The configured guardianmesh logger.
    """
    global _INITIALIZED

    logger = logging.getLogger("guardianmesh")
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers on repeated setup calls
    logger.handlers.clear()

    formatter = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(numeric_level)
        logger.addHandler(console_handler)

    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
            file_handler.setFormatter(formatter)
            file_handler.setLevel(numeric_level)
            logger.addHandler(file_handler)
        except OSError:
            # Fall back safely if log directory cannot be created
            pass

    _INITIALIZED = True
    return logger


def get_logger(name: str = "guardianmesh") -> logging.Logger:
    """Get a logger within the GuardianMesh namespace."""
    if not name.startswith("guardianmesh"):
        name = f"guardianmesh.{name}"
    return logging.getLogger(name)
