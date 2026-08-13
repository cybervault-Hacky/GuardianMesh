"""Tests for logging setup, redaction formatter, and structured errors."""

from __future__ import annotations

import logging
from pathlib import Path

from guardianmesh.core.errors import GuardianMeshError
from guardianmesh.core.logging import RedactingFormatter, get_logger, redact_sensitive_data, setup_logging


def test_structured_error_details() -> None:
    """Test GuardianMeshError details formatting."""
    err_simple = GuardianMeshError("Simple message")
    assert str(err_simple) == "Simple message"
    assert err_simple.code == "GuardianMeshError"

    err_detailed = GuardianMeshError(
        "Failure occurred",
        code="CUSTOM_CODE",
        details={"key": "val", "num": 10},
    )
    assert "details:" in str(err_detailed)
    assert err_detailed.code == "CUSTOM_CODE"
    assert err_detailed.details == {"key": "val", "num": 10}


def test_redacting_formatter_record() -> None:
    """Test RedactingFormatter formats a logging record and strips secrets."""
    formatter = RedactingFormatter(fmt="%(levelname)s: %(message)s")
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Authentication token: 'secret-auth-token-12345'",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "token=[REDACTED]" in formatted
    assert "secret-auth-token-12345" not in formatted


def test_setup_logging_file_and_console(tmp_path: Path) -> None:
    """Test setup_logging with file handler and console handler."""
    log_file = tmp_path / "test.log"
    logger = setup_logging(level="DEBUG", log_file=log_file, console_output=True)

    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 2

    test_msg = "Logging test entry with password: 'Secret123'"
    logger.info(test_msg)

    # Flush handlers
    for h in logger.handlers:
        h.flush()

    assert log_file.is_file()
    content = log_file.read_text(encoding="utf-8")
    assert "password=[REDACTED]" in content
    assert "Secret123" not in content


def test_get_logger_namespacing() -> None:
    """Test get_logger creates namespaced loggers."""
    log1 = get_logger("crypto")
    assert log1.name == "guardianmesh.crypto"

    log2 = get_logger("guardianmesh.storage")
    assert log2.name == "guardianmesh.storage"


def test_redact_non_string() -> None:
    """Test redact_sensitive_data safely passes through non-string types."""
    assert redact_sensitive_data(12345) == 12345  # type: ignore
    assert redact_sensitive_data(None) is None  # type: ignore
