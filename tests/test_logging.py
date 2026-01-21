"""Tests for logging configuration and functionality."""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from chatfilter.main import setup_logging


@pytest.fixture(autouse=True)
def reset_logging() -> Generator[None, None, None]:
    """Reset logging state between tests."""
    # Store original handlers
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers.copy()
    original_level = root_logger.level

    yield

    # Restore original state
    root_logger.handlers = original_handlers
    root_logger.setLevel(original_level)


def test_setup_logging_console_only() -> None:
    """Test logging setup with console output only."""
    setup_logging(level="INFO", debug=False, log_to_file=False)

    root_logger = logging.getLogger()

    # Should have one handler (console)
    assert len(root_logger.handlers) == 1
    assert isinstance(root_logger.handlers[0], logging.StreamHandler)
    assert root_logger.level == logging.INFO


def test_setup_logging_debug_mode() -> None:
    """Test logging setup in debug mode overrides log level."""
    setup_logging(level="INFO", debug=True, log_to_file=False)

    root_logger = logging.getLogger()

    # Debug should override INFO level
    assert root_logger.level == logging.DEBUG


def test_setup_logging_with_file() -> None:
    """Test logging setup with file handler."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
            log_file_max_bytes=1024,
            log_file_backup_count=3,
        )

        root_logger = logging.getLogger()

        # Should have two handlers (console + file)
        assert len(root_logger.handlers) == 2

        # Find the file handler
        file_handlers = [
            h for h in root_logger.handlers if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert len(file_handlers) == 1

        file_handler = file_handlers[0]
        assert file_handler.maxBytes == 1024
        assert file_handler.backupCount == 3

        # Test that logging actually writes to file
        test_logger = logging.getLogger("test")
        test_logger.info("Test message")

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content
        assert "[INFO]" in content


def test_setup_logging_file_rotation() -> None:
    """Test that log rotation works correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        # Set very small max bytes to trigger rotation
        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
            log_file_max_bytes=100,  # Very small to trigger rotation
            log_file_backup_count=2,
        )

        test_logger = logging.getLogger("rotation_test")

        # Write enough logs to trigger rotation
        for i in range(20):
            test_logger.info(f"This is a longer test message number {i} to trigger rotation")

        # Check that rotation occurred
        # Should have main log file and at least one backup
        log_files = list(Path(tmpdir).glob("test.log*"))
        assert len(log_files) > 1  # Main file + backups
        assert log_file.exists()


def test_setup_logging_invalid_path() -> None:
    """Test graceful handling of invalid log file path."""
    # Try to write to a path that doesn't exist and can't be created
    invalid_path = Path("/nonexistent/directory/log.log")

    # Should not raise exception, just fall back to console-only
    setup_logging(
        level="INFO",
        debug=False,
        log_to_file=True,
        log_file_path=invalid_path,
    )

    root_logger = logging.getLogger()

    # Should still have console handler
    assert len(root_logger.handlers) >= 1


def test_setup_logging_format() -> None:
    """Test that log format is correct."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("format_test")
        test_logger.info("Format test message")

        content = log_file.read_text()

        # Check format includes all expected parts
        assert "format_test" in content  # Logger name
        assert "[INFO]" in content  # Log level
        assert "Format test message" in content  # Message
        # Check timestamp format (YYYY-MM-DD HH:MM:SS)
        import re

        timestamp_pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
        assert re.search(timestamp_pattern, content)


def test_logging_levels() -> None:
    """Test different logging levels."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        # Set to WARNING level
        setup_logging(
            level="WARNING",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("level_test")

        test_logger.debug("Debug message")  # Should not appear
        test_logger.info("Info message")  # Should not appear
        test_logger.warning("Warning message")  # Should appear
        test_logger.error("Error message")  # Should appear

        content = log_file.read_text()

        assert "Debug message" not in content
        assert "Info message" not in content
        assert "Warning message" in content
        assert "Error message" in content


def test_setup_logging_clears_existing_handlers() -> None:
    """Test that setup_logging clears existing handlers."""
    # Add a dummy handler
    root_logger = logging.getLogger()
    dummy_handler = logging.NullHandler()
    root_logger.addHandler(dummy_handler)

    # Setup logging should clear existing handlers
    setup_logging(level="INFO", debug=False, log_to_file=False)

    # Should have exactly one handler (console), not multiple
    assert len(root_logger.handlers) == 1
    assert dummy_handler not in root_logger.handlers


def test_log_sanitization_session_tokens() -> None:
    """Test that session tokens are sanitized from logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("sanitization_test")

        # Log messages with sensitive data
        test_logger.info("Telegram session: 1234567890:AbCdEfGhIjKlMnOpQrStUvWxYz0123456")
        test_logger.info("API key: api_key=sk_test_1234567890abcdefghijklmnop")
        test_logger.info("Password: password=MySecretPass123")

        content = log_file.read_text()

        # Verify sensitive data is masked
        assert "1234567890:AbCdEfGhIjKlMnOpQrStUvWxYz0123456" not in content
        assert "***SESSION_TOKEN***" in content

        assert "sk_test_1234567890abcdefghijklmnop" not in content
        assert "***TOKEN***" in content

        assert "MySecretPass123" not in content
        assert "***PASSWORD***" in content


def test_log_sanitization_phone_numbers() -> None:
    """Test that phone numbers are sanitized from logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("phone_test")

        # Log phone numbers
        test_logger.info("User phone: +12345678901")
        test_logger.info("Contact: +441234567890")

        content = log_file.read_text()

        # Verify phone numbers are masked
        assert "+12345678901" not in content
        assert "+441234567890" not in content
        assert "***PHONE***" in content


def test_log_sanitization_bot_tokens() -> None:
    """Test that bot tokens are sanitized from logs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("bot_token_test")

        # Log bot token
        test_logger.info("Bot token: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567")

        content = log_file.read_text()

        # Verify bot token is masked
        assert "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567" not in content
        assert "***BOT_TOKEN***" in content


def test_correlation_id_in_logs() -> None:
    """Test that correlation IDs appear in log messages."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        from chatfilter.utils.logging import clear_correlation_id, set_correlation_id

        test_logger = logging.getLogger("correlation_test")

        # Test without correlation ID
        clear_correlation_id()
        test_logger.info("Message without correlation ID")

        # Test with correlation ID
        set_correlation_id("abc123def456")
        test_logger.info("Message with correlation ID")

        # Clear correlation ID
        clear_correlation_id()

        content = log_file.read_text()

        # Check that correlation ID appears in the right place
        assert "[-]" in content  # No correlation ID
        assert "[abc123def456]" in content  # With correlation ID


def test_correlation_id_context_isolation() -> None:
    """Test that correlation IDs are properly isolated in context."""
    from chatfilter.utils.logging import (
        clear_correlation_id,
        get_correlation_id,
        set_correlation_id,
    )

    # Initially no correlation ID
    assert get_correlation_id() is None

    # Set correlation ID
    set_correlation_id("test-123")
    assert get_correlation_id() == "test-123"

    # Clear correlation ID
    clear_correlation_id()
    assert get_correlation_id() is None


def test_generate_correlation_id() -> None:
    """Test correlation ID generation."""
    from chatfilter.utils.logging import generate_correlation_id

    # Generate IDs
    id1 = generate_correlation_id()
    id2 = generate_correlation_id()

    # Should be 16 characters (hex UUID prefix)
    assert len(id1) == 16
    assert len(id2) == 16

    # Should be different
    assert id1 != id2

    # Should be hexadecimal
    assert all(c in "0123456789abcdef" for c in id1)
    assert all(c in "0123456789abcdef" for c in id2)


def test_exception_traceback_sanitization() -> None:
    """Test that exception tracebacks are sanitized when logged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("exception_test")

        # Create an exception with a session token in the message
        session_token = "1234567890123:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        try:
            raise ValueError(f"Failed to connect with session: {session_token}")
        except ValueError:
            test_logger.exception("Connection error occurred")

        content = log_file.read_text()

        # The session token should be masked in the exception message
        assert session_token not in content
        assert "***SESSION_TOKEN***" in content
        # The exception should still be logged (just sanitized)
        assert "ValueError" in content
        assert "Connection error occurred" in content


def test_exception_with_bot_token_sanitization() -> None:
    """Test that bot tokens in exceptions are sanitized."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("bot_exception_test")

        # Create an exception with a bot token
        bot_token = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567"
        try:
            raise RuntimeError(f"Bot authentication failed: {bot_token}")
        except RuntimeError:
            test_logger.exception("Bot error")

        content = log_file.read_text()

        # The bot token should be masked
        assert bot_token not in content
        assert "***BOT_TOKEN***" in content


def test_sanitize_text_function() -> None:
    """Test the standalone sanitize_text function."""
    from chatfilter.utils.logging import sanitize_text

    # Test various sensitive data types
    assert "***SESSION_TOKEN***" in sanitize_text(
        "session: 1234567890123:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    )
    assert "***BOT_TOKEN***" in sanitize_text("bot: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567")
    assert "***PHONE***" in sanitize_text("phone: +12345678901234")
    assert "***PASSWORD***" in sanitize_text("password=secret123")
    assert "***AUTH***" in sanitize_text("Authorization: Bearer token123")


def test_sanitizing_formatter_directly() -> None:
    """Test SanitizingFormatter directly."""
    from chatfilter.utils.logging import SanitizingFormatter

    formatter = SanitizingFormatter("%(message)s")

    # Create a log record with sensitive data
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Token: 1234567890123:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert "1234567890123:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in formatted
    assert "***SESSION_TOKEN***" in formatted
