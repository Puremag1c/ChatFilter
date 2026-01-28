"""Tests for logging configuration and functionality."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
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

    # Close all current handlers to release file locks (required on Windows)
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)

    # Restore original state
    root_logger.handlers = original_handlers
    root_logger.setLevel(original_level)


@pytest.fixture
def log_temp_dir() -> Generator[Path, None, None]:
    """Create a temp directory that handles Windows file locking for log files.

    On Windows, file handlers must be closed before the temp directory can be deleted.
    This fixture ensures proper cleanup order by closing handlers before rmtree.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        yield Path(tmpdir)
    finally:
        # Close all file handlers before deleting the directory (required on Windows)
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            if isinstance(handler, logging.FileHandler):
                handler.close()
                root_logger.removeHandler(handler)
        # Now safe to delete the directory
        shutil.rmtree(tmpdir, ignore_errors=True)


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


def test_setup_logging_with_file(log_temp_dir: Path) -> None:
    """Test logging setup with file handler."""
    log_file = log_temp_dir / "test.log"

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


def test_setup_logging_file_rotation(log_temp_dir: Path) -> None:
    """Test that log rotation works correctly."""
    log_file = log_temp_dir / "test.log"

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
    log_files = list(log_temp_dir.glob("test.log*"))
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


def test_setup_logging_format(log_temp_dir: Path) -> None:
    """Test that log format is correct."""
    log_file = log_temp_dir / "test.log"

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


def test_logging_levels(log_temp_dir: Path) -> None:
    """Test different logging levels."""
    log_file = log_temp_dir / "test.log"

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


def test_log_sanitization_session_tokens(log_temp_dir: Path) -> None:
    """Test that session tokens are sanitized from logs."""
    log_file = log_temp_dir / "test.log"

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


def test_log_sanitization_phone_numbers(log_temp_dir: Path) -> None:
    """Test that phone numbers are sanitized from logs."""
    log_file = log_temp_dir / "test.log"

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


def test_log_sanitization_ip_addresses(log_temp_dir: Path) -> None:
    """Test that IP addresses (IPv4 and IPv6) are sanitized from logs."""
    log_file = log_temp_dir / "test.log"

    setup_logging(
        level="INFO",
        debug=False,
        log_to_file=True,
        log_file_path=log_file,
    )

    test_logger = logging.getLogger("ip_test")

    # Log IPv4 addresses
    test_logger.info("Client IP: 192.168.1.100")
    test_logger.info("Server at 10.0.0.1 responded")
    test_logger.info("Connection from 203.0.113.42")

    # Log IPv6 addresses
    test_logger.info("IPv6 client: 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    test_logger.info("Compressed IPv6: fe80::1")
    test_logger.info("Another IPv6: 2001:db8::8a2e:370:7334")

    content = log_file.read_text()

    # Verify IPv4 addresses are masked
    assert "192.168.1.100" not in content
    assert "10.0.0.1" not in content
    assert "203.0.113.42" not in content

    # Verify IPv6 addresses are masked
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in content
    assert "fe80::1" not in content
    assert "2001:db8::8a2e:370:7334" not in content

    # Verify all are replaced with mask
    assert "***IP***" in content


def test_log_sanitization_bot_tokens(log_temp_dir: Path) -> None:
    """Test that bot tokens are sanitized from logs."""
    log_file = log_temp_dir / "test.log"

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


def test_log_sanitization_api_hash(log_temp_dir: Path) -> None:
    """Test that api_hash values are sanitized from logs."""
    log_file = log_temp_dir / "test.log"

    setup_logging(
        level="INFO",
        debug=False,
        log_to_file=True,
        log_file_path=log_file,
    )

    test_logger = logging.getLogger("api_hash_test")

    # Log api_hash in various formats
    test_logger.info("api_hash=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0")
    test_logger.info("Config: api-hash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0")
    test_logger.info('api_hash="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"')

    content = log_file.read_text()

    # Verify api_hash is masked
    assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0" not in content
    assert "***TOKEN***" in content


def test_correlation_id_in_logs(log_temp_dir: Path) -> None:
    """Test that correlation IDs appear in log messages."""
    log_file = log_temp_dir / "test.log"

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


def test_exception_traceback_sanitization(log_temp_dir: Path) -> None:
    """Test that exception tracebacks are sanitized when logged."""
    log_file = log_temp_dir / "test.log"

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


def test_exception_with_bot_token_sanitization(log_temp_dir: Path) -> None:
    """Test that bot tokens in exceptions are sanitized."""
    log_file = log_temp_dir / "test.log"

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


# --- New tests for enhanced logging features ---


def test_json_formatter() -> None:
    """Test JSONFormatter outputs valid JSON with required fields."""
    from chatfilter.utils.logging import JSONFormatter

    formatter = JSONFormatter(sanitize=True)

    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    record.correlation_id = "abc123"
    record.chat_id = "12345"

    formatted = formatter.format(record)

    # Should be valid JSON
    data = json.loads(formatted)

    # Check required fields
    assert "timestamp" in data
    assert data["level"] == "INFO"
    assert data["logger"] == "test.module"
    assert data["message"] == "Test message"
    assert data["correlation_id"] == "abc123"
    assert data["chat_id"] == "12345"


def test_json_formatter_sanitizes_sensitive_data() -> None:
    """Test JSONFormatter sanitizes sensitive data in messages."""
    from chatfilter.utils.logging import JSONFormatter

    formatter = JSONFormatter(sanitize=True)

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
    data = json.loads(formatted)

    # Sensitive data should be masked
    assert "1234567890123:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in data["message"]
    assert "***SESSION_TOKEN***" in data["message"]


def test_json_formatter_includes_extra_fields() -> None:
    """Test JSONFormatter includes extra fields from log record."""
    from chatfilter.utils.logging import JSONFormatter

    formatter = JSONFormatter(sanitize=False)

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    # Add extra field
    record.duration_ms = 123.45
    record.status_code = 200

    formatted = formatter.format(record)
    data = json.loads(formatted)

    # Extra fields should be included
    assert data["duration_ms"] == 123.45
    assert data["status_code"] == 200


def test_chat_context_filter() -> None:
    """Test ChatContextFilter adds chat_id to log records."""
    from typing import Any

    from chatfilter.utils.logging import ChatContextFilter, clear_chat_id, set_chat_id

    filter_instance = ChatContextFilter()

    # Test without chat ID
    clear_chat_id()
    record: Any = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(record)
    assert record.chat_id == "-"

    # Test with chat ID
    set_chat_id(12345)
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(record)
    assert record.chat_id == "12345"

    # Cleanup
    clear_chat_id()


def test_chat_context_functions() -> None:
    """Test chat context set/get/clear functions."""
    from chatfilter.utils.logging import clear_chat_id, get_chat_id, set_chat_id

    # Initially no chat ID
    clear_chat_id()
    assert get_chat_id() is None

    # Set chat ID
    set_chat_id(12345)
    assert get_chat_id() == 12345

    # Set string chat ID
    set_chat_id("channel_123")
    assert get_chat_id() == "channel_123"

    # Clear
    clear_chat_id()
    assert get_chat_id() is None


def test_timing_context() -> None:
    """Test TimingContext measures operation duration."""
    from chatfilter.utils.logging import TimingContext

    with TimingContext("test_operation") as timing:
        time.sleep(0.01)  # 10ms

    # Should have recorded duration
    assert timing.duration_ms >= 10  # At least 10ms
    assert timing.duration_ms < 1000  # Less than 1 second
    assert timing.duration_s >= 0.01


def test_timing_context_decorator() -> None:
    """Test TimingContext decorator works for functions."""
    from chatfilter.utils.logging import TimingContext

    @TimingContext.decorator("decorated_operation")
    def slow_function() -> str:
        time.sleep(0.01)
        return "done"

    result = slow_function()
    assert result == "done"


def test_module_log_levels() -> None:
    """Test per-module log level configuration."""
    from chatfilter.utils.logging import (
        configure_module_levels,
        set_module_log_level,
    )

    # Set individual module level
    set_module_log_level("test.module1", "DEBUG")
    assert logging.getLogger("test.module1").level == logging.DEBUG

    set_module_log_level("test.module2", logging.WARNING)
    assert logging.getLogger("test.module2").level == logging.WARNING

    # Configure multiple modules at once
    configure_module_levels(
        {
            "test.module3": "ERROR",
            "test.module4": "INFO",
        }
    )
    assert logging.getLogger("test.module3").level == logging.ERROR
    assert logging.getLogger("test.module4").level == logging.INFO


def test_setup_logging_with_json_format(log_temp_dir: Path) -> None:
    """Test setup_logging with JSON format."""
    log_file = log_temp_dir / "test.log"

    setup_logging(
        level="INFO",
        debug=False,
        log_to_file=True,
        log_file_path=log_file,
        log_format="json",
    )

    test_logger = logging.getLogger("json_format_test")
    test_logger.info("Test JSON log message")

    content = log_file.read_text()
    lines = content.strip().split("\n")

    # At least one line should be valid JSON
    found_json = False
    for line in lines:
        try:
            data = json.loads(line)
            if data.get("message") == "Test JSON log message":
                found_json = True
                assert data["level"] == "INFO"
                assert data["logger"] == "json_format_test"
                break
        except json.JSONDecodeError:
            continue

    assert found_json, "Did not find JSON log entry"


def test_setup_logging_with_verbose_mode() -> None:
    """Test setup_logging with verbose mode enables DEBUG level."""
    setup_logging(
        level="INFO",  # Would normally be INFO
        debug=False,
        verbose=True,  # Should override to DEBUG
        log_to_file=False,
    )

    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG


def test_setup_logging_with_module_levels() -> None:
    """Test setup_logging configures per-module log levels."""
    setup_logging(
        level="INFO",
        debug=False,
        log_to_file=False,
        module_levels={
            "chatfilter.telegram": "DEBUG",
            "chatfilter.web": "WARNING",
        },
    )

    assert logging.getLogger("chatfilter.telegram").level == logging.DEBUG
    assert logging.getLogger("chatfilter.web").level == logging.WARNING


def test_log_format_with_chat_id(log_temp_dir: Path) -> None:
    """Test that logs include chat ID when set."""
    log_file = log_temp_dir / "test.log"

    setup_logging(
        level="INFO",
        debug=False,
        log_to_file=True,
        log_file_path=log_file,
        log_format="text",
    )

    from chatfilter.utils.logging import clear_chat_id, set_chat_id

    test_logger = logging.getLogger("chat_context_test")

    # Log without chat ID
    clear_chat_id()
    test_logger.info("Message without chat")

    # Log with chat ID
    set_chat_id(12345)
    test_logger.info("Message with chat")

    clear_chat_id()

    content = log_file.read_text()

    # Should contain chat context markers
    assert "[chat:-]" in content
    assert "[chat:12345]" in content
