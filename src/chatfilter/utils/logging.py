"""Logging utilities with sanitization, correlation ID, and structured logging support.

This module provides:
- Log sanitization to mask sensitive data (tokens, passwords, keys)
- Correlation ID support for tracking requests through the system
- Thread-safe context management for correlation IDs
- SanitizingFormatter for complete output sanitization including exceptions
- JSONFormatter for structured JSON logging (log aggregators)
- ChatContextFilter for adding chat ID context to Telegram operations
- TimingContext for measuring operation durations
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import time
from datetime import UTC, datetime
from typing import Any, ClassVar

# Context variable for storing correlation IDs
correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)

# Shared patterns for sensitive data detection
# Used by both LogSanitizer and SanitizingFormatter
SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Session strings (Telegram format: base64-like strings) - check first for 10+ digits
    (re.compile(r"\d{10,}:[A-Za-z0-9_\-]{30,}"), "***SESSION_TOKEN***"),
    # Bot tokens (Telegram format: digits:alphanumeric) - 8-9 digits only
    (re.compile(r"\d{8,9}:[A-Za-z0-9_\-]{30,}"), "***BOT_TOKEN***"),
    # API tokens (various formats)
    (
        re.compile(r"(api[_-]?(?:key|hash)|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})"),
        r"\1=***TOKEN***",
    ),
    # Phone numbers (international format)
    (re.compile(r"\+?[1-9]\d{10,14}"), "***PHONE***"),
    # IP addresses (IPv4)
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "***IP***"),
    # IP addresses (IPv6 - full and compressed forms)
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"), "***IP***"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"), "***IP***"),
    # Passwords in various contexts
    (
        re.compile(r"(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{3,})"),
        r"\1=***PASSWORD***",
    ),
    # Secret keys
    (
        re.compile(r"(secret[_-]?key|private[_-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})"),
        r"\1=***SECRET***",
    ),
    # Authorization headers
    (re.compile(r"(Authorization|Bearer)\s*:\s*([A-Za-z0-9_\-\.=]+)"), r"\1: ***AUTH***"),
    # Credit card numbers (basic pattern)
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "***CARD***"),
    # Email addresses (partial masking)
    (re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"), r"***@\2"),
    # AWS keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "***AWS_KEY***"),
    # Generic secrets (common patterns)
    (re.compile(r"['\"]?[a-f0-9]{32,}['\"]?"), "***HEX_SECRET***"),
]


def sanitize_text(text: str) -> str:
    """Apply all sanitization patterns to text.

    Args:
        text: The text to sanitize

    Returns:
        Sanitized text with sensitive data masked
    """
    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class LogSanitizer(logging.Filter):
    """Filter that sanitizes sensitive data from log records.

    Protects against accidental logging of:
    - Session tokens and API keys
    - Passwords and credentials
    - Phone numbers and personal data
    - Secret keys and encryption keys

    Note: This filter sanitizes msg and args, but exception tracebacks
    are sanitized by SanitizingFormatter at format time.
    """

    # Class attribute pointing to module-level patterns for backward compatibility
    PATTERNS: ClassVar[list[tuple[re.Pattern[str], str]]] = SENSITIVE_PATTERNS

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize the log record message and args.

        Args:
            record: The log record to sanitize

        Returns:
            Always True (record is always processed)
        """
        # Sanitize the message
        if record.msg:
            record.msg = sanitize_text(str(record.msg))

        # Sanitize args if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._sanitize_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._sanitize_value(arg) for arg in record.args)

        return True

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize a single value recursively.

        Args:
            value: The value to sanitize

        Returns:
            Sanitized value
        """
        if isinstance(value, str):
            return sanitize_text(value)
        elif isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        elif isinstance(value, list | tuple):
            sanitized = [self._sanitize_value(item) for item in value]
            return type(value)(sanitized)
        return value


class SanitizingFormatter(logging.Formatter):
    """Formatter that sanitizes the final formatted output.

    This formatter sanitizes the complete formatted log message including
    exception tracebacks, ensuring no sensitive data escapes through
    exception messages or stack traces.

    Unlike LogSanitizer (which operates on msg/args before formatting),
    this formatter sanitizes the final output after all formatting is done,
    catching sensitive data in:
    - Exception messages
    - Stack traces
    - Formatted string representations of objects
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format the record and sanitize the result.

        Args:
            record: The log record to format

        Returns:
            Sanitized formatted log message
        """
        # Get the standard formatted message (includes exc_text if present)
        formatted = super().format(record)
        # Sanitize the complete output
        return sanitize_text(formatted)


class CorrelationIDFilter(logging.Filter):
    """Filter that adds correlation ID to log records.

    Correlation IDs help track requests through the system across
    multiple log entries and async operations.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add correlation ID to the log record.

        Args:
            record: The log record to enhance

        Returns:
            Always True (record is always processed)
        """
        # Get correlation ID from context
        cid = correlation_id.get()
        record.correlation_id = cid if cid else "-"
        return True


def get_correlation_id() -> str | None:
    """Get the current correlation ID from context.

    Returns:
        Current correlation ID or None if not set
    """
    return correlation_id.get()


def set_correlation_id(cid: str) -> None:
    """Set the correlation ID in context.

    Args:
        cid: The correlation ID to set
    """
    correlation_id.set(cid)


def clear_correlation_id() -> None:
    """Clear the correlation ID from context."""
    correlation_id.set(None)


def generate_correlation_id() -> str:
    """Generate a new correlation ID.

    Returns:
        A unique correlation ID string
    """
    import uuid

    return uuid.uuid4().hex[:16]


# Context variable for chat ID (Telegram operations)
chat_id_context: contextvars.ContextVar[int | str | None] = contextvars.ContextVar(
    "chat_id", default=None
)


def get_chat_id() -> int | str | None:
    """Get the current chat ID from context.

    Returns:
        Current chat ID or None if not set
    """
    return chat_id_context.get()


def set_chat_id(chat_id: int | str | None) -> contextvars.Token[int | str | None]:
    """Set the chat ID in context.

    Args:
        chat_id: The chat ID to set

    Returns:
        Token for resetting the context
    """
    return chat_id_context.set(chat_id)


def clear_chat_id() -> None:
    """Clear the chat ID from context."""
    chat_id_context.set(None)


class ChatContextFilter(logging.Filter):
    """Filter that adds chat ID context to log records.

    This helps track which Telegram chat operations are being logged.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Add chat ID to the log record.

        Args:
            record: The log record to enhance

        Returns:
            Always True (record is always processed)
        """
        # Get chat ID from context
        cid = chat_id_context.get()
        record.chat_id = str(cid) if cid else "-"
        return True


class JSONFormatter(logging.Formatter):
    """Formatter that outputs logs as JSON for log aggregators.

    Produces structured JSON logs suitable for:
    - Elasticsearch/ELK stack
    - Datadog
    - CloudWatch
    - Splunk
    - Any log aggregation system

    Each log entry includes:
    - timestamp: ISO 8601 format
    - level: Log level name
    - logger: Logger name
    - message: Log message (sanitized)
    - correlation_id: Request correlation ID
    - chat_id: Telegram chat ID (if set)
    - Extra fields from log record
    """

    def __init__(self, sanitize: bool = True) -> None:
        """Initialize JSON formatter.

        Args:
            sanitize: If True, sanitize sensitive data in output
        """
        super().__init__()
        self.sanitize = sanitize

    def format(self, record: logging.LogRecord) -> str:
        """Format the record as JSON.

        Args:
            record: The log record to format

        Returns:
            JSON-formatted log line
        """
        # Build base log entry
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if present
        if hasattr(record, "correlation_id"):
            log_entry["correlation_id"] = record.correlation_id

        # Add chat ID if present
        if hasattr(record, "chat_id") and record.chat_id != "-":
            log_entry["chat_id"] = record.chat_id

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields (excluding standard LogRecord attributes)
        standard_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "correlation_id",
            "chat_id",
            "message",
        }
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                # Try to serialize the value
                try:
                    json.dumps(value)  # Test if serializable
                    log_entry[key] = value
                except (TypeError, ValueError):
                    log_entry[key] = str(value)

        # Sanitize if enabled
        if self.sanitize:
            log_entry = self._sanitize_dict(log_entry)

        return json.dumps(log_entry, ensure_ascii=False, default=str)

    def _sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively sanitize a dictionary.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = sanitize_text(value)
            elif isinstance(value, dict):
                result[key] = self._sanitize_dict(dict(value))
            elif isinstance(value, list):
                result[key] = self._sanitize_list(value)
            else:
                result[key] = value
        return result

    def _sanitize_list(self, data: list[Any]) -> list[Any]:
        """Recursively sanitize a list.

        Args:
            data: List to sanitize

        Returns:
            Sanitized list
        """
        result: list[Any] = []
        for item in data:
            if isinstance(item, dict):
                result.append(self._sanitize_dict(dict(item)))
            elif isinstance(item, str):
                result.append(sanitize_text(item))
            else:
                result.append(item)
        return result


class TimingContext:
    """Context manager for measuring operation duration.

    Usage:
        with TimingContext("fetch_messages") as timing:
            # ... do work ...
        logger.info(f"Operation completed", extra={"duration_ms": timing.duration_ms})

    Or as a decorator:
        @TimingContext.decorator("process_chat")
        def process_chat(chat_id):
            # ... do work ...
    """

    def __init__(self, operation_name: str, logger: logging.Logger | None = None) -> None:
        """Initialize timing context.

        Args:
            operation_name: Name of the operation being timed
            logger: Logger to use for automatic logging (optional)
        """
        self.operation_name = operation_name
        self.logger = logger
        self.start_time: float | None = None
        self.end_time: float | None = None

    def __enter__(self) -> TimingContext:
        """Start timing."""
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Stop timing and optionally log."""
        self.end_time = time.perf_counter()
        if self.logger:
            level = logging.WARNING if exc_type else logging.DEBUG
            self.logger.log(
                level,
                f"{self.operation_name} completed",
                extra={
                    "operation": self.operation_name,
                    "duration_ms": self.duration_ms,
                    "success": exc_type is None,
                },
            )

    @property
    def duration_ms(self) -> float:
        """Get duration in milliseconds.

        Returns:
            Duration in milliseconds, or 0 if not yet completed
        """
        if self.start_time is None:
            return 0.0
        end = self.end_time if self.end_time else time.perf_counter()
        return (end - self.start_time) * 1000

    @property
    def duration_s(self) -> float:
        """Get duration in seconds.

        Returns:
            Duration in seconds, or 0 if not yet completed
        """
        return self.duration_ms / 1000

    @classmethod
    def decorator(cls, operation_name: str, logger: logging.Logger | None = None) -> Any:
        """Create a decorator that times function execution.

        Args:
            operation_name: Name of the operation
            logger: Logger for automatic logging

        Returns:
            Decorator function
        """
        import functools

        def decorator_func(func: Any) -> Any:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                with cls(operation_name, logger):
                    return func(*args, **kwargs)

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                with cls(operation_name, logger):
                    return await func(*args, **kwargs)

            import asyncio

            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            return wrapper

        return decorator_func


# Per-module log level configuration
_module_levels: dict[str, int] = {}


def set_module_log_level(module_name: str, level: str | int) -> None:
    """Set log level for a specific module.

    Args:
        module_name: Module name (e.g., "chatfilter.telegram")
        level: Log level (string like "DEBUG" or int like logging.DEBUG)
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    _module_levels[module_name] = level
    logger = logging.getLogger(module_name)
    logger.setLevel(level)


def configure_module_levels(config: dict[str, str]) -> None:
    """Configure log levels for multiple modules.

    Args:
        config: Dict mapping module names to log levels
               Example: {"chatfilter.telegram": "DEBUG", "chatfilter.web": "WARNING"}
    """
    for module_name, level in config.items():
        set_module_log_level(module_name, level)
