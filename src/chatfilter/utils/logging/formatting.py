"""Log formatting utilities for structured and timing logging.

This module provides:
- JSONFormatter: Structured JSON logging for log aggregators
- TimingContext: Context manager for measuring operation durations
- set_module_log_level(): Configure log levels per module
- configure_module_levels(): Batch configure multiple module levels
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

from .sanitizer import sanitize_text


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
