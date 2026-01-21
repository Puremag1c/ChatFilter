"""Logging utilities with sanitization and correlation ID support.

This module provides:
- Log sanitization to mask sensitive data (tokens, passwords, keys)
- Correlation ID support for tracking requests through the system
- Thread-safe context management for correlation IDs
"""

from __future__ import annotations

import contextvars
import logging
import re
from typing import Any

# Context variable for storing correlation IDs
correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)


class LogSanitizer(logging.Filter):
    """Filter that sanitizes sensitive data from log records.

    Protects against accidental logging of:
    - Session tokens and API keys
    - Passwords and credentials
    - Phone numbers and personal data
    - Secret keys and encryption keys
    """

    # Patterns for sensitive data detection
    PATTERNS: list[tuple[re.Pattern[str], str]] = [
        # Session strings (Telegram format: base64-like strings) - check first for 10+ digits
        (re.compile(r"\d{10,}:[A-Za-z0-9_\-]{30,}"), "***SESSION_TOKEN***"),
        # Bot tokens (Telegram format: digits:alphanumeric) - 8-9 digits only
        (re.compile(r"\d{8,9}:[A-Za-z0-9_\-]{30,}"), "***BOT_TOKEN***"),
        # API tokens (various formats)
        (
            re.compile(r"(api[_-]?key|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})"),
            r"\1=***TOKEN***",
        ),
        # Phone numbers (international format)
        (re.compile(r"\+?[1-9]\d{10,14}"), "***PHONE***"),
        # Passwords in various contexts
        (
            re.compile(r"(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{3,})"),
            r"\1=***PASSWORD***",
        ),
        # Secret keys
        (
            re.compile(
                r"(secret[_-]?key|private[_-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})"
            ),
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

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize the log record message and args.

        Args:
            record: The log record to sanitize

        Returns:
            Always True (record is always processed)
        """
        # Sanitize the message
        if record.msg:
            record.msg = self._sanitize_text(str(record.msg))

        # Sanitize args if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._sanitize_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._sanitize_value(arg) for arg in record.args)

        return True

    def _sanitize_text(self, text: str) -> str:
        """Apply all sanitization patterns to text.

        Args:
            text: The text to sanitize

        Returns:
            Sanitized text with sensitive data masked
        """
        for pattern, replacement in self.PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize a single value recursively.

        Args:
            value: The value to sanitize

        Returns:
            Sanitized value
        """
        if isinstance(value, str):
            return self._sanitize_text(value)
        elif isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        elif isinstance(value, list | tuple):
            sanitized = [self._sanitize_value(item) for item in value]
            return type(value)(sanitized)
        return value


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


def configure_sanitized_logging(logger: logging.Logger) -> None:
    """Configure a logger with sanitization and correlation ID filters.

    Args:
        logger: The logger to configure
    """
    # Add sanitizer filter
    logger.addFilter(LogSanitizer())

    # Add correlation ID filter
    logger.addFilter(CorrelationIDFilter())
