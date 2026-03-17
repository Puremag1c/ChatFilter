"""Context management for logging correlation IDs and chat IDs.

This module provides:
- correlation_id: ContextVar for request correlation
- chat_id_context: ContextVar for Telegram chat tracking
- CorrelationIDFilter: Filter that adds correlation IDs to log records
- ChatContextFilter: Filter that adds chat IDs to log records
- Utility functions: get/set/clear for both context vars
- generate_correlation_id(): Create new correlation IDs
"""

from __future__ import annotations

import contextvars
import logging

# Context variable for storing correlation IDs
correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "correlation_id", default=None
)

# Context variable for chat ID (Telegram operations)
chat_id_context: contextvars.ContextVar[int | str | None] = contextvars.ContextVar(
    "chat_id", default=None
)


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
