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

# Import from context module
from .context import (
    ChatContextFilter,
    CorrelationIDFilter,
    chat_id_context,
    clear_chat_id,
    clear_correlation_id,
    correlation_id,
    generate_correlation_id,
    get_chat_id,
    get_correlation_id,
    set_chat_id,
    set_correlation_id,
)

# Import from formatting module
from .formatting import (
    JSONFormatter,
    TimingContext,
    configure_module_levels,
    set_module_log_level,
)

# Import from sanitizer module
from .sanitizer import (
    SENSITIVE_PATTERNS,
    LogSanitizer,
    SanitizingFormatter,
    sanitize_text,
)

# Re-export all public names for backward compatibility
__all__ = [
    # Sanitizer
    "SENSITIVE_PATTERNS",
    "sanitize_text",
    "LogSanitizer",
    "SanitizingFormatter",
    # Context
    "correlation_id",
    "CorrelationIDFilter",
    "get_correlation_id",
    "set_correlation_id",
    "clear_correlation_id",
    "generate_correlation_id",
    "chat_id_context",
    "ChatContextFilter",
    "get_chat_id",
    "set_chat_id",
    "clear_chat_id",
    # Formatting
    "JSONFormatter",
    "TimingContext",
    "set_module_log_level",
    "configure_module_levels",
]
