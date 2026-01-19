"""Telegram integration module."""

from chatfilter.telegram.client import (
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    get_dialogs,
)

__all__ = [
    "SessionFileError",
    "TelegramClientLoader",
    "TelegramConfig",
    "TelegramConfigError",
    "get_dialogs",
]
