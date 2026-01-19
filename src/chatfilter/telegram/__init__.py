"""Telegram integration module."""

from chatfilter.telegram.client import (
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    get_dialogs,
)
from chatfilter.telegram.session_manager import (
    SessionConnectError,
    SessionError,
    SessionInfo,
    SessionManager,
    SessionNotConnectedError,
    SessionState,
    SessionTimeoutError,
)

__all__ = [
    "SessionConnectError",
    "SessionError",
    "SessionFileError",
    "SessionInfo",
    "SessionManager",
    "SessionNotConnectedError",
    "SessionState",
    "SessionTimeoutError",
    "TelegramClientLoader",
    "TelegramConfig",
    "TelegramConfigError",
    "get_dialogs",
]
