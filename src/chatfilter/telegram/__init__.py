"""Telegram integration module."""

from chatfilter.telegram.client import (
    MessageFetchError,
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    get_dialogs,
    get_messages,
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
    "MessageFetchError",
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
    "get_messages",
]
