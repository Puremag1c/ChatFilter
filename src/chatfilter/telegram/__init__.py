"""Telegram integration module."""

from chatfilter.telegram.client import (
    JoinChatError,
    MessageFetchError,
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    get_dialogs,
    get_messages,
    join_chat,
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
    "JoinChatError",
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
    "join_chat",
]
