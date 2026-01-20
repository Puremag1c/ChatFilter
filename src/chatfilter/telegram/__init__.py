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
from chatfilter.telegram.rate_limiter import (
    RateLimitConfig,
    TelegramRateLimiter,
    get_rate_limiter,
    set_rate_limiter,
)
from chatfilter.telegram.session_manager import (
    SessionConnectError,
    SessionError,
    SessionInfo,
    SessionInvalidError,
    SessionManager,
    SessionNotConnectedError,
    SessionReauthRequiredError,
    SessionState,
    SessionTimeoutError,
)

__all__ = [
    "JoinChatError",
    "MessageFetchError",
    "RateLimitConfig",
    "SessionConnectError",
    "SessionError",
    "SessionFileError",
    "SessionInfo",
    "SessionInvalidError",
    "SessionManager",
    "SessionNotConnectedError",
    "SessionReauthRequiredError",
    "SessionState",
    "SessionTimeoutError",
    "TelegramClientLoader",
    "TelegramConfig",
    "TelegramConfigError",
    "TelegramRateLimiter",
    "get_dialogs",
    "get_messages",
    "get_rate_limiter",
    "join_chat",
    "set_rate_limiter",
]
