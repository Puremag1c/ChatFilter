"""Telegram client initialization and operations.

This package provides a split module structure for better organization:
- config: Configuration and credential management
- loader: Client creation and initialization
- chats: Dialog fetching and chat operations
- messages: Message fetching and streaming
- membership: Join/leave operations and account info

All public APIs are re-exported here for backward compatibility.
"""

# Re-export config module
from .config import (
    SessionBlockedError,
    SessionFileError,
    TelegramConfig,
    TelegramConfigError,
    validate_session_file,
)

# Re-export loader module
from .loader import TelegramClientLoader

# Re-export chats module
from .chats import get_chat_slowmode, get_dialogs

# Re-export messages module
from .messages import (
    TELEGRAM_BATCH_SIZE,
    ChatAccessDeniedError,
    MAX_MESSAGES_LIMIT,
    MessageFetchError,
    _telethon_message_to_model,
    get_messages,
    get_messages_since,
    get_messages_streaming,
)

# Re-export membership module
from .membership import (
    JoinChatError,
    LeaveChatError,
    RateLimitedJoinError,
    _parse_chat_reference,
    get_account_info,
    join_chat,
    join_chat_with_rotation,
    leave_chat,
)

__all__ = [
    # Config
    "TelegramConfigError",
    "SessionFileError",
    "SessionBlockedError",
    "TelegramConfig",
    "validate_session_file",
    # Loader
    "TelegramClientLoader",
    # Chats
    "get_dialogs",
    "get_chat_slowmode",
    # Messages
    "MessageFetchError",
    "ChatAccessDeniedError",
    "_telethon_message_to_model",
    "get_messages",
    "get_messages_streaming",
    "get_messages_since",
    "MAX_MESSAGES_LIMIT",
    "TELEGRAM_BATCH_SIZE",
    # Membership
    "JoinChatError",
    "RateLimitedJoinError",
    "LeaveChatError",
    "_parse_chat_reference",
    "join_chat",
    "leave_chat",
    "join_chat_with_rotation",
    "get_account_info",
]
