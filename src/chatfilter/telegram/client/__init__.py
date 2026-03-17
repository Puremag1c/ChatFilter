"""Telegram client initialization and operations.

This package provides a split module structure for better organization:
- config: Configuration and credential management
- loader: Client creation and initialization
- chats: Dialog fetching and chat operations
- messages: Message fetching and streaming
- membership: Join/leave operations and account info

Only public APIs used by telegram/__init__.py are re-exported here.
"""

# Re-export config module
from .config import (
    SessionFileError,
    TelegramConfig,
    TelegramConfigError,
)

# Re-export loader module
from .loader import TelegramClientLoader

# Re-export chats module
from .chats import get_dialogs

# Re-export messages module
from .messages import (
    ChatAccessDeniedError,
    MessageFetchError,
    get_messages,
    get_messages_since,
    get_messages_streaming,
)

# Re-export membership module
from .membership import (
    JoinChatError,
    LeaveChatError,
    get_account_info,
    join_chat,
    join_chat_with_rotation,
    leave_chat,
)

__all__ = [
    # Config
    "TelegramConfigError",
    "SessionFileError",
    "TelegramConfig",
    # Loader
    "TelegramClientLoader",
    # Chats
    "get_dialogs",
    # Messages
    "MessageFetchError",
    "ChatAccessDeniedError",
    "get_messages",
    "get_messages_streaming",
    "get_messages_since",
    # Membership
    "JoinChatError",
    "LeaveChatError",
    "join_chat",
    "leave_chat",
    "join_chat_with_rotation",
    "get_account_info",
]
