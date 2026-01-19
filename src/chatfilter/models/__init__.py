"""Domain models for ChatFilter.

This module provides Pydantic models for representing Telegram data
in a type-safe, validated manner independent of Telethon internals.

Models:
    Chat: Telegram chat representation
    ChatType: Enum of chat types (private, group, channel, etc.)
    Message: Telegram message representation
    ChatMetrics: Computed metrics from message analysis
    AnalysisResult: Complete analysis result combining chat and metrics
"""

from .analysis import AnalysisResult, ChatMetrics
from .chat import Chat, ChatType
from .message import Message

__all__ = [
    "AnalysisResult",
    "Chat",
    "ChatMetrics",
    "ChatType",
    "Message",
]
