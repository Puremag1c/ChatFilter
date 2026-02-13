"""Domain models for ChatFilter.

This module provides Pydantic models for representing Telegram data
in a type-safe, validated manner independent of Telethon internals.

Models:
    Chat: Telegram chat representation
    ChatType: Enum of chat types (private, group, channel, etc.)
    Message: Telegram message representation
    ChatMetrics: Computed metrics from message analysis
    AnalysisResult: Complete analysis result combining chat and metrics
    AccountInfo: Telegram account information with subscription limits
    ChatMonitorState: Persistent state for continuous chat monitoring
    SyncSnapshot: Point-in-time metrics snapshot for trend tracking
    MonitoringSummary: Summary of monitoring status for API responses
    GrowthMetrics: Growth metrics over a time period
    ProxyEntry: Proxy configuration entry for the proxy pool
    ChatGroup: Group of chats for batch analysis
    GroupChat: Individual chat entry within a group
    GroupSettings: Settings for group analysis
    GroupStats: Statistics for group processing
    GroupStatus: Enum of group statuses
    ChatTypeEnum: Enum of chat type classifications for groups
    GroupChatStatus: Enum of individual chat processing statuses
"""

from .account import (
    CRITICAL_THRESHOLD,
    PREMIUM_CHAT_LIMIT,
    STANDARD_CHAT_LIMIT,
    WARNING_THRESHOLD,
    AccountInfo,
)
from .analysis import AnalysisResult, ChatMetrics
from .chat import Chat, ChatType
from .group import (
    ChatGroup,
    ChatTypeEnum,
    GroupChat,
    GroupChatStatus,
    GroupSettings,
    GroupStats,
    GroupStatus,
)
from .message import Message
from .monitoring import ChatMonitorState, GrowthMetrics, MonitoringSummary, SyncSnapshot
from .proxy import ProxyEntry

__all__ = [
    "AccountInfo",
    "AnalysisResult",
    "Chat",
    "ChatGroup",
    "ChatMetrics",
    "ChatMonitorState",
    "ChatType",
    "ChatTypeEnum",
    "CRITICAL_THRESHOLD",
    "GroupChat",
    "GroupChatStatus",
    "GroupSettings",
    "GroupStats",
    "GroupStatus",
    "GrowthMetrics",
    "Message",
    "MonitoringSummary",
    "PREMIUM_CHAT_LIMIT",
    "ProxyEntry",
    "STANDARD_CHAT_LIMIT",
    "SyncSnapshot",
    "WARNING_THRESHOLD",
]
