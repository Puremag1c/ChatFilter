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
from .message import Message
from .monitoring import ChatMonitorState, GrowthMetrics, MonitoringSummary, SyncSnapshot
from .proxy import ProxyEntry

__all__ = [
    "AccountInfo",
    "AnalysisResult",
    "Chat",
    "ChatMetrics",
    "ChatMonitorState",
    "ChatType",
    "CRITICAL_THRESHOLD",
    "GrowthMetrics",
    "Message",
    "MonitoringSummary",
    "PREMIUM_CHAT_LIMIT",
    "ProxyEntry",
    "STANDARD_CHAT_LIMIT",
    "SyncSnapshot",
    "WARNING_THRESHOLD",
]
