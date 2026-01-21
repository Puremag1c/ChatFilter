"""Service layer for ChatFilter.

This module provides a clean abstraction between the web UI and the
underlying Telegram and analysis functionality. Services encapsulate
business logic and can be easily tested with mocked dependencies.
"""

from __future__ import annotations

from chatfilter.service.chat_analysis import ChatAnalysisService
from chatfilter.service.monitoring import (
    MonitoringError,
    MonitoringService,
    MonitorNotFoundError,
    get_monitoring_service,
    reset_monitoring_service,
)

__all__ = [
    "ChatAnalysisService",
    "MonitoringError",
    "MonitoringService",
    "MonitorNotFoundError",
    "get_monitoring_service",
    "reset_monitoring_service",
]
