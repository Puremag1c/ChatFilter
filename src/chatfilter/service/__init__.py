"""Service layer for ChatFilter.

This module provides a clean abstraction between the web UI and the
underlying Telegram and analysis functionality. Services encapsulate
business logic and can be easily tested with mocked dependencies.
"""

from __future__ import annotations

from chatfilter.service.chat_analysis import ChatAnalysisService

__all__ = ["ChatAnalysisService"]
