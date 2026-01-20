"""Chat analysis service layer.

This module provides the main service for chat analysis, encapsulating
business logic related to Telegram sessions, chat listing, and analysis.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from chatfilter.analyzer import compute_metrics
from chatfilter.models import AnalysisResult, Chat, ChatType
from chatfilter.telegram.client import TelegramClientLoader, get_dialogs, get_messages
from chatfilter.telegram.session_manager import SessionManager

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)


class SessionNotFoundError(Exception):
    """Raised when a session is not found or incomplete."""

    pass


class ChatAnalysisService:
    """Service for chat analysis operations.

    This service encapsulates all business logic related to:
    - Session management and validation
    - Chat listing from Telegram
    - Message fetching and analysis

    The service accepts dependencies via constructor for testability.

    Example:
        ```python
        service = ChatAnalysisService(
            session_manager=SessionManager(),
            data_dir=Path("data/sessions")
        )
        chats = await service.get_chats("my-session")
        result = await service.analyze_chat("my-session", 123456)
        ```
    """

    def __init__(
        self,
        session_manager: SessionManager,
        data_dir: Path,
    ) -> None:
        """Initialize the service.

        Args:
            session_manager: Session manager for Telegram connections
            data_dir: Directory containing session data
        """
        self._session_manager = session_manager
        self._data_dir = data_dir
        self._loaders: dict[str, TelegramClientLoader] = {}
        self._chat_cache: dict[str, dict[int, Chat]] = {}

    def _get_session_paths(self, session_id: str) -> tuple[Path, Path]:
        """Get session and config file paths for a session ID.

        Args:
            session_id: Session identifier

        Returns:
            Tuple of (session_path, config_path)

        Raises:
            SessionNotFoundError: If session not found or incomplete
        """
        session_dir = self._data_dir / session_id

        if not session_dir.exists():
            raise SessionNotFoundError(f"Session '{session_id}' not found")

        session_path = session_dir / "session.session"
        config_path = session_dir / "config.json"

        if not session_path.exists() or not config_path.exists():
            raise SessionNotFoundError(
                f"Session '{session_id}' is incomplete (missing files)"
            )

        return session_path, config_path

    def _ensure_loader(self, session_id: str) -> None:
        """Ensure loader is registered for session.

        Args:
            session_id: Session identifier

        Raises:
            SessionNotFoundError: If session not found
        """
        if session_id not in self._loaders:
            session_path, config_path = self._get_session_paths(session_id)
            loader = TelegramClientLoader(session_path, config_path)
            loader.validate()
            self._session_manager.register(session_id, loader)
            self._loaders[session_id] = loader

    async def get_chats(self, session_id: str) -> list[Chat]:
        """Get list of chats from a Telegram session.

        Args:
            session_id: Session identifier

        Returns:
            List of Chat objects

        Raises:
            SessionNotFoundError: If session not found
            Exception: If connection or fetch fails
        """
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            chats = await get_dialogs(client)

            # Cache chat info for later use
            if session_id not in self._chat_cache:
                self._chat_cache[session_id] = {}
            for chat in chats:
                self._chat_cache[session_id][chat.id] = chat

            logger.info(f"Fetched {len(chats)} chats from session '{session_id}'")
            return chats

    async def get_chats_paginated(
        self, session_id: str, offset: int = 0, limit: int = 100
    ) -> tuple[list[Chat], int]:
        """Get paginated list of chats from a Telegram session.

        This method fetches all chats (cached if available) and returns
        a slice based on offset/limit to support pagination.

        Args:
            session_id: Session identifier
            offset: Number of chats to skip (default: 0)
            limit: Maximum number of chats to return (default: 100)

        Returns:
            Tuple of (chat_list_slice, total_count)

        Raises:
            SessionNotFoundError: If session not found
            Exception: If connection or fetch fails
        """
        # Get all chats (will be cached after first call)
        all_chats = await self.get_chats(session_id)
        total_count = len(all_chats)

        # Return paginated slice
        end_index = min(offset + limit, total_count)
        paginated_chats = all_chats[offset:end_index]

        logger.info(
            f"Returning {len(paginated_chats)} chats "
            f"(offset={offset}, limit={limit}, total={total_count}) "
            f"from session '{session_id}'"
        )
        return paginated_chats, total_count

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get cached chat info.

        Args:
            session_id: Session identifier
            chat_id: Chat ID

        Returns:
            Chat object if found in cache, None otherwise
        """
        if session_id in self._chat_cache and chat_id in self._chat_cache[session_id]:
            return self._chat_cache[session_id][chat_id]
        return None

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
        message_limit: int = 1000,
    ) -> AnalysisResult:
        """Analyze a single chat.

        Fetches messages from the chat and computes metrics.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to analyze
            message_limit: Maximum messages to fetch (default 1000)

        Returns:
            AnalysisResult with metrics

        Raises:
            SessionNotFoundError: If session not found
            Exception: If fetch or analysis fails
        """
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            # Fetch messages
            messages = await get_messages(client, chat_id, limit=message_limit)

            # Compute metrics
            metrics = compute_metrics(messages)

            # Get chat info from cache
            chat = await self.get_chat_info(session_id, chat_id)
            if chat is None:
                # Create minimal chat info
                chat = Chat(
                    id=chat_id,
                    title=f"Chat {chat_id}",
                    chat_type=ChatType.GROUP,
                )

            return AnalysisResult(
                chat=chat,
                metrics=metrics,
                analyzed_at=datetime.now(UTC),
            )

    async def validate_session(self, session_id: str) -> bool:
        """Validate that a session exists and can be loaded.

        Args:
            session_id: Session identifier

        Returns:
            True if session is valid, False otherwise
        """
        try:
            self._ensure_loader(session_id)
            return True
        except (SessionNotFoundError, Exception) as e:
            logger.debug(f"Session validation failed for '{session_id}': {e}")
            return False
