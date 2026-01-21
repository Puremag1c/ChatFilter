"""Chat analysis service layer.

This module provides the main service for chat analysis, encapsulating
business logic related to Telegram sessions, chat listing, and analysis.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from chatfilter.analyzer import compute_metrics
from chatfilter.analyzer.metrics import StreamingMetricsAggregator
from chatfilter.models import AccountInfo, AnalysisResult, Chat, ChatType
from chatfilter.telegram.client import (
    TelegramClientLoader,
    get_account_info,
    get_chat_slowmode,
    get_dialogs,
    get_messages,
    get_messages_streaming,
    join_chat,
    join_chat_with_rotation,
    leave_chat,
)
from chatfilter.telegram.session_manager import SessionManager
from chatfilter.utils.memory import MemoryMonitor, MemoryTracker, log_memory_usage

if TYPE_CHECKING:
    pass

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
            raise SessionNotFoundError(f"Session '{session_id}' is incomplete (missing files)")

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

    async def validate_chat_ids(
        self,
        session_id: str,
        chat_ids: list[int],
    ) -> tuple[list[int], list[int]]:
        """Validate that chat IDs are still accessible in the Telegram session.

        This method fetches the current list of chats from Telegram to ensure
        that selected chat IDs are not stale (e.g., chats deleted or removed
        between selection and analysis start).

        Args:
            session_id: Session identifier
            chat_ids: List of chat IDs to validate

        Returns:
            Tuple of (valid_chat_ids, invalid_chat_ids)
            - valid_chat_ids: List of chat IDs that exist and are accessible
            - invalid_chat_ids: List of chat IDs that are stale or inaccessible

        Raises:
            SessionNotFoundError: If session not found
            Exception: If connection or fetch fails
        """
        # Force fresh fetch from Telegram (bypass cache)
        # Clear cache for this session to ensure we get current state
        if session_id in self._chat_cache:
            del self._chat_cache[session_id]

        # Fetch current chat list from Telegram
        current_chats = await self.get_chats(session_id)
        current_chat_ids = {chat.id for chat in current_chats}

        # Separate valid and invalid chat IDs
        valid_ids = [chat_id for chat_id in chat_ids if chat_id in current_chat_ids]
        invalid_ids = [chat_id for chat_id in chat_ids if chat_id not in current_chat_ids]

        logger.info(
            f"Validated {len(chat_ids)} chat IDs for session '{session_id}': "
            f"{len(valid_ids)} valid, {len(invalid_ids)} invalid/stale"
        )

        return valid_ids, invalid_ids

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
        message_limit: int = 1000,
        batch_size: int = 1000,
        use_streaming: bool | None = None,
        memory_limit_mb: float = 1024.0,
        enable_memory_monitoring: bool = False,
        batch_progress_callback: Callable[..., Awaitable[None]] | None = None,
    ) -> AnalysisResult:
        """Analyze a single chat.

        Fetches messages from the chat and computes metrics. For large chats
        (>100k messages), automatically uses streaming to avoid memory issues.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to analyze
            message_limit: Maximum messages to fetch (default 1000)
            batch_size: Batch size for streaming mode (default 1000)
            use_streaming: Force streaming mode (None = auto-detect based on limit)
            memory_limit_mb: Memory threshold in MB (default 1024MB)
            enable_memory_monitoring: Enable memory monitoring and logging
            batch_progress_callback: Optional callback for batch progress updates

        Returns:
            AnalysisResult with metrics

        Raises:
            SessionNotFoundError: If session not found
            MemoryError: If memory limit exceeded (when monitoring enabled)
            Exception: If fetch or analysis fails
        """
        import time

        start_time = time.perf_counter()

        self._ensure_loader(session_id)

        # Auto-detect streaming mode for large chats
        if use_streaming is None:
            use_streaming = message_limit > 100_000

        # Auto-enable memory monitoring for large chats or streaming mode
        if not enable_memory_monitoring and (use_streaming or message_limit > 50_000):
            enable_memory_monitoring = True
            logger.info(
                f"Auto-enabled memory monitoring for chat {chat_id} "
                f"(limit={message_limit}, streaming={use_streaming})"
            )

        # Setup memory monitoring if enabled
        memory_monitor = None
        memory_tracker = None
        if enable_memory_monitoring:
            memory_monitor = MemoryMonitor(
                threshold_mb=memory_limit_mb,
                circuit_breaker=False,  # Log warnings but don't raise
            )
            memory_tracker = MemoryTracker()
            memory_tracker.snapshot("start")
            log_memory_usage(f"Starting analysis for chat {chat_id}")

            # Check memory before starting - warn if already high
            initial_check = memory_monitor.check()
            if not initial_check:
                logger.warning(
                    f"Memory usage is already high before starting analysis of chat {chat_id}. "
                    f"Consider using streaming mode or increasing memory_limit_mb."
                )

                # Auto-enable streaming if memory is already high
                if not use_streaming and message_limit > 10_000:
                    logger.warning(
                        f"Auto-switching to streaming mode for chat {chat_id} "
                        f"due to high memory usage"
                    )
                    use_streaming = True

        async with self._session_manager.session(session_id) as client:
            if use_streaming:
                # Stream processing for large chats
                logger.info(
                    f"Using streaming mode for chat {chat_id} "
                    f"(limit={message_limit}, batch_size={batch_size})"
                )

                aggregator = StreamingMetricsAggregator()
                batch_count = 0

                async for batch in get_messages_streaming(
                    client, chat_id, batch_size=batch_size, max_messages=message_limit
                ):
                    batch_count += 1
                    aggregator.add_batch(batch)

                    # Log batch progress
                    logger.debug(
                        f"Processed batch {batch_count}: "
                        f"+{len(batch)} messages, "
                        f"total={aggregator.message_count}"
                    )

                    # Report batch progress to callback
                    if batch_progress_callback:
                        estimated_total_batches = (
                            (message_limit + batch_size - 1) // batch_size
                            if message_limit
                            else None
                        )
                        await batch_progress_callback(
                            messages_processed=aggregator.message_count,
                            batch_number=batch_count,
                            total_batches=estimated_total_batches,
                        )

                    # Check memory periodically
                    if memory_monitor and batch_count % 10 == 0:
                        memory_monitor.check()
                        if memory_tracker:
                            memory_tracker.snapshot(f"batch_{batch_count}")

                # Get final metrics from aggregator
                metrics = aggregator.get_metrics()

                logger.info(
                    f"Streaming analysis complete for chat {chat_id}: "
                    f"{metrics.message_count} messages in {batch_count} batches"
                )

            else:
                # Standard processing for smaller chats
                logger.debug(f"Using standard mode for chat {chat_id} (limit={message_limit})")

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

            # Enrich chat with slowmode info if available
            slowmode_seconds = await get_chat_slowmode(client, chat_id)
            if slowmode_seconds is not None:
                # Create new Chat instance with slowmode info (Chat is frozen/immutable)
                chat = Chat(
                    id=chat.id,
                    title=chat.title,
                    chat_type=chat.chat_type,
                    username=chat.username,
                    member_count=chat.member_count,
                    is_archived=chat.is_archived,
                    slowmode_seconds=slowmode_seconds,
                )

            # Log final memory usage
            if memory_tracker:
                memory_tracker.snapshot("end")
                memory_tracker.log_diff("start", "end")
                log_memory_usage(f"Completed analysis for chat {chat_id}")

            # Calculate analysis duration
            duration_seconds = time.perf_counter() - start_time

            # Add duration to metrics (use model_copy since ChatMetrics is frozen)
            metrics_with_duration = metrics.model_copy(
                update={"duration_seconds": duration_seconds}
            )

            return AnalysisResult(
                chat=chat,
                metrics=metrics_with_duration,
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

    def clear_cache(self, session_id: str | None = None) -> None:
        """Clear cached data for a session or all sessions.

        This method removes cached chat data and loaders to free memory.
        Should be called periodically for long-running services or when
        a session is no longer needed.

        Args:
            session_id: Session ID to clear cache for. If None, clears all caches.
        """
        if session_id:
            # Clear cache for specific session
            if session_id in self._chat_cache:
                count = len(self._chat_cache[session_id])
                del self._chat_cache[session_id]
                logger.info(f"Cleared {count} cached chats for session '{session_id}'")

            if session_id in self._loaders:
                del self._loaders[session_id]
                logger.info(f"Cleared loader for session '{session_id}'")
        else:
            # Clear all caches
            chat_count = sum(len(chats) for chats in self._chat_cache.values())
            loader_count = len(self._loaders)

            self._chat_cache.clear()
            self._loaders.clear()

            logger.info(f"Cleared all caches: {chat_count} chats, {loader_count} loaders")

    def get_cache_stats(self) -> dict[str, int]:
        """Get statistics about cached data.

        Returns:
            Dictionary with cache statistics:
            - total_sessions: Number of sessions with cached data
            - total_chats: Total number of cached chats
            - total_loaders: Number of registered loaders
        """
        return {
            "total_sessions": len(self._chat_cache),
            "total_chats": sum(len(chats) for chats in self._chat_cache.values()),
            "total_loaders": len(self._loaders),
        }

    async def get_account_info(self, session_id: str) -> AccountInfo:
        """Get account information including Premium status and subscription limits.

        Args:
            session_id: Session identifier

        Returns:
            AccountInfo with Premium status, chat count, and computed limits

        Raises:
            SessionNotFoundError: If session not found
            Exception: If connection or fetch fails
        """
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            info = await get_account_info(client)
            logger.info(
                f"Account info for session '{session_id}': "
                f"{info.display_name}, Premium={info.is_premium}, "
                f"Chats={info.chat_count}/{info.chat_limit}"
            )
            return info

    async def leave_chat(
        self,
        session_id: str,
        chat_id: int,
    ) -> bool:
        """Leave a chat to free up a subscription slot.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to leave

        Returns:
            True if successfully left the chat

        Raises:
            SessionNotFoundError: If session not found
            LeaveChatError: If leaving fails
        """
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            result = await leave_chat(client, chat_id)

            # Invalidate chat cache since we left a chat
            if session_id in self._chat_cache and chat_id in self._chat_cache[session_id]:
                del self._chat_cache[session_id][chat_id]
                logger.info(f"Removed chat {chat_id} from cache after leaving")

            return result

    async def join_chat(
        self,
        session_id: str,
        chat_ref: str,
    ) -> Chat:
        """Join a chat by username or invite link.

        Args:
            session_id: Session identifier
            chat_ref: Chat reference (username or link)

        Returns:
            Chat model of the joined chat

        Raises:
            SessionNotFoundError: If session not found
            JoinChatError: If joining fails
        """
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            chat = await join_chat(client, chat_ref)

            # Add to cache
            if session_id not in self._chat_cache:
                self._chat_cache[session_id] = {}
            self._chat_cache[session_id][chat.id] = chat

            logger.info(f"Joined chat {chat.title} ({chat.id}) for session '{session_id}'")
            return chat

    async def join_chat_with_rotation(
        self,
        session_id: str,
        chat_ref: str,
        chats_to_leave: list[int] | None = None,
    ) -> tuple[Chat, list[int]]:
        """Join a chat, automatically leaving old chats if at subscription limit.

        This method enables bulk chat analysis workflows by automatically
        managing subscription limits.

        Args:
            session_id: Session identifier
            chat_ref: Chat reference to join (username or link)
            chats_to_leave: Optional list of chat IDs to leave if at limit.
                           If None and at limit, raises JoinChatError.

        Returns:
            Tuple of (joined_chat, actually_left_chat_ids)

        Raises:
            SessionNotFoundError: If session not found
            JoinChatError: If joining fails or at limit with no chats to leave
        """
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            chat, left_ids = await join_chat_with_rotation(client, chat_ref, chats_to_leave)

            # Update cache - remove left chats
            if session_id in self._chat_cache:
                for left_id in left_ids:
                    if left_id in self._chat_cache[session_id]:
                        del self._chat_cache[session_id][left_id]

            # Add joined chat to cache
            if session_id not in self._chat_cache:
                self._chat_cache[session_id] = {}
            self._chat_cache[session_id][chat.id] = chat

            logger.info(
                f"Joined chat {chat.title} ({chat.id}) for session '{session_id}', "
                f"left {len(left_ids)} chats for rotation"
            )
            return chat, left_ids
