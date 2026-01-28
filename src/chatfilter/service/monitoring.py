"""Monitoring service for incremental/continuous chat analysis.

This module provides functionality to:
- Enable/disable continuous monitoring for specific chats
- Perform delta sync to fetch only new messages
- Update metrics incrementally without re-fetching history
- Track growth over time (messages/hour, new authors, etc.)
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from chatfilter.models import ChatMonitorState, GrowthMetrics, MonitoringSummary, SyncSnapshot
from chatfilter.storage.database import MonitoringDatabase
from chatfilter.telegram.client import get_messages, get_messages_since
from chatfilter.telegram.session_manager import SessionManager

if TYPE_CHECKING:
    from chatfilter.telegram.client import TelegramClientLoader

logger = logging.getLogger(__name__)


class MonitoringError(Exception):
    """Base exception for monitoring errors."""


class MonitorNotFoundError(MonitoringError):
    """Raised when a monitored chat is not found."""


class MonitoringService:
    """Service for continuous chat monitoring with incremental updates.

    This service enables tracking chat activity over time by:
    1. Storing the last analyzed message ID per chat
    2. Fetching only new messages since last sync (delta sync)
    3. Updating metrics incrementally
    4. Recording sync snapshots for trend analysis

    Example:
        ```python
        service = MonitoringService(
            session_manager=SessionManager(),
            data_dir=Path("data/sessions"),
            db_path=Path("data/monitoring.db"),
        )

        # Enable monitoring for a chat
        state = await service.enable_monitoring("my-session", chat_id=123456)

        # Perform initial sync
        result = await service.sync_chat("my-session", 123456)
        print(f"Synced {result.new_messages} new messages")

        # Later, sync again for delta updates
        result = await service.sync_chat("my-session", 123456)
        print(f"Found {result.new_messages} new messages since last sync")

        # Get growth metrics over last 24 hours
        growth = await service.get_growth_metrics("my-session", 123456, hours=24)
        print(f"Messages/hour: {growth.messages_per_hour}")
        ```
    """

    def __init__(
        self,
        session_manager: SessionManager,
        data_dir: Path,
        db_path: Path | None = None,
    ) -> None:
        """Initialize the monitoring service.

        Args:
            session_manager: Session manager for Telegram connections
            data_dir: Directory containing session data
            db_path: Path to monitoring database (default: data_dir/monitoring.db)
        """
        self._session_manager = session_manager
        self._data_dir = data_dir
        self._loaders: dict[str, TelegramClientLoader] = {}

        # Initialize database
        if db_path is None:
            db_path = data_dir / "monitoring.db"
        self._db = MonitoringDatabase(db_path)

    def _ensure_loader(self, session_id: str) -> None:
        """Ensure loader is registered for session.

        Args:
            session_id: Session identifier

        Raises:
            MonitoringError: If session not found
        """
        from chatfilter.telegram.client import TelegramClientLoader

        if session_id not in self._loaders:
            session_dir = self._data_dir / session_id
            session_path = session_dir / "session.session"
            config_path = session_dir / "config.json"

            if not session_path.exists():
                raise MonitoringError(f"Session '{session_id}' not found")

            loader = TelegramClientLoader(session_path, config_path)
            loader.validate()
            self._session_manager.register(session_id, loader)
            self._loaders[session_id] = loader

    async def enable_monitoring(
        self,
        session_id: str,
        chat_id: int,
        initial_message_limit: int = 1000,
    ) -> ChatMonitorState:
        """Enable monitoring for a chat.

        Performs an initial sync to establish baseline metrics.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to monitor
            initial_message_limit: Max messages to fetch for initial sync

        Returns:
            ChatMonitorState with initial metrics

        Raises:
            MonitoringError: If enabling fails
        """
        self._ensure_loader(session_id)

        # Check if already monitoring
        existing = self._db.load_monitor_state(session_id, chat_id)
        if existing is not None:
            if existing.is_enabled:
                logger.info(f"Chat {chat_id} already monitored, returning existing state")
                return existing
            else:
                # Re-enable existing monitor
                existing.is_enabled = True
                self._db.save_monitor_state(existing)
                logger.info(f"Re-enabled monitoring for chat {chat_id}")
                return existing

        # Create new monitor state
        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            created_at=datetime.now(UTC),
        )

        # Perform initial sync
        start_time = time.perf_counter()

        async with self._session_manager.session(session_id) as client:
            messages = await get_messages(client, chat_id, limit=initial_message_limit)

        if messages:
            # Update state with initial metrics
            author_ids = list({msg.author_id for msg in messages})
            message_ids = [msg.id for msg in messages]
            timestamps = [msg.timestamp for msg in messages]

            state.message_count = len(messages)
            state.unique_author_ids = author_ids
            state.last_message_id = max(message_ids)
            state.last_message_at = max(timestamps)
            state.first_message_at = min(timestamps)
            state.last_sync_at = datetime.now(UTC)

        duration = time.perf_counter() - start_time

        # Save state
        self._db.save_monitor_state(state)

        # Save initial snapshot
        snapshot = SyncSnapshot(
            chat_id=chat_id,
            sync_at=datetime.now(UTC),
            message_count=state.message_count,
            unique_authors=state.unique_authors,
            new_messages=state.message_count,  # All messages are "new" on initial sync
            new_authors=state.unique_authors,
            sync_duration_seconds=duration,
        )
        self._db.save_snapshot(session_id, snapshot)

        logger.info(
            f"Enabled monitoring for chat {chat_id}: "
            f"{state.message_count} messages, {state.unique_authors} authors"
        )

        return state

    async def disable_monitoring(
        self,
        session_id: str,
        chat_id: int,
        delete_data: bool = False,
    ) -> bool:
        """Disable monitoring for a chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to stop monitoring
            delete_data: If True, delete all monitoring data. If False, just disable.

        Returns:
            True if monitoring was disabled, False if not found
        """
        if delete_data:
            deleted = self._db.delete_monitor_state(session_id, chat_id)
            if deleted:
                logger.info(f"Deleted monitoring data for chat {chat_id}")
            return deleted
        else:
            state = self._db.load_monitor_state(session_id, chat_id)
            if state is None:
                return False

            state.is_enabled = False
            self._db.save_monitor_state(state)
            logger.info(f"Disabled monitoring for chat {chat_id}")
            return True

    async def sync_chat(
        self,
        session_id: str,
        chat_id: int,
        max_messages: int | None = None,
    ) -> SyncSnapshot:
        """Perform delta sync for a monitored chat.

        Fetches only new messages since the last sync and updates metrics
        incrementally. Creates a sync snapshot for trend tracking.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to sync
            max_messages: Maximum new messages to fetch per sync (uses settings.max_messages_limit if not provided)

        Returns:
            SyncSnapshot with sync results

        Raises:
            MonitorNotFoundError: If chat is not being monitored
            MonitoringError: If sync fails
        """
        from chatfilter.config import get_settings

        if max_messages is None:
            max_messages = get_settings().max_messages_limit

        self._ensure_loader(session_id)

        # Load existing state
        state = self._db.load_monitor_state(session_id, chat_id)
        if state is None:
            raise MonitorNotFoundError(f"Chat {chat_id} is not being monitored")

        if not state.is_enabled:
            raise MonitoringError(f"Monitoring is disabled for chat {chat_id}")

        start_time = time.perf_counter()
        new_messages_count = 0
        new_authors_count = 0

        async with self._session_manager.session(session_id) as client:
            if state.last_message_id is not None and state.last_message_id > 0:
                # Delta sync - fetch only new messages
                new_messages = await get_messages_since(
                    client, chat_id, min_id=state.last_message_id, limit=max_messages
                )
            else:
                # First sync or no previous messages
                new_messages = await get_messages(client, chat_id, limit=max_messages)

        if new_messages:
            new_messages_count = len(new_messages)

            # Calculate new authors
            existing_authors = set(state.unique_author_ids)
            new_author_ids = {msg.author_id for msg in new_messages}
            truly_new_authors = new_author_ids - existing_authors
            new_authors_count = len(truly_new_authors)

            # Update state incrementally
            state.message_count += new_messages_count
            state.unique_author_ids = list(existing_authors | new_author_ids)

            # Update message bounds
            message_ids = [msg.id for msg in new_messages]
            timestamps = [msg.timestamp for msg in new_messages]

            state.last_message_id = max(message_ids)
            state.last_message_at = max(timestamps)

            if state.first_message_at is None:
                state.first_message_at = min(timestamps)

        state.last_sync_at = datetime.now(UTC)
        duration = time.perf_counter() - start_time

        # Save updated state
        self._db.save_monitor_state(state)

        # Create and save snapshot
        snapshot = SyncSnapshot(
            chat_id=chat_id,
            sync_at=datetime.now(UTC),
            message_count=state.message_count,
            unique_authors=state.unique_authors,
            new_messages=new_messages_count,
            new_authors=new_authors_count,
            sync_duration_seconds=duration,
        )
        self._db.save_snapshot(session_id, snapshot)

        # Cleanup old snapshots (keep last 1000)
        self._db.delete_old_snapshots(session_id, chat_id, keep_count=1000)

        logger.info(
            f"Synced chat {chat_id}: {new_messages_count} new messages, "
            f"{new_authors_count} new authors (total: {state.message_count} messages)"
        )

        return snapshot

    async def sync_all_enabled(
        self,
        session_id: str,
        max_messages_per_chat: int | None = None,
    ) -> list[SyncSnapshot]:
        """Sync all enabled monitors for a session.

        Args:
            session_id: Session identifier
            max_messages_per_chat: Maximum new messages per chat (uses settings.max_messages_limit if not provided)

        Returns:
            List of SyncSnapshots, one per successfully synced chat
        """
        monitors = self._db.load_enabled_monitors(session_id)
        snapshots: list[SyncSnapshot] = []

        for monitor in monitors:
            try:
                snapshot = await self.sync_chat(
                    session_id,
                    monitor.chat_id,
                    max_messages=max_messages_per_chat,
                )
                snapshots.append(snapshot)
            except Exception as e:
                logger.warning(f"Failed to sync chat {monitor.chat_id}: {e}")
                continue

        logger.info(f"Synced {len(snapshots)}/{len(monitors)} enabled monitors")
        return snapshots

    def get_monitor_state(
        self,
        session_id: str,
        chat_id: int,
    ) -> ChatMonitorState | None:
        """Get current monitoring state for a chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID

        Returns:
            ChatMonitorState or None if not monitored
        """
        return self._db.load_monitor_state(session_id, chat_id)

    def list_monitors(
        self,
        session_id: str,
        enabled_only: bool = False,
    ) -> list[ChatMonitorState]:
        """List all monitored chats for a session.

        Args:
            session_id: Session identifier
            enabled_only: If True, only return enabled monitors

        Returns:
            List of ChatMonitorState objects
        """
        if enabled_only:
            return self._db.load_enabled_monitors(session_id)
        return self._db.load_all_monitors(session_id)

    def get_monitoring_summary(
        self,
        session_id: str,
        chat_id: int,
        chat_title: str | None = None,
    ) -> MonitoringSummary | None:
        """Get a summary of monitoring state for a chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID
            chat_title: Optional chat title for the summary

        Returns:
            MonitoringSummary or None if not monitored
        """
        state = self._db.load_monitor_state(session_id, chat_id)
        if state is None:
            return None

        sync_count = self._db.count_snapshots(session_id, chat_id)

        return MonitoringSummary(
            session_id=session_id,
            chat_id=chat_id,
            chat_title=chat_title,
            is_enabled=state.is_enabled,
            last_sync_at=state.last_sync_at,
            message_count=state.message_count,
            unique_authors=state.unique_authors,
            messages_per_hour=state.messages_per_hour,
            history_hours=state.history_hours,
            sync_count=sync_count,
        )

    def get_growth_metrics(
        self,
        session_id: str,
        chat_id: int,
        hours: float = 24.0,
    ) -> GrowthMetrics | None:
        """Calculate growth metrics over a time period.

        Analyzes sync snapshots to compute:
        - Total new messages during period
        - Total new authors during period
        - Message rate (messages/hour)
        - Author growth rate

        Args:
            session_id: Session identifier
            chat_id: Chat ID
            hours: Number of hours to analyze (default: 24)

        Returns:
            GrowthMetrics or None if no data available
        """
        since = datetime.now(UTC) - timedelta(hours=hours)
        snapshots = self._db.load_snapshots(session_id, chat_id, since=since)

        if not snapshots:
            return None

        # Snapshots are newest first, reverse for chronological order
        snapshots = list(reversed(snapshots))

        period_end = datetime.now(UTC)
        period_start = snapshots[0].sync_at

        total_new_messages = sum(s.new_messages for s in snapshots)
        total_new_authors = sum(s.new_authors for s in snapshots)

        period_hours = (period_end - period_start).total_seconds() / 3600.0
        messages_per_hour = total_new_messages / period_hours if period_hours > 0 else 0.0
        author_growth_rate = total_new_authors / period_hours if period_hours > 0 else 0.0

        return GrowthMetrics(
            chat_id=chat_id,
            period_start=period_start,
            period_end=period_end,
            period_hours=period_hours,
            total_new_messages=total_new_messages,
            total_new_authors=total_new_authors,
            messages_per_hour=messages_per_hour,
            author_growth_rate=author_growth_rate,
            snapshots=snapshots,
        )

    def get_snapshots(
        self,
        session_id: str,
        chat_id: int,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[SyncSnapshot]:
        """Get sync snapshots for a chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID
            since: Only return snapshots after this time
            limit: Maximum number of snapshots to return

        Returns:
            List of SyncSnapshot objects (newest first)
        """
        return self._db.load_snapshots(session_id, chat_id, since=since, limit=limit)


# Global monitoring service instance
_monitoring_service: MonitoringService | None = None


def get_monitoring_service(
    session_manager: SessionManager | None = None,
    data_dir: Path | None = None,
    db_path: Path | None = None,
) -> MonitoringService:
    """Get or create the global monitoring service instance.

    Args:
        session_manager: Session manager (required on first call)
        data_dir: Data directory (required on first call)
        db_path: Optional database path

    Returns:
        MonitoringService singleton
    """
    global _monitoring_service

    if _monitoring_service is None:
        if session_manager is None or data_dir is None:
            raise ValueError(
                "session_manager and data_dir required on first call to get_monitoring_service"
            )
        _monitoring_service = MonitoringService(
            session_manager=session_manager,
            data_dir=data_dir,
            db_path=db_path,
        )

    return _monitoring_service


def reset_monitoring_service() -> None:
    """Reset the global monitoring service (for testing)."""
    global _monitoring_service
    _monitoring_service = None
