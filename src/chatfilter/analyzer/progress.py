"""Progress tracking and SSE event publishing for group analysis.

This module provides:
- GroupProgressEvent: dataclass for progress events
- ProgressTracker: pub/sub manager for SSE events with subscribers
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from chatfilter.models.group import GroupStatus

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)


@dataclass
class GroupProgressEvent:
    """Progress event for group analysis workflow.

    Attributes:
        group_id: Group identifier
        status: Current status
        current: Current chat index
        total: Total number of chats
        chat_title: Currently processing chat title
        message: Status message
        error: Error message if failed
        task_id: Optional underlying task_id
        breakdown: Status breakdown {done, error, dead, pending} counts
        flood_wait_until: FloodWait expiry timestamp (when waiting globally)
    """

    group_id: str
    status: str
    current: int
    total: int
    chat_title: str | None = None
    message: str | None = None
    error: str | None = None
    task_id: UUID | None = None
    breakdown: dict[str, int] | None = None
    flood_wait_until: datetime | None = None


class ProgressTracker:
    """Manages SSE event subscribers and publishes progress updates."""

    def __init__(self, db: GroupDatabase) -> None:
        """Initialize progress tracker.

        Args:
            db: GroupDatabase instance for querying stats
        """
        self._db = db
        self._subscribers: dict[str, list[asyncio.Queue[GroupProgressEvent]]] = {}

    def subscribe(self, group_id: str) -> asyncio.Queue[GroupProgressEvent]:
        """Subscribe to progress events for a group analysis.

        Args:
            group_id: Group identifier to subscribe to.

        Returns:
            Queue that will receive progress events.
        """
        queue: asyncio.Queue[GroupProgressEvent] = asyncio.Queue()
        self._subscribers.setdefault(group_id, []).append(queue)
        return queue

    def publish(self, event: GroupProgressEvent) -> None:
        """Publish progress event to all subscribers of the group.

        Args:
            event: Progress event to publish.
        """
        subscribers = self._subscribers.get(event.group_id, [])
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    f"Subscriber queue full for group '{event.group_id}', "
                    f"dropping event"
                )

    def publish_from_db(
        self,
        group_id: str,
        chat_title: str,
        message: str | None = None,
        error: str | None = None,
    ) -> None:
        """Publish progress event with global counts and status breakdown from DB.

        Counts processed (done + failed + dead) and total chats from DB,
        then publishes GroupProgressEvent with status breakdown for live badge updates.

        Args:
            group_id: Group identifier
            chat_title: Title of the chat that triggered this progress update
            message: Optional status message
            error: Optional error message
        """
        processed, total = self._db.count_processed_chats(group_id)

        # Get detailed stats for badge breakdown
        stats_dict = self._db.get_group_stats(group_id)
        by_status = stats_dict.get("by_status", {})
        by_type = stats_dict.get("by_type", {})

        # Build breakdown for SSE (matches GroupStats structure used in templates)
        breakdown = {
            "done": by_status.get("done", 0),
            "error": by_status.get("error", 0),
            "dead": by_type.get("dead", 0),
            "pending": by_status.get("pending", 0),
        }

        event = GroupProgressEvent(
            group_id=group_id,
            status=GroupStatus.IN_PROGRESS.value,
            chat_title=chat_title,
            current=processed,
            total=total,
            message=message,
            error=error,
            breakdown=breakdown,
        )
        self.publish(event)

    def signal_completion(self, group_id: str) -> None:
        """Send completion sentinel (None) to all subscribers.

        Args:
            group_id: Group identifier
        """
        subscribers = self._subscribers.get(group_id, [])
        for queue in subscribers:
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                logger.warning(
                    f"Subscriber queue full for group '{group_id}', "
                    f"dropping completion sentinel"
                )


def compute_group_status(db: GroupDatabase, group_id: str) -> str:
    """Compute group status from chat statuses.

    Aggregates individual chat statuses to determine overall group state:
    - All pending → PENDING
    - All error → FAILED
    - All done → COMPLETED
    - Mixed or some done → IN_PROGRESS

    Args:
        db: Database instance
        group_id: Group identifier

    Returns:
        GroupStatus value (pending/in_progress/completed/failed)
    """
    return db.compute_group_status(group_id)
