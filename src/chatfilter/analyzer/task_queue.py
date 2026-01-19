"""Asyncio-based task queue for chat analysis.

Provides:
- Task creation with UUID tracking
- In-memory task state management
- Progress event publishing via asyncio.Queue
- Injectable executor for testing
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from chatfilter.models import AnalysisResult, Chat

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Status of an analysis task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ProgressEvent:
    """Progress update event for SSE streaming."""

    task_id: UUID
    status: TaskStatus
    current: int  # Current chat index (0-based)
    total: int  # Total number of chats
    chat_title: str | None = None  # Currently processing chat
    message: str | None = None  # Optional status message
    error: str | None = None  # Error message if failed


@dataclass
class AnalysisTask:
    """Represents an analysis task in the queue."""

    task_id: UUID
    session_id: str
    chat_ids: list[int]
    message_limit: int = 1000
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    results: list[AnalysisResult] = field(default_factory=list)
    error: str | None = None
    current_chat_index: int = 0


class AnalysisExecutor(Protocol):
    """Protocol for analysis executor (allows test injection)."""

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
        message_limit: int = 1000,
    ) -> AnalysisResult:
        """Analyze a single chat and return results."""
        ...

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get chat info for a chat ID."""
        ...


class TaskQueue:
    """In-memory task queue for analysis jobs.

    Thread-safe asyncio-based queue with progress event publishing.

    Example:
        ```python
        queue = TaskQueue()

        # Create a task
        task = queue.create_task("session1", [123, 456, 789])

        # Subscribe to progress events
        async for event in queue.subscribe(task.task_id):
            print(f"Progress: {event.current}/{event.total}")

        # Get task status
        task = queue.get_task(task.task_id)
        print(f"Status: {task.status}")
        ```
    """

    def __init__(self) -> None:
        """Initialize the task queue."""
        self._tasks: dict[UUID, AnalysisTask] = {}
        self._subscribers: dict[UUID, list[asyncio.Queue[ProgressEvent | None]]] = {}
        self._lock = asyncio.Lock()

    def create_task(
        self,
        session_id: str,
        chat_ids: list[int],
        message_limit: int = 1000,
    ) -> AnalysisTask:
        """Create a new analysis task.

        Args:
            session_id: Session identifier for Telegram connection
            chat_ids: List of chat IDs to analyze
            message_limit: Maximum messages to fetch per chat (default 1000)

        Returns:
            Created AnalysisTask with generated UUID
        """
        task = AnalysisTask(
            task_id=uuid4(),
            session_id=session_id,
            chat_ids=chat_ids,
            message_limit=message_limit,
        )
        self._tasks[task.task_id] = task
        self._subscribers[task.task_id] = []
        logger.info(f"Created analysis task {task.task_id} for {len(chat_ids)} chats")
        return task

    def get_task(self, task_id: UUID) -> AnalysisTask | None:
        """Get task by ID.

        Args:
            task_id: Task UUID

        Returns:
            AnalysisTask or None if not found
        """
        return self._tasks.get(task_id)

    def get_all_tasks(self) -> list[AnalysisTask]:
        """Get all tasks.

        Returns:
            List of all tasks (newest first)
        """
        return sorted(
            self._tasks.values(),
            key=lambda t: t.created_at,
            reverse=True,
        )

    async def subscribe(
        self,
        task_id: UUID,
    ) -> asyncio.Queue[ProgressEvent | None]:
        """Subscribe to progress events for a task.

        Args:
            task_id: Task UUID to subscribe to

        Returns:
            asyncio.Queue that receives ProgressEvent objects.
            None is sent when task completes/fails to signal end.

        Raises:
            KeyError: If task not found
        """
        if task_id not in self._tasks:
            raise KeyError(f"Task {task_id} not found")

        queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers[task_id].append(queue)

        logger.debug(f"New subscriber for task {task_id}")
        return queue

    async def unsubscribe(
        self,
        task_id: UUID,
        queue: asyncio.Queue[ProgressEvent | None],
    ) -> None:
        """Unsubscribe from progress events.

        Args:
            task_id: Task UUID
            queue: Queue to unsubscribe
        """
        async with self._lock:
            if task_id in self._subscribers:
                try:
                    self._subscribers[task_id].remove(queue)
                    logger.debug(f"Unsubscribed from task {task_id}")
                except ValueError:
                    pass

    async def _publish_event(self, event: ProgressEvent) -> None:
        """Publish a progress event to all subscribers.

        Args:
            event: Event to publish
        """
        async with self._lock:
            subscribers = self._subscribers.get(event.task_id, [])
            for queue in subscribers:
                try:
                    # Non-blocking put with backpressure handling
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    # Drop oldest event to prevent memory issues
                    try:
                        queue.get_nowait()
                        queue.put_nowait(event)
                    except asyncio.QueueEmpty:
                        pass

    async def _signal_completion(self, task_id: UUID) -> None:
        """Signal task completion to all subscribers.

        Args:
            task_id: Completed task ID
        """
        async with self._lock:
            subscribers = self._subscribers.get(task_id, [])
            for queue in subscribers:
                try:
                    queue.put_nowait(None)
                except asyncio.QueueFull:
                    pass

    async def run_task(
        self,
        task_id: UUID,
        executor: AnalysisExecutor,
    ) -> None:
        """Execute an analysis task.

        Processes each chat, publishes progress events, and stores results.

        Args:
            task_id: Task UUID to run
            executor: Analysis executor implementation

        Raises:
            KeyError: If task not found
        """
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"Task {task_id} not found")

        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now(UTC)

        try:
            for i, chat_id in enumerate(task.chat_ids):
                task.current_chat_index = i

                # Get chat info for progress display
                chat_info = await executor.get_chat_info(task.session_id, chat_id)
                chat_title = chat_info.title if chat_info else f"Chat {chat_id}"

                # Publish progress event
                await self._publish_event(
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.IN_PROGRESS,
                        current=i,
                        total=len(task.chat_ids),
                        chat_title=chat_title,
                        message=f"Analyzing {chat_title}...",
                    )
                )

                # Analyze chat
                try:
                    result = await executor.analyze_chat(
                        task.session_id,
                        chat_id,
                        task.message_limit,
                    )
                    task.results.append(result)
                except Exception as e:
                    logger.warning(f"Failed to analyze chat {chat_id}: {e}")
                    # Continue with other chats

            # Mark completed
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(UTC)

            await self._publish_event(
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.COMPLETED,
                    current=len(task.chat_ids),
                    total=len(task.chat_ids),
                    message=f"Analysis complete. {len(task.results)} chats analyzed.",
                )
            )

            logger.info(f"Task {task_id} completed with {len(task.results)} results")

        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.now(UTC)

            await self._publish_event(
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    current=task.current_chat_index,
                    total=len(task.chat_ids),
                    error=str(e),
                )
            )

            logger.exception(f"Task {task_id} failed: {e}")

        finally:
            await self._signal_completion(task_id)

    def cancel_task(self, task_id: UUID) -> bool:
        """Cancel a pending or in-progress task.

        Args:
            task_id: Task UUID to cancel

        Returns:
            True if cancelled, False if task not found or already completed
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False

        if task.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now(UTC)
            logger.info(f"Task {task_id} cancelled")
            return True

        return False

    def clear_completed(self) -> int:
        """Remove all completed/failed/cancelled tasks.

        Returns:
            Number of tasks removed
        """
        to_remove = [
            task_id
            for task_id, task in self._tasks.items()
            if task.status
            in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
        ]

        for task_id in to_remove:
            del self._tasks[task_id]
            self._subscribers.pop(task_id, None)

        if to_remove:
            logger.info(f"Cleared {len(to_remove)} completed tasks")

        return len(to_remove)


# Global task queue instance
_task_queue: TaskQueue | None = None


def get_task_queue() -> TaskQueue:
    """Get the global task queue instance.

    Returns:
        TaskQueue singleton
    """
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue()
    return _task_queue


def reset_task_queue() -> None:
    """Reset the global task queue (for testing)."""
    global _task_queue
    _task_queue = None
