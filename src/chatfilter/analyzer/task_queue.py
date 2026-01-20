"""Asyncio-based task queue for chat analysis.

Provides:
- Task creation with UUID tracking
- Persistent task state management with SQLite
- Progress event publishing via asyncio.Queue
- Injectable executor for testing
- Recovery of incomplete tasks on startup
- Automatic memory cleanup for completed tasks
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
    from chatfilter.storage.database import TaskDatabase

from chatfilter.telegram.client import ChatAccessDeniedError

try:
    from chatfilter.utils.memory import MemoryMonitor, log_memory_usage
except ImportError:
    # Memory monitoring is optional (requires psutil)
    MemoryMonitor = None  # type: ignore
    log_memory_usage = None  # type: ignore

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
    """Persistent task queue for analysis jobs with SQLite backend.

    Thread-safe asyncio-based queue with progress event publishing
    and recovery of incomplete tasks on startup.

    Example:
        ```python
        queue = TaskQueue(db=TaskDatabase("tasks.db"))

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

    def __init__(
        self,
        db: TaskDatabase | None = None,
        auto_cleanup_threshold: int = 100,
        memory_threshold_mb: float = 2048.0,
        enable_memory_monitoring: bool = True,
    ) -> None:
        """Initialize the task queue.

        Args:
            db: Optional TaskDatabase instance. If None, persistence is disabled.
            auto_cleanup_threshold: Number of completed tasks before automatic cleanup
                (default 100). Set to 0 to disable automatic cleanup.
            memory_threshold_mb: Memory usage threshold in MB for warnings (default 2048MB).
                Set to 0 to disable memory monitoring.
            enable_memory_monitoring: Enable periodic memory logging (default True)
        """
        self._db = db
        self._tasks: dict[UUID, AnalysisTask] = {}
        self._subscribers: dict[UUID, list[asyncio.Queue[ProgressEvent | None]]] = {}
        self._lock = asyncio.Lock()
        self._auto_cleanup_threshold = auto_cleanup_threshold
        self._enable_memory_monitoring = enable_memory_monitoring and MemoryMonitor is not None

        # Initialize memory monitor
        self._memory_monitor: MemoryMonitor | None = None
        if self._enable_memory_monitoring and memory_threshold_mb > 0:
            self._memory_monitor = MemoryMonitor(
                threshold_mb=memory_threshold_mb,
                on_threshold_exceeded=self._on_memory_threshold_exceeded,
                circuit_breaker=False,  # Don't break, just warn
            )
            logger.info(f"Memory monitoring enabled (threshold: {memory_threshold_mb}MB)")

        # Load incomplete tasks from database
        if self._db:
            self._load_incomplete_tasks()

    def _on_memory_threshold_exceeded(self, stats) -> None:
        """Callback when memory threshold is exceeded.

        Args:
            stats: MemoryStats object with current memory usage
        """
        logger.warning(
            f"Memory threshold exceeded during task execution: {stats.rss_mb:.1f}MB. "
            f"Task count: {len(self._tasks)}, Subscriber count: {len(self._subscribers)}"
        )

        # Try to free memory by clearing completed tasks
        cleared = self.clear_completed()
        if cleared > 0:
            logger.info(f"Freed memory by clearing {cleared} completed tasks")

    def _load_incomplete_tasks(self) -> None:
        """Load incomplete tasks from database on startup."""
        if not self._db:
            return

        try:
            incomplete_tasks = self._db.load_incomplete_tasks()
            for task in incomplete_tasks:
                self._tasks[task.task_id] = task
                self._subscribers[task.task_id] = []
                # Reset in-progress tasks to pending for recovery
                if task.status == TaskStatus.IN_PROGRESS:
                    task.status = TaskStatus.PENDING
                    self._db.save_task(task)

            if incomplete_tasks:
                logger.info(
                    f"Recovered {len(incomplete_tasks)} incomplete tasks from database"
                )
        except Exception as e:
            logger.exception(f"Failed to load incomplete tasks from database: {e}")

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

        # Persist to database
        if self._db:
            self._db.save_task(task)

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

    def find_active_task(
        self,
        session_id: str,
        chat_ids: list[int],
        message_limit: int,
    ) -> AnalysisTask | None:
        """Find an active (pending or in-progress) task with matching parameters.

        This is used for deduplication to prevent running the same analysis
        multiple times simultaneously.

        Args:
            session_id: Session identifier
            chat_ids: List of chat IDs (order independent)
            message_limit: Message limit per chat

        Returns:
            Active task if found, None otherwise
        """
        # Normalize chat_ids for comparison (sort to handle different orders)
        normalized_chat_ids = sorted(chat_ids)

        for task in self._tasks.values():
            # Only check active tasks
            if task.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue

            # Check if parameters match
            if (
                task.session_id == session_id
                and sorted(task.chat_ids) == normalized_chat_ids
                and task.message_limit == message_limit
            ):
                return task

        return None

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

        # Persist status change
        if self._db:
            self._db.save_task(task)

        # Log memory at task start
        if self._enable_memory_monitoring and log_memory_usage:
            log_memory_usage(f"Task {task_id} start")

        try:
            for i, chat_id in enumerate(task.chat_ids):
                # Check if task was cancelled
                if task.status == TaskStatus.CANCELLED:
                    logger.info(f"Task {task_id} was cancelled, stopping execution")
                    partial_count = len(task.results)
                    await self._publish_event(
                        ProgressEvent(
                            task_id=task_id,
                            status=TaskStatus.CANCELLED,
                            current=i,
                            total=len(task.chat_ids),
                            message=f"Analysis cancelled. {partial_count} chats analyzed before cancellation.",
                        )
                    )
                    break

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

                    # Persist result and update task state
                    if self._db:
                        self._db.save_task_result(task_id, result)
                        self._db.save_task(task)

                    # Check memory after each chat
                    if self._memory_monitor:
                        self._memory_monitor.check()

                except ChatAccessDeniedError as e:
                    # Chat is inaccessible (kicked, banned, left, or private/deleted)
                    logger.info(f"Skipping inaccessible chat {chat_id} ({chat_title}): {e}")
                    # Continue with other chats - this is expected behavior
                except Exception as e:
                    # Unexpected error - log as warning
                    logger.warning(f"Failed to analyze chat {chat_id} ({chat_title}): {e}")
                    # Continue with other chats

            # Only mark as completed if not cancelled
            if task.status != TaskStatus.CANCELLED:
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now(UTC)

                # Persist completion
                if self._db:
                    self._db.save_task(task)

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

                # Log memory at task completion
                if self._enable_memory_monitoring and log_memory_usage:
                    log_memory_usage(f"Task {task_id} completed")
            else:
                # Task was cancelled
                logger.info(f"Task {task_id} cancelled with {len(task.results)} partial results")

        except Exception as e:
            # Only mark as failed if not cancelled
            if task.status != TaskStatus.CANCELLED:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                task.completed_at = datetime.now(UTC)

                # Persist failure
                if self._db:
                    self._db.save_task(task)

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
            # Automatic cleanup: check if we should clear old completed tasks
            await self._auto_cleanup_if_needed()

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

            # Persist cancellation
            if self._db:
                self._db.save_task(task)

            logger.info(f"Task {task_id} cancelled")
            return True

        return False

    def clear_completed(self) -> int:
        """Remove all completed/failed/cancelled tasks from memory and database.

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

            # Remove from database
            if self._db:
                self._db.delete_task(task_id)

        if to_remove:
            logger.info(f"Cleared {len(to_remove)} completed tasks")

        return len(to_remove)

    async def _auto_cleanup_if_needed(self) -> None:
        """Check and perform automatic cleanup if threshold reached.

        Called after each task completes to prevent unbounded memory growth.
        """
        if self._auto_cleanup_threshold <= 0:
            return

        completed_count = sum(
            1
            for task in self._tasks.values()
            if task.status
            in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)
        )

        if completed_count >= self._auto_cleanup_threshold:
            logger.info(
                f"Auto-cleanup triggered: {completed_count} completed tasks "
                f"(threshold: {self._auto_cleanup_threshold})"
            )
            self.clear_completed()

    async def cleanup_orphaned_subscribers(self) -> int:
        """Clean up subscriber queues for completed/failed/cancelled tasks.

        Orphaned subscribers can occur when clients disconnect abruptly
        without properly unsubscribing. This method removes subscriber
        lists for tasks that are no longer active.

        Returns:
            Number of subscriber lists cleaned up
        """
        async with self._lock:
            cleaned_count = 0
            for task_id in list(self._subscribers.keys()):
                task = self._tasks.get(task_id)
                # Clean subscribers for completed/failed/cancelled tasks
                if task and task.status in (
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.CANCELLED,
                ):
                    subscriber_count = len(self._subscribers[task_id])
                    if subscriber_count > 0:
                        logger.info(
                            f"Cleaning {subscriber_count} orphaned subscribers "
                            f"for task {task_id} (status: {task.status})"
                        )
                        self._subscribers[task_id].clear()
                        cleaned_count += 1
                # Also clean subscribers for non-existent tasks
                elif task is None:
                    subscriber_count = len(self._subscribers[task_id])
                    if subscriber_count > 0:
                        logger.warning(
                            f"Cleaning {subscriber_count} orphaned subscribers "
                            f"for non-existent task {task_id}"
                        )
                        del self._subscribers[task_id]
                        cleaned_count += 1
            return cleaned_count


# Global task queue instance
_task_queue: TaskQueue | None = None


def get_task_queue(db: TaskDatabase | None = None) -> TaskQueue:
    """Get the global task queue instance.

    Args:
        db: Optional TaskDatabase instance. Only used on first call to initialize queue.
            Subsequent calls ignore this parameter and return existing singleton.

    Returns:
        TaskQueue singleton
    """
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue(db=db)
    return _task_queue


def reset_task_queue() -> None:
    """Reset the global task queue (for testing)."""
    global _task_queue
    _task_queue = None
