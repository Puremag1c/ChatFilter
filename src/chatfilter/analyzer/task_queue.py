"""Asyncio-based task queue for chat analysis.

Orchestrates task CRUD, lifecycle, and cleanup. Delegates to:
- task_models: Data classes, enums, protocols
- task_publisher: SSE event publishing and subscriber management
- task_execution: Task execution, recovery, and stall monitoring
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

# Re-export all public symbols from task_models for backward compatibility
from chatfilter.analyzer.task_models import (
    AnalysisExecutor,
    AnalysisTask,
    BatchProgressCallback,
    ProgressEvent,
    QueueFullError,
    SubscriberHealth,
    TaskStatus,
)

from chatfilter.analyzer import task_execution, task_publisher

if TYPE_CHECKING:
    from chatfilter.storage.database import TaskDatabase

try:
    from chatfilter.utils.memory import MemoryMonitor
except ImportError:
    # Memory monitoring is optional (requires psutil)
    MemoryMonitor = None  # type: ignore[misc,assignment]  # Optional dependency fallback

logger = logging.getLogger(__name__)

# Re-export for backward compatibility
__all__ = [
    "AnalysisExecutor",
    "AnalysisTask",
    "BatchProgressCallback",
    "ProgressEvent",
    "QueueFullError",
    "SubscriberHealth",
    "TaskStatus",
    "TaskQueue",
    "get_task_queue",
    "reset_task_queue",
]


class TaskQueue:
    """Persistent task queue for analysis jobs with SQLite backend.

    Thread-safe asyncio-based queue with progress event publishing
    and recovery of incomplete tasks on startup.
    """

    def __init__(
        self,
        db: TaskDatabase | None = None,
        auto_cleanup_threshold: int = 100,
        memory_threshold_mb: float = 2048.0,
        enable_memory_monitoring: bool = True,
        task_timeout_seconds: float = 3600.0,  # 1 hour default
        per_chat_timeout_seconds: float = 300.0,  # 5 minutes per chat default
        progress_stall_timeout_seconds: float = 600.0,  # 10 minutes of no progress
        stall_check_interval_seconds: float = 60.0,  # How often to check for stalls
        stale_task_threshold_hours: float = 24.0,  # Hours after which in-progress tasks are stale
        max_concurrent_tasks: int = 10,  # Maximum number of concurrent active tasks
        max_consecutive_full_queue: int = 10,  # Disconnect after N consecutive full queues
        subscriber_disconnect_threshold: int = 50,  # Disconnect after N dropped events
    ) -> None:
        """Initialize the task queue.

        All timeout/threshold parameters can be set to 0 to disable the feature.
        See parameter inline comments for defaults.
        """
        self._db = db
        self._tasks: dict[UUID, AnalysisTask] = {}
        self._subscribers: dict[UUID, list[SubscriberHealth]] = {}
        self._running_tasks: dict[
            UUID, asyncio.Task[None]
        ] = {}  # Track asyncio tasks for cancellation
        self._lock = asyncio.Lock()
        self._auto_cleanup_threshold = auto_cleanup_threshold
        self._enable_memory_monitoring = enable_memory_monitoring and MemoryMonitor is not None
        self._task_timeout_seconds = task_timeout_seconds
        self._per_chat_timeout_seconds = per_chat_timeout_seconds
        self._progress_stall_timeout_seconds = progress_stall_timeout_seconds
        self._stall_check_interval_seconds = stall_check_interval_seconds
        self._stale_task_threshold_hours = stale_task_threshold_hours
        self._max_concurrent_tasks = max_concurrent_tasks
        self._max_consecutive_full_queue = max_consecutive_full_queue
        self._subscriber_disconnect_threshold = subscriber_disconnect_threshold
        self._monitor_task: asyncio.Task[None] | None = None  # Background monitor for stalled tasks

        # Initialize memory monitor
        self._memory_monitor: MemoryMonitor | None = None
        if self._enable_memory_monitoring and memory_threshold_mb > 0:
            self._memory_monitor = MemoryMonitor(
                threshold_mb=memory_threshold_mb,
                on_threshold_exceeded=self._on_memory_threshold_exceeded,
                circuit_breaker=False,  # Don't break, just warn
            )
            logger.info(f"Memory monitoring enabled (threshold: {memory_threshold_mb}MB)")

        # Start background monitoring if stall detection is enabled
        if self._progress_stall_timeout_seconds > 0:
            try:
                asyncio.get_running_loop()
                self._monitor_task = asyncio.create_task(
                    task_execution.monitor_stalled_tasks(self)
                )
                logger.info(
                    f"Task stall monitoring enabled (timeout: {progress_stall_timeout_seconds}s)"
                )
            except RuntimeError:
                logger.debug("Event loop not running, will start monitor on first task run")

        # Load incomplete tasks from database
        if self._db:
            task_execution.load_incomplete_tasks(self)

    def _on_memory_threshold_exceeded(self, stats: Any) -> None:
        """Callback when memory threshold is exceeded."""
        logger.warning(
            f"Memory threshold exceeded during task execution: {stats.rss_mb:.1f}MB. "
            f"Task count: {len(self._tasks)}, Subscriber count: {len(self._subscribers)}"
        )
        cleared = self.clear_completed()
        if cleared > 0:
            logger.info(f"Freed memory by clearing {cleared} completed tasks")

    # --- Task CRUD ---

    def count_active_tasks(self) -> int:
        """Count the number of active (PENDING or IN_PROGRESS) tasks."""
        active_statuses = {TaskStatus.PENDING, TaskStatus.IN_PROGRESS}
        return sum(1 for task in self._tasks.values() if task.status in active_statuses)

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

        Raises:
            QueueFullError: If maximum concurrent tasks limit is reached
        """
        if self._max_concurrent_tasks > 0:
            active_count = self.count_active_tasks()
            if active_count >= self._max_concurrent_tasks:
                logger.warning(
                    f"Task queue is full: {active_count}/{self._max_concurrent_tasks} concurrent tasks"
                )
                raise QueueFullError(active_count, self._max_concurrent_tasks)

        task = AnalysisTask(
            task_id=uuid4(),
            session_id=session_id,
            chat_ids=chat_ids,
            message_limit=message_limit,
        )
        self._tasks[task.task_id] = task
        self._subscribers[task.task_id] = []

        if self._db:
            self._db.save_task(task)

        logger.info(f"Created analysis task {task.task_id} for {len(chat_ids)} chats")
        return task

    def get_task(self, task_id: UUID, include_historical: bool = False) -> AnalysisTask | None:
        """Get task by ID.

        Args:
            task_id: Task UUID
            include_historical: If True, also check database for historical tasks
                not currently in memory (default: False)

        Returns:
            AnalysisTask or None if not found
        """
        task = self._tasks.get(task_id)
        if task is not None:
            return task

        if include_historical and self._db:
            return self._db.load_task(task_id)

        return None

    def get_all_tasks(self) -> list[AnalysisTask]:
        """Get all tasks (newest first)."""
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

        Used for deduplication to prevent running the same analysis multiple times.

        Args:
            session_id: Session identifier
            chat_ids: List of chat IDs (order independent)
            message_limit: Message limit per chat

        Returns:
            Active task if found, None otherwise
        """
        normalized_chat_ids = sorted(chat_ids)

        for task in self._tasks.values():
            if task.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue
            if (
                task.session_id == session_id
                and sorted(task.chat_ids) == normalized_chat_ids
                and task.message_limit == message_limit
            ):
                return task

        return None

    # --- SSE Pub/Sub (delegates to task_publisher) ---

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
        return await task_publisher.subscribe(
            self._subscribers, self._lock, task_id, self._tasks
        )

    async def unsubscribe(
        self,
        task_id: UUID,
        queue: asyncio.Queue[ProgressEvent | None],
    ) -> None:
        """Unsubscribe from progress events."""
        await task_publisher.unsubscribe(self._subscribers, self._lock, task_id, queue)

    async def _publish_event(self, event: ProgressEvent) -> None:
        """Publish a progress event to all subscribers."""
        await task_publisher.publish_event(
            event,
            self._subscribers,
            self._lock,
            self._tasks,
            self._max_consecutive_full_queue,
            self._subscriber_disconnect_threshold,
        )

    async def _signal_completion(self, task_id: UUID) -> None:
        """Signal task completion to all subscribers."""
        await task_publisher.signal_completion(task_id, self._subscribers, self._lock)

    # --- Task Execution (delegates to task_execution) ---

    def _ensure_monitor_started(self) -> None:
        """Ensure the stall monitor task is running."""
        if self._progress_stall_timeout_seconds > 0 and (
            self._monitor_task is None or self._monitor_task.done()
        ):
            try:
                asyncio.get_running_loop()
                self._monitor_task = asyncio.create_task(
                    task_execution.monitor_stalled_tasks(self)
                )
                logger.info(
                    f"Task stall monitoring started (timeout: {self._progress_stall_timeout_seconds}s)"
                )
            except RuntimeError:
                pass

    async def run_task(
        self,
        task_id: UUID,
        executor: AnalysisExecutor,
    ) -> None:
        """Execute an analysis task with timeout protection.

        Processes each chat, publishes progress events, and stores results.
        Applies task-level and per-chat timeouts to prevent hanging.

        Args:
            task_id: Task UUID to run
            executor: Analysis executor implementation

        Raises:
            KeyError: If task not found
        """
        await task_execution.run_task_with_timeout(task_id, executor, self)

    # --- Task Lifecycle ---

    def cancel_task(self, task_id: UUID) -> bool:
        """Cancel a pending or in-progress task.

        Returns:
            True if cancelled, False if task not found or already completed
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False

        if task.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now(UTC)

            if self._db:
                self._db.save_task(task)

            logger.info(f"Task {task_id} cancelled")
            return True

        return False

    async def force_cancel_task(
        self,
        task_id: UUID,
        reason: str = "Forced cancellation",
    ) -> bool:
        """Forcefully cancel a running task by canceling its asyncio Task.

        More aggressive than cancel_task() which waits for graceful completion.
        Use for hung/deadlocked tasks.

        Returns:
            True if cancelled, False if task not found or not running
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False

        asyncio_task = self._running_tasks.get(task_id)
        if asyncio_task and not asyncio_task.done():
            logger.info(f"Force cancelling task {task_id}: {reason}")
            asyncio_task.cancel()
            return True

        if task.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now(UTC)
            task.error = reason

            if self._db:
                self._db.save_task(task)

            logger.info(f"Task {task_id} cancelled (not running): {reason}")
            return True

        return False

    async def shutdown(self) -> None:
        """Gracefully shutdown the task queue."""
        logger.info("Shutting down task queue...")

        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task

        for task_id in list(self._running_tasks.keys()):
            await self.force_cancel_task(task_id, reason="System shutdown")

        logger.info("Task queue shutdown complete")

    # --- Cleanup ---

    def clear_completed(self) -> int:
        """Remove all completed/failed/cancelled/timeout tasks from memory.

        Tasks are removed from memory only, not from the database.

        Returns:
            Number of tasks removed from memory
        """
        to_remove = [
            task_id
            for task_id, task in self._tasks.items()
            if task.status
            in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMEOUT)
        ]

        for task_id in to_remove:
            del self._tasks[task_id]
            self._subscribers.pop(task_id, None)

        if to_remove:
            logger.info(
                f"Cleared {len(to_remove)} completed tasks from memory (preserved in database)"
            )

        return len(to_remove)

    async def _auto_cleanup_if_needed(self) -> None:
        """Check and perform automatic cleanup if threshold reached."""
        if self._auto_cleanup_threshold <= 0:
            return

        completed_count = sum(
            1
            for task in self._tasks.values()
            if task.status
            in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMEOUT)
        )

        if completed_count >= self._auto_cleanup_threshold:
            logger.info(
                f"Auto-cleanup triggered: {completed_count} completed tasks "
                f"(threshold: {self._auto_cleanup_threshold})"
            )
            self.clear_completed()

    async def cleanup_orphaned_subscribers(self) -> int:
        """Clean up subscriber queues for completed/failed/cancelled/timeout tasks.

        Returns:
            Number of subscriber lists cleaned up
        """
        return await task_publisher.cleanup_orphaned_subscribers(
            self._subscribers, self._lock, self._tasks
        )


# Global task queue instance
_task_queue: TaskQueue | None = None


def get_task_queue(
    db: TaskDatabase | None = None,
    stale_task_threshold_hours: float = 24.0,
) -> TaskQueue:
    """Get the global task queue instance.

    Args:
        db: Optional TaskDatabase instance. Only used on first call to initialize queue.
            Subsequent calls ignore this parameter and return existing singleton.
        stale_task_threshold_hours: Hours after which in-progress tasks are considered stale
            on recovery. Only used on first call.

    Returns:
        TaskQueue singleton
    """
    global _task_queue
    if _task_queue is None:
        _task_queue = TaskQueue(db=db, stale_task_threshold_hours=stale_task_threshold_hours)
    return _task_queue


def reset_task_queue() -> None:
    """Reset the global task queue (for testing)."""
    global _task_queue
    _task_queue = None
