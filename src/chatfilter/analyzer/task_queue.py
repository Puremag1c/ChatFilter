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
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol
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


class QueueFullError(Exception):
    """Raised when task queue has reached maximum concurrent tasks."""

    def __init__(self, current: int, limit: int):
        """Initialize error.

        Args:
            current: Current number of active tasks
            limit: Maximum allowed concurrent tasks
        """
        self.current = current
        self.limit = limit
        super().__init__(
            f"Task queue is full: {current}/{limit} concurrent tasks. "
            f"Please wait for some tasks to complete before starting new ones."
        )


class TaskStatus(str, Enum):
    """Status of an analysis task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"  # Task exceeded time limit


@dataclass
class ProgressEvent:
    """Progress update event for SSE streaming."""

    task_id: UUID
    status: TaskStatus
    current: int  # Current chat index (0-based)
    total: int  # Total number of chats
    sequence: int  # Monotonically increasing event sequence number for ordering
    chat_title: str | None = None  # Currently processing chat
    message: str | None = None  # Optional status message
    error: str | None = None  # Error message if failed
    # Batch-level progress (for large chats with streaming)
    messages_processed: int | None = None  # Total messages processed so far
    batch_number: int | None = None  # Current batch number
    total_batches: int | None = None  # Estimated total batches (if known)


@dataclass
class SubscriberHealth:
    """Track health metrics for a subscriber to detect slow/hung clients."""

    queue: asyncio.Queue[ProgressEvent | None]
    consecutive_full_count: int = 0  # Consecutive times queue was full
    total_events_dropped: int = 0  # Total events dropped for this subscriber
    last_full_time: datetime | None = None  # Last time queue was full
    is_disconnected: bool = False  # True if forcibly disconnected


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
    last_progress_at: datetime | None = None  # Track last progress for deadlock detection
    event_sequence: int = 0  # Monotonically increasing sequence for SSE event ordering


class BatchProgressCallback(Protocol):
    """Callback protocol for batch progress updates."""

    async def __call__(
        self,
        messages_processed: int,
        batch_number: int,
        total_batches: int | None = None,
    ) -> None:
        """Report batch progress.

        Args:
            messages_processed: Total messages processed so far
            batch_number: Current batch number
            total_batches: Estimated total batches (if known)
        """
        ...


class AnalysisExecutor(Protocol):
    """Protocol for analysis executor (allows test injection)."""

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
        message_limit: int = 1000,
        batch_size: int = 1000,
        use_streaming: bool | None = None,
        memory_limit_mb: float = 1024.0,
        enable_memory_monitoring: bool = False,
        batch_progress_callback: BatchProgressCallback | None = None,
    ) -> AnalysisResult:
        """Analyze a single chat and return results.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to analyze
            message_limit: Maximum messages to fetch
            batch_size: Batch size for streaming mode
            use_streaming: Force streaming mode (None = auto-detect)
            memory_limit_mb: Memory threshold in MB
            enable_memory_monitoring: Enable memory monitoring
            batch_progress_callback: Optional callback for batch progress updates
        """
        ...

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get chat info for a chat ID."""
        ...

    async def pre_cache_chats(
        self,
        session_id: str,
    ) -> None:
        """Pre-cache all chat info for better progress display.

        This method is called at the start of background task execution
        to fetch and cache chat metadata. This prevents the HTTP request
        from blocking on Telegram connection.

        Args:
            session_id: Session identifier

        Raises:
            Exception: Connection or fetch errors (non-fatal, can continue with minimal info)
        """
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

        Args:
            db: Optional TaskDatabase instance. If None, persistence is disabled.
            auto_cleanup_threshold: Number of completed tasks before automatic cleanup
                (default 100). Set to 0 to disable automatic cleanup.
            memory_threshold_mb: Memory usage threshold in MB for warnings (default 2048MB).
                Set to 0 to disable memory monitoring.
            enable_memory_monitoring: Enable periodic memory logging (default True)
            task_timeout_seconds: Maximum time for entire task execution (default 3600s = 1 hour).
                Set to 0 to disable task timeout.
            per_chat_timeout_seconds: Maximum time for analyzing a single chat (default 300s = 5 minutes).
                Set to 0 to disable per-chat timeout.
            progress_stall_timeout_seconds: Time without progress before considering task stalled
                (default 600s = 10 minutes). Set to 0 to disable stall detection.
            stall_check_interval_seconds: How often to check for stalled tasks (default 60s).
                Only used when stall detection is enabled.
            stale_task_threshold_hours: Hours after which in-progress tasks are considered stale
                on recovery (default 24h). Stale tasks are marked as FAILED instead of PENDING.
            max_concurrent_tasks: Maximum number of concurrent active (PENDING or IN_PROGRESS)
                tasks allowed (default 10). Set to 0 to disable limit.
            max_consecutive_full_queue: Disconnect client after N consecutive full queue events
                (default 10). Prevents slow/hung clients from consuming resources. Set to 0 to disable.
            subscriber_disconnect_threshold: Disconnect client after N total dropped events
                (default 50). Prevents persistently slow clients from staying connected. Set to 0 to disable.
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
        # Only create the task if we're in an async context (event loop running)
        if self._progress_stall_timeout_seconds > 0:
            try:
                # Check if event loop is running before creating coroutine
                asyncio.get_running_loop()
                self._monitor_task = asyncio.create_task(self._monitor_stalled_tasks())
                logger.info(
                    f"Task stall monitoring enabled (timeout: {progress_stall_timeout_seconds}s)"
                )
            except RuntimeError:
                # No event loop running - will start monitor on first task run
                logger.debug("Event loop not running, will start monitor on first task run")

        # Load incomplete tasks from database
        if self._db:
            self._load_incomplete_tasks()

    def _on_memory_threshold_exceeded(self, stats: Any) -> None:
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
        """Load incomplete tasks from database on startup.

        For tasks left in IN_PROGRESS status (from crashes):
        - If age > stale_task_threshold_hours: mark as FAILED
        - Otherwise: reset to PENDING for retry
        """
        if not self._db:
            return

        try:
            incomplete_tasks = self._db.load_incomplete_tasks()
            recovered_count = 0
            stale_count = 0

            for task in incomplete_tasks:
                self._tasks[task.task_id] = task
                self._subscribers[task.task_id] = []

                # Handle in-progress tasks based on age
                if task.status == TaskStatus.IN_PROGRESS:
                    # Calculate task age using started_at if available, else created_at
                    task_timestamp = task.started_at if task.started_at else task.created_at

                    # Ensure task_timestamp is timezone-aware (for database compatibility)
                    if task_timestamp.tzinfo is None:
                        task_timestamp = task_timestamp.replace(tzinfo=UTC)

                    task_age_hours = (datetime.now(UTC) - task_timestamp).total_seconds() / 3600

                    if task_age_hours > self._stale_task_threshold_hours:
                        # Task is stale - mark as failed
                        task.status = TaskStatus.FAILED
                        task.error = (
                            f"Task abandoned after application crash "
                            f"(stale for {task_age_hours:.1f} hours, threshold: {self._stale_task_threshold_hours}h)"
                        )
                        task.completed_at = datetime.now(UTC)
                        self._db.save_task(task)
                        stale_count += 1
                        logger.warning(
                            f"Marked stale task {task.task_id} as FAILED (age: {task_age_hours:.1f}h)"
                        )
                    else:
                        # Task is recent - reset to pending for retry
                        # Note: Partial results are preserved; task will resume from checkpoint
                        task.status = TaskStatus.PENDING
                        self._db.save_task(task)
                        recovered_count += 1
                        partial_results = len(task.results)
                        logger.info(
                            f"Recovered task {task.task_id} for retry (age: {task_age_hours:.1f}h, "
                            f"{partial_results} results preserved)"
                        )
                else:
                    # Non in-progress tasks just get loaded
                    recovered_count += 1

            if incomplete_tasks:
                logger.info(
                    f"Task recovery complete: {recovered_count} recovered, {stale_count} marked stale"
                )
        except Exception as e:
            logger.exception(f"Failed to load incomplete tasks from database: {e}")

    def count_active_tasks(self) -> int:
        """Count the number of active (PENDING or IN_PROGRESS) tasks.

        Returns:
            Number of active tasks currently in the queue
        """
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
        # Check concurrent task limit if enabled
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

        # Persist to database
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
        # First check in-memory tasks
        task = self._tasks.get(task_id)
        if task is not None:
            return task

        # If not in memory and historical lookup is enabled, check database
        if include_historical and self._db:
            return self._db.load_task(task_id)

        return None

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
        health = SubscriberHealth(queue=queue)

        async with self._lock:
            self._subscribers[task_id].append(health)

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
                # Find and remove subscriber health by queue reference
                for health in self._subscribers[task_id][:]:  # Copy list to iterate safely
                    if health.queue is queue:
                        self._subscribers[task_id].remove(health)
                        logger.debug(f"Unsubscribed from task {task_id}")
                        break

    async def _publish_event(self, event: ProgressEvent) -> None:
        """Publish a progress event to all subscribers.

        Args:
            event: Event to publish
        """
        # Update last progress time for deadlock detection
        task = self._tasks.get(event.task_id)
        if task and event.status == TaskStatus.IN_PROGRESS:
            task.last_progress_at = datetime.now(UTC)

        async with self._lock:
            subscribers = self._subscribers.get(event.task_id, [])
            subscribers_to_remove: list[SubscriberHealth] = []

            for health in subscribers:
                # Skip already disconnected subscribers
                if health.is_disconnected:
                    continue

                try:
                    # Non-blocking put with backpressure handling
                    health.queue.put_nowait(event)
                    # Queue accepted event - reset consecutive counter
                    health.consecutive_full_count = 0

                except asyncio.QueueFull:
                    # Queue is full - track this for backpressure
                    health.consecutive_full_count += 1
                    health.total_events_dropped += 1
                    health.last_full_time = datetime.now(UTC)

                    # Check if client should be forcibly disconnected
                    should_disconnect = False
                    disconnect_reason = ""

                    if (
                        self._max_consecutive_full_queue > 0
                        and health.consecutive_full_count >= self._max_consecutive_full_queue
                    ):
                        should_disconnect = True
                        disconnect_reason = (
                            f"consecutive full queue ({health.consecutive_full_count} times)"
                        )

                    elif (
                        self._subscriber_disconnect_threshold > 0
                        and health.total_events_dropped >= self._subscriber_disconnect_threshold
                    ):
                        should_disconnect = True
                        disconnect_reason = f"total dropped events ({health.total_events_dropped})"

                    if should_disconnect:
                        health.is_disconnected = True
                        subscribers_to_remove.append(health)
                        logger.warning(
                            f"Forcibly disconnecting slow SSE client for task {event.task_id}: "
                            f"{disconnect_reason}. This prevents memory leaks from clients that "
                            f"read events slower than they're generated."
                        )
                        # Send a final None to signal disconnection
                        # Clear space in queue if needed to ensure None is delivered
                        try:
                            health.queue.put_nowait(None)
                        except asyncio.QueueFull:
                            # Queue is full, clear oldest event and add None
                            with contextlib.suppress(asyncio.QueueEmpty):
                                health.queue.get_nowait()
                            # Try again to send None
                            with contextlib.suppress(asyncio.QueueFull):
                                health.queue.put_nowait(None)
                    else:
                        # Drop oldest event to prevent memory issues
                        try:
                            health.queue.get_nowait()
                            health.queue.put_nowait(event)
                        except asyncio.QueueEmpty:
                            # Queue was emptied concurrently, try to add event again
                            with contextlib.suppress(asyncio.QueueFull):
                                health.queue.put_nowait(event)

            # Remove disconnected subscribers
            for health in subscribers_to_remove:
                with contextlib.suppress(ValueError):
                    subscribers.remove(health)

    async def _signal_completion(self, task_id: UUID) -> None:
        """Signal task completion to all subscribers.

        Args:
            task_id: Completed task ID
        """
        async with self._lock:
            subscribers = self._subscribers.get(task_id, [])
            for health in subscribers:
                with contextlib.suppress(asyncio.QueueFull):
                    health.queue.put_nowait(None)

    def _ensure_monitor_started(self) -> None:
        """Ensure the stall monitor task is running.

        Called at the start of task execution to start the monitor
        if it wasn't started during __init__ (no event loop at that time).
        """
        if self._progress_stall_timeout_seconds > 0 and (
            self._monitor_task is None or self._monitor_task.done()
        ):
            try:
                # Check if event loop is running before creating coroutine
                asyncio.get_running_loop()
                self._monitor_task = asyncio.create_task(self._monitor_stalled_tasks())
                logger.info(
                    f"Task stall monitoring started (timeout: {self._progress_stall_timeout_seconds}s)"
                )
            except RuntimeError:
                # Event loop not available yet
                pass

    async def _monitor_stalled_tasks(self) -> None:
        """Background task to monitor for stalled/hung tasks.

        Checks periodically for tasks that haven't made progress within
        the configured stall timeout period.
        """
        while True:
            try:
                await asyncio.sleep(self._stall_check_interval_seconds)

                now = datetime.now(UTC)
                for task_id, task in list(self._tasks.items()):
                    if task.status != TaskStatus.IN_PROGRESS:
                        continue

                    # Check if task has stalled (no progress for too long)
                    if task.last_progress_at:
                        time_since_progress = (now - task.last_progress_at).total_seconds()
                        if time_since_progress > self._progress_stall_timeout_seconds:
                            logger.warning(
                                f"Task {task_id} detected as stalled "
                                f"({time_since_progress:.0f}s since last progress). "
                                f"Forcing cancellation."
                            )
                            await self.force_cancel_task(
                                task_id,
                                reason=f"Task stalled: no progress for {time_since_progress:.0f}s",
                            )

            except asyncio.CancelledError:
                logger.info("Task stall monitor shutting down")
                break
            except Exception as e:
                logger.exception(f"Error in stall monitor: {e}")
                # Continue monitoring despite errors

    async def force_cancel_task(
        self,
        task_id: UUID,
        reason: str = "Forced cancellation",
    ) -> bool:
        """Forcefully cancel a running task by canceling its asyncio Task.

        This is more aggressive than cancel_task() which waits for graceful completion.
        Use this for hung/deadlocked tasks that aren't responding.

        Args:
            task_id: Task UUID to cancel
            reason: Reason for cancellation

        Returns:
            True if cancelled, False if task not found or not running
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False

        # Cancel the asyncio task if it's running
        asyncio_task = self._running_tasks.get(task_id)
        if asyncio_task and not asyncio_task.done():
            logger.info(f"Force cancelling task {task_id}: {reason}")
            asyncio_task.cancel()
            return True

        # If not running, fallback to graceful cancellation
        if task.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
            task.status = TaskStatus.CANCELLED
            task.completed_at = datetime.now(UTC)
            task.error = reason

            # Persist cancellation
            if self._db:
                self._db.save_task(task)

            logger.info(f"Task {task_id} cancelled (not running): {reason}")
            return True

        return False

    async def shutdown(self) -> None:
        """Gracefully shutdown the task queue.

        Stops background monitoring and cancels all running tasks.
        """
        logger.info("Shutting down task queue...")

        # Stop background monitor
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitor_task

        # Cancel all running tasks
        for task_id in list(self._running_tasks.keys()):
            await self.force_cancel_task(task_id, reason="System shutdown")

        logger.info("Task queue shutdown complete")

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
        # Ensure stall monitor is running (in case it wasn't started during __init__)
        self._ensure_monitor_started()

        # Create asyncio task and track it for forced cancellation
        current_task = asyncio.current_task()
        if current_task:
            self._running_tasks[task_id] = current_task

        try:
            # Apply task-level timeout if configured
            if self._task_timeout_seconds > 0:
                await asyncio.wait_for(
                    self._run_task_impl(task_id, executor),
                    timeout=self._task_timeout_seconds,
                )
            else:
                await self._run_task_impl(task_id, executor)
        except TimeoutError:
            # Task exceeded time limit
            task = self._tasks.get(task_id)
            if task:
                task.status = TaskStatus.TIMEOUT
                task.error = f"Task exceeded maximum execution time ({self._task_timeout_seconds}s)"
                task.completed_at = datetime.now(UTC)

                if self._db:
                    self._db.save_task(task)

                task.event_sequence += 1
                await self._publish_event(
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.TIMEOUT,
                        current=task.current_chat_index,
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
                        error=task.error,
                    )
                )

                logger.error(f"Task {task_id} timed out after {self._task_timeout_seconds}s")
                await self._signal_completion(task_id)
        except asyncio.CancelledError:
            # Task was force-cancelled
            task = self._tasks.get(task_id)
            if task and task.status != TaskStatus.CANCELLED:
                task.status = TaskStatus.CANCELLED
                task.error = task.error or "Task was force-cancelled"
                task.completed_at = datetime.now(UTC)

                if self._db:
                    self._db.save_task(task)

                task.event_sequence += 1
                await self._publish_event(
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.CANCELLED,
                        current=task.current_chat_index,
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
                        message="Task was force-cancelled",
                    )
                )

                logger.info(f"Task {task_id} was force-cancelled")
                await self._signal_completion(task_id)
            raise  # Re-raise to properly handle cancellation
        finally:
            # Clean up running task tracking
            self._running_tasks.pop(task_id, None)

    async def _run_task_impl(
        self,
        task_id: UUID,
        executor: AnalysisExecutor,
    ) -> None:
        """Internal implementation of task execution.

        Args:
            task_id: Task UUID to run
            executor: Analysis executor implementation
        """
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"Task {task_id} not found")

        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now(UTC)
        task.last_progress_at = datetime.now(UTC)  # Initialize progress tracking

        # Persist status change
        if self._db:
            self._db.save_task(task)

        # Log memory at task start
        if self._enable_memory_monitoring and log_memory_usage is not None:
            log_memory_usage(f"Task {task_id} start")

        # Pre-cache chat info for better progress display
        # This is done in the background task (not HTTP request) to prevent request timeouts
        try:
            await executor.pre_cache_chats(task.session_id)
        except Exception as e:
            # Non-fatal: we can still proceed with minimal chat info
            logger.warning(f"Failed to pre-cache chat info for task {task_id}: {e}")

        # Checkpoint resume: skip already-analyzed chats
        resume_index = len(task.results)
        if resume_index > 0:
            logger.info(
                f"Resuming task {task_id} from checkpoint: "
                f"{resume_index}/{len(task.chat_ids)} chats already analyzed"
            )
            task.event_sequence += 1
            await self._publish_event(
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.IN_PROGRESS,
                    current=resume_index,
                    total=len(task.chat_ids),
                    sequence=task.event_sequence,
                    message=f"Resuming from checkpoint ({resume_index} chats already analyzed)...",
                )
            )

        try:
            for i in range(resume_index, len(task.chat_ids)):
                chat_id = task.chat_ids[i]
                # Check if task was cancelled
                if task.status == TaskStatus.CANCELLED:
                    logger.info(f"Task {task_id} was cancelled, stopping execution")
                    partial_count = len(task.results)
                    task.event_sequence += 1
                    await self._publish_event(
                        ProgressEvent(
                            task_id=task_id,
                            status=TaskStatus.CANCELLED,
                            current=i,
                            total=len(task.chat_ids),
                            sequence=task.event_sequence,
                            message=f"Analysis cancelled. {partial_count} chats analyzed before cancellation.",
                        )
                    )
                    break

                task.current_chat_index = i

                # Get chat info for progress display
                chat_info = await executor.get_chat_info(task.session_id, chat_id)
                chat_title = chat_info.title if chat_info else f"Chat {chat_id}"

                # Publish progress event
                task.event_sequence += 1
                await self._publish_event(
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.IN_PROGRESS,
                        current=i,
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
                        chat_title=chat_title,
                        message=f"Analyzing {chat_title}...",
                    )
                )

                # Create batch progress callback
                async def batch_progress_callback(
                    messages_processed: int,
                    batch_number: int,
                    total_batches: int | None = None,
                    *,
                    current_index: int = i,
                    current_chat_title: str = chat_title,
                ) -> None:
                    """Report batch progress to subscribers."""
                    task.event_sequence += 1
                    await self._publish_event(
                        ProgressEvent(
                            task_id=task_id,
                            status=TaskStatus.IN_PROGRESS,
                            current=current_index,
                            total=len(task.chat_ids),
                            sequence=task.event_sequence,
                            chat_title=current_chat_title,
                            message=f"Processing batch {batch_number}...",
                            messages_processed=messages_processed,
                            batch_number=batch_number,
                            total_batches=total_batches,
                        )
                    )
                    # Update last progress timestamp for stall detection
                    task.last_progress_at = datetime.now(UTC)

                # Analyze chat with per-chat timeout
                try:
                    if self._per_chat_timeout_seconds > 0:
                        result = await asyncio.wait_for(
                            executor.analyze_chat(
                                session_id=task.session_id,
                                chat_id=chat_id,
                                message_limit=task.message_limit,
                                batch_progress_callback=batch_progress_callback,
                            ),
                            timeout=self._per_chat_timeout_seconds,
                        )
                    else:
                        result = await executor.analyze_chat(
                            session_id=task.session_id,
                            chat_id=chat_id,
                            message_limit=task.message_limit,
                            batch_progress_callback=batch_progress_callback,
                        )
                    task.results.append(result)

                    # Persist result and update task state
                    if self._db:
                        self._db.save_task_result(task_id, result)
                        self._db.save_task(task)

                    # Check memory after each chat
                    if self._memory_monitor:
                        self._memory_monitor.check()

                except TimeoutError:
                    # Per-chat timeout exceeded
                    logger.warning(
                        f"Chat {chat_id} ({chat_title}) analysis timed out "
                        f"after {self._per_chat_timeout_seconds}s. Skipping and continuing."
                    )
                    # Continue with other chats - don't fail entire task
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

                task.event_sequence += 1
                await self._publish_event(
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.COMPLETED,
                        current=len(task.chat_ids),
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
                        message=f"Analysis complete. {len(task.results)} chats analyzed.",
                    )
                )

                logger.info(f"Task {task_id} completed with {len(task.results)} results")

                # Log memory at task completion
                if self._enable_memory_monitoring and log_memory_usage is not None:
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

                task.event_sequence += 1
                await self._publish_event(
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.FAILED,
                        current=task.current_chat_index,
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
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
        """Remove all completed/failed/cancelled/timeout tasks from memory.

        Note: Tasks are removed from memory only, not from the database.
        This preserves analysis history while freeing up memory.

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

            # NOTE: Tasks are NOT deleted from database to preserve history
            # Historical tasks can be retrieved via TaskDatabase.load_task()
            # or TaskDatabase.load_all_tasks()

        if to_remove:
            logger.info(
                f"Cleared {len(to_remove)} completed tasks from memory (preserved in database)"
            )

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
                # Clean subscribers for completed/failed/cancelled/timeout tasks
                if task and task.status in (
                    TaskStatus.COMPLETED,
                    TaskStatus.FAILED,
                    TaskStatus.CANCELLED,
                    TaskStatus.TIMEOUT,
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
