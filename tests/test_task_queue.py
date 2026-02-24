"""Tests for the analysis task queue.

DEPRECATED: TaskQueue was part of the old individual chat analysis system.
The system has been replaced with group-based analysis using ProgressTracker.

Tests are kept for reference but marked with skip since TaskQueue is no longer used.
See test_unified_sse_groups.py for new architecture tests.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime
from uuid import UUID

import pytest

# Old imports - no longer available (task_queue removed)
# from chatfilter.analyzer.task_queue import (
#     ProgressEvent,
#     QueueFullError,
#     TaskQueue,
#     TaskStatus,
#     get_task_queue,
#     reset_task_queue,
# )

# Stub imports for tests to at least load
class TaskQueue:
    """Stub for removed TaskQueue."""
    pass

class TaskStatus:
    """Stub for removed TaskStatus."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class QueueFullError(Exception):
    """Stub for removed QueueFullError."""
    def __init__(self, message, current=0, limit=0):
        super().__init__(message)
        self.current = current
        self.limit = limit

class ProgressEvent:
    """Stub for removed ProgressEvent."""
    pass

def get_task_queue():
    """Stub for removed get_task_queue."""
    return TaskQueue()

def reset_task_queue():
    """Stub for removed reset_task_queue."""
    pass

from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType


class MockExecutor:
    """Mock executor for testing."""

    def __init__(
        self,
        chats: dict[int, Chat] | None = None,
        delay: float = 0.0,
        fail_on: set[int] | None = None,
    ) -> None:
        self.chats = chats or {}
        self.delay = delay
        self.fail_on = fail_on or set()
        self.analyzed_chats: list[int] = []

    async def get_chat_info(self, session_id: str, chat_id: int) -> Chat | None:
        return self.chats.get(chat_id)

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
        message_limit: int = 1000,
        batch_size: int = 1000,
        use_streaming: bool | None = None,
        memory_limit_mb: float = 1024.0,
        enable_memory_monitoring: bool = False,
        batch_progress_callback=None,
    ) -> AnalysisResult:
        if self.delay > 0:
            await asyncio.sleep(self.delay)

        if chat_id in self.fail_on:
            raise ValueError(f"Failed to analyze chat {chat_id}")

        self.analyzed_chats.append(chat_id)

        chat = self.chats.get(chat_id) or Chat(
            id=chat_id,
            title=f"Chat {chat_id}",
            chat_type=ChatType.GROUP,
        )

        return AnalysisResult(
            chat=chat,
            metrics=ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=24.0,
                first_message_at=datetime.now(UTC),
                last_message_at=datetime.now(UTC),
            ),
            analyzed_at=datetime.now(UTC),
        )


@pytest.fixture
def task_queue() -> TaskQueue:
    """Provide a fresh task queue for each test."""
    return TaskQueue()


@pytest.fixture(autouse=True)
def reset_global_queue() -> None:
    """Reset global task queue before and after each test."""
    reset_task_queue()
    yield
    reset_task_queue()


@pytest.mark.skip(reason="TaskQueue removed - replaced with ProgressTracker for groups")
class TestTaskQueue:
    """Tests for TaskQueue class.

    DEPRECATED: TaskQueue is no longer used.
    """

    def test_create_task(self, task_queue: TaskQueue) -> None:
        """Test creating a new task."""
        task = task_queue.create_task("session1", [1, 2, 3])

        assert isinstance(task.task_id, UUID)
        assert task.session_id == "session1"
        assert task.chat_ids == [1, 2, 3]
        assert task.status == TaskStatus.PENDING
        assert task.results == []
        assert task.error is None

    def test_get_task(self, task_queue: TaskQueue) -> None:
        """Test retrieving a task by ID."""
        task = task_queue.create_task("session1", [1, 2, 3])

        retrieved = task_queue.get_task(task.task_id)
        assert retrieved is not None
        assert retrieved.task_id == task.task_id

    def test_get_nonexistent_task(self, task_queue: TaskQueue) -> None:
        """Test retrieving a non-existent task returns None."""
        from uuid import uuid4

        result = task_queue.get_task(uuid4())
        assert result is None

    def test_get_all_tasks(self, task_queue: TaskQueue) -> None:
        """Test retrieving all tasks."""
        task1 = task_queue.create_task("session1", [1])
        task2 = task_queue.create_task("session2", [2])

        all_tasks = task_queue.get_all_tasks()
        assert len(all_tasks) == 2
        # Verify both tasks are present (order may vary if created_at is identical)
        task_ids = {t.task_id for t in all_tasks}
        assert task_ids == {task1.task_id, task2.task_id}

    @pytest.mark.asyncio
    async def test_run_task_success(self, task_queue: TaskQueue) -> None:
        """Test running a task successfully."""
        chat1 = Chat(id=1, title="Chat 1", chat_type=ChatType.GROUP)
        chat2 = Chat(id=2, title="Chat 2", chat_type=ChatType.CHANNEL)

        executor = MockExecutor(chats={1: chat1, 2: chat2})
        task = task_queue.create_task("session1", [1, 2])

        await task_queue.run_task(task.task_id, executor)

        assert task.status == TaskStatus.COMPLETED
        assert len(task.results) == 2
        assert task.completed_at is not None
        assert task.error is None
        assert executor.analyzed_chats == [1, 2]

    @pytest.mark.asyncio
    async def test_run_task_partial_failure(self, task_queue: TaskQueue) -> None:
        """Test that task continues even if some chats fail."""
        executor = MockExecutor(fail_on={2})
        task = task_queue.create_task("session1", [1, 2, 3])

        await task_queue.run_task(task.task_id, executor)

        # Task should complete despite chat 2 failing
        assert task.status == TaskStatus.COMPLETED
        assert len(task.results) == 2  # Only 1 and 3 succeeded
        assert executor.analyzed_chats == [1, 3]

    @pytest.mark.asyncio
    async def test_subscribe_and_receive_events(self, task_queue: TaskQueue) -> None:
        """Test subscribing to progress events."""
        executor = MockExecutor()
        task = task_queue.create_task("session1", [1, 2])

        # Subscribe before running
        queue = await task_queue.subscribe(task.task_id)

        # Run in background
        run_task = asyncio.create_task(task_queue.run_task(task.task_id, executor))

        # Collect events
        events: list[ProgressEvent | None] = []
        while True:
            event = await asyncio.wait_for(queue.get(), timeout=5.0)
            events.append(event)
            if event is None:
                break

        await run_task

        # Should have progress events plus completion signal
        assert len(events) >= 3  # At least 2 progress events + None
        assert events[-1] is None  # Completion signal

        # Verify progress events
        progress_events = [e for e in events if e is not None]
        assert any(e.status == TaskStatus.IN_PROGRESS for e in progress_events)
        assert any(e.status == TaskStatus.COMPLETED for e in progress_events)

    @pytest.mark.asyncio
    async def test_subscribe_nonexistent_task(self, task_queue: TaskQueue) -> None:
        """Test subscribing to non-existent task raises error."""
        from uuid import uuid4

        with pytest.raises(KeyError):
            await task_queue.subscribe(uuid4())

    def test_cancel_pending_task(self, task_queue: TaskQueue) -> None:
        """Test cancelling a pending task."""
        task = task_queue.create_task("session1", [1, 2, 3])

        result = task_queue.cancel_task(task.task_id)

        assert result is True
        assert task.status == TaskStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_in_progress_task(self, task_queue: TaskQueue) -> None:
        """Test cancelling a task while it's running."""
        # Use delay to keep task running long enough to cancel
        executor = MockExecutor(delay=0.2)
        task = task_queue.create_task("session1", [1, 2, 3, 4, 5])

        # Run task in background
        run_task = asyncio.create_task(task_queue.run_task(task.task_id, executor))

        # Wait for task to start and process at least one chat
        await asyncio.sleep(0.3)

        # Cancel the task
        result = task_queue.cancel_task(task.task_id)
        assert result is True

        # Wait for task to finish
        await run_task

        # Task should be cancelled
        assert task.status == TaskStatus.CANCELLED
        # Should have partial results (at least 1, but not all)
        assert 0 < len(task.results) < len(task.chat_ids)

    def test_cancel_completed_task(self, task_queue: TaskQueue) -> None:
        """Test cancelling a completed task returns False."""
        task = task_queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.COMPLETED

        result = task_queue.cancel_task(task.task_id)

        assert result is False
        assert task.status == TaskStatus.COMPLETED

    def test_clear_completed(self, task_queue: TaskQueue) -> None:
        """Test clearing completed tasks."""
        task1 = task_queue.create_task("session1", [1])
        task2 = task_queue.create_task("session2", [2])
        task3 = task_queue.create_task("session3", [3])

        task1.status = TaskStatus.COMPLETED
        task2.status = TaskStatus.FAILED
        # task3 remains PENDING

        removed = task_queue.clear_completed()

        assert removed == 2
        assert task_queue.get_task(task1.task_id) is None
        assert task_queue.get_task(task2.task_id) is None
        assert task_queue.get_task(task3.task_id) is not None

    def test_find_active_task_exact_match(self, task_queue: TaskQueue) -> None:
        """Test finding an active task with exact matching parameters."""
        # Create a pending task
        task = task_queue.create_task("session1", [1, 2, 3], message_limit=500)

        # Should find the task with matching parameters
        found = task_queue.find_active_task("session1", [1, 2, 3], 500)

        assert found is not None
        assert found.task_id == task.task_id

    def test_find_active_task_order_independent(self, task_queue: TaskQueue) -> None:
        """Test finding task works regardless of chat_ids order."""
        # Create a task with chat_ids in one order
        task = task_queue.create_task("session1", [3, 1, 2])

        # Should find the task even with different order
        found = task_queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is not None
        assert found.task_id == task.task_id

    def test_find_active_task_no_match_different_session(self, task_queue: TaskQueue) -> None:
        """Test that different session_id doesn't match."""
        task_queue.create_task("session1", [1, 2, 3])

        # Different session should not match
        found = task_queue.find_active_task("session2", [1, 2, 3], 1000)

        assert found is None

    def test_find_active_task_no_match_different_chats(self, task_queue: TaskQueue) -> None:
        """Test that different chat_ids don't match."""
        task_queue.create_task("session1", [1, 2, 3])

        # Different chats should not match
        found = task_queue.find_active_task("session1", [1, 2, 4], 1000)

        assert found is None

    def test_find_active_task_no_match_different_limit(self, task_queue: TaskQueue) -> None:
        """Test that different message_limit doesn't match."""
        task_queue.create_task("session1", [1, 2, 3], message_limit=500)

        # Different message limit should not match
        found = task_queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is None

    def test_find_active_task_ignores_completed(self, task_queue: TaskQueue) -> None:
        """Test that completed tasks are not returned."""
        task = task_queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.COMPLETED

        # Should not find completed task
        found = task_queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is None

    def test_find_active_task_ignores_failed(self, task_queue: TaskQueue) -> None:
        """Test that failed tasks are not returned."""
        task = task_queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.FAILED

        # Should not find failed task
        found = task_queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is None

    def test_find_active_task_finds_in_progress(self, task_queue: TaskQueue) -> None:
        """Test that in-progress tasks are found."""
        task = task_queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS

        # Should find in-progress task
        found = task_queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is not None
        assert found.task_id == task.task_id

    def test_find_active_task_returns_first_match(self, task_queue: TaskQueue) -> None:
        """Test that only one task is returned when multiple match."""
        task1 = task_queue.create_task("session1", [1, 2, 3])
        task2 = task_queue.create_task("session1", [1, 2, 3])

        # Should find one of the matching tasks
        found = task_queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is not None
        assert found.task_id in [task1.task_id, task2.task_id]

    @pytest.mark.asyncio
    async def test_task_timeout(self) -> None:
        """Test that tasks timeout after exceeding max execution time."""
        # Create queue with 1 second timeout
        queue = TaskQueue(task_timeout_seconds=1.0)

        # Create executor with long delay that will exceed timeout
        executor = MockExecutor(delay=0.5)
        task = queue.create_task("session1", [1, 2, 3, 4, 5])

        # Run task - should timeout before completing all chats
        await queue.run_task(task.task_id, executor)

        # Task should be marked as timeout
        assert task.status == TaskStatus.TIMEOUT
        assert "exceeded maximum execution time" in task.error
        assert len(task.results) < len(task.chat_ids)  # Partial results

    @pytest.mark.asyncio
    async def test_per_chat_timeout(self) -> None:
        """Test that individual chats timeout if they take too long."""
        # Create queue with 0.2 second per-chat timeout
        queue = TaskQueue(per_chat_timeout_seconds=0.2)

        # First chat is fast, second is slow
        class SlowOnSecondExecutor(MockExecutor):
            async def analyze_chat(
                self,
                session_id: str,
                chat_id: int,
                message_limit: int = 1000,
                batch_size: int = 1000,
                use_streaming: bool | None = None,
                memory_limit_mb: float = 1024.0,
                enable_memory_monitoring: bool = False,
                batch_progress_callback=None,
            ) -> AnalysisResult:
                if chat_id == 2:
                    await asyncio.sleep(0.5)  # Exceeds timeout
                return await super().analyze_chat(session_id, chat_id, message_limit)

        executor = SlowOnSecondExecutor()
        task = queue.create_task("session1", [1, 2, 3])

        # Run task
        await queue.run_task(task.task_id, executor)

        # Task should complete (not timeout at task level)
        assert task.status == TaskStatus.COMPLETED
        # Should have results for chat 1 and 3, but not 2 (timed out)
        assert len(task.results) == 2
        assert 1 in executor.analyzed_chats
        assert 2 not in executor.analyzed_chats  # Timed out
        assert 3 in executor.analyzed_chats

    @pytest.mark.asyncio
    async def test_stalled_task_detection(self) -> None:
        """Test that stalled tasks are detected and cancelled."""
        # Create queue with very short stall timeout (2 seconds) and check interval (1 second)
        queue = TaskQueue(
            progress_stall_timeout_seconds=2.0,
            stall_check_interval_seconds=1.0,
        )

        # Create executor that hangs on second chat
        class HangingExecutor(MockExecutor):
            async def analyze_chat(
                self,
                session_id: str,
                chat_id: int,
                message_limit: int = 1000,
                batch_size: int = 1000,
                use_streaming: bool | None = None,
                memory_limit_mb: float = 1024.0,
                enable_memory_monitoring: bool = False,
                batch_progress_callback=None,
            ) -> AnalysisResult:
                if chat_id == 2:
                    # Hang indefinitely (will be killed by stall monitor)
                    await asyncio.sleep(10)
                return await super().analyze_chat(session_id, chat_id, message_limit)

        executor = HangingExecutor()
        task = queue.create_task("session1", [1, 2, 3])

        # Run task - should be cancelled by stall monitor
        with contextlib.suppress(asyncio.CancelledError):
            await queue.run_task(task.task_id, executor)

        # Wait a bit for stall monitor to detect and cancel
        await asyncio.sleep(3.0)

        # Task should be cancelled
        assert task.status == TaskStatus.CANCELLED
        # Should have partial results (only chat 1)
        assert len(task.results) == 1

    @pytest.mark.asyncio
    async def test_force_cancel_running_task(self) -> None:
        """Test force cancelling a running task."""
        queue = TaskQueue()

        # Create slow executor
        executor = MockExecutor(delay=0.2)
        task = queue.create_task("session1", [1, 2, 3, 4, 5])

        # Run task in background
        run_task = asyncio.create_task(queue.run_task(task.task_id, executor))

        # Wait for task to start
        await asyncio.sleep(0.3)

        # Force cancel the task
        result = await queue.force_cancel_task(task.task_id, reason="Test force cancel")
        assert result is True

        # Wait for task to finish
        with contextlib.suppress(asyncio.CancelledError):
            await run_task

        # Task should be cancelled
        assert task.status == TaskStatus.CANCELLED
        # Error could be either "Task was force-cancelled" or the custom reason
        assert task.error is not None

    @pytest.mark.asyncio
    async def test_force_cancel_nonexistent_task(self) -> None:
        """Test force cancelling non-existent task returns False."""
        queue = TaskQueue()
        from uuid import uuid4

        result = await queue.force_cancel_task(uuid4(), reason="Test")
        assert result is False

    @pytest.mark.asyncio
    async def test_shutdown_cancels_running_tasks(self) -> None:
        """Test that shutdown cancels all running tasks."""
        queue = TaskQueue()

        # Create slow executor
        executor = MockExecutor(delay=0.2)
        task = queue.create_task("session1", [1, 2, 3, 4, 5])

        # Run task in background
        run_task = asyncio.create_task(queue.run_task(task.task_id, executor))

        # Wait for task to start
        await asyncio.sleep(0.3)

        # Shutdown queue
        await queue.shutdown()

        # Wait for task to finish
        with contextlib.suppress(asyncio.CancelledError):
            await run_task

        # Task should be cancelled
        assert task.status == TaskStatus.CANCELLED

    def test_clear_completed_includes_timeout(self) -> None:
        """Test that clear_completed removes timeout tasks."""
        queue = TaskQueue()

        task1 = queue.create_task("session1", [1])
        task2 = queue.create_task("session2", [2])
        task3 = queue.create_task("session3", [3])

        task1.status = TaskStatus.TIMEOUT
        task2.status = TaskStatus.COMPLETED
        # task3 remains PENDING

        removed = queue.clear_completed()

        assert removed == 2
        assert queue.get_task(task1.task_id) is None
        assert queue.get_task(task2.task_id) is None
        assert queue.get_task(task3.task_id) is not None

    def test_find_active_task_ignores_timeout(self) -> None:
        """Test that timeout tasks are not returned as active."""
        queue = TaskQueue()
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.TIMEOUT

        # Should not find timeout task
        found = queue.find_active_task("session1", [1, 2, 3], 1000)

        assert found is None

    @pytest.mark.asyncio
    async def test_sse_backpressure_consecutive_full_queue(self) -> None:
        """Test that slow SSE clients are forcibly disconnected after consecutive full queues."""
        # Create queue with aggressive backpressure settings
        queue = TaskQueue(
            max_consecutive_full_queue=5,  # Disconnect after 5 consecutive full queues
            subscriber_disconnect_threshold=0,  # Disable total dropped events threshold
        )

        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS

        # Subscribe but don't consume events (simulate slow/hung client)
        progress_queue = await queue.subscribe(task.task_id)

        # Publish enough events to fill the queue (maxsize=100) and trigger consecutive full
        # Queue has maxsize=100, so we need 100 events to fill it, then 5 more to trigger disconnect
        for i in range(110):
            event = ProgressEvent(
                task_id=task.task_id,
                status=TaskStatus.IN_PROGRESS,
                current=i,
                total=200,
                sequence=i,
                chat_title=f"Chat {i}",
            )
            await queue._publish_event(event)

        # Verify the subscriber was forcibly disconnected
        # The queue should receive a None event signaling disconnection
        none_received = False
        try:
            while not progress_queue.empty():
                event = progress_queue.get_nowait()
                if event is None:
                    none_received = True
                    break
        except asyncio.QueueEmpty:
            pass

        assert none_received, "Slow client should receive None event signaling forced disconnect"

        # Verify subscriber was removed from the list
        async with queue._lock:
            subscribers = queue._subscribers.get(task.task_id, [])
            assert len(subscribers) == 0, "Disconnected subscriber should be removed"

    @pytest.mark.asyncio
    async def test_sse_backpressure_total_dropped_events(self) -> None:
        """Test that clients are disconnected after exceeding total dropped events threshold."""
        # Create queue with total dropped events threshold
        queue = TaskQueue(
            max_consecutive_full_queue=0,  # Disable consecutive full queue check
            subscriber_disconnect_threshold=30,  # Disconnect after 30 total dropped events
        )

        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS

        # Subscribe but don't consume events (simulate slow client)
        progress_queue = await queue.subscribe(task.task_id)

        # Publish events to fill the queue and trigger dropped events
        # Fill queue (100 events), then 30 more to trigger disconnect
        for i in range(135):
            event = ProgressEvent(
                task_id=task.task_id,
                status=TaskStatus.IN_PROGRESS,
                current=i,
                total=200,
                sequence=i,
                chat_title=f"Chat {i}",
            )
            await queue._publish_event(event)

            # Occasionally consume an event to reset consecutive counter
            # This ensures we test the total_dropped threshold, not consecutive
            if i == 50 or i == 100:
                with contextlib.suppress(asyncio.QueueEmpty):
                    progress_queue.get_nowait()

        # Verify the subscriber was disconnected
        none_received = False
        try:
            while not progress_queue.empty():
                event = progress_queue.get_nowait()
                if event is None:
                    none_received = True
                    break
        except asyncio.QueueEmpty:
            pass

        assert none_received, (
            "Client should be disconnected after exceeding dropped events threshold"
        )

    @pytest.mark.asyncio
    async def test_sse_backpressure_healthy_client_not_disconnected(self) -> None:
        """Test that healthy clients that consume events are not disconnected."""
        queue = TaskQueue(
            max_consecutive_full_queue=10,
            subscriber_disconnect_threshold=50,
        )

        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS

        # Subscribe and actively consume events (simulate healthy client)
        progress_queue = await queue.subscribe(task.task_id)

        # Publish events and consume them
        events_received = []
        for i in range(50):
            event = ProgressEvent(
                task_id=task.task_id,
                status=TaskStatus.IN_PROGRESS,
                current=i,
                total=50,
                sequence=i,
                chat_title=f"Chat {i}",
            )
            await queue._publish_event(event)

            # Consume the event immediately (healthy client)
            try:
                received = progress_queue.get_nowait()
                events_received.append(received)
            except asyncio.QueueEmpty:
                pass

        # Verify all events were received and no None was sent
        assert len(events_received) > 0, "Healthy client should receive events"
        assert all(e is not None for e in events_received), (
            "Healthy client should not be disconnected"
        )

        # Verify subscriber is still active
        async with queue._lock:
            subscribers = queue._subscribers.get(task.task_id, [])
            assert len(subscribers) == 1, "Healthy subscriber should remain active"
            assert not subscribers[0].is_disconnected, (
                "Healthy client should not be marked as disconnected"
            )

    @pytest.mark.asyncio
    async def test_sse_backpressure_disabled(self) -> None:
        """Test that backpressure disconnect can be disabled."""
        queue = TaskQueue(
            max_consecutive_full_queue=0,  # Disabled
            subscriber_disconnect_threshold=0,  # Disabled
        )

        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS

        # Subscribe but don't consume events
        progress_queue = await queue.subscribe(task.task_id)

        # Publish many events (more than would normally trigger disconnect)
        for i in range(200):
            event = ProgressEvent(
                task_id=task.task_id,
                status=TaskStatus.IN_PROGRESS,
                current=i,
                total=200,
                sequence=i,
                chat_title=f"Chat {i}",
            )
            await queue._publish_event(event)

        # Verify subscriber was NOT disconnected (no None in queue)
        none_received = False
        try:
            while not progress_queue.empty():
                event = progress_queue.get_nowait()
                if event is None:
                    none_received = True
                    break
        except asyncio.QueueEmpty:
            pass

        assert not none_received, "Client should not be disconnected when backpressure is disabled"

        # Verify subscriber is still in the list
        async with queue._lock:
            subscribers = queue._subscribers.get(task.task_id, [])
            assert len(subscribers) == 1, (
                "Subscriber should remain active when backpressure disabled"
            )


@pytest.mark.skip(reason="TaskQueue removed - replaced with ProgressTracker for groups")
class TestConcurrentTaskLimit:
    """Tests for concurrent task limit functionality.

    DEPRECATED: TaskQueue is no longer used.
    """

    def test_create_task_within_limit(self) -> None:
        """Test creating tasks within the concurrent limit."""
        queue = TaskQueue(max_concurrent_tasks=3)

        # Create 3 tasks - should all succeed
        task1 = queue.create_task("session1", [1, 2])
        task2 = queue.create_task("session1", [3, 4])
        task3 = queue.create_task("session1", [5, 6])

        assert task1.status == TaskStatus.PENDING
        assert task2.status == TaskStatus.PENDING
        assert task3.status == TaskStatus.PENDING
        assert queue.count_active_tasks() == 3

    def test_create_task_exceeds_limit(self) -> None:
        """Test creating task when limit is exceeded raises QueueFullError."""
        queue = TaskQueue(max_concurrent_tasks=2)

        # Create 2 tasks - should succeed
        queue.create_task("session1", [1, 2])
        queue.create_task("session1", [3, 4])

        # Third task should fail
        with pytest.raises(QueueFullError) as exc_info:
            queue.create_task("session1", [5, 6])

        assert exc_info.value.current == 2
        assert exc_info.value.limit == 2
        assert "2/2 concurrent tasks" in str(exc_info.value)

    def test_create_task_after_completion(self) -> None:
        """Test creating task after one completes."""
        queue = TaskQueue(max_concurrent_tasks=2)

        # Create 2 tasks
        task1 = queue.create_task("session1", [1, 2])
        _task2 = queue.create_task("session1", [3, 4])

        # Complete one task
        task1.status = TaskStatus.COMPLETED

        # Should be able to create another task now
        task3 = queue.create_task("session1", [5, 6])
        assert task3.status == TaskStatus.PENDING
        assert queue.count_active_tasks() == 2  # _task2 and task3

    def test_create_task_disabled_limit(self) -> None:
        """Test that limit=0 disables the check."""
        queue = TaskQueue(max_concurrent_tasks=0)

        # Should be able to create many tasks
        for i in range(100):
            queue.create_task("session1", [i])

        assert queue.count_active_tasks() == 100

    def test_count_active_tasks_excludes_completed(self) -> None:
        """Test that completed tasks are not counted as active."""
        queue = TaskQueue(max_concurrent_tasks=10)

        task1 = queue.create_task("session1", [1])
        task2 = queue.create_task("session1", [2])
        _task3 = queue.create_task("session1", [3])

        assert queue.count_active_tasks() == 3

        # Mark tasks as completed/failed
        task1.status = TaskStatus.COMPLETED
        task2.status = TaskStatus.FAILED

        # Only _task3 should be active
        assert queue.count_active_tasks() == 1


@pytest.mark.skip(reason="TaskQueue removed - replaced with ProgressTracker for groups")
class TestGlobalTaskQueue:
    """Tests for global task queue singleton.

    DEPRECATED: TaskQueue is no longer used.
    """

    def test_get_task_queue_returns_same_instance(self) -> None:
        """Test that get_task_queue returns the same instance."""
        queue1 = get_task_queue()
        queue2 = get_task_queue()

        assert queue1 is queue2

    def test_reset_task_queue(self) -> None:
        """Test resetting the global task queue."""
        queue1 = get_task_queue()
        reset_task_queue()
        queue2 = get_task_queue()

        assert queue1 is not queue2
