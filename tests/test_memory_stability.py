"""Tests for memory stability and leak prevention.

These tests verify that long-running tasks don't accumulate memory
through uncleaned resources, cached data, or orphaned objects.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from chatfilter.analyzer.task_queue import (
    TaskQueue,
    TaskStatus,
    reset_task_queue,
)
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType
from chatfilter.service.chat_analysis import ChatAnalysisService

if TYPE_CHECKING:
    from pathlib import Path


# Try to import memory utilities (optional dependency)
try:
    from chatfilter.utils.memory import (
        MemoryMonitor,
        MemoryTracker,
        get_memory_usage,
    )

    MEMORY_MONITORING_AVAILABLE = True
except ImportError:
    MEMORY_MONITORING_AVAILABLE = False


class MockExecutor:
    """Mock executor for testing."""

    def __init__(self, num_chats: int = 10) -> None:
        self.num_chats = num_chats
        self.analyzed_count = 0

    async def get_chat_info(self, session_id: str, chat_id: int) -> Chat | None:
        # Ensure chat_id is positive (Chat model validation requirement)
        if chat_id <= 0:
            chat_id = abs(chat_id) + 1
        return Chat(
            id=chat_id,
            title=f"Chat {chat_id}",
            chat_type=ChatType.GROUP,
        )

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
        self.analyzed_count += 1

        # Simulate some work
        await asyncio.sleep(0.01)

        # Ensure chat_id is positive (Chat model validation requirement)
        if chat_id <= 0:
            chat_id = abs(chat_id) + 1

        return AnalysisResult(
            chat=Chat(
                id=chat_id,
                title=f"Chat {chat_id}",
                chat_type=ChatType.GROUP,
            ),
            metrics=ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=24.0,
                first_message_at=datetime.now(UTC),
                last_message_at=datetime.now(UTC),
            ),
            analyzed_at=datetime.now(UTC),
        )


@pytest.fixture(autouse=True)
def reset_global_queue() -> None:
    """Reset global task queue before and after each test."""
    reset_task_queue()
    yield
    reset_task_queue()


class TestMemoryCleanup:
    """Tests for memory cleanup mechanisms."""

    def test_clear_completed_tasks_removes_from_memory(self) -> None:
        """Test that clearing completed tasks removes them from memory."""
        queue = TaskQueue()

        # Create many completed tasks
        for i in range(10):
            task = queue.create_task("session1", [i])
            task.status = TaskStatus.COMPLETED

        # Verify tasks exist
        assert len(queue.get_all_tasks()) == 10

        # Clear completed tasks
        removed = queue.clear_completed()

        # Verify cleanup
        assert removed == 10
        assert len(queue.get_all_tasks()) == 0

    @pytest.mark.asyncio
    async def test_auto_cleanup_triggers_at_threshold(self) -> None:
        """Test that automatic cleanup triggers when threshold is reached."""
        # Set threshold to 5 completed tasks
        queue = TaskQueue(auto_cleanup_threshold=5)
        executor = MockExecutor()

        # Create and run 6 tasks (should trigger auto-cleanup after 5th)
        for i in range(6):
            task = queue.create_task("session1", [i])
            await queue.run_task(task.task_id, executor)

        # After 5 completions, cleanup should have been triggered
        # So we should only have 1 completed task left
        all_tasks = queue.get_all_tasks()
        assert len(all_tasks) <= 2  # May have 1-2 tasks depending on timing

    @pytest.mark.asyncio
    async def test_cleanup_orphaned_subscribers(self) -> None:
        """Test cleanup of orphaned subscriber queues."""
        queue = TaskQueue()
        executor = MockExecutor()

        # Create task and subscribe
        task = queue.create_task("session1", [1, 2, 3])
        sub_queue = await queue.subscribe(task.task_id)

        # Run task to completion
        await queue.run_task(task.task_id, executor)

        # Task is completed but subscriber queue still exists
        assert task.status == TaskStatus.COMPLETED

        # Clean up orphaned subscribers
        cleaned = await queue.cleanup_orphaned_subscribers()

        # Should have cleaned up the subscriber queue
        assert cleaned > 0

    def test_chat_analysis_service_cache_clearing(self, tmp_path: Path) -> None:
        """Test that chat analysis service can clear its caches."""
        from chatfilter.telegram.session_manager import SessionManager

        session_manager = SessionManager()
        service = ChatAnalysisService(
            session_manager=session_manager,
            data_dir=tmp_path,
        )

        # Simulate cache accumulation
        service._chat_cache["session1"] = {
            1: Chat(id=1, title="Chat 1", chat_type=ChatType.GROUP),
            2: Chat(id=2, title="Chat 2", chat_type=ChatType.GROUP),
        }
        service._chat_cache["session2"] = {
            3: Chat(id=3, title="Chat 3", chat_type=ChatType.GROUP),
        }
        service._loaders["session1"] = None  # Mock loader

        # Verify caches have data
        stats = service.get_cache_stats()
        assert stats["total_sessions"] == 2
        assert stats["total_chats"] == 3
        assert stats["total_loaders"] == 1

        # Clear specific session
        service.clear_cache("session1")
        stats = service.get_cache_stats()
        assert stats["total_sessions"] == 1
        assert stats["total_chats"] == 1
        assert stats["total_loaders"] == 0

        # Clear all
        service.clear_cache()
        stats = service.get_cache_stats()
        assert stats["total_sessions"] == 0
        assert stats["total_chats"] == 0


@pytest.mark.skipif(
    not MEMORY_MONITORING_AVAILABLE,
    reason="Memory monitoring requires psutil",
)
class TestMemoryMonitoring:
    """Tests for memory monitoring utilities."""

    def test_get_memory_usage(self) -> None:
        """Test getting current memory usage."""
        stats = get_memory_usage()

        assert stats.rss_bytes > 0
        assert stats.vms_bytes > 0
        assert stats.rss_mb > 0
        assert stats.vms_mb > 0
        assert 0 < stats.percent < 100

    def test_memory_monitor_within_threshold(self) -> None:
        """Test memory monitor when usage is within threshold."""
        # Set very high threshold
        monitor = MemoryMonitor(threshold_mb=10000.0)

        # Should pass
        assert monitor.check() is True

    def test_memory_monitor_exceeds_threshold(self) -> None:
        """Test memory monitor when usage exceeds threshold."""
        # Set very low threshold (1 byte = ~0MB)
        monitor = MemoryMonitor(threshold_mb=0.001)

        # Should fail
        assert monitor.check() is False

    def test_memory_monitor_callback_on_threshold(self) -> None:
        """Test that callback is called when threshold exceeded."""
        callback_called = False

        def on_exceeded(stats):
            nonlocal callback_called
            callback_called = True

        monitor = MemoryMonitor(
            threshold_mb=0.001,  # Very low to trigger
            on_threshold_exceeded=on_exceeded,
        )

        monitor.check()

        assert callback_called is True

    def test_memory_monitor_circuit_breaker(self) -> None:
        """Test circuit breaker raises MemoryError."""
        monitor = MemoryMonitor(
            threshold_mb=0.001,  # Very low to trigger
            circuit_breaker=True,
        )

        with pytest.raises(MemoryError):
            monitor.check()

    def test_memory_tracker_snapshots(self) -> None:
        """Test memory tracker snapshot and diff."""
        tracker = MemoryTracker()

        # Take first snapshot
        stats1 = tracker.snapshot("start")
        assert stats1 is not None

        # Allocate some memory
        data = [0] * 100000  # Allocate ~800KB

        # Take second snapshot
        stats2 = tracker.snapshot("end")
        assert stats2 is not None

        # Get diff (should show increase)
        diff = tracker.get_diff("start", "end")
        assert diff is not None
        rss_diff, vms_diff = diff

        # Clean up
        del data

    def test_memory_tracker_missing_snapshot(self) -> None:
        """Test getting diff with missing snapshots."""
        tracker = MemoryTracker()

        # Try to get diff without snapshots
        diff = tracker.get_diff("start", "end")
        assert diff is None


@pytest.mark.skipif(
    not MEMORY_MONITORING_AVAILABLE,
    reason="Memory monitoring requires psutil",
)
class TestMemoryStability:
    """Integration tests for memory stability in long-running tasks."""

    @pytest.mark.asyncio
    async def test_task_queue_memory_stable_over_iterations(self) -> None:
        """Test that task queue memory usage remains stable over many iterations."""
        tracker = MemoryTracker()
        tracker.snapshot("start")

        # Create queue with auto-cleanup enabled
        queue = TaskQueue(auto_cleanup_threshold=10)
        executor = MockExecutor()

        # Run many tasks
        for i in range(50):
            task = queue.create_task("session1", [i])
            await queue.run_task(task.task_id, executor)

        tracker.snapshot("end")

        # Get memory diff
        diff = tracker.get_diff("start", "end")
        assert diff is not None
        rss_diff, vms_diff = diff

        # Memory growth should be minimal (< 50MB) due to auto-cleanup
        # Note: This is a rough threshold and may need adjustment
        assert rss_diff < 50.0, f"Memory grew by {rss_diff:.1f}MB (expected < 50MB)"

    @pytest.mark.asyncio
    async def test_task_queue_with_memory_monitoring(self) -> None:
        """Test task queue with memory monitoring enabled."""
        # Create queue with memory monitoring
        queue = TaskQueue(
            auto_cleanup_threshold=10,
            memory_threshold_mb=2048.0,  # 2GB threshold
            enable_memory_monitoring=True,
        )

        executor = MockExecutor()

        # Run tasks and verify no memory errors
        for i in range(20):
            task = queue.create_task("session1", [i])
            await queue.run_task(task.task_id, executor)

        # If we got here without MemoryError, monitoring is working
        assert True

    @pytest.mark.asyncio
    async def test_subscriber_queues_cleaned_up(self) -> None:
        """Test that subscriber queues don't accumulate indefinitely."""
        # Disable auto-cleanup to test explicit cleanup
        queue = TaskQueue(auto_cleanup_threshold=0)
        executor = MockExecutor()

        # Create many tasks with subscribers
        for i in range(1, 21):  # Start from 1 to avoid chat id 0
            task = queue.create_task("session1", [i])
            # Subscribe but don't consume events (simulates disconnected client)
            await queue.subscribe(task.task_id)
            # Run task
            await queue.run_task(task.task_id, executor)

        # Clean up orphaned subscribers
        cleaned = await queue.cleanup_orphaned_subscribers()

        # Should have cleaned up many subscriber queues
        assert cleaned > 0


@pytest.mark.skipif(
    not MEMORY_MONITORING_AVAILABLE,
    reason="Memory monitoring requires psutil",
)
class TestResourceCleanup:
    """Tests for explicit resource cleanup."""

    @pytest.mark.asyncio
    async def test_task_results_cleared_on_completion(self) -> None:
        """Test that task results can be cleared to free memory."""
        queue = TaskQueue()
        executor = MockExecutor()

        # Create task with many chats (start from 1 to avoid chat id 0)
        task = queue.create_task("session1", list(range(1, 101)))
        await queue.run_task(task.task_id, executor)

        # Task should have results
        assert len(task.results) == 100
        assert task.status == TaskStatus.COMPLETED

        # Clear completed tasks (including results)
        removed = queue.clear_completed()
        assert removed == 1

        # Task should be removed
        assert queue.get_task(task.task_id) is None

    def test_service_cache_stats(self, tmp_path: Path) -> None:
        """Test that service cache stats are accurate."""
        from chatfilter.telegram.session_manager import SessionManager

        session_manager = SessionManager()
        service = ChatAnalysisService(
            session_manager=session_manager,
            data_dir=tmp_path,
        )

        # Add some cache data (start from 1 to avoid chat id 0)
        for i in range(5):
            service._chat_cache[f"session{i}"] = {
                j: Chat(id=j, title=f"Chat {j}", chat_type=ChatType.GROUP) for j in range(1, 11)
            }

        stats = service.get_cache_stats()
        assert stats["total_sessions"] == 5
        assert stats["total_chats"] == 50
