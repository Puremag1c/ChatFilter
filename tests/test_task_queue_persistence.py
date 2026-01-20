"""Tests for TaskQueue persistence and recovery."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from chatfilter.analyzer.task_queue import AnalysisTask, TaskQueue, TaskStatus
from chatfilter.storage.database import TaskDatabase


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_tasks.db"
        yield TaskDatabase(db_path)


def test_task_queue_with_database(temp_db):
    """Test that TaskQueue can be initialized with a database."""
    queue = TaskQueue(db=temp_db)
    assert queue._db is not None


def test_task_queue_without_database():
    """Test that TaskQueue works without a database (in-memory only)."""
    queue = TaskQueue(db=None)
    assert queue._db is None

    # Should still be able to create tasks
    task = queue.create_task("session1", [1, 2, 3])
    assert task.task_id is not None
    assert queue.get_task(task.task_id) is not None


def test_create_task_persists_to_database(temp_db):
    """Test that creating a task persists it to the database."""
    queue = TaskQueue(db=temp_db)

    task = queue.create_task("session1", [123, 456], message_limit=500)

    # Verify task is in database
    loaded_task = temp_db.load_task(task.task_id)
    assert loaded_task is not None
    assert loaded_task.session_id == "session1"
    assert loaded_task.chat_ids == [123, 456]
    assert loaded_task.message_limit == 500


def test_recovery_loads_incomplete_tasks(temp_db):
    """Test that TaskQueue loads incomplete tasks on initialization."""
    # Create some tasks directly in database
    pending_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session1",
        chat_ids=[1, 2, 3],
        message_limit=1000,
        status=TaskStatus.PENDING,
        created_at=datetime.now(UTC),
    )
    in_progress_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session2",
        chat_ids=[4, 5, 6],
        message_limit=1000,
        status=TaskStatus.IN_PROGRESS,
        created_at=datetime.now(UTC),
    )
    completed_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session3",
        chat_ids=[7, 8, 9],
        message_limit=1000,
        status=TaskStatus.COMPLETED,
        created_at=datetime.now(UTC),
    )

    temp_db.save_task(pending_task)
    temp_db.save_task(in_progress_task)
    temp_db.save_task(completed_task)

    # Create new queue instance - should load incomplete tasks
    queue = TaskQueue(db=temp_db)

    # Check that incomplete tasks are loaded
    assert queue.get_task(pending_task.task_id) is not None
    assert queue.get_task(in_progress_task.task_id) is not None

    # Completed task should not be loaded
    assert queue.get_task(completed_task.task_id) is None


def test_recovery_resets_in_progress_to_pending(temp_db):
    """Test that in-progress tasks are reset to pending on recovery."""
    # Create an in-progress task
    in_progress_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session1",
        chat_ids=[1, 2, 3],
        message_limit=1000,
        status=TaskStatus.IN_PROGRESS,
        started_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
    )

    temp_db.save_task(in_progress_task)

    # Create new queue - should reset status
    queue = TaskQueue(db=temp_db)

    # Task should be loaded but reset to PENDING
    recovered_task = queue.get_task(in_progress_task.task_id)
    assert recovered_task is not None
    assert recovered_task.status == TaskStatus.PENDING

    # Verify it's also updated in database
    db_task = temp_db.load_task(in_progress_task.task_id)
    assert db_task.status == TaskStatus.PENDING


def test_cancel_task_persists_to_database(temp_db):
    """Test that cancelling a task persists the change."""
    queue = TaskQueue(db=temp_db)

    task = queue.create_task("session1", [1, 2, 3])
    queue.cancel_task(task.task_id)

    # Verify in database
    db_task = temp_db.load_task(task.task_id)
    assert db_task.status == TaskStatus.CANCELLED
    assert db_task.completed_at is not None


def test_clear_completed_removes_from_database(temp_db):
    """Test that clearing completed tasks removes them from database."""
    queue = TaskQueue(db=temp_db)

    # Create tasks with different statuses
    task1 = queue.create_task("session1", [1])
    task2 = queue.create_task("session2", [2])
    task3 = queue.create_task("session3", [3])

    # Mark some as completed
    task1.status = TaskStatus.COMPLETED
    task1.completed_at = datetime.now(UTC)
    temp_db.save_task(task1)

    task2.status = TaskStatus.FAILED
    task2.completed_at = datetime.now(UTC)
    temp_db.save_task(task2)

    # Leave task3 as pending

    # Clear completed tasks
    cleared_count = queue.clear_completed()

    assert cleared_count == 2

    # Verify tasks are removed from database
    assert temp_db.load_task(task1.task_id) is None
    assert temp_db.load_task(task2.task_id) is None
    assert temp_db.load_task(task3.task_id) is not None


@pytest.mark.asyncio
async def test_run_task_persists_progress(temp_db):
    """Test that task progress is persisted during execution."""
    from chatfilter.models.analysis import AnalysisResult, ChatMetrics
    from chatfilter.models.chat import Chat, ChatType

    # Mock executor
    class MockExecutor:
        async def analyze_chat(self, session_id, chat_id, message_limit):
            chat = Chat(
                id=chat_id,
                title=f"Chat {chat_id}",
                chat_type=ChatType.SUPERGROUP,
            )
            metrics = ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=24.0,
                first_message_at=datetime.now(UTC),
                last_message_at=datetime.now(UTC),
            )
            return AnalysisResult(
                chat=chat,
                metrics=metrics,
                analyzed_at=datetime.now(UTC),
            )

        async def get_chat_info(self, session_id, chat_id):
            return Chat(
                id=chat_id,
                title=f"Chat {chat_id}",
                chat_type=ChatType.SUPERGROUP,
            )

    queue = TaskQueue(db=temp_db)
    task = queue.create_task("session1", [1, 2, 3])

    # Run task
    executor = MockExecutor()
    await queue.run_task(task.task_id, executor)

    # Verify final state is persisted
    db_task = temp_db.load_task(task.task_id)
    assert db_task.status == TaskStatus.COMPLETED
    assert db_task.completed_at is not None
    assert len(db_task.results) == 3


@pytest.mark.asyncio
async def test_run_task_persists_failure(temp_db):
    """Test that task failures are persisted."""

    # Mock executor that fails
    class FailingExecutor:
        async def analyze_chat(self, session_id, chat_id, message_limit):
            raise RuntimeError("Test error")

        async def get_chat_info(self, session_id, chat_id):
            from chatfilter.models.chat import Chat, ChatType

            return Chat(
                id=chat_id,
                title=f"Chat {chat_id}",
                chat_type=ChatType.SUPERGROUP,
            )

    queue = TaskQueue(db=temp_db)
    task = queue.create_task("session1", [1])

    # Run task (should fail)
    executor = FailingExecutor()
    await queue.run_task(task.task_id, executor)

    # Verify failure is persisted
    db_task = temp_db.load_task(task.task_id)
    assert db_task.status == TaskStatus.FAILED
    assert db_task.error is not None
    assert "Test error" in db_task.error


def test_get_task_queue_with_database():
    """Test global get_task_queue function with database."""
    from chatfilter.analyzer.task_queue import get_task_queue, reset_task_queue

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_tasks.db"
        db = TaskDatabase(db_path)

        # Reset to ensure clean state
        reset_task_queue()

        # Get queue with database
        queue = get_task_queue(db=db)

        assert queue._db is not None

        # Subsequent calls should return same instance
        queue2 = get_task_queue()
        assert queue2 is queue

        # Cleanup
        reset_task_queue()
