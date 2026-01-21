"""Tests for task database persistence."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from chatfilter.analyzer.task_queue import AnalysisTask, TaskStatus
from chatfilter.models.analysis import AnalysisResult, ChatMetrics
from chatfilter.models.chat import Chat, ChatType
from chatfilter.storage.database import TaskDatabase


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_tasks.db"
        yield TaskDatabase(db_path)


@pytest.fixture
def sample_task():
    """Create a sample task for testing."""
    return AnalysisTask(
        task_id=uuid4(),
        session_id="test_session",
        chat_ids=[123, 456, 789],
        message_limit=1000,
        status=TaskStatus.PENDING,
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_result():
    """Create a sample analysis result for testing."""
    chat = Chat(
        id=123,
        title="Test Chat",
        chat_type=ChatType.SUPERGROUP,
        username="testchat",
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


def test_database_initialization(temp_db):
    """Test that database initializes with correct schema."""
    # Database should be created and tables should exist
    with temp_db._connection() as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]

    assert "tasks" in tables
    assert "task_results" in tables


def test_save_and_load_task(temp_db, sample_task):
    """Test saving and loading a task."""
    # Save task
    temp_db.save_task(sample_task)

    # Load task
    loaded_task = temp_db.load_task(sample_task.task_id)

    assert loaded_task is not None
    assert loaded_task.task_id == sample_task.task_id
    assert loaded_task.session_id == sample_task.session_id
    assert loaded_task.chat_ids == sample_task.chat_ids
    assert loaded_task.message_limit == sample_task.message_limit
    assert loaded_task.status == sample_task.status
    assert loaded_task.results == []


def test_load_nonexistent_task(temp_db):
    """Test loading a task that doesn't exist."""
    result = temp_db.load_task(uuid4())
    assert result is None


def test_update_task_status(temp_db, sample_task):
    """Test updating task status."""
    # Save initial task
    temp_db.save_task(sample_task)

    # Update status
    sample_task.status = TaskStatus.IN_PROGRESS
    sample_task.started_at = datetime.now(UTC)
    temp_db.save_task(sample_task)

    # Load and verify
    loaded_task = temp_db.load_task(sample_task.task_id)
    assert loaded_task.status == TaskStatus.IN_PROGRESS
    assert loaded_task.started_at is not None


def test_save_task_result(temp_db, sample_task, sample_result):
    """Test saving analysis results."""
    # Save task first
    temp_db.save_task(sample_task)

    # Save result
    temp_db.save_task_result(sample_task.task_id, sample_result)

    # Load task and verify results
    loaded_task = temp_db.load_task(sample_task.task_id)
    assert len(loaded_task.results) == 1
    assert loaded_task.results[0].chat.id == sample_result.chat.id
    assert loaded_task.results[0].chat.title == sample_result.chat.title
    assert loaded_task.results[0].metrics.message_count == sample_result.metrics.message_count


def test_save_multiple_results(temp_db, sample_task):
    """Test saving multiple results for a task."""
    temp_db.save_task(sample_task)

    # Create and save multiple results
    for chat_id in [123, 456, 789]:
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
        result = AnalysisResult(
            chat=chat,
            metrics=metrics,
            analyzed_at=datetime.now(UTC),
        )
        temp_db.save_task_result(sample_task.task_id, result)

    # Load and verify
    loaded_task = temp_db.load_task(sample_task.task_id)
    assert len(loaded_task.results) == 3
    assert loaded_task.results[0].chat.id == 123
    assert loaded_task.results[1].chat.id == 456
    assert loaded_task.results[2].chat.id == 789


def test_load_all_tasks(temp_db):
    """Test loading all tasks."""
    # Create and save multiple tasks
    tasks = [
        AnalysisTask(
            task_id=uuid4(),
            session_id=f"session_{i}",
            chat_ids=[100 * i, 100 * i + 1],
            message_limit=1000,
        )
        for i in range(3)
    ]

    for task in tasks:
        temp_db.save_task(task)

    # Load all tasks
    loaded_tasks = temp_db.load_all_tasks()

    assert len(loaded_tasks) == 3
    # Should be sorted by created_at desc (newest first)
    assert all(t.task_id in [task.task_id for task in tasks] for t in loaded_tasks)


def test_load_incomplete_tasks(temp_db):
    """Test loading only incomplete tasks."""
    # Create tasks with different statuses
    pending_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session1",
        chat_ids=[1, 2],
        message_limit=1000,
        status=TaskStatus.PENDING,
    )
    in_progress_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session2",
        chat_ids=[3, 4],
        message_limit=1000,
        status=TaskStatus.IN_PROGRESS,
    )
    completed_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session3",
        chat_ids=[5, 6],
        message_limit=1000,
        status=TaskStatus.COMPLETED,
    )
    failed_task = AnalysisTask(
        task_id=uuid4(),
        session_id="session4",
        chat_ids=[7, 8],
        message_limit=1000,
        status=TaskStatus.FAILED,
    )

    for task in [pending_task, in_progress_task, completed_task, failed_task]:
        temp_db.save_task(task)

    # Load incomplete tasks
    incomplete = temp_db.load_incomplete_tasks()

    assert len(incomplete) == 2
    assert pending_task.task_id in [t.task_id for t in incomplete]
    assert in_progress_task.task_id in [t.task_id for t in incomplete]
    assert completed_task.task_id not in [t.task_id for t in incomplete]
    assert failed_task.task_id not in [t.task_id for t in incomplete]


def test_delete_task(temp_db, sample_task):
    """Test deleting a task."""
    # Save task
    temp_db.save_task(sample_task)

    # Verify it exists
    assert temp_db.load_task(sample_task.task_id) is not None

    # Delete task
    temp_db.delete_task(sample_task.task_id)

    # Verify it's gone
    assert temp_db.load_task(sample_task.task_id) is None


def test_delete_task_cascades_results(temp_db, sample_task, sample_result):
    """Test that deleting a task also deletes its results."""
    # Save task and result
    temp_db.save_task(sample_task)
    temp_db.save_task_result(sample_task.task_id, sample_result)

    # Verify result exists
    loaded_task = temp_db.load_task(sample_task.task_id)
    assert len(loaded_task.results) == 1

    # Delete task
    temp_db.delete_task(sample_task.task_id)

    # Verify results are also deleted
    with temp_db._connection() as conn:
        cursor = conn.execute(
            "SELECT COUNT(*) FROM task_results WHERE task_id = ?",
            (str(sample_task.task_id),),
        )
        count = cursor.fetchone()[0]

    assert count == 0


def test_delete_completed_tasks(temp_db):
    """Test bulk deletion of completed tasks."""
    # Create tasks with different statuses
    statuses = [
        TaskStatus.PENDING,
        TaskStatus.IN_PROGRESS,
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
    ]

    tasks = []
    for i, status in enumerate(statuses):
        task = AnalysisTask(
            task_id=uuid4(),
            session_id=f"session_{i}",
            chat_ids=[i],
            message_limit=1000,
            status=status,
        )
        tasks.append(task)
        temp_db.save_task(task)

    # Delete completed tasks
    deleted_count = temp_db.delete_completed_tasks()

    # Should delete COMPLETED, FAILED, and CANCELLED (3 tasks)
    assert deleted_count == 3

    # Verify only PENDING and IN_PROGRESS remain
    remaining_tasks = temp_db.load_all_tasks()
    assert len(remaining_tasks) == 2
    assert all(t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS) for t in remaining_tasks)


def test_task_with_error(temp_db):
    """Test saving and loading a task with an error."""
    task = AnalysisTask(
        task_id=uuid4(),
        session_id="session1",
        chat_ids=[1],
        message_limit=1000,
        status=TaskStatus.FAILED,
        error="Something went wrong",
        completed_at=datetime.now(UTC),
    )

    temp_db.save_task(task)
    loaded_task = temp_db.load_task(task.task_id)

    assert loaded_task.status == TaskStatus.FAILED
    assert loaded_task.error == "Something went wrong"
    assert loaded_task.completed_at is not None


def test_current_chat_index_persistence(temp_db):
    """Test that current_chat_index is persisted correctly."""
    task = AnalysisTask(
        task_id=uuid4(),
        session_id="session1",
        chat_ids=[1, 2, 3, 4, 5],
        message_limit=1000,
        status=TaskStatus.IN_PROGRESS,
        current_chat_index=2,
    )

    temp_db.save_task(task)
    loaded_task = temp_db.load_task(task.task_id)

    assert loaded_task.current_chat_index == 2
