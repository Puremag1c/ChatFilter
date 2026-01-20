"""Tests for analysis history functionality."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

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
def sample_completed_tasks():
    """Create sample completed tasks for testing."""
    base_time = datetime.now(UTC)

    tasks = []
    for i in range(5):
        task = AnalysisTask(
            task_id=uuid4(),
            session_id=f"session_{i}",
            chat_ids=[100 + i, 200 + i],
            message_limit=1000,
            status=TaskStatus.COMPLETED,
            created_at=base_time - timedelta(hours=10 - i),
            started_at=base_time - timedelta(hours=9 - i),
            completed_at=base_time - timedelta(hours=8 - i),
        )
        tasks.append(task)

    return tasks


@pytest.fixture
def sample_result():
    """Create a sample analysis result."""
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


class TestDatabaseHistoryMethods:
    """Test database methods for history functionality."""

    def test_load_completed_tasks_all(self, temp_db, sample_completed_tasks):
        """Test loading all completed tasks."""
        # Save tasks
        for task in sample_completed_tasks:
            temp_db.save_task(task)

        # Load all completed tasks
        loaded = temp_db.load_completed_tasks()

        assert len(loaded) == 5
        # Should be sorted by completion time (newest first)
        assert loaded[0].task_id == sample_completed_tasks[-1].task_id

    def test_load_completed_tasks_pagination(self, temp_db, sample_completed_tasks):
        """Test loading completed tasks with pagination."""
        # Save tasks
        for task in sample_completed_tasks:
            temp_db.save_task(task)

        # Load first page (2 tasks)
        page1 = temp_db.load_completed_tasks(limit=2, offset=0)
        assert len(page1) == 2

        # Load second page (2 tasks)
        page2 = temp_db.load_completed_tasks(limit=2, offset=2)
        assert len(page2) == 2

        # Load third page (1 task)
        page3 = temp_db.load_completed_tasks(limit=2, offset=4)
        assert len(page3) == 1

        # Ensure no overlap
        page1_ids = {t.task_id for t in page1}
        page2_ids = {t.task_id for t in page2}
        assert not page1_ids.intersection(page2_ids)

    def test_load_completed_tasks_status_filter(self, temp_db):
        """Test loading completed tasks with status filter."""
        # Create tasks with different statuses
        completed_task = AnalysisTask(
            task_id=uuid4(),
            session_id="session1",
            chat_ids=[1],
            status=TaskStatus.COMPLETED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        failed_task = AnalysisTask(
            task_id=uuid4(),
            session_id="session2",
            chat_ids=[2],
            status=TaskStatus.FAILED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        cancelled_task = AnalysisTask(
            task_id=uuid4(),
            session_id="session3",
            chat_ids=[3],
            status=TaskStatus.CANCELLED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

        temp_db.save_task(completed_task)
        temp_db.save_task(failed_task)
        temp_db.save_task(cancelled_task)

        # Load only completed tasks
        completed_only = temp_db.load_completed_tasks(
            status_filter=[TaskStatus.COMPLETED]
        )
        assert len(completed_only) == 1
        assert completed_only[0].status == TaskStatus.COMPLETED

        # Load only failed tasks
        failed_only = temp_db.load_completed_tasks(status_filter=[TaskStatus.FAILED])
        assert len(failed_only) == 1
        assert failed_only[0].status == TaskStatus.FAILED

        # Load completed and failed tasks
        multiple_status = temp_db.load_completed_tasks(
            status_filter=[TaskStatus.COMPLETED, TaskStatus.FAILED]
        )
        assert len(multiple_status) == 2

    def test_count_completed_tasks(self, temp_db, sample_completed_tasks):
        """Test counting completed tasks."""
        # Save tasks
        for task in sample_completed_tasks:
            temp_db.save_task(task)

        # Count all completed tasks
        total = temp_db.count_completed_tasks()
        assert total == 5

    def test_count_completed_tasks_with_filter(self, temp_db):
        """Test counting with status filter."""
        # Create mixed status tasks
        for status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            task = AnalysisTask(
                task_id=uuid4(),
                session_id="session",
                chat_ids=[1],
                status=status,
                created_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
            temp_db.save_task(task)

        # Count completed only
        completed_count = temp_db.count_completed_tasks(
            status_filter=[TaskStatus.COMPLETED]
        )
        assert completed_count == 1

        # Count all
        total_count = temp_db.count_completed_tasks()
        assert total_count == 3

    def test_load_completed_tasks_with_results(self, temp_db, sample_result):
        """Test that completed tasks include their results."""
        task = AnalysisTask(
            task_id=uuid4(),
            session_id="session",
            chat_ids=[123],
            status=TaskStatus.COMPLETED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

        # Save task and result
        temp_db.save_task(task)
        temp_db.save_task_result(task.task_id, sample_result)

        # Load completed tasks
        loaded = temp_db.load_completed_tasks()
        assert len(loaded) == 1
        assert len(loaded[0].results) == 1
        assert loaded[0].results[0].chat.id == 123


class TestTaskQueueHistoryPreservation:
    """Test that TaskQueue preserves history in database."""

    def test_clear_completed_preserves_database(self, temp_db):
        """Test that clear_completed removes from memory but not from database."""
        from chatfilter.analyzer.task_queue import TaskQueue

        # Create queue with database
        queue = TaskQueue(db=temp_db, auto_cleanup_threshold=0)

        # Create and complete a task
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now(UTC)
        temp_db.save_task(task)

        # Task should be in memory
        assert queue.get_task(task.task_id) is not None

        # Clear completed tasks
        cleared = queue.clear_completed()
        assert cleared == 1

        # Task should NOT be in memory
        assert queue.get_task(task.task_id) is None

        # Task SHOULD still be in database
        db_task = temp_db.load_task(task.task_id)
        assert db_task is not None
        assert db_task.status == TaskStatus.COMPLETED

    def test_get_task_with_include_historical(self, temp_db):
        """Test retrieving historical tasks from database."""
        from chatfilter.analyzer.task_queue import TaskQueue

        # Create queue
        queue = TaskQueue(db=temp_db, auto_cleanup_threshold=0)

        # Create completed task
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now(UTC)
        temp_db.save_task(task)

        # Clear from memory
        queue.clear_completed()

        # Should not find without historical flag
        assert queue.get_task(task.task_id, include_historical=False) is None

        # Should find with historical flag
        historical = queue.get_task(task.task_id, include_historical=True)
        assert historical is not None
        assert historical.task_id == task.task_id


class TestHistoryAPI:
    """Test history API endpoints."""

    @pytest.fixture
    def client(self, temp_db, monkeypatch):
        """Create test client with mocked dependencies."""
        from chatfilter.web.app import create_app

        # Mock get_database to return our temp database
        def mock_get_database():
            return temp_db

        monkeypatch.setattr(
            "chatfilter.web.routers.history.get_database", mock_get_database
        )

        app = create_app(debug=True)
        return TestClient(app)

    def test_list_history_endpoint(self, client, temp_db, sample_completed_tasks):
        """Test GET /api/history endpoint."""
        # Save tasks
        for task in sample_completed_tasks:
            temp_db.save_task(task)

        # Request history
        response = client.get("/api/history/")
        assert response.status_code == 200

        data = response.json()
        assert data["total"] == 5
        assert len(data["tasks"]) == 5
        assert data["page"] == 1
        assert data["page_size"] == 20
        assert not data["has_more"]

    def test_list_history_pagination(self, client, temp_db, sample_completed_tasks):
        """Test pagination in history list."""
        # Save tasks
        for task in sample_completed_tasks:
            temp_db.save_task(task)

        # Request first page
        response = client.get("/api/history/?page=1&page_size=2")
        assert response.status_code == 200

        data = response.json()
        assert len(data["tasks"]) == 2
        assert data["total"] == 5
        assert data["has_more"]

        # Request second page
        response = client.get("/api/history/?page=2&page_size=2")
        assert response.status_code == 200

        data = response.json()
        assert len(data["tasks"]) == 2
        assert data["has_more"]

    def test_list_history_status_filter(self, client, temp_db):
        """Test status filtering in history list."""
        # Create tasks with different statuses
        completed = AnalysisTask(
            task_id=uuid4(),
            session_id="s1",
            chat_ids=[1],
            status=TaskStatus.COMPLETED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        failed = AnalysisTask(
            task_id=uuid4(),
            session_id="s2",
            chat_ids=[2],
            status=TaskStatus.FAILED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )

        temp_db.save_task(completed)
        temp_db.save_task(failed)

        # Filter by completed
        response = client.get("/api/history/?status=completed")
        assert response.status_code == 200
        data = response.json()
        assert len(data["tasks"]) == 1
        assert data["tasks"][0]["status"] == "completed"

    def test_get_task_history_detail(self, client, temp_db, sample_result):
        """Test GET /api/history/{task_id} endpoint."""
        # Create task with results
        task = AnalysisTask(
            task_id=uuid4(),
            session_id="session1",
            chat_ids=[123],
            message_limit=1000,
            status=TaskStatus.COMPLETED,
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        temp_db.save_task(task)
        temp_db.save_task_result(task.task_id, sample_result)

        # Request task detail
        response = client.get(f"/api/history/{task.task_id}")
        assert response.status_code == 200

        data = response.json()
        assert data["task_id"] == str(task.task_id)
        assert data["session_id"] == "session1"
        assert len(data["results"]) == 1
        assert data["results"][0]["chat"]["id"] == 123

    def test_get_nonexistent_task_history(self, client):
        """Test requesting history for nonexistent task."""
        fake_id = uuid4()
        response = client.get(f"/api/history/{fake_id}")
        assert response.status_code == 404

    def test_history_stats_endpoint(self, client, temp_db):
        """Test GET /api/history/stats endpoint."""
        # Create tasks with different statuses
        statuses = [
            TaskStatus.COMPLETED,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.TIMEOUT,
        ]

        for status in statuses:
            task = AnalysisTask(
                task_id=uuid4(),
                session_id="session",
                chat_ids=[1],
                status=status,
                created_at=datetime.now(UTC),
                completed_at=datetime.now(UTC),
            )
            temp_db.save_task(task)

        # Request stats
        response = client.get("/api/history/stats")
        assert response.status_code == 200

        data = response.json()
        assert data["total_tasks"] == 5
        assert data["completed_tasks"] == 2
        assert data["failed_tasks"] == 1
        assert data["cancelled_tasks"] == 1
        assert data["timeout_tasks"] == 1
