"""Tests for the analysis router."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from chatfilter.analyzer.task_queue import TaskStatus, get_task_queue, reset_task_queue
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType
from chatfilter.web.app import create_app


@pytest.fixture
def client() -> TestClient:
    """Provide a test client for the web app."""
    app = create_app()
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_queue() -> None:
    """Reset the global task queue before each test."""
    reset_task_queue()
    yield
    reset_task_queue()


class TestAnalysisStatusEndpoint:
    """Tests for GET /api/analysis/{task_id}/status endpoint."""

    def test_get_status_valid_task(self, client: TestClient) -> None:
        """Test getting status of a valid task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])

        response = client.get(f"/api/analysis/{task.task_id}/status")

        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == str(task.task_id)
        assert data["status"] == "pending"
        assert data["total"] == 3
        assert data["current"] == 0
        assert data["results_count"] == 0

    def test_get_status_invalid_uuid(self, client: TestClient) -> None:
        """Test getting status with invalid UUID format."""
        response = client.get("/api/analysis/not-a-uuid/status")

        assert response.status_code == 400
        assert "Invalid task ID format" in response.json()["detail"]

    def test_get_status_nonexistent_task(self, client: TestClient) -> None:
        """Test getting status of non-existent task."""
        response = client.get(f"/api/analysis/{uuid4()}/status")

        assert response.status_code == 404
        assert "Task not found" in response.json()["detail"]


class TestAnalysisResultsEndpoint:
    """Tests for GET /api/analysis/{task_id}/results endpoint."""

    def test_get_results_completed_task(self, client: TestClient) -> None:
        """Test getting results of a completed task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1])
        task.status = TaskStatus.COMPLETED
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="Test Chat", chat_type=ChatType.GROUP),
                metrics=ChatMetrics(
                    message_count=100,
                    unique_authors=10,
                    history_hours=24.0,
                    first_message_at=datetime.now(UTC),
                    last_message_at=datetime.now(UTC),
                ),
                analyzed_at=datetime.now(UTC),
            )
        ]

        response = client.get(f"/api/analysis/{task.task_id}/results")

        assert response.status_code == 200
        assert "Test Chat" in response.text
        assert "100" in response.text  # message count

    def test_get_results_in_progress_task(self, client: TestClient) -> None:
        """Test getting results of an in-progress task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1])
        task.status = TaskStatus.IN_PROGRESS

        response = client.get(f"/api/analysis/{task.task_id}/results")

        assert response.status_code == 200
        assert "still in progress" in response.text.lower()

    def test_get_results_failed_task(self, client: TestClient) -> None:
        """Test getting results of a failed task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1])
        task.status = TaskStatus.FAILED
        task.error = "Connection failed"

        response = client.get(f"/api/analysis/{task.task_id}/results")

        assert response.status_code == 200
        assert "Connection failed" in response.text

    def test_get_results_invalid_uuid(self, client: TestClient) -> None:
        """Test getting results with invalid UUID."""
        response = client.get("/api/analysis/invalid/results")

        assert response.status_code == 200
        assert "Invalid task ID format" in response.text


class TestProgressStreamEndpoint:
    """Tests for GET /api/analysis/{task_id}/progress SSE endpoint."""

    def test_progress_stream_invalid_uuid(self, client: TestClient) -> None:
        """Test SSE stream with invalid UUID."""
        response = client.get("/api/analysis/invalid/progress")

        assert response.status_code == 400
        assert "Invalid task ID format" in response.json()["detail"]

    def test_progress_stream_nonexistent_task(self, client: TestClient) -> None:
        """Test SSE stream for non-existent task."""
        response = client.get(f"/api/analysis/{uuid4()}/progress")

        assert response.status_code == 404
        assert "Task not found" in response.json()["detail"]

    def test_progress_stream_valid_task(self, client: TestClient) -> None:
        """Test SSE endpoint accepts valid task and returns correct response type.

        Note: Full SSE streaming tests require integration testing with a real
        async client. This unit test only verifies the endpoint accepts valid
        tasks and returns the correct content-type. The actual SSE stream would
        block in sync mode, so we skip reading the stream content.
        """
        queue = get_task_queue()
        task = queue.create_task("session1", [1])

        # Mark task as already completed to ensure stream closes quickly
        task.status = TaskStatus.COMPLETED

        # Use sync client - the endpoint should still work
        # Note: Starlette's TestClient reads the full response before returning
        # For SSE with completed tasks, this should return quickly
        response = client.get(f"/api/analysis/{task.task_id}/progress")

        # Verify the response
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]

        # Verify SSE content structure (init event should be present)
        content = response.text
        assert "event: init" in content or "event:" in content


class TestResultsPage:
    """Tests for the results page."""

    def test_results_page_no_task_id(self, client: TestClient) -> None:
        """Test results page without task ID shows empty state."""
        response = client.get("/results")

        assert response.status_code == 200
        assert "No analysis results" in response.text or "Start Analysis" in response.text

    def test_results_page_with_valid_task(self, client: TestClient) -> None:
        """Test results page with valid task ID shows results."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1])
        task.status = TaskStatus.COMPLETED
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="My Test Chat", chat_type=ChatType.SUPERGROUP),
                metrics=ChatMetrics(
                    message_count=500,
                    unique_authors=25,
                    history_hours=72.0,
                    first_message_at=datetime.now(UTC),
                    last_message_at=datetime.now(UTC),
                ),
                analyzed_at=datetime.now(UTC),
            )
        ]

        response = client.get(f"/results?task_id={task.task_id}")

        assert response.status_code == 200
        assert "My Test Chat" in response.text
        assert "500" in response.text  # message count
        assert "supergroup" in response.text.lower()

    def test_results_page_with_invalid_task(self, client: TestClient) -> None:
        """Test results page with invalid task ID shows error."""
        response = client.get(f"/results?task_id={uuid4()}")

        assert response.status_code == 200
        assert "Task not found" in response.text
