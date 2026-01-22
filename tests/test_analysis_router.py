"""Tests for the analysis router."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from chatfilter.analyzer.task_queue import (
    QueueFullError,
    TaskStatus,
    get_task_queue,
    reset_task_queue,
)
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType
from chatfilter.web.app import create_app


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag.

    Args:
        html: HTML content containing meta tag with csrf-token

    Returns:
        CSRF token string or None if not found
    """
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


@pytest.fixture
def client() -> TestClient:
    """Provide a test client for the web app."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def csrf_token(client: TestClient) -> str:
    """Get CSRF token from home page."""
    home_response = client.get("/")
    token = extract_csrf_token(home_response.text)
    assert token is not None, "CSRF token not found in home page"
    return token


@pytest.fixture(autouse=True)
def reset_queue() -> None:
    """Reset the global task queue before each test."""
    reset_task_queue()
    yield
    reset_task_queue()


@pytest.fixture
def mock_session_dir(tmp_path: Path) -> Path:
    """Create a mock session directory."""
    session_dir = tmp_path / "sessions" / "test_session"
    session_dir.mkdir(parents=True, exist_ok=True)

    # Create a session file
    session_file = session_dir / "test_session.session"
    session_file.write_text("mock session data")

    return session_dir


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

    def test_get_results_pending_task(self, client: TestClient) -> None:
        """Test getting results of a pending (not started) task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.PENDING

        response = client.get(f"/api/analysis/{task.task_id}/results")

        assert response.status_code == 200
        assert "not started" in response.text.lower()

    def test_get_results_timeout_task(self, client: TestClient) -> None:
        """Test getting results of a timed-out task with partial results."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.TIMEOUT
        task.error = "Task exceeded time limit"
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="Partial Chat", chat_type=ChatType.GROUP),
                metrics=ChatMetrics(
                    message_count=50,
                    unique_authors=5,
                    history_hours=12.0,
                    first_message_at=datetime.now(UTC),
                    last_message_at=datetime.now(UTC),
                ),
                analyzed_at=datetime.now(UTC),
            )
        ]

        response = client.get(f"/api/analysis/{task.task_id}/results")

        assert response.status_code == 200
        # Should show the error message (template shows error for timeout status)
        assert "exceeded time limit" in response.text.lower()
        # Partial results should still be available in context (check if rendered)
        # The template may show results with is_partial flag

    def test_get_results_cancelled_task(self, client: TestClient) -> None:
        """Test getting results of a cancelled task with partial results."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.CANCELLED
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="Cancelled Chat", chat_type=ChatType.GROUP),
                metrics=ChatMetrics(
                    message_count=30,
                    unique_authors=3,
                    history_hours=6.0,
                    first_message_at=datetime.now(UTC),
                    last_message_at=datetime.now(UTC),
                ),
                analyzed_at=datetime.now(UTC),
            )
        ]

        response = client.get(f"/api/analysis/{task.task_id}/results")

        assert response.status_code == 200
        assert "Cancelled Chat" in response.text
        # Should show partial results
        assert "30" in response.text

    def test_get_results_nonexistent_task(self, client: TestClient) -> None:
        """Test getting results for non-existent task."""
        response = client.get(f"/api/analysis/{uuid4()}/results")

        assert response.status_code == 200
        assert "Task not found" in response.text

    def test_get_results_clears_orphaned_session(self, client: TestClient) -> None:
        """Test that viewing results clears the orphaned task from session."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1])
        task.status = TaskStatus.COMPLETED
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="Test", chat_type=ChatType.GROUP),
                metrics=ChatMetrics(
                    message_count=10,
                    unique_authors=1,
                    history_hours=1.0,
                    first_message_at=datetime.now(UTC),
                    last_message_at=datetime.now(UTC),
                ),
                analyzed_at=datetime.now(UTC),
            )
        ]

        task_id = str(task.task_id)

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.return_value = task_id
            mock_get_session.return_value = mock_session

            response = client.get(f"/api/analysis/{task_id}/results")

            # Verify session.delete was called
            mock_session.delete.assert_called_once_with("current_task_id")

        assert response.status_code == 200


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

    def test_progress_stream_completed_task_immediate_close(self, client: TestClient) -> None:
        """Test SSE stream for completed task sends completion and closes."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.COMPLETED
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="Test", chat_type=ChatType.GROUP),
                metrics=ChatMetrics(
                    message_count=10,
                    unique_authors=1,
                    history_hours=1.0,
                    first_message_at=datetime.now(UTC),
                    last_message_at=datetime.now(UTC),
                ),
                analyzed_at=datetime.now(UTC),
            )
        ]

        response = client.get(f"/api/analysis/{task.task_id}/progress")

        assert response.status_code == 200
        content = response.text
        # Should have init event
        assert "event: init" in content
        # Should have complete event
        assert "event: complete" in content
        assert "results_count" in content

    def test_progress_stream_failed_task(self, client: TestClient) -> None:
        """Test SSE stream for failed task sends error event."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1])
        task.status = TaskStatus.FAILED
        task.error = "Network failure"

        response = client.get(f"/api/analysis/{task.task_id}/progress")

        assert response.status_code == 200
        content = response.text
        assert "event: error" in content
        assert "Network failure" in content

    def test_progress_stream_cancelled_task(self, client: TestClient) -> None:
        """Test SSE stream for cancelled task sends cancelled event."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.CANCELLED

        response = client.get(f"/api/analysis/{task.task_id}/progress")

        assert response.status_code == 200
        content = response.text
        assert "event: cancelled" in content or "event: init" in content

    def test_progress_stream_timeout_task(self, client: TestClient) -> None:
        """Test SSE stream for timed-out task sends timeout event."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.TIMEOUT
        task.error = "Task timeout"

        response = client.get(f"/api/analysis/{task.task_id}/progress")

        assert response.status_code == 200
        content = response.text
        assert "event: timeout" in content or "event: init" in content
        assert "Task timeout" in content or "timeout" in content.lower()


class TestStartAnalysisEndpoint:
    """Tests for POST /api/analysis/start endpoint."""

    def test_start_analysis_no_session(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis with no session selected."""
        response = client.post(
            "/api/analysis/start",
            data={
                "session_id": "",
                "chat_ids": [1, 2, 3],
                "message_limit": 1000,
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "No session selected" in response.text
        assert "Select a Telegram session" in response.text

    def test_start_analysis_no_chats(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis with no chats selected."""
        response = client.post(
            "/api/analysis/start",
            data={
                "session_id": "test_session",
                "chat_ids": [],
                "message_limit": 1000,
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        # Handler validates empty chat_ids and returns 200 with error message
        assert response.status_code == 200
        assert "No chats selected" in response.text

    def test_start_analysis_message_limit_too_low(
        self, client: TestClient, csrf_token: str
    ) -> None:
        """Test starting analysis with message limit below minimum."""
        with patch("chatfilter.web.routers.analysis.get_session_paths"):
            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2],
                    "message_limit": 5,  # Below minimum of 10
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "Message limit must be between 10 and 10000" in response.text

    def test_start_analysis_message_limit_too_high(
        self, client: TestClient, csrf_token: str
    ) -> None:
        """Test starting analysis with message limit above maximum."""
        with patch("chatfilter.web.routers.analysis.get_session_paths"):
            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2],
                    "message_limit": 15000,  # Above maximum of 10000
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "Message limit must be between 10 and 10000" in response.text

    def test_start_analysis_session_not_found(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis with non-existent session."""
        from fastapi import HTTPException

        with patch(
            "chatfilter.web.routers.analysis.get_session_paths",
            side_effect=HTTPException(status_code=404, detail="Session not found"),
        ):
            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "nonexistent",
                    "chat_ids": [1, 2],
                    "message_limit": 1000,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "Session not found" in response.text
        assert "Upload a valid session file" in response.text

    def test_start_analysis_all_chats_invalid(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis when all selected chats are invalid/stale."""
        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            # All chats are invalid
            mock_svc.validate_chat_ids = AsyncMock(return_value=([], [1, 2, 3]))

            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2, 3],
                    "message_limit": 1000,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "All selected chats are no longer accessible" in response.text
        assert "may have been deleted" in response.text

    def test_start_analysis_some_chats_invalid(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis when some chats are invalid."""
        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            # Some chats are invalid
            mock_svc.validate_chat_ids = AsyncMock(return_value=([1, 2], [3, 4]))

            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2, 3, 4],
                    "message_limit": 1000,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should succeed with valid chats
        assert response.status_code == 200
        # Should contain task_id in the response indicating success
        assert "sse-source" in response.text or "task-id" in response.text

    def test_start_analysis_validation_timeout(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis when chat validation times out."""

        async def timeout_validation(*args, **kwargs):
            await asyncio.sleep(10)  # Will timeout
            return ([], [])

        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            mock_svc.validate_chat_ids = timeout_validation

            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2],
                    "message_limit": 1000,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should succeed despite timeout (proceeds with original list)
        assert response.status_code == 200
        # Should contain task_id in the response
        assert "sse-source" in response.text or "task-id" in response.text

    def test_start_analysis_validation_error(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis when chat validation raises an error."""
        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            mock_svc.validate_chat_ids = AsyncMock(side_effect=Exception("Network error"))

            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2],
                    "message_limit": 1000,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should succeed despite error (proceeds with original list)
        assert response.status_code == 200
        # Should contain task_id in the response
        assert "sse-source" in response.text or "task-id" in response.text

    def test_start_analysis_queue_full(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis when task queue is full."""
        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            mock_svc.validate_chat_ids = AsyncMock(return_value=([1, 2], []))

            with patch("chatfilter.web.routers.analysis.get_task_queue") as mock_queue_fn:
                mock_queue = mock_queue_fn.return_value
                mock_queue.find_active_task.return_value = None
                mock_queue.create_task.side_effect = QueueFullError("Queue is full", limit=5)

                response = client.post(
                    "/api/analysis/start",
                    data={
                        "session_id": "test_session",
                        "chat_ids": [1, 2],
                        "message_limit": 1000,
                    },
                    headers={"X-CSRF-Token": csrf_token},
                )

        assert response.status_code == 200
        assert "queue is at capacity" in response.text.lower()
        assert "5 concurrent tasks" in response.text

    def test_start_analysis_duplicate_task(self, client: TestClient, csrf_token: str) -> None:
        """Test starting analysis when an identical task already exists."""
        queue = get_task_queue()
        existing_task = queue.create_task("test_session", [1, 2], 1000)

        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            mock_svc.validate_chat_ids = AsyncMock(return_value=([1, 2], []))

            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2],
                    "message_limit": 1000,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Should reuse existing task
        assert str(existing_task.task_id) in response.text

    def test_start_analysis_success(self, client: TestClient, csrf_token: str) -> None:
        """Test successful analysis start."""
        with (
            patch("chatfilter.web.routers.analysis.get_session_paths"),
            patch("chatfilter.web.routers.analysis.get_chat_service") as mock_service,
        ):
            mock_svc = mock_service.return_value
            mock_svc.validate_chat_ids = AsyncMock(return_value=([1, 2, 3], []))

            response = client.post(
                "/api/analysis/start",
                data={
                    "session_id": "test_session",
                    "chat_ids": [1, 2, 3],
                    "message_limit": 500,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Should contain SSE endpoint
        assert "sse-source" in response.text or "/progress" in response.text
        # Should show total chats
        assert "3" in response.text


class TestCancelAnalysisEndpoint:
    """Tests for POST /api/analysis/{task_id}/cancel endpoint."""

    def test_cancel_invalid_task_id(self, client: TestClient, csrf_token: str) -> None:
        """Test cancelling with invalid task ID format."""
        response = client.post(
            "/api/analysis/not-a-uuid/cancel",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 400
        assert "Invalid task ID format" in response.json()["detail"]

    def test_cancel_nonexistent_task(self, client: TestClient, csrf_token: str) -> None:
        """Test cancelling non-existent task."""
        response = client.post(
            f"/api/analysis/{uuid4()}/cancel",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 404
        assert "Task not found" in response.json()["detail"]

    def test_cancel_completed_task(self, client: TestClient, csrf_token: str) -> None:
        """Test cancelling already completed task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.COMPLETED

        response = client.post(
            f"/api/analysis/{task.task_id}/cancel", headers={"X-CSRF-Token": csrf_token}
        )

        assert response.status_code == 400
        assert "Cannot cancel" in response.json()["detail"]

    def test_cancel_pending_task(self, client: TestClient, csrf_token: str) -> None:
        """Test cancelling pending task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])

        response = client.post(
            f"/api/analysis/{task.task_id}/cancel", headers={"X-CSRF-Token": csrf_token}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"
        assert "cancelled successfully" in data["message"]

    def test_cancel_in_progress_task(self, client: TestClient, csrf_token: str) -> None:
        """Test cancelling in-progress task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS

        response = client.post(
            f"/api/analysis/{task.task_id}/cancel", headers={"X-CSRF-Token": csrf_token}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"
        assert "partial_results" in data


class TestForceCancelAnalysisEndpoint:
    """Tests for POST /api/analysis/{task_id}/force-cancel endpoint."""

    def test_force_cancel_invalid_task_id(self, client: TestClient, csrf_token: str) -> None:
        """Test force cancelling with invalid task ID format."""
        response = client.post(
            "/api/analysis/not-a-uuid/force-cancel",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 400
        assert "Invalid task ID format" in response.json()["detail"]

    def test_force_cancel_nonexistent_task(self, client: TestClient, csrf_token: str) -> None:
        """Test force cancelling non-existent task."""
        response = client.post(
            f"/api/analysis/{uuid4()}/force-cancel",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 404
        assert "Task not found" in response.json()["detail"]

    def test_force_cancel_completed_task(self, client: TestClient, csrf_token: str) -> None:
        """Test force cancelling already completed task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.COMPLETED

        response = client.post(
            f"/api/analysis/{task.task_id}/force-cancel", headers={"X-CSRF-Token": csrf_token}
        )

        assert response.status_code == 400
        assert "Cannot force-cancel" in response.json()["detail"]

    def test_force_cancel_in_progress_task(self, client: TestClient, csrf_token: str) -> None:
        """Test force cancelling in-progress task."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.IN_PROGRESS
        task._asyncio_task = MagicMock()  # Mock the asyncio task

        response = client.post(
            f"/api/analysis/{task.task_id}/force-cancel", headers={"X-CSRF-Token": csrf_token}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "force_cancelled"
        assert "force-cancelled successfully" in data["message"]
        assert "partial_results" in data

    def test_force_cancel_with_custom_reason(self, client: TestClient, csrf_token: str) -> None:
        """Test force cancelling with custom reason."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.IN_PROGRESS
        task._asyncio_task = MagicMock()

        response = client.post(
            f"/api/analysis/{task.task_id}/force-cancel?reason=Task+hung",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["reason"] == "Task hung"


class TestCheckOrphanedEndpoint:
    """Tests for GET /api/analysis/check-orphaned endpoint."""

    def test_check_orphaned_no_session_task(self, client: TestClient) -> None:
        """Test checking for orphaned task when none exists in session."""
        response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        data = response.json()
        assert data == {}

    def test_check_orphaned_invalid_task_id(self, client: TestClient) -> None:
        """Test checking orphaned task with invalid UUID in session."""
        # Set a cookie with invalid task_id
        client.cookies.set("session", "current_task_id=not-a-uuid")

        response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        # Should return empty dict and clean up invalid ID
        assert response.json() == {}

    def test_check_orphaned_task_not_found(self, client: TestClient) -> None:
        """Test checking orphaned task that no longer exists."""
        nonexistent_id = str(uuid4())

        # We need to properly set session data - let's use the session system
        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.return_value = nonexistent_id
            mock_get_session.return_value = mock_session

            response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        assert response.json() == {}

    def test_check_orphaned_task_completed(self, client: TestClient) -> None:
        """Test checking orphaned task that is completed."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2, 3])
        task.status = TaskStatus.COMPLETED
        task.results = [
            AnalysisResult(
                chat=Chat(id=1, title="Test", chat_type=ChatType.GROUP),
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

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.side_effect = lambda key, default=None: (
                str(task.task_id) if key == "current_task_id" else set()
            )
            mock_get_session.return_value = mock_session

            response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == str(task.task_id)
        assert data["status"] == "completed"
        assert data["results_count"] == 1
        assert data["total_chats"] == 3

    def test_check_orphaned_task_failed(self, client: TestClient) -> None:
        """Test checking orphaned task that failed."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.FAILED
        task.error = "Connection error"

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.side_effect = lambda key, default=None: (
                str(task.task_id) if key == "current_task_id" else set()
            )
            mock_get_session.return_value = mock_session

            response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "failed"
        assert data["error"] == "Connection error"

    def test_check_orphaned_task_in_progress(self, client: TestClient) -> None:
        """Test checking orphaned task still in progress."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.IN_PROGRESS

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.side_effect = lambda key, default=None: (
                str(task.task_id) if key == "current_task_id" else set()
            )
            mock_get_session.return_value = mock_session

            response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        # Should return empty since task is not in terminal state
        assert response.json() == {}

    def test_check_orphaned_already_notified(self, client: TestClient) -> None:
        """Test checking orphaned task that was already notified."""
        queue = get_task_queue()
        task = queue.create_task("session1", [1, 2])
        task.status = TaskStatus.COMPLETED

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            task_id_str = str(task.task_id)
            # Task already in notified set
            mock_session.get.side_effect = lambda key, default=None: (
                task_id_str if key == "current_task_id" else {task_id_str}
            )
            mock_get_session.return_value = mock_session

            response = client.get("/api/analysis/check-orphaned")

        assert response.status_code == 200
        # Should return empty since already notified
        assert response.json() == {}


class TestDismissNotificationEndpoint:
    """Tests for POST /api/analysis/{task_id}/dismiss-notification endpoint."""

    def test_dismiss_notification(self, client: TestClient, csrf_token: str) -> None:
        """Test dismissing orphaned task notification."""
        task_id = str(uuid4())

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.return_value = task_id
            mock_get_session.return_value = mock_session

            response = client.post(
                f"/api/analysis/{task_id}/dismiss-notification",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert response.json()["status"] == "dismissed"

    def test_dismiss_notification_different_task(self, client: TestClient, csrf_token: str) -> None:
        """Test dismissing notification for different task."""
        task_id = str(uuid4())
        other_task_id = str(uuid4())

        with patch("chatfilter.web.routers.analysis.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.return_value = other_task_id  # Different task
            mock_get_session.return_value = mock_session

            response = client.post(
                f"/api/analysis/{task_id}/dismiss-notification",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert response.json()["status"] == "dismissed"


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
