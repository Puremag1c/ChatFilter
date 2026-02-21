"""Smoke test for SSE progress endpoint.

Tests that the SSE endpoint for group analysis progress:
- Returns a valid SSE stream
- Emits events with progress data
- Includes current_chat and analyzed_count fields
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.analyzer.progress import GroupProgressEvent
from chatfilter.models.group import GroupSettings, GroupStats, GroupStatus
from chatfilter.web.app import create_app


class TestSSEProgressEndpoint:
    """Smoke test for SSE progress endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create FastAPI test client."""
        app = create_app()
        return TestClient(app)

    @pytest.fixture
    def mock_group_service(self):
        """Mock GroupService for isolated testing."""
        with patch("chatfilter.web.routers.groups._get_group_service") as mock:
            service = MagicMock()

            # Create a mock group with IN_PROGRESS status
            mock_group = MagicMock()
            mock_group.id = "test-group-123"
            mock_group.name = "Test Group"
            mock_group.status = GroupStatus.IN_PROGRESS
            mock_group.settings = GroupSettings(
                detect_chat_type=True,
                detect_subscribers=True,
                detect_activity=True,
                time_window=24,
            )

            service.get_group.return_value = mock_group
            service.get_group_stats.return_value = GroupStats(
                total=10,
                analyzed=3,
                failed=1,
                pending=6,
                dead=0,
                groups=0,
                forums=0,
                channels_with_comments=0,
                channels_no_comments=0,
                skipped_moderation=0,
            )

            # Mock database layer (_db)
            mock_db = MagicMock()
            mock_db.count_processed_chats.return_value = (3, 10)
            mock_db.get_analysis_started_at.return_value = datetime.now(UTC)
            service._db = mock_db

            mock.return_value = service
            yield service

    @pytest.fixture
    def mock_group_engine(self):
        """Mock GroupAnalysisEngine for isolated testing."""
        with patch("chatfilter.web.routers.groups._get_group_engine") as mock:
            engine = MagicMock()

            def mock_subscribe(group_id: str):
                """Mock subscribe that returns a queue with test events."""
                queue = asyncio.Queue()

                # Pre-populate the queue with test events (synchronously)
                # The actual code will await queue.get() to retrieve them
                queue.put_nowait(
                    GroupProgressEvent(
                        group_id=group_id,
                        status="analyzing",
                        current=4,
                        total=10,
                        chat_title="@testchat",
                        message="Analyzing chat...",
                    )
                )

                queue.put_nowait(
                    GroupProgressEvent(
                        group_id=group_id,
                        status="analyzing",
                        current=5,
                        total=10,
                        chat_title="@anotherchat",
                        message="Analyzing chat...",
                    )
                )

                # Signal completion
                queue.put_nowait(None)

                return queue

            engine.subscribe = mock_subscribe
            mock.return_value = engine
            yield engine

    @pytest.mark.asyncio
    async def test_sse_progress_endpoint_exists(
        self, client: TestClient, mock_group_service, mock_group_engine
    ) -> None:
        """SSE progress endpoint should be defined and accessible."""
        # Make request to endpoint
        response = client.get(
            "/api/groups/test-group-123/progress",
            headers={"Accept": "text/event-stream"},
        )

        # Should return 200 (streaming starts)
        assert response.status_code == 200

        # Should have SSE headers
        assert response.headers["content-type"] == "text/event-stream; charset=utf-8"
        assert "no-cache" in response.headers.get("cache-control", "").lower()

    @pytest.mark.asyncio
    async def test_sse_progress_stream_emits_events(
        self, client: TestClient, mock_group_service, mock_group_engine
    ) -> None:
        """SSE stream should emit events with progress data."""
        # Make request to endpoint
        response = client.get(
            "/api/groups/test-group-123/progress",
            headers={"Accept": "text/event-stream"},
        )

        # Parse SSE events from response
        events = []
        for line in response.text.split("\n\n"):
            if line.strip():
                # Parse SSE event
                event_type = None
                event_data = None

                for part in line.split("\n"):
                    if part.startswith("event:"):
                        event_type = part[6:].strip()
                    elif part.startswith("data:"):
                        event_data = part[5:].strip()

                if event_data:
                    events.append({
                        "type": event_type,
                        "data": json.loads(event_data),
                    })

        # Should have at least init and progress events
        assert len(events) >= 2, f"Expected at least 2 events, got {len(events)}"

        # First event should be 'init' with current stats
        init_event = events[0]
        assert init_event["type"] == "init"
        assert "group_id" in init_event["data"]
        assert "total" in init_event["data"]
        assert "processed" in init_event["data"]

        # Should have progress events with current_chat
        progress_events = [e for e in events if e["type"] == "progress"]
        assert len(progress_events) >= 1, "Should have at least one progress event"

        # Verify progress event structure
        progress = progress_events[0]["data"]
        assert "group_id" in progress
        assert "processed" in progress
        assert "total" in progress
        assert "chat_title" in progress  # current_chat equivalent
        assert progress["chat_title"] is not None

    @pytest.mark.asyncio
    async def test_sse_progress_includes_analyzed_count(
        self, client: TestClient, mock_group_service, mock_group_engine
    ) -> None:
        """SSE events should include analyzed_count (processed field)."""
        # Make request to endpoint
        response = client.get(
            "/api/groups/test-group-123/progress",
            headers={"Accept": "text/event-stream"},
        )

        # Parse events
        events = []
        for line in response.text.split("\n\n"):
            if line.strip():
                event_data = None
                for part in line.split("\n"):
                    if part.startswith("data:"):
                        event_data = part[5:].strip()

                if event_data:
                    events.append(json.loads(event_data))

        # Find progress events and verify they have 'processed' (analyzed_count)
        has_processed_field = False
        for event in events:
            if "processed" in event:
                has_processed_field = True
                # Verify it's a valid number
                assert isinstance(event["processed"], int)
                assert event["processed"] >= 0

        assert has_processed_field, "No events with 'processed' field (analyzed_count) found"

    @pytest.mark.asyncio
    async def test_sse_progress_group_not_found(
        self, client: TestClient, mock_group_service
    ) -> None:
        """SSE endpoint should return 404 when group doesn't exist."""
        # Configure service to return None (group not found)
        mock_group_service.get_group.return_value = None

        # Make request to non-existent group
        response = client.get(
            "/api/groups/nonexistent-group/progress",
            headers={"Accept": "text/event-stream"},
        )

        # Should return 404
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_sse_progress_valid_event_stream(
        self, client: TestClient, mock_group_service, mock_group_engine
    ) -> None:
        """SSE stream should emit valid Server-Sent Events format."""
        # Make request to endpoint
        response = client.get(
            "/api/groups/test-group-123/progress",
            headers={"Accept": "text/event-stream"},
        )

        # Response text should contain SSE format
        assert "event:" in response.text or "data:" in response.text

        # Should have proper SSE newline formatting (events separated by \n\n)
        assert "\n\n" in response.text or response.text.endswith("\n")

        # Parse and verify at least one valid event
        valid_events = 0
        for chunk in response.text.split("\n\n"):
            if "data:" in chunk:
                # Extract data line
                for line in chunk.split("\n"):
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        try:
                            # Should be valid JSON
                            json.loads(data)
                            valid_events += 1
                        except json.JSONDecodeError:
                            pass

        assert valid_events > 0, "No valid SSE events found in stream"
