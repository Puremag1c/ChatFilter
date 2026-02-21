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
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.analyzer.progress import GroupProgressEvent
from chatfilter.models.group import GroupSettings, GroupStats, GroupStatus


class TestSSEProgressEndpoint:
    """Smoke test for SSE progress endpoint."""

    @pytest.fixture
    def mock_request(self):
        """Mock FastAPI Request object."""
        mock = AsyncMock()
        mock.is_disconnected = AsyncMock(return_value=False)
        return mock

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
    def mock_progress_tracker(self):
        """Mock ProgressTracker for isolated testing."""
        with patch("chatfilter.web.routers.groups._get_progress_tracker") as mock:
            tracker = MagicMock()

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

            tracker.subscribe = mock_subscribe
            mock.return_value = tracker
            yield tracker

    @pytest.mark.asyncio
    async def test_sse_progress_endpoint_exists(
        self, mock_request, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE progress endpoint should be defined and accessible."""
        from chatfilter.web.routers.groups import get_group_progress

        # Call handler directly (not via HTTP)
        response = await get_group_progress("test-group-123", mock_request)

        # Should return StreamingResponse
        from fastapi.responses import StreamingResponse
        assert isinstance(response, StreamingResponse)

        # Should have SSE headers
        assert response.media_type == "text/event-stream"
        assert "Cache-Control" in response.headers
        assert "no-cache" in response.headers["Cache-Control"].lower()

    @pytest.mark.asyncio
    async def test_sse_progress_stream_emits_events(
        self, mock_request, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE stream should emit events with progress data."""
        from chatfilter.web.routers.groups import get_group_progress

        # Call handler and get streaming response
        response = await get_group_progress("test-group-123", mock_request)

        # Iterate through SSE generator and collect events
        events = []
        iterator = response.body_iterator

        try:
            # Collect events (should get init + progress events + complete)
            for _ in range(10):  # Limit iterations to avoid infinite loop
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
                    # Parse SSE format: "event: type\ndata: json\n\n"
                    lines = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

                    event_type = None
                    event_data = None

                    for line in lines.split("\n"):
                        if line.startswith("event:"):
                            event_type = line[6:].strip()
                        elif line.startswith("data:"):
                            event_data = line[5:].strip()

                    if event_data:
                        events.append({
                            "type": event_type,
                            "data": json.loads(event_data),
                        })
                except (StopAsyncIteration, asyncio.TimeoutError):
                    break
        finally:
            await iterator.aclose()

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
        self, mock_request, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE events should include analyzed_count (processed field)."""
        from chatfilter.web.routers.groups import get_group_progress

        # Call handler and get streaming response
        response = await get_group_progress("test-group-123", mock_request)

        # Iterate through SSE generator and collect events
        events = []
        iterator = response.body_iterator

        try:
            for _ in range(10):
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
                    lines = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

                    for line in lines.split("\n"):
                        if line.startswith("data:"):
                            event_data = line[5:].strip()
                            if event_data:
                                events.append(json.loads(event_data))
                except (StopAsyncIteration, asyncio.TimeoutError):
                    break
        finally:
            await iterator.aclose()

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
        self, mock_request, mock_group_service
    ) -> None:
        """SSE endpoint should return 404 when group doesn't exist."""
        from chatfilter.web.routers.groups import get_group_progress
        from fastapi import HTTPException

        # Configure service to return None (group not found)
        mock_group_service.get_group.return_value = None

        # Should raise HTTPException with 404
        with pytest.raises(HTTPException) as exc_info:
            await get_group_progress("nonexistent-group", mock_request)

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_sse_progress_valid_event_stream(
        self, mock_request, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE stream should emit valid Server-Sent Events format."""
        from chatfilter.web.routers.groups import get_group_progress

        # Call handler and get streaming response
        response = await get_group_progress("test-group-123", mock_request)

        # Collect raw SSE chunks
        chunks = []
        iterator = response.body_iterator

        try:
            for _ in range(10):
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
                    text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
                    chunks.append(text)
                except (StopAsyncIteration, asyncio.TimeoutError):
                    break
        finally:
            await iterator.aclose()

        # Join all chunks
        full_text = "".join(chunks)

        # Response text should contain SSE format
        assert "event:" in full_text or "data:" in full_text

        # Should have proper SSE newline formatting (events separated by \n\n)
        assert "\n\n" in full_text or full_text.endswith("\n")

        # Parse and verify at least one valid event
        valid_events = 0
        for chunk in full_text.split("\n\n"):
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
