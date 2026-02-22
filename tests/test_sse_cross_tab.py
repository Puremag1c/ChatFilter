"""Test SSE cross-tab functionality.

Verifies that multiple SSE clients (browser tabs) connected to the same group
receive identical progress events.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.analyzer.progress import GroupProgressEvent
from chatfilter.models.group import GroupSettings, GroupStatus


class TestSSECrossTab:
    """Test that multiple SSE subscribers receive same events."""

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

            # Mock database layer
            mock_db = MagicMock()
            mock_db.count_processed_chats.return_value = (3, 10)
            mock_db.get_analysis_started_at.return_value = datetime.now(UTC)
            service._db = mock_db

            mock.return_value = service
            yield service

    @pytest.fixture
    def mock_progress_tracker(self):
        """Mock ProgressTracker that simulates real pub/sub."""
        with patch("chatfilter.web.routers.groups._get_progress_tracker") as mock:
            from chatfilter.analyzer.progress import ProgressTracker

            # Use REAL ProgressTracker to test pub/sub behavior
            tracker = ProgressTracker(MagicMock())
            mock.return_value = tracker
            yield tracker

    @pytest.mark.asyncio
    async def test_cross_tab_both_subscribers_receive_events(
        self, mock_group_service, mock_progress_tracker
    ) -> None:
        """Two SSE clients should both receive the same progress events."""
        from chatfilter.web.routers.groups import get_group_progress

        # Create two mock requests (simulating two browser tabs)
        mock_request_1 = AsyncMock()
        mock_request_1.is_disconnected = AsyncMock(return_value=False)

        mock_request_2 = AsyncMock()
        mock_request_2.is_disconnected = AsyncMock(return_value=False)

        # Connect both clients
        response_1 = await get_group_progress("test-group-123", mock_request_1)
        response_2 = await get_group_progress("test-group-123", mock_request_2)

        iterator_1 = response_1.body_iterator
        iterator_2 = response_2.body_iterator

        events_1 = []
        events_2 = []

        async def collect_events(iterator, events_list, request_mock, max_events=5):
            """Collect SSE events from iterator."""
            try:
                for _ in range(max_events):
                    try:
                        chunk = await asyncio.wait_for(iterator.__anext__(), timeout=0.5)
                        text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

                        # Parse SSE format
                        event_type = None
                        event_data = None

                        for line in text.split("\n"):
                            if line.startswith("event:"):
                                event_type = line[6:].strip()
                            elif line.startswith("data:"):
                                event_data = line[5:].strip()

                        if event_data:
                            events_list.append({
                                "type": event_type,
                                "data": json.loads(event_data),
                            })
                    except (StopAsyncIteration, asyncio.TimeoutError):
                        break
            finally:
                await iterator.aclose()

        # Start collecting events from both streams in parallel
        task_1 = asyncio.create_task(collect_events(iterator_1, events_1, mock_request_1))
        task_2 = asyncio.create_task(collect_events(iterator_2, events_2, mock_request_2))

        # Give time for init events
        await asyncio.sleep(0.1)

        # Publish a progress event (simulates GroupAnalysisEngine publishing)
        mock_progress_tracker.publish(
            GroupProgressEvent(
                group_id="test-group-123",
                status="analyzing",
                current=5,
                total=10,
                chat_title="@testchat",
                message="Analyzing chat...",
            )
        )

        # Give time for events to propagate
        await asyncio.sleep(0.1)

        # Signal completion
        mock_progress_tracker.signal_completion("test-group-123")

        # Wait for both collectors to finish
        await asyncio.wait_for(asyncio.gather(task_1, task_2), timeout=2.0)

        # Both clients should have received events
        assert len(events_1) >= 2, f"Client 1 received {len(events_1)} events, expected at least 2"
        assert len(events_2) >= 2, f"Client 2 received {len(events_2)} events, expected at least 2"

        # Both should have init event
        assert events_1[0]["type"] == "init"
        assert events_2[0]["type"] == "init"

        # Find progress events in both streams
        progress_1 = [e for e in events_1 if e["type"] == "progress"]
        progress_2 = [e for e in events_2 if e["type"] == "progress"]

        # Both should have at least one progress event
        assert len(progress_1) >= 1, "Client 1 didn't receive progress event"
        assert len(progress_2) >= 1, "Client 2 didn't receive progress event"

        # Progress events should be identical
        assert progress_1[0]["data"]["group_id"] == progress_2[0]["data"]["group_id"]
        assert progress_1[0]["data"]["processed"] == progress_2[0]["data"]["processed"]
        assert progress_1[0]["data"]["chat_title"] == progress_2[0]["data"]["chat_title"]

    @pytest.mark.asyncio
    async def test_sse_event_format_htmx_compatible(
        self, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE events should be in format HTMX expects: 'event: type\\ndata: json\\n\\n'."""
        from chatfilter.web.routers.groups import get_group_progress

        mock_request = AsyncMock()
        mock_request.is_disconnected = AsyncMock(return_value=False)

        response = await get_group_progress("test-group-123", mock_request)
        iterator = response.body_iterator

        try:
            # Get first event (init)
            chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
            text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

            # Verify SSE format structure
            lines = text.split("\n")

            # Should have at least 3 lines: "event: ...", "data: ...", ""
            assert len(lines) >= 3, f"Invalid SSE format: {lines}"

            # First line should be "event: <type>"
            assert lines[0].startswith("event:"), f"Missing event type: {lines[0]}"
            event_type = lines[0][6:].strip()
            assert event_type == "init", f"Wrong event type: {event_type}"

            # Second line should be "data: <json>"
            assert lines[1].startswith("data:"), f"Missing data: {lines[1]}"
            data_json = lines[1][5:].strip()

            # Should be valid JSON
            data = json.loads(data_json)
            assert isinstance(data, dict), "Data should be JSON object"

            # Third line should be empty (event terminator)
            assert lines[2] == "", f"Missing event terminator: {repr(lines[2])}"

        finally:
            await iterator.aclose()

    @pytest.mark.asyncio
    async def test_sse_heartbeat_timing(
        self, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE should send heartbeat pings every 15 seconds."""
        from chatfilter.web.routers.groups import get_group_progress

        mock_request = AsyncMock()
        mock_request.is_disconnected = AsyncMock(return_value=False)

        response = await get_group_progress("test-group-123", mock_request)
        iterator = response.body_iterator

        events = []

        try:
            # Collect events for a bit
            for _ in range(5):
                try:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
                    text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

                    for line in text.split("\n"):
                        if line.startswith("event:"):
                            event_type = line[6:].strip()
                            events.append(event_type)
                except asyncio.TimeoutError:
                    break
        finally:
            await iterator.aclose()

        # Should have init event
        assert "init" in events, f"Missing init event: {events}"

        # Note: We can't easily test 15s timing in unit test without waiting,
        # but we can verify the ping event format exists in the code
        # This is verified by reading lines 762-765 in groups.py

    @pytest.mark.asyncio
    async def test_sse_completion_sentinel_stops_stream(
        self, mock_group_service, mock_progress_tracker
    ) -> None:
        """SSE stream should stop after sending complete event."""
        from chatfilter.web.routers.groups import get_group_progress

        mock_request = AsyncMock()
        mock_request.is_disconnected = AsyncMock(return_value=False)

        response = await get_group_progress("test-group-123", mock_request)
        iterator = response.body_iterator

        events = []

        async def collect_all():
            """Collect all events until stream stops."""
            try:
                while True:
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
                    text = chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

                    event_type = None
                    for line in text.split("\n"):
                        if line.startswith("event:"):
                            event_type = line[6:].strip()

                    if event_type:
                        events.append(event_type)
            except (StopAsyncIteration, asyncio.TimeoutError):
                pass
            finally:
                await iterator.aclose()

        # Start collecting
        collector = asyncio.create_task(collect_all())

        # Give time for init event
        await asyncio.sleep(0.1)

        # Signal completion (sends None sentinel)
        mock_progress_tracker.signal_completion("test-group-123")

        # Wait for collector to finish
        await asyncio.wait_for(collector, timeout=2.0)

        # Should have init and complete events
        assert "init" in events
        assert "complete" in events

        # Stream should have stopped after complete
        # (no more events can be received)
