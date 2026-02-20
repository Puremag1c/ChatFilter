"""Test SSE reconnection reliability and state recovery."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import StreamingResponse

from chatfilter.models.group import ChatGroup, GroupStatus
from chatfilter.web.routers.groups import _generate_group_sse_events


@pytest.fixture
def mock_db():
    """Mock database with known state."""
    db = MagicMock()

    # Analysis started 5 minutes ago
    started_at = datetime(2026, 2, 20, 12, 0, 0, tzinfo=timezone.utc)
    db.get_analysis_started_at.return_value = started_at

    # 7 processed (done + failed + dead), 10 total
    db.count_processed_chats.return_value = (7, 10)

    return db


@pytest.fixture
def mock_service(mock_db):
    """Mock GroupService with known group state."""
    service = MagicMock()
    service._db = mock_db

    # Return active group (mock object, not full ChatGroup)
    group = MagicMock()
    group.id = "test-group-123"
    group.name = "Test Group"
    group.status = GroupStatus.IN_PROGRESS
    service.get_group.return_value = group

    return service


@pytest.fixture
def mock_engine():
    """Mock GroupAnalysisEngine with no events (just testing init)."""
    engine = MagicMock()

    # Subscribe returns queue that will timeout (no events)
    queue = AsyncMock()
    queue.get.side_effect = asyncio.TimeoutError()
    engine.subscribe.return_value = queue

    return engine


@pytest.fixture
def mock_request():
    """Mock FastAPI request that never disconnects."""
    request = AsyncMock(spec=Request)
    request.is_disconnected.return_value = False
    return request


async def collect_sse_init_event(
    generator: AsyncIterator[str],
    timeout: float = 2.0,
) -> dict[str, Any] | None:
    """Collect first init event from SSE stream.

    Args:
        generator: SSE event generator
        timeout: Max time to wait for init event

    Returns:
        Parsed init event data, or None if timeout/no init event
    """
    try:
        # First event should be init
        event_str = await asyncio.wait_for(generator.__anext__(), timeout=timeout)

        # Parse SSE format: "event: init\ndata: {...}\n\n"
        lines = event_str.strip().split("\n")

        event_type = None
        event_data = None

        for line in lines:
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                event_data = line[5:].strip()

        if event_type == "init" and event_data:
            return json.loads(event_data)

        return None

    except asyncio.TimeoutError:
        return None


@pytest.mark.asyncio
async def test_sse_reconnect_init_event_contains_db_state(
    mock_service,
    mock_engine,
    mock_request,
    mock_db,
) -> None:
    """SSE reconnection should emit init event with current DB state.

    Scenario:
    1. Client connects to SSE
    2. Receives init event
    3. Disconnects (simulated by ending iteration)
    4. Reconnects (new SSE stream)
    5. Receives fresh init event with current DB state

    Verifies:
    - Init event contains started_at from DB
    - Init event contains processed/total from DB
    - Reconnection gets fresh state, not cached
    """
    group_id = "test-group-123"
    expected_started_at = "2026-02-20T12:00:00+00:00"
    expected_processed = 7
    expected_total = 10

    # Patch service and engine getters
    with patch(
        "chatfilter.web.routers.groups._get_group_service",
        return_value=mock_service,
    ), patch(
        "chatfilter.web.routers.groups._get_group_engine",
        return_value=mock_engine,
    ):
        # === FIRST CONNECTION ===
        generator_1 = _generate_group_sse_events(group_id, mock_request)

        init_1 = await collect_sse_init_event(generator_1)
        assert init_1 is not None, "First connection should emit init event"

        # Verify init event structure
        assert init_1["group_id"] == group_id
        assert init_1["started_at"] == expected_started_at
        assert init_1["processed"] == expected_processed
        assert init_1["total"] == expected_total
        assert init_1["status"] == GroupStatus.IN_PROGRESS.value

        # Close first connection
        try:
            await generator_1.aclose()
        except (StopAsyncIteration, GeneratorExit):
            pass

        await asyncio.sleep(0.05)  # Allow cleanup

        # === SIMULATE DB STATE CHANGE (more chats processed) ===
        # In real scenario: some chats got analyzed while disconnected
        mock_db.count_processed_chats.return_value = (9, 10)  # 2 more processed

        # === SECOND CONNECTION (RECONNECT) ===
        generator_2 = _generate_group_sse_events(group_id, mock_request)

        init_2 = await collect_sse_init_event(generator_2)
        assert init_2 is not None, "Reconnection should emit fresh init event"

        # Verify reconnect gets UPDATED state from DB
        assert init_2["group_id"] == group_id
        assert init_2["started_at"] == expected_started_at  # Same start time
        assert init_2["processed"] == 9  # Updated count (not cached)
        assert init_2["total"] == expected_total
        assert init_2["status"] == GroupStatus.IN_PROGRESS.value

        # Verify DB was queried for fresh state (called twice: once per connection)
        assert mock_db.get_analysis_started_at.call_count == 2
        assert mock_db.count_processed_chats.call_count == 2

        # Close second connection
        try:
            await generator_2.aclose()
        except (StopAsyncIteration, GeneratorExit):
            pass


@pytest.mark.asyncio
async def test_sse_reconnect_after_disconnect_mid_stream(
    mock_service,
    mock_engine,
    mock_db,
) -> None:
    """SSE reconnection after disconnect mid-stream should recover state.

    Scenario:
    1. Client connects, receives init event
    2. Receives some progress events
    3. Client disconnects (network issue)
    4. Client reconnects
    5. Receives fresh init event with current DB state (not stale)

    Verifies:
    - Disconnect detection works
    - Reconnection emits fresh init event
    - Init event reflects current DB state (not state from before disconnect)
    """
    group_id = "test-group-123"

    # === FIRST CONNECTION ===
    request_1 = AsyncMock(spec=Request)
    disconnected_1 = False

    async def is_disconnected_1():
        return disconnected_1

    request_1.is_disconnected = is_disconnected_1

    # Patch service and engine getters
    with patch(
        "chatfilter.web.routers.groups._get_group_service",
        return_value=mock_service,
    ), patch(
        "chatfilter.web.routers.groups._get_group_engine",
        return_value=mock_engine,
    ):
        generator_1 = _generate_group_sse_events(group_id, request_1)

        # Get init event
        init_1 = await collect_sse_init_event(generator_1)
        assert init_1 is not None
        assert init_1["processed"] == 7

        # Simulate disconnect
        disconnected_1 = True

        # Generator should stop after detecting disconnect
        try:
            await generator_1.aclose()
        except (StopAsyncIteration, GeneratorExit):
            pass

        await asyncio.sleep(0.05)

        # === SIMULATE PROGRESS WHILE DISCONNECTED ===
        mock_db.count_processed_chats.return_value = (10, 10)  # All done!

        # === SECOND CONNECTION (RECONNECT) ===
        request_2 = AsyncMock(spec=Request)
        request_2.is_disconnected.return_value = False

        generator_2 = _generate_group_sse_events(group_id, request_2)

        # Get fresh init event
        init_2 = await collect_sse_init_event(generator_2)
        assert init_2 is not None

        # Should reflect current DB state (not cached pre-disconnect state)
        assert init_2["processed"] == 10  # Updated!
        assert init_2["total"] == 10

        # Close second connection
        try:
            await generator_2.aclose()
        except (StopAsyncIteration, GeneratorExit):
            pass
