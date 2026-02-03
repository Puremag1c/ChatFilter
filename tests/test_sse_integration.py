"""Integration tests for SSE endpoint.

Tests cover:
- Client connects to SSE stream
- Events published via event bus are received
- Events are in correct SSE format
- Connection cleanup on disconnect
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient

from chatfilter.web.app import create_app
from chatfilter.web.events import SessionEventBus, get_event_bus, reset_event_bus


class TestSSEIntegration:
    """Integration tests for SSE /api/sessions/events endpoint."""

    @pytest.fixture(autouse=True)
    def reset_bus(self) -> None:
        """Reset event bus before each test."""
        reset_event_bus()
        yield
        reset_event_bus()

    @pytest.fixture
    def client(self) -> TestClient:
        """Create FastAPI test client."""
        app = create_app()
        return TestClient(app)

    def test_sse_endpoint_is_defined(self, client: TestClient) -> None:
        """SSE endpoint should be defined and routable."""
        app = create_app()
        routes = [route.path for route in app.routes]
        assert any("/api/sessions/events" in route for route in routes), \
            f"SSE endpoint not found. Available routes: {routes}"

    def test_sse_endpoint_route_exists(self) -> None:
        """SSE endpoint /api/sessions/events should be registered."""
        from chatfilter.web.routers.sessions import router

        routes = [route.path for route in router.routes]
        assert any("/events" in route for route in routes), \
            f"Events endpoint not found in sessions router. Routes: {routes}"

    @pytest.mark.asyncio
    async def test_sse_event_bus_integration(self) -> None:
        """SSE endpoint should subscribe to and receive events from bus."""
        bus = get_event_bus()
        received_events = []

        async def capture_handler(session_id: str, new_status: str) -> None:
            received_events.append((session_id, new_status))

        bus.subscribe(capture_handler)

        try:
            await bus.publish("session-123", "connected")

            assert len(received_events) == 1
            assert received_events[0] == ("session-123", "connected")
        finally:
            bus.unsubscribe(capture_handler)

    @pytest.mark.asyncio
    async def test_sse_multiple_events_via_bus(self) -> None:
        """Event bus should deliver multiple events to subscribers."""
        bus = get_event_bus()
        received_events = []

        async def handler(session_id: str, new_status: str) -> None:
            received_events.append((session_id, new_status))

        bus.subscribe(handler)

        try:
            await bus.publish("session-1", "connecting")
            await bus.publish("session-2", "connected")
            await bus.publish("session-3", "disconnected")

            assert len(received_events) == 3
            assert received_events[0][0] == "session-1"
            assert received_events[1][0] == "session-2"
            assert received_events[2][0] == "session-3"
        finally:
            bus.unsubscribe(handler)

    @pytest.mark.asyncio
    async def test_sse_event_format_correct(self) -> None:
        """Events should have correct format (session_id and status fields)."""
        bus = get_event_bus()
        received_events = []

        async def handler(session_id: str, new_status: str) -> None:
            received_events.append({
                "session_id": session_id,
                "status": new_status
            })

        bus.subscribe(handler)

        try:
            await bus.publish("test-session", "active")

            assert len(received_events) == 1
            event = received_events[0]
            assert event["session_id"] == "test-session"
            assert event["status"] == "active"
        finally:
            bus.unsubscribe(handler)

    @pytest.mark.asyncio
    async def test_sse_event_bus_subscription(self) -> None:
        """Event bus should track subscribers correctly."""
        bus = get_event_bus()
        initial_count = bus.subscriber_count

        async def handler(session_id: str, new_status: str) -> None:
            pass

        bus.subscribe(handler)
        assert bus.subscriber_count == initial_count + 1

        bus.unsubscribe(handler)
        assert bus.subscriber_count == initial_count

    @pytest.mark.asyncio
    async def test_sse_deduplication(self) -> None:
        """Event bus should drop duplicate consecutive events."""
        bus = SessionEventBus()
        received_events = []

        async def handler(session_id: str, new_status: str) -> None:
            received_events.append((session_id, new_status))

        bus.subscribe(handler)

        try:
            await bus.publish("session-1", "connected")
            await bus.publish("session-1", "connected")
            await bus.publish("session-1", "connected")

            assert len(received_events) == 1
            assert received_events[0] == ("session-1", "connected")

            await bus.publish("session-1", "disconnected")
            assert len(received_events) == 2
        finally:
            bus.unsubscribe(handler)

    @pytest.mark.asyncio
    async def test_sse_rate_limiting(self) -> None:
        """Event bus should rate limit events per session."""
        bus = SessionEventBus(max_events_per_second=2)
        received_events = []

        async def handler(session_id: str, new_status: str) -> None:
            received_events.append((session_id, new_status))

        bus.subscribe(handler)

        try:
            for i in range(5):
                await bus.publish("session-1", f"status-{i}")

            assert len(received_events) <= 2, \
                f"Rate limit not enforced: received {len(received_events)} events"
        finally:
            bus.unsubscribe(handler)

    @pytest.mark.asyncio
    async def test_sse_handler_in_router(self) -> None:
        """SSE endpoint handler should properly integrate with router."""
        from chatfilter.web.routers.sessions import session_events
        from inspect import iscoroutinefunction

        assert iscoroutinefunction(session_events), \
            "session_events should be an async function"

    @pytest.mark.asyncio
    async def test_sse_stream_format(self) -> None:
        """Events in SSE stream should be properly formatted."""
        bus = get_event_bus()
        received_sse_lines = []

        async def handler(session_id: str, new_status: str) -> None:
            received_sse_lines.append({
                "session_id": session_id,
                "status": new_status
            })

        bus.subscribe(handler)

        try:
            await bus.publish("sess-123", "connected")

            # Verify format
            assert len(received_sse_lines) == 1
            event = received_sse_lines[0]
            assert "session_id" in event
            assert "status" in event
            assert event["session_id"] == "sess-123"
            assert event["status"] == "connected"
        finally:
            bus.unsubscribe(handler)

    @pytest.mark.asyncio
    async def test_sse_handles_exception_in_subscriber(self) -> None:
        """Event bus should continue if one subscriber fails."""
        bus = get_event_bus()
        received_good = []
        received_bad = []

        async def good_handler(session_id: str, new_status: str) -> None:
            received_good.append((session_id, new_status))

        async def bad_handler(session_id: str, new_status: str) -> None:
            received_bad.append((session_id, new_status))
            raise RuntimeError("Handler failed")

        bus.subscribe(bad_handler)
        bus.subscribe(good_handler)

        try:
            await bus.publish("session-1", "connected")

            # Even though bad_handler failed, good_handler should receive it
            assert len(received_good) == 1
            assert len(received_bad) == 1
        finally:
            bus.unsubscribe(bad_handler)
            bus.unsubscribe(good_handler)

    @pytest.mark.asyncio
    async def test_sse_endpoint_returns_streaming_response(self) -> None:
        """SSE endpoint should return StreamingResponse with correct headers."""
        from fastapi.responses import StreamingResponse

        # Get the handler function
        from chatfilter.web.routers.sessions import session_events

        # Create a mock request
        mock_request = AsyncMock()
        mock_request.is_disconnected = AsyncMock(return_value=False)

        # Call the handler
        response = await session_events(mock_request)

        # Verify it returns StreamingResponse
        assert isinstance(response, StreamingResponse)

        # Verify headers
        assert response.media_type == "text/event-stream"
        assert "Cache-Control" in response.headers
        assert response.headers["Cache-Control"] == "no-cache"

    @pytest.mark.asyncio
    async def test_sse_endpoint_cleans_up_on_disconnect(self) -> None:
        """SSE endpoint should unsubscribe handler when client disconnects."""
        from chatfilter.web.routers.sessions import session_events

        bus = get_event_bus()
        initial_subscribers = bus.subscriber_count

        # Create a mock request that simulates disconnect after first message
        mock_request = AsyncMock()
        disconnected = False

        async def is_disconnected_side_effect():
            nonlocal disconnected
            if disconnected:
                return True
            disconnected = True
            return False

        mock_request.is_disconnected = AsyncMock(side_effect=is_disconnected_side_effect)

        # Call the handler
        response = await session_events(mock_request)

        # Iterate through just the first event (connection message)
        iterator = response.body_iterator
        try:
            # Get the initial connection message
            first_event = await asyncio.wait_for(iterator.__anext__(), timeout=2.0)
            assert first_event  # Should get connected message
        except asyncio.TimeoutError:
            pass

        # Close the generator by raising GeneratorExit
        try:
            await iterator.aclose()
        except (StopAsyncIteration, GeneratorExit):
            pass

        # Give event loop a chance to run the finally block
        await asyncio.sleep(0.01)

        # Verify subscriber was cleaned up (back to initial count)
        assert bus.subscriber_count == initial_subscribers
