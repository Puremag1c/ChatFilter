"""Tests for session event bus module.

Tests cover:
- Event subscription and unsubscription
- Event publishing to subscribers
- Multiple subscribers receiving events
- Subscriber isolation (one failure doesn't affect others)
- Global event bus singleton
"""

from __future__ import annotations

import asyncio
import pytest

from chatfilter.web.events import (
    SessionEventBus,
    get_event_bus,
    reset_event_bus,
)


class TestSessionEventBus:
    """Tests for SessionEventBus class."""

    def test_initialization(self) -> None:
        """Event bus should initialize with no subscribers."""
        bus = SessionEventBus()
        assert bus.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_subscribe_and_publish(self) -> None:
        """Subscriber should receive published events."""
        bus = SessionEventBus()
        received_events = []

        async def handler(session_id: str, new_status: str) -> None:
            received_events.append((session_id, new_status))

        bus.subscribe(handler)
        await bus.publish("session123", "connected")

        assert len(received_events) == 1
        assert received_events[0] == ("session123", "connected")

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self) -> None:
        """Multiple subscribers should all receive events."""
        bus = SessionEventBus()
        received1 = []
        received2 = []

        async def handler1(session_id: str, new_status: str) -> None:
            received1.append((session_id, new_status))

        async def handler2(session_id: str, new_status: str) -> None:
            received2.append((session_id, new_status))

        bus.subscribe(handler1)
        bus.subscribe(handler2)
        await bus.publish("session456", "disconnected")

        assert received1 == [("session456", "disconnected")]
        assert received2 == [("session456", "disconnected")]

    @pytest.mark.asyncio
    async def test_unsubscribe(self) -> None:
        """Unsubscribed handlers should not receive events."""
        bus = SessionEventBus()
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)
        await bus.publish("session1", "status1")

        bus.unsubscribe(handler)
        await bus.publish("session2", "status2")

        # Should only have received the first event
        assert len(received) == 1
        assert received[0] == ("session1", "status1")

    @pytest.mark.asyncio
    async def test_duplicate_subscription(self) -> None:
        """Subscribing same handler twice should only register once."""
        bus = SessionEventBus()
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)
        bus.subscribe(handler)  # Subscribe again
        await bus.publish("session1", "status1")

        # Should only receive event once
        assert len(received) == 1
        assert bus.subscriber_count == 1

    @pytest.mark.asyncio
    async def test_unsubscribe_nonexistent(self) -> None:
        """Unsubscribing non-existent handler should not raise error."""
        bus = SessionEventBus()

        async def handler(session_id: str, new_status: str) -> None:
            pass

        # Should not raise
        bus.unsubscribe(handler)
        assert bus.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_publish_without_subscribers(self) -> None:
        """Publishing without subscribers should not raise error."""
        bus = SessionEventBus()
        # Should not raise
        await bus.publish("session1", "status1")

    @pytest.mark.asyncio
    async def test_subscriber_exception_isolation(self) -> None:
        """One subscriber failing should not affect others."""
        bus = SessionEventBus()
        received = []

        async def failing_handler(session_id: str, new_status: str) -> None:
            raise ValueError("Handler failure")

        async def working_handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(failing_handler)
        bus.subscribe(working_handler)

        # Should not raise, working handler should still receive event
        await bus.publish("session1", "status1")

        assert len(received) == 1
        assert received[0] == ("session1", "status1")

    @pytest.mark.asyncio
    async def test_multiple_events(self) -> None:
        """Subscriber should receive all published events in order."""
        bus = SessionEventBus()
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        await bus.publish("session1", "connecting")
        await bus.publish("session1", "connected")
        await bus.publish("session1", "disconnected")

        assert len(received) == 3
        assert received[0] == ("session1", "connecting")
        assert received[1] == ("session1", "connected")
        assert received[2] == ("session1", "disconnected")

    def test_clear_subscribers(self) -> None:
        """clear_subscribers should remove all subscribers."""
        bus = SessionEventBus()

        async def handler(session_id: str, new_status: str) -> None:
            pass

        bus.subscribe(handler)
        assert bus.subscriber_count == 1

        bus.clear_subscribers()
        assert bus.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_async_handler_execution(self) -> None:
        """Handlers should execute asynchronously."""
        bus = SessionEventBus()
        execution_order = []

        async def slow_handler(session_id: str, new_status: str) -> None:
            await asyncio.sleep(0.1)
            execution_order.append("slow")

        async def fast_handler(session_id: str, new_status: str) -> None:
            execution_order.append("fast")

        bus.subscribe(slow_handler)
        bus.subscribe(fast_handler)

        await bus.publish("session1", "status1")

        # Both should have executed
        assert len(execution_order) == 2
        # Fast handler should have completed first
        assert execution_order[0] == "fast"
        assert execution_order[1] == "slow"


class TestGlobalEventBus:
    """Tests for global event bus singleton."""

    def test_get_event_bus_singleton(self) -> None:
        """get_event_bus should return the same instance."""
        reset_event_bus()  # Start fresh
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2

    @pytest.mark.asyncio
    async def test_global_bus_persistence(self) -> None:
        """Global bus should maintain subscribers across get_event_bus calls."""
        reset_event_bus()  # Start fresh
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus1 = get_event_bus()
        bus1.subscribe(handler)

        bus2 = get_event_bus()
        await bus2.publish("session1", "status1")

        assert len(received) == 1

    def test_reset_event_bus(self) -> None:
        """reset_event_bus should create a new instance."""
        bus1 = get_event_bus()
        reset_event_bus()
        bus2 = get_event_bus()
        assert bus1 is not bus2


class TestEventBusIntegration:
    """Integration tests for event bus workflow."""

    @pytest.mark.asyncio
    async def test_session_lifecycle_events(self) -> None:
        """Test event bus handling typical session lifecycle."""
        bus = SessionEventBus()
        events = []

        async def logger(session_id: str, new_status: str) -> None:
            events.append(f"{session_id}: {new_status}")

        bus.subscribe(logger)

        # Simulate session lifecycle
        await bus.publish("user123", "connecting")
        await bus.publish("user123", "needs_code")
        await bus.publish("user123", "needs_2fa")
        await bus.publish("user123", "connected")
        await bus.publish("user123", "disconnected")

        assert events == [
            "user123: connecting",
            "user123: needs_code",
            "user123: needs_2fa",
            "user123: connected",
            "user123: disconnected",
        ]

    @pytest.mark.asyncio
    async def test_multiple_sessions(self) -> None:
        """Test event bus handling multiple concurrent sessions."""
        bus = SessionEventBus()
        events = []

        async def logger(session_id: str, new_status: str) -> None:
            events.append((session_id, new_status))

        bus.subscribe(logger)

        # Simulate multiple sessions
        await bus.publish("session1", "connected")
        await bus.publish("session2", "connected")
        await bus.publish("session1", "disconnected")
        await bus.publish("session3", "connected")
        await bus.publish("session2", "disconnected")

        assert len(events) == 5
        # Verify specific events
        assert ("session1", "connected") in events
        assert ("session2", "connected") in events
        assert ("session3", "connected") in events


class TestEventThrottling:
    """Tests for event throttling and rate limiting."""

    @pytest.mark.asyncio
    async def test_deduplication(self) -> None:
        """Duplicate consecutive events should be dropped."""
        bus = SessionEventBus()
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        # Publish same status twice
        await bus.publish("session1", "connected")
        await bus.publish("session1", "connected")  # Should be dropped

        # Only first event should be received
        assert len(received) == 1
        assert received[0] == ("session1", "connected")

    @pytest.mark.asyncio
    async def test_deduplication_different_status(self) -> None:
        """Different statuses should not be deduplicated."""
        bus = SessionEventBus()
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        await bus.publish("session1", "connected")
        await bus.publish("session1", "disconnected")

        # Both events should be received
        assert len(received) == 2
        assert received[0] == ("session1", "connected")
        assert received[1] == ("session1", "disconnected")

    @pytest.mark.asyncio
    async def test_rate_limiting(self) -> None:
        """Events exceeding rate limit should be dropped."""
        bus = SessionEventBus(max_events_per_second=3)
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        # Rapidly publish events (alternating statuses to avoid deduplication)
        for i in range(10):
            status = "status_a" if i % 2 == 0 else "status_b"
            await bus.publish("session1", status)

        # Should only receive up to max_events_per_second
        assert len(received) <= 3

    @pytest.mark.asyncio
    async def test_rate_limiting_per_session(self) -> None:
        """Rate limiting should be per session_id."""
        bus = SessionEventBus(max_events_per_second=2)
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        # Rapidly publish events for different sessions
        await bus.publish("session1", "status1")
        await bus.publish("session2", "status1")
        await bus.publish("session1", "status2")
        await bus.publish("session2", "status2")
        await bus.publish("session1", "status3")  # Should be rate limited
        await bus.publish("session2", "status3")  # Should be rate limited

        # Each session should have received up to max_events_per_second
        session1_events = [e for e in received if e[0] == "session1"]
        session2_events = [e for e in received if e[0] == "session2"]

        assert len(session1_events) <= 2
        assert len(session2_events) <= 2

    @pytest.mark.asyncio
    async def test_slow_subscriber_timeout(self) -> None:
        """Slow subscribers should timeout and not block publishing."""
        bus = SessionEventBus()
        fast_received = []

        async def slow_handler(session_id: str, new_status: str) -> None:
            await asyncio.sleep(10)  # Will timeout at 5s

        async def fast_handler(session_id: str, new_status: str) -> None:
            fast_received.append((session_id, new_status))

        bus.subscribe(slow_handler)
        bus.subscribe(fast_handler)

        # Should complete quickly despite slow handler
        start = asyncio.get_event_loop().time()
        await bus.publish("session1", "status1")
        elapsed = asyncio.get_event_loop().time() - start

        # Should timeout in ~5s, not wait 10s
        assert elapsed < 7.0
        # Fast handler should still receive event
        assert len(fast_received) == 1

    @pytest.mark.asyncio
    async def test_rate_limiting_window_resets(self) -> None:
        """Rate limit should reset after time window passes."""
        bus = SessionEventBus(max_events_per_second=2)
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        # Send 2 events (at limit)
        await bus.publish("session1", "status1")
        await bus.publish("session1", "status2")

        # Wait for rate limit window to pass
        await asyncio.sleep(1.1)

        # Should be able to send more events
        await bus.publish("session1", "status3")
        await bus.publish("session1", "status4")

        # Should have received 4 events total
        assert len(received) == 4

    @pytest.mark.asyncio
    async def test_reset_session_status_allows_duplicate(self) -> None:
        """reset_session_status allows same status to be sent again.

        This is critical for reconnect flows:
        - disconnected (initial state)
        - reset_session_status() called
        - connecting (HTMX response)
        - disconnected (SSE if reconnect fails) <- must not be dropped!
        """
        bus = SessionEventBus()
        received = []

        async def handler(session_id: str, new_status: str) -> None:
            received.append((session_id, new_status))

        bus.subscribe(handler)

        # First event
        await bus.publish("session1", "disconnected")
        assert len(received) == 1

        # Same status - should be dropped (deduplication)
        await bus.publish("session1", "disconnected")
        assert len(received) == 1  # Still 1

        # Reset session status
        bus.reset_session_status("session1")

        # Same status again - NOW it should be sent!
        await bus.publish("session1", "disconnected")
        assert len(received) == 2  # Now 2
        assert received[0] == ("session1", "disconnected")
        assert received[1] == ("session1", "disconnected")

    def test_reset_session_status_nonexistent_session(self) -> None:
        """reset_session_status should not raise for nonexistent session."""
        bus = SessionEventBus()
        # Should not raise
        bus.reset_session_status("nonexistent")
