"""Event bus for broadcasting session status changes.

This module provides a simple publish-subscribe event bus for notifying
subscribers about session status changes in real-time.

All session status-changing endpoints publish events via get_event_bus().publish():

Endpoints that publish events:
- POST /api/sessions/{session_id}/connect
  - Success: publishes actual state (connected, needs_code, etc.)
  - Timeout: publishes "error"
  - Exception: publishes classified error state

- POST /api/sessions/{session_id}/disconnect
  - Success: publishes config_status
  - Exception: publishes "error"

- POST /api/sessions/{session_id}/send-code
  - Success: publishes "needs_code"
  - Proxy error/timeout: publishes "proxy_error"
  - Auth restart: publishes "needs_auth"

- POST /api/sessions/{session_id}/verify-code
  - Success: publishes "connected"
  - 2FA required: publishes "needs_2fa"
  - Proxy error/timeout: publishes "proxy_error"

- POST /api/sessions/{session_id}/verify-2fa
  - Success: publishes "connected"
  - Proxy error/timeout: publishes "proxy_error"
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Callable, Awaitable


class SessionEventBus:
    """Event bus for broadcasting session status changes.

    Usage:
        bus = SessionEventBus()

        # Subscribe to events
        async def handler(session_id: str, new_status: str):
            print(f"Session {session_id} changed to {new_status}")

        bus.subscribe(handler)

        # Publish events
        await bus.publish("session123", "connected")
    """

    def __init__(self, max_events_per_second: int = 10):
        """Initialize the event bus.

        Args:
            max_events_per_second: Maximum events per session per second (default: 10)
        """
        self._subscribers: list[Callable[[str, str], Awaitable[None]]] = []
        self._max_events_per_second = max_events_per_second

        # Deduplication: track last status per session
        self._last_status: dict[str, str] = {}

        # Rate limiting: track event timestamps per session
        self._event_times: dict[str, list[float]] = defaultdict(list)

    def subscribe(self, callback: Callable[[str, str], Awaitable[None]]) -> None:
        """Subscribe to session status change events.

        Duplicate subscriptions are automatically prevented. If the same callback
        is already subscribed, this call is a no-op. This guards against subscriber
        leaks during SSE reconnect scenarios.

        Args:
            callback: Async function that receives (session_id, new_status)
        """
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[str, str], Awaitable[None]]) -> None:
        """Unsubscribe from session status change events.

        Args:
            callback: Previously subscribed callback function
        """
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def _should_throttle(self, session_id: str, new_status: str) -> bool:
        """Check if event should be throttled.

        Returns:
            True if event should be dropped, False otherwise
        """
        # Deduplication: drop if same status as last event
        if self._last_status.get(session_id) == new_status:
            return True

        # Rate limiting: drop if exceeds rate limit
        now = time.time()
        event_times = self._event_times[session_id]

        # Remove events older than 1 second
        event_times[:] = [t for t in event_times if now - t < 1.0]

        # Check rate limit
        if len(event_times) >= self._max_events_per_second:
            return True

        return False

    async def publish(self, session_id: str, new_status: str) -> None:
        """Publish a session status change event to all subscribers.

        Events are throttled to prevent flooding:
        - Duplicate consecutive events are dropped
        - Events exceeding rate limit are dropped
        - Slow subscribers don't block event publishing

        Args:
            session_id: ID of the session that changed
            new_status: New status of the session
        """
        # Throttle check
        if self._should_throttle(session_id, new_status):
            return

        # Update tracking
        self._last_status[session_id] = new_status
        self._event_times[session_id].append(time.time())

        # Call all subscribers concurrently with timeout
        if self._subscribers:
            tasks = [
                asyncio.wait_for(callback(session_id, new_status), timeout=5.0)
                for callback in self._subscribers
            ]
            await asyncio.gather(
                *tasks,
                return_exceptions=True  # Don't let one failing subscriber break others
            )

    def clear_subscribers(self) -> None:
        """Remove all subscribers. Useful for testing."""
        self._subscribers.clear()

    @property
    def subscriber_count(self) -> int:
        """Get the number of active subscribers."""
        return len(self._subscribers)


# Global event bus instance
_event_bus: SessionEventBus | None = None


def get_event_bus() -> SessionEventBus:
    """Get the global event bus instance.

    Returns:
        The global SessionEventBus instance
    """
    global _event_bus
    if _event_bus is None:
        _event_bus = SessionEventBus()
    return _event_bus


def reset_event_bus() -> None:
    """Reset the global event bus. Useful for testing."""
    global _event_bus
    _event_bus = None
