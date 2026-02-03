"""Event bus for broadcasting session status changes.

This module provides a simple publish-subscribe event bus for notifying
subscribers about session status changes in real-time.
"""

from __future__ import annotations

import asyncio
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

    def __init__(self):
        """Initialize the event bus."""
        self._subscribers: list[Callable[[str, str], Awaitable[None]]] = []

    def subscribe(self, callback: Callable[[str, str], Awaitable[None]]) -> None:
        """Subscribe to session status change events.

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

    async def publish(self, session_id: str, new_status: str) -> None:
        """Publish a session status change event to all subscribers.

        Args:
            session_id: ID of the session that changed
            new_status: New status of the session
        """
        # Call all subscribers concurrently
        if self._subscribers:
            await asyncio.gather(
                *[callback(session_id, new_status) for callback in self._subscribers],
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
