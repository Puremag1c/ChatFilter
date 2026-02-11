"""Tests for SessionManager.adopt_client() method.

Tests the new adopt_client() method that registers an already-connected
and authorized TelegramClient without disconnecting and reconnecting.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.telegram.session_manager import (
    SessionConnectError,
    SessionManager,
    SessionState,
)


class MockClient:
    """Mock TelegramClient for testing adopt_client."""

    def __init__(
        self,
        *,
        is_connected: bool = True,
        is_authorized: bool = True,
    ) -> None:
        self._is_connected = is_connected
        self._is_authorized = is_authorized
        self.disconnect_calls = 0

    def is_connected(self) -> bool:
        """Mock is_connected (sync in Telethon)."""
        return self._is_connected

    async def is_user_authorized(self) -> bool:
        """Mock is_user_authorized (async in Telethon)."""
        return self._is_authorized

    async def disconnect(self) -> None:
        """Mock disconnect."""
        self.disconnect_calls += 1
        self._is_connected = False


@pytest.mark.asyncio
class TestAdoptClient:
    """Tests for SessionManager.adopt_client()."""

    async def test_adopt_client_registers_correctly(self) -> None:
        """Test adopt_client() registers client with state=CONNECTED."""
        manager = SessionManager()
        client = MockClient(is_connected=True, is_authorized=True)

        # Mock event bus to avoid actual SSE publishing
        with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
            mock_bus = AsyncMock()
            mock_event_bus.return_value = mock_bus

            # Adopt the client
            await manager.adopt_client("test_session", client)

            # Verify client is registered
            assert "test_session" in manager._sessions
            session = manager._sessions["test_session"]

            # Verify state is CONNECTED
            assert session.state == SessionState.CONNECTED

            # Verify connected_at and last_activity are set
            assert session.connected_at is not None
            assert session.last_activity is not None

            # Verify client is the same instance
            assert session.client is client

            # Verify SSE 'connected' event was published
            mock_bus.publish.assert_called_once_with("test_session", "connected")

    async def test_adopt_client_disconnects_old_client(self) -> None:
        """Test adopt_client() disconnects old client if session already CONNECTED."""
        manager = SessionManager()

        # Create first client and adopt it
        old_client = MockClient(is_connected=True, is_authorized=True)

        with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
            mock_bus = AsyncMock()
            mock_event_bus.return_value = mock_bus

            await manager.adopt_client("test_session", old_client)

            # Reset mock to clear first publish call
            mock_bus.publish.reset_mock()

            # Create second client and adopt it (should disconnect old)
            new_client = MockClient(is_connected=True, is_authorized=True)
            await manager.adopt_client("test_session", new_client)

            # Verify old client was disconnected
            assert old_client.disconnect_calls == 1

            # Verify new client is registered
            session = manager._sessions["test_session"]
            assert session.client is new_client
            assert session.client is not old_client

            # Verify SSE event published again
            mock_bus.publish.assert_called_once_with("test_session", "connected")

    async def test_adopt_client_rejects_not_connected(self) -> None:
        """Test adopt_client() raises error if client is not connected."""
        manager = SessionManager()
        client = MockClient(is_connected=False, is_authorized=True)

        with pytest.raises(SessionConnectError, match="client is not connected"):
            await manager.adopt_client("test_session", client)

        # Verify session was NOT registered
        assert "test_session" not in manager._sessions

    async def test_adopt_client_rejects_not_authorized(self) -> None:
        """Test adopt_client() raises error if client is not authorized."""
        manager = SessionManager()
        client = MockClient(is_connected=True, is_authorized=False)

        with pytest.raises(SessionConnectError, match="client is not authorized"):
            await manager.adopt_client("test_session", client)

        # Verify session was NOT registered
        assert "test_session" not in manager._sessions

    async def test_adopt_client_sets_timestamps(self) -> None:
        """Test adopt_client() sets connected_at and last_activity to current time."""
        manager = SessionManager()
        client = MockClient(is_connected=True, is_authorized=True)

        with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
            mock_bus = AsyncMock()
            mock_event_bus.return_value = mock_bus

            # Get current time before adopting
            before_time = asyncio.get_event_loop().time()

            await manager.adopt_client("test_session", client)

            # Get time after adopting
            after_time = asyncio.get_event_loop().time()

            session = manager._sessions["test_session"]

            # Verify timestamps are in the expected range
            assert session.connected_at is not None
            assert session.last_activity is not None
            assert before_time <= session.connected_at <= after_time
            assert before_time <= session.last_activity <= after_time

    async def test_adopt_client_thread_safety(self) -> None:
        """Test adopt_client() uses _global_lock for thread safety."""
        manager = SessionManager()
        client1 = MockClient(is_connected=True, is_authorized=True)
        client2 = MockClient(is_connected=True, is_authorized=True)

        with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
            mock_bus = AsyncMock()
            mock_event_bus.return_value = mock_bus

            # Adopt two clients in parallel for different sessions
            # If lock works correctly, no race condition should occur
            await asyncio.gather(
                manager.adopt_client("session1", client1),
                manager.adopt_client("session2", client2),
            )

            # Verify both sessions registered
            assert "session1" in manager._sessions
            assert "session2" in manager._sessions
            assert manager._sessions["session1"].client is client1
            assert manager._sessions["session2"].client is client2
