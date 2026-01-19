"""Tests for SessionManager."""

import asyncio
from unittest.mock import MagicMock

import pytest

from chatfilter.telegram.session_manager import (
    SessionConnectError,
    SessionError,
    SessionManager,
    SessionState,
    SessionTimeoutError,
)


class MockClient:
    """Mock Telethon client for testing."""

    def __init__(self, *, fail_connect: bool = False, hang_connect: bool = False) -> None:
        self.fail_connect = fail_connect
        self.hang_connect = hang_connect
        self.connected = False
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.get_me_calls = 0

    async def connect(self) -> None:
        self.connect_calls += 1
        if self.hang_connect:
            await asyncio.sleep(100)  # Will timeout
        if self.fail_connect:
            raise ConnectionError("Mock connection failure")
        self.connected = True

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        self.connected = False

    async def get_me(self) -> MagicMock:
        self.get_me_calls += 1
        if not self.connected:
            raise ConnectionError("Not connected")
        return MagicMock(id=12345, username="testuser")


class MockFactory:
    """Mock client factory for testing."""

    def __init__(self, client: MockClient | None = None) -> None:
        self._client = client or MockClient()

    def create_client(self) -> MockClient:
        return self._client


class TestSessionManagerRegistration:
    """Tests for session registration."""

    def test_register_session(self) -> None:
        """Test registering a session."""
        manager = SessionManager()
        factory = MockFactory()

        manager.register("test_session", factory)

        assert "test_session" in manager.list_sessions()

    def test_list_sessions_empty(self) -> None:
        """Test listing sessions when empty."""
        manager = SessionManager()

        assert manager.list_sessions() == []

    def test_unregister_session(self) -> None:
        """Test unregistering a session."""
        manager = SessionManager()
        factory = MockFactory()
        manager.register("test_session", factory)

        manager.unregister("test_session")

        assert "test_session" not in manager.list_sessions()


class TestSessionManagerConnect:
    """Tests for session connection."""

    @pytest.mark.asyncio
    async def test_connect_success(self) -> None:
        """Test successful connection."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))

        result = await manager.connect("test")

        assert result is client
        assert client.connected
        assert client.connect_calls == 1

    @pytest.mark.asyncio
    async def test_connect_already_connected(self) -> None:
        """Test that connecting an already connected session returns same client."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))

        client1 = await manager.connect("test")
        client2 = await manager.connect("test")

        assert client1 is client2
        assert client.connect_calls == 1  # Only connected once

    @pytest.mark.asyncio
    async def test_connect_failure(self) -> None:
        """Test connection failure."""
        manager = SessionManager()
        client = MockClient(fail_connect=True)
        manager.register("test", MockFactory(client))

        with pytest.raises(SessionConnectError, match="Failed to connect"):
            await manager.connect("test")

        info = manager.get_info("test")
        assert info is not None
        assert info.state == SessionState.ERROR

    @pytest.mark.asyncio
    async def test_connect_timeout(self) -> None:
        """Test connection timeout."""
        manager = SessionManager(connect_timeout=0.1)
        client = MockClient(hang_connect=True)
        manager.register("test", MockFactory(client))

        with pytest.raises(SessionTimeoutError, match="timeout"):
            await manager.connect("test")

    @pytest.mark.asyncio
    async def test_connect_unregistered_session(self) -> None:
        """Test connecting unregistered session raises KeyError."""
        manager = SessionManager()

        with pytest.raises(KeyError, match="not registered"):
            await manager.connect("nonexistent")


class TestSessionManagerDisconnect:
    """Tests for session disconnection."""

    @pytest.mark.asyncio
    async def test_disconnect_connected_session(self) -> None:
        """Test disconnecting a connected session."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        await manager.disconnect("test")

        assert not client.connected
        assert client.disconnect_calls == 1

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self) -> None:
        """Test disconnecting a session that was never connected."""
        manager = SessionManager()
        manager.register("test", MockFactory())

        # Should not raise
        await manager.disconnect("test")

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent(self) -> None:
        """Test disconnecting a nonexistent session."""
        manager = SessionManager()

        # Should not raise
        await manager.disconnect("nonexistent")

    @pytest.mark.asyncio
    async def test_disconnect_all(self) -> None:
        """Test disconnecting all sessions."""
        manager = SessionManager()
        client1 = MockClient()
        client2 = MockClient()
        manager.register("test1", MockFactory(client1))
        manager.register("test2", MockFactory(client2))
        await manager.connect("test1")
        await manager.connect("test2")

        await manager.disconnect_all()

        assert not client1.connected
        assert not client2.connected


class TestSessionManagerContextManager:
    """Tests for session context manager."""

    @pytest.mark.asyncio
    async def test_context_manager_auto_disconnect(self) -> None:
        """Test that context manager auto-disconnects."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))

        async with manager.session("test") as c:
            assert c is client
            assert client.connected

        assert not client.connected

    @pytest.mark.asyncio
    async def test_context_manager_no_auto_disconnect(self) -> None:
        """Test context manager with auto_disconnect=False."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))

        async with manager.session("test", auto_disconnect=False) as c:
            assert c is client

        assert client.connected  # Still connected

    @pytest.mark.asyncio
    async def test_context_manager_exception_still_disconnects(self) -> None:
        """Test that context manager disconnects even on exception."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))

        with pytest.raises(ValueError):
            async with manager.session("test"):
                raise ValueError("Test error")

        assert not client.connected


class TestSessionManagerHealthCheck:
    """Tests for health check functionality."""

    @pytest.mark.asyncio
    async def test_is_healthy_connected(self) -> None:
        """Test health check for connected session."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        result = await manager.is_healthy("test")

        assert result is True
        assert client.get_me_calls == 1

    @pytest.mark.asyncio
    async def test_is_healthy_not_connected(self) -> None:
        """Test health check for disconnected session."""
        manager = SessionManager()
        manager.register("test", MockFactory())

        result = await manager.is_healthy("test")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_healthy_nonexistent(self) -> None:
        """Test health check for nonexistent session."""
        manager = SessionManager()

        result = await manager.is_healthy("nonexistent")

        assert result is False


class TestSessionManagerInfo:
    """Tests for session info."""

    def test_get_info_registered_not_connected(self) -> None:
        """Test getting info for registered but not connected session."""
        manager = SessionManager()
        manager.register("test", MockFactory())

        info = manager.get_info("test")

        assert info is not None
        assert info.session_id == "test"
        assert info.state == SessionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_get_info_connected(self) -> None:
        """Test getting info for connected session."""
        manager = SessionManager()
        manager.register("test", MockFactory())
        await manager.connect("test")

        info = manager.get_info("test")

        assert info is not None
        assert info.state == SessionState.CONNECTED
        assert info.connected_at is not None

    def test_get_info_nonexistent(self) -> None:
        """Test getting info for nonexistent session."""
        manager = SessionManager()

        info = manager.get_info("nonexistent")

        assert info is None


class TestSessionManagerLocking:
    """Tests for per-session locking."""

    @pytest.mark.asyncio
    async def test_concurrent_connects_serialized(self) -> None:
        """Test that concurrent connects are serialized."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))

        # Start multiple connects concurrently
        results = await asyncio.gather(
            manager.connect("test"),
            manager.connect("test"),
            manager.connect("test"),
        )

        # All should return the same client
        assert all(r is client for r in results)
        # Should only connect once
        assert client.connect_calls == 1

    @pytest.mark.asyncio
    async def test_unregister_connected_raises(self) -> None:
        """Test that unregistering a connected session raises error."""
        manager = SessionManager()
        manager.register("test", MockFactory())
        await manager.connect("test")

        with pytest.raises(SessionError, match="Cannot unregister connected"):
            manager.unregister("test")
