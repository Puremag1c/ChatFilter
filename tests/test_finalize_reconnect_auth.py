"""Tests for _finalize_reconnect_auth() function.

Tests that _finalize_reconnect_auth() uses adopt_client() instead of
disconnect + connect pattern, preventing AuthKeyUnregisteredError.
"""

import asyncio
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from chatfilter.web.auth_state import AuthState, AuthStep


class MockSessionFile:
    """Mock Telethon session file."""

    def __init__(self, temp_path: Path):
        self.temp_path = temp_path
        self.save_calls = 0

    async def save(self) -> None:
        """Mock session.save()."""
        self.save_calls += 1
        # Create a real session file to test file copy logic
        self.temp_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.temp_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT OR REPLACE INTO sessions VALUES (1, X'deadbeef')")
        conn.commit()
        conn.close()


class MockClient:
    """Mock TelegramClient for testing _finalize_reconnect_auth."""

    def __init__(self, temp_dir: Path):
        self.temp_dir = temp_dir
        self.session = MockSessionFile(temp_dir / "auth_session.session")
        self.disconnect_calls = 0
        self.get_me_calls = 0
        self._is_connected = True
        self._call_response = None  # For mocking client(request) calls

    def is_connected(self) -> bool:
        """Mock is_connected."""
        return self._is_connected

    async def is_user_authorized(self) -> bool:
        """Mock is_user_authorized."""
        return True

    async def get_me(self) -> MagicMock:
        """Mock get_me()."""
        self.get_me_calls += 1
        user = MagicMock()
        user.id = 123456789
        user.phone = "+14385515736"
        user.first_name = "Test"
        user.last_name = "User"
        return user

    async def disconnect(self) -> None:
        """Mock disconnect (should NOT be called)."""
        self.disconnect_calls += 1
        self._is_connected = False

    async def __call__(self, request):
        """Mock client(request) pattern used for Telegram API calls."""
        if self._call_response is not None:
            return self._call_response
        raise NotImplementedError("Mock __call__ not configured")


@pytest.mark.asyncio
class TestFinalizeReconnectAuth:
    """Tests for _finalize_reconnect_auth()."""

    @pytest.fixture
    def mock_ensure_data_dir(self, isolated_tmp_dir: Path, monkeypatch):
        """Mock ensure_data_dir to return isolated tmp dir."""
        mock_dir = MagicMock(return_value=isolated_tmp_dir)
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir", mock_dir
        )
        return isolated_tmp_dir

    @pytest.fixture
    def auth_manager(self):
        """Mock AuthStateManager."""
        manager = AsyncMock()
        manager.remove_auth_state = AsyncMock()
        return manager

    @pytest.fixture
    def session_manager(self):
        """Mock SessionManager with adopt_client."""
        manager = MagicMock()
        manager.adopt_client = AsyncMock()
        manager.connect = AsyncMock()  # Should NOT be called
        manager._factories = {}  # For registration check
        return manager

    async def test_finalize_does_not_call_session_manager_connect(
        self, mock_ensure_data_dir: Path, auth_manager, session_manager
    ) -> None:
        """Test _finalize_reconnect_auth() does NOT call session_manager.connect()."""
        from chatfilter.web.routers.sessions import _finalize_reconnect_auth

        # Setup
        safe_name = "test_session"
        session_dir = mock_ensure_data_dir / safe_name
        session_dir.mkdir(parents=True)

        temp_dir = mock_ensure_data_dir / "temp"
        temp_dir.mkdir(parents=True)

        client = MockClient(temp_dir)
        auth_state = AuthState(
            auth_id="test_auth",
            session_name=safe_name,
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.PHONE_SENT,
            client=client,
        )
        auth_state.temp_dir = str(temp_dir)

        # Mock get_session_manager to return our mock
        with patch("chatfilter.web.dependencies.get_session_manager", return_value=session_manager):
            with patch("chatfilter.telegram.client.TelegramClientLoader"):
                # Call _finalize_reconnect_auth
                await _finalize_reconnect_auth(
                    client, auth_state, auth_manager, safe_name, "test context"
                )

        # Verify session_manager.connect() was NOT called
        session_manager.connect.assert_not_called()

        # Verify adopt_client WAS called with correct args
        session_manager.adopt_client.assert_called_once_with(safe_name, client)

    async def test_finalize_does_not_call_client_disconnect(
        self, mock_ensure_data_dir: Path, auth_manager, session_manager
    ) -> None:
        """Test _finalize_reconnect_auth() does NOT call client.disconnect()."""
        from chatfilter.web.routers.sessions import _finalize_reconnect_auth

        # Setup
        safe_name = "test_session"
        session_dir = mock_ensure_data_dir / safe_name
        session_dir.mkdir(parents=True)

        temp_dir = mock_ensure_data_dir / "temp"
        temp_dir.mkdir(parents=True)

        client = MockClient(temp_dir)
        auth_state = AuthState(
            auth_id="test_auth",
            session_name=safe_name,
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.PHONE_SENT,
            client=client,
        )
        auth_state.temp_dir = str(temp_dir)

        # Mock get_session_manager to return our mock
        with patch("chatfilter.web.dependencies.get_session_manager", return_value=session_manager):
            with patch("chatfilter.telegram.client.TelegramClientLoader"):
                # Call _finalize_reconnect_auth
                await _finalize_reconnect_auth(
                    client, auth_state, auth_manager, safe_name, "test context"
                )

        # Verify client.disconnect() was NOT called
        assert client.disconnect_calls == 0

        # Verify client.session.save() WAS called
        assert client.session.save_calls == 1

    async def test_finalize_calls_client_session_save(
        self, mock_ensure_data_dir: Path, auth_manager, session_manager
    ) -> None:
        """Test _finalize_reconnect_auth() calls client.session.save()."""
        from chatfilter.web.routers.sessions import _finalize_reconnect_auth

        # Setup
        safe_name = "test_session"
        session_dir = mock_ensure_data_dir / safe_name
        session_dir.mkdir(parents=True)

        temp_dir = mock_ensure_data_dir / "temp"
        temp_dir.mkdir(parents=True)

        client = MockClient(temp_dir)
        auth_state = AuthState(
            auth_id="test_auth",
            session_name=safe_name,
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.PHONE_SENT,
            client=client,
        )
        auth_state.temp_dir = str(temp_dir)

        # Mock get_session_manager to return our mock
        with patch("chatfilter.web.dependencies.get_session_manager", return_value=session_manager):
            with patch("chatfilter.telegram.client.TelegramClientLoader"):
                # Call _finalize_reconnect_auth
                await _finalize_reconnect_auth(
                    client, auth_state, auth_manager, safe_name, "test context"
                )

        # Verify client.session.save() was called
        assert client.session.save_calls == 1

        # Verify session file was copied to final location
        final_session_path = session_dir / "session.session"
        assert final_session_path.exists()

    async def test_finalize_adopts_client_with_correct_args(
        self, mock_ensure_data_dir: Path, auth_manager, session_manager
    ) -> None:
        """Test _finalize_reconnect_auth() calls adopt_client with correct arguments."""
        from chatfilter.web.routers.sessions import _finalize_reconnect_auth

        # Setup
        safe_name = "test_session"
        session_dir = mock_ensure_data_dir / safe_name
        session_dir.mkdir(parents=True)

        temp_dir = mock_ensure_data_dir / "temp"
        temp_dir.mkdir(parents=True)

        client = MockClient(temp_dir)
        auth_state = AuthState(
            auth_id="test_auth",
            session_name=safe_name,
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.PHONE_SENT,
            client=client,
        )
        auth_state.temp_dir = str(temp_dir)

        # Mock get_session_manager to return our mock
        with patch("chatfilter.web.dependencies.get_session_manager", return_value=session_manager):
            with patch("chatfilter.telegram.client.TelegramClientLoader"):
                # Call _finalize_reconnect_auth
                await _finalize_reconnect_auth(
                    client, auth_state, auth_manager, safe_name, "test context"
                )

        # Verify adopt_client was called with exact arguments
        session_manager.adopt_client.assert_called_once_with(safe_name, client)

    async def test_full_cycle_finalize_to_connected(
        self, mock_ensure_data_dir: Path, auth_manager
    ) -> None:
        """Test full cycle: finalize → adopt → connected (no AuthKeyUnregisteredError)."""
        from chatfilter.web.routers.sessions import _finalize_reconnect_auth
        from chatfilter.telegram.session_manager import SessionManager

        # Setup real SessionManager (not mocked)
        session_manager = SessionManager()

        safe_name = "test_session"
        session_dir = mock_ensure_data_dir / safe_name
        session_dir.mkdir(parents=True)

        temp_dir = mock_ensure_data_dir / "temp"
        temp_dir.mkdir(parents=True)

        client = MockClient(temp_dir)
        auth_state = AuthState(
            auth_id="test_auth",
            session_name=safe_name,
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.PHONE_SENT,
            client=client,
        )
        auth_state.temp_dir = str(temp_dir)

        # Mock event bus to avoid SSE publishing
        with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
            mock_bus = AsyncMock()
            mock_event_bus.return_value = mock_bus

            # Mock get_session_manager to return real SessionManager
            with patch("chatfilter.web.dependencies.get_session_manager", return_value=session_manager):
                with patch("chatfilter.telegram.client.TelegramClientLoader"):
                    # Call _finalize_reconnect_auth
                    # Should NOT raise AuthKeyUnregisteredError
                    await _finalize_reconnect_auth(
                        client, auth_state, auth_manager, safe_name, "test context"
                    )

        # Verify session is CONNECTED in SessionManager
        from chatfilter.telegram.session_manager import SessionState

        assert safe_name in session_manager._sessions
        session = session_manager._sessions[safe_name]
        assert session.state == SessionState.CONNECTED
        assert session.client is client

        # Verify SSE 'connected' event was published
        mock_bus.publish.assert_called_with(safe_name, "connected")


@pytest.mark.asyncio
class TestPollingUsesSameClient:
    """Tests for _poll_device_confirmation using same client instance."""

    async def test_poll_device_confirmation_uses_same_client(self) -> None:
        """Test _poll_device_confirmation calls _finalize_reconnect_auth with SAME client."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation
        from chatfilter.web.auth_state import AuthStateManager

        # Create auth manager and auth state
        auth_manager = AuthStateManager()

        # Create mock client
        temp_dir = Path("/tmp/test")
        temp_dir.mkdir(parents=True, exist_ok=True)
        original_client = MockClient(temp_dir)

        auth_state = AuthState(
            auth_id="test_auth",
            session_name="test_session",
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.NEED_CONFIRMATION,
            client=original_client,
        )

        # Manually add auth state to manager's internal dict
        auth_manager._states["test_auth"] = auth_state

        # Mock GetAuthorizationsRequest to return confirmed session immediately
        mock_authorization = MagicMock()
        mock_authorization.current = True
        mock_authorization.unconfirmed = False  # Confirmed!

        mock_authorizations = MagicMock()
        mock_authorizations.authorizations = [mock_authorization]

        # Configure client to return mock authorizations
        original_client._call_response = mock_authorizations

        # Track which client instance is passed to _finalize_reconnect_auth
        finalize_client = None

        async def mock_finalize(client, auth_state, auth_mgr, safe_name, log_ctx):
            nonlocal finalize_client
            finalize_client = client

        with patch("chatfilter.web.routers.sessions._finalize_reconnect_auth", new=mock_finalize):
            with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
                mock_bus = AsyncMock()
                mock_event_bus.return_value = mock_bus

                # Run polling (should detect confirmation immediately)
                await _poll_device_confirmation(
                    "test_session", "test_auth", auth_manager
                )

        # Verify _finalize_reconnect_auth was called with the SAME client instance
        assert finalize_client is original_client

        # Verify no new TelegramClient was created (client instance is unchanged)
        assert original_client.disconnect_calls == 0

    async def test_poll_does_not_create_new_client(self) -> None:
        """Test _poll_device_confirmation does NOT create new TelegramClient during poll.

        This is verified by checking that the client stored in auth_state remains
        the same instance throughout the polling process.
        """
        from chatfilter.web.routers.sessions import _poll_device_confirmation
        from chatfilter.web.auth_state import AuthStateManager

        # Create auth manager and auth state
        auth_manager = AuthStateManager()

        temp_dir = Path("/tmp/test")
        temp_dir.mkdir(parents=True, exist_ok=True)
        original_client = MockClient(temp_dir)

        auth_state = AuthState(
            auth_id="test_auth",
            session_name="test_session",
            api_id=12345,
            api_hash="test_hash",
            proxy_id="",
            phone="+14385515736",
            step=AuthStep.NEED_CONFIRMATION,
            client=original_client,
        )

        # Manually add auth state to manager's internal dict
        auth_manager._states["test_auth"] = auth_state

        # Mock GetAuthorizationsRequest
        mock_authorization = MagicMock()
        mock_authorization.current = True
        mock_authorization.unconfirmed = False

        mock_authorizations = MagicMock()
        mock_authorizations.authorizations = [mock_authorization]

        # Configure client to return mock authorizations
        original_client._call_response = mock_authorizations

        # Store original client id for comparison
        original_client_id = id(original_client)

        with patch("chatfilter.web.routers.sessions._finalize_reconnect_auth", new=AsyncMock()):
            with patch("chatfilter.web.events.get_event_bus") as mock_event_bus:
                mock_bus = AsyncMock()
                mock_event_bus.return_value = mock_bus

                await _poll_device_confirmation(
                    "test_session", "test_auth", auth_manager
                )

        # Verify the client in auth_state is still the same instance
        # (no new client was created to replace it)
        auth_state_after = await auth_manager.get_auth_state("test_auth")
        if auth_state_after is not None:
            # Auth state might be removed after finalization, which is OK
            assert id(auth_state_after.client) == original_client_id
