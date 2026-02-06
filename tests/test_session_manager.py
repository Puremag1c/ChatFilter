"""Tests for SessionManager."""

import asyncio
from unittest.mock import MagicMock

import pytest
from telethon import errors

from chatfilter.telegram.session_manager import (
    SessionConnectError,
    SessionError,
    SessionInvalidError,
    SessionManager,
    SessionReauthRequiredError,
    SessionState,
    SessionTimeoutError,
)


class MockClient:
    """Mock Telethon client for testing."""

    def __init__(
        self,
        *,
        fail_connect: bool = False,
        hang_connect: bool = False,
        connect_delay: float = 0.0,
        auth_error: Exception | None = None,
    ) -> None:
        self.fail_connect = fail_connect
        self.hang_connect = hang_connect
        self.connect_delay = connect_delay
        self.auth_error = auth_error
        self.connected = False
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.get_me_calls = 0

    async def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_delay > 0:
            await asyncio.sleep(self.connect_delay)
        if self.hang_connect:
            await asyncio.sleep(100)  # Will timeout
        if self.auth_error:
            raise self.auth_error
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

    async def iter_dialogs(self, limit: int = 100):
        """Mock iter_dialogs - async generator that yields nothing."""
        if not self.connected:
            raise ConnectionError("Not connected")
        # Yield nothing - just verifies we can iterate
        return
        yield  # Make this an async generator


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
    async def test_concurrent_connects_rejected(self) -> None:
        """Test that concurrent connect requests are rejected with SessionBusyError."""
        from chatfilter.telegram.session_manager import SessionBusyError

        manager = SessionManager()
        # Use a slow connecting client to ensure concurrent requests
        client = MockClient(connect_delay=0.5)
        manager.register("test", MockFactory(client))

        # Start first connect
        connect_task = asyncio.create_task(manager.connect("test"))

        # Wait a bit to ensure first connect has acquired the lock
        await asyncio.sleep(0.1)

        # Second concurrent connect should be rejected immediately
        with pytest.raises(SessionBusyError, match="already busy"):
            await manager.connect("test")

        # First connect should succeed
        result = await connect_task
        assert result is client
        assert client.connect_calls == 1

    @pytest.mark.asyncio
    async def test_unregister_connected_raises(self) -> None:
        """Test that unregistering a connected session raises error."""
        manager = SessionManager()
        manager.register("test", MockFactory())
        await manager.connect("test")

        with pytest.raises(SessionError, match="Cannot unregister connected"):
            manager.unregister("test")


class TestSessionAuthErrors:
    """Tests for session authentication error handling."""

    @pytest.mark.asyncio
    async def test_connect_session_revoked_error(self) -> None:
        """Test connection with SessionRevokedError raises SessionInvalidError."""
        manager = SessionManager()
        # Telethon errors need a mock request object
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionRevokedError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(
            SessionInvalidError,
            match="permanently invalid.*SessionRevokedError",
        ):
            await manager.connect("test")

    @pytest.mark.asyncio
    async def test_connect_auth_key_unregistered_error(self) -> None:
        """Test connection with AuthKeyUnregisteredError raises SessionInvalidError."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.AuthKeyUnregisteredError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(
            SessionInvalidError,
            match="permanently invalid.*AuthKeyUnregisteredError",
        ):
            await manager.connect("test")

    @pytest.mark.asyncio
    async def test_connect_phone_banned_error(self) -> None:
        """Test connection with PhoneNumberBannedError raises SessionInvalidError."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.PhoneNumberBannedError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(
            SessionInvalidError,
            match="cannot be used.*PhoneNumberBannedError",
        ):
            await manager.connect("test")

        # Verify error message mentions account ban/deactivation
        info = manager.get_info("test")
        assert info is not None
        assert "deactivated or banned" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_connect_user_deactivated_ban_error(self) -> None:
        """Test connection with UserDeactivatedBanError raises SessionInvalidError."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.UserDeactivatedBanError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(
            SessionInvalidError,
            match="cannot be used.*UserDeactivatedBanError",
        ):
            await manager.connect("test")

        # Verify error message mentions account deactivation
        info = manager.get_info("test")
        assert info is not None
        assert "deactivated or banned" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_connect_session_password_needed_error(self) -> None:
        """Test connection with SessionPasswordNeededError raises SessionReauthRequiredError."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionPasswordNeededError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(
            SessionReauthRequiredError,
            match="requires 2FA password",
        ):
            await manager.connect("test")

    @pytest.mark.asyncio
    async def test_connect_session_expired_error(self) -> None:
        """Test connection with SessionExpiredError raises SessionReauthRequiredError."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionExpiredError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(
            SessionReauthRequiredError,
            match="has expired",
        ):
            await manager.connect("test")

    @pytest.mark.asyncio
    async def test_invalid_session_state_and_error_message(self) -> None:
        """Test that session state is set to ERROR with appropriate message."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionRevokedError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(SessionInvalidError):
            await manager.connect("test")

        info = manager.get_info("test")
        assert info is not None
        assert info.state == SessionState.ERROR
        assert "Session is invalid" in info.error_message
        assert "new session file" in info.error_message

    @pytest.mark.asyncio
    async def test_reauth_required_state_and_error_message(self) -> None:
        """Test that session state is set to ERROR with appropriate message for reauth."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionPasswordNeededError(request=mock_request))
        manager.register("test", MockFactory(client))

        with pytest.raises(SessionReauthRequiredError):
            await manager.connect("test")

        info = manager.get_info("test")
        assert info is not None
        assert info.state == SessionState.ERROR
        assert "2FA" in info.error_message or "Two-factor" in info.error_message


class TestNetworkSwitchHandling:
    """Tests for network switch detection and handling."""

    def test_is_network_switch_error_broken_pipe(self) -> None:
        """Test detection of BrokenPipeError as network switch."""
        manager = SessionManager()
        error = BrokenPipeError("Broken pipe")

        result = manager._is_network_switch_error(error)

        assert result is True

    def test_is_network_switch_error_connection_reset(self) -> None:
        """Test detection of ConnectionResetError as network switch."""
        manager = SessionManager()
        error = ConnectionResetError("Connection reset by peer")

        result = manager._is_network_switch_error(error)

        assert result is True

    def test_is_network_switch_error_connection_aborted(self) -> None:
        """Test detection of ConnectionAbortedError as network switch."""
        manager = SessionManager()
        error = ConnectionAbortedError("Connection aborted")

        result = manager._is_network_switch_error(error)

        assert result is True

    def test_is_network_switch_error_oserror_with_errno(self) -> None:
        """Test detection of OSError with network errno as network switch."""
        manager = SessionManager()
        # errno 101 = ENETUNREACH (network unreachable)
        error = OSError(101, "Network is unreachable")

        result = manager._is_network_switch_error(error)

        assert result is True

    def test_is_network_switch_error_oserror_by_message(self) -> None:
        """Test detection of OSError by message content as network switch."""
        manager = SessionManager()
        error = OSError("Host is unreachable")

        result = manager._is_network_switch_error(error)

        assert result is True

    def test_is_network_switch_error_regular_error(self) -> None:
        """Test that regular errors are not detected as network switch."""
        manager = SessionManager()
        error = ValueError("Regular error")

        result = manager._is_network_switch_error(error)

        assert result is False

    @pytest.mark.asyncio
    async def test_handle_network_switch_reconnects(self) -> None:
        """Test that network switch handling reconnects the session."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        # Simulate network switch
        await manager._handle_network_switch("test")

        # Should have disconnected and reconnected
        assert client.disconnect_calls == 1
        assert client.connect_calls == 2  # Initial + reconnect
        assert client.connected

    @pytest.mark.asyncio
    async def test_handle_network_switch_sets_recovery_flag(self) -> None:
        """Test that network switch handling sets recovery flag during operation."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        # Create a slow connect to check flag during recovery
        original_connect = client.connect

        async def slow_connect():
            session = manager._sessions["test"]
            # Check flag is set during recovery
            assert session.is_recovering_from_switch
            await original_connect()

        client.connect = slow_connect

        # Get session reference
        session = manager._sessions["test"]

        # Initially not recovering
        assert not session.is_recovering_from_switch

        # Simulate network switch
        await manager._handle_network_switch("test")

        # Should be cleared after recovery
        assert not session.is_recovering_from_switch

    @pytest.mark.asyncio
    async def test_handle_network_switch_resets_error_tracking(self) -> None:
        """Test that successful network switch recovery resets error tracking."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        session = manager._sessions["test"]
        session.network_error_count = 5
        session.last_network_error_at = 12345.0

        # Simulate network switch
        await manager._handle_network_switch("test")

        # Error tracking should be reset
        assert session.network_error_count == 0
        assert session.last_network_error_at is None

    @pytest.mark.asyncio
    async def test_network_error_tracking_in_info(self) -> None:
        """Test that network error tracking is included in session info."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        session = manager._sessions["test"]
        session.network_error_count = 3
        session.last_network_error_at = 54321.0
        session.is_recovering_from_switch = True

        info = manager.get_info("test")

        assert info is not None
        assert info.network_error_count == 3
        assert info.last_network_error_at == 54321.0
        assert info.is_recovering_from_switch is True

    @pytest.mark.asyncio
    async def test_health_check_clears_old_network_errors(self) -> None:
        """Test that successful health checks clear old network errors."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        session = manager._sessions["test"]
        # Set old network error (> 60 seconds ago)
        current_time = asyncio.get_event_loop().time()
        session.network_error_count = 5
        session.last_network_error_at = current_time - 70

        # Run health check
        await manager._check_session_health("test")

        # Old network errors should be cleared
        assert session.network_error_count == 0
        assert session.last_network_error_at is None


class MockClientWithNetworkErrors(MockClient):
    """Mock client that can simulate network errors."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.network_error_on_next_get_me = False

    async def get_me(self) -> MagicMock:
        if self.network_error_on_next_get_me:
            self.network_error_on_next_get_me = False
            raise ConnectionResetError("Connection reset by peer")
        return await super().get_me()


class TestNetworkSwitchIntegration:
    """Integration tests for network switch handling."""

    @pytest.mark.asyncio
    async def test_health_check_detects_and_recovers_from_network_switch(self) -> None:
        """Test that health check detects network switch and triggers recovery."""
        manager = SessionManager()
        client = MockClientWithNetworkErrors()
        manager.register("test", MockFactory(client))
        await manager.connect("test")

        # Simulate network switch error on next health check
        client.network_error_on_next_get_me = True

        # Run health check - should detect error and trigger reconnection
        await manager._check_session_health("test")

        # Should have reconnected
        assert client.connect_calls == 2  # Initial + recovery
        assert client.disconnect_calls == 1
        assert client.connected

        session = manager._sessions["test"]
        assert session.network_error_count == 0  # Reset after successful recovery


class TestDeadSessionRecoveryFlow:
    """Tests for dead session detection and recovery UX flow."""

    @pytest.mark.asyncio
    async def test_dead_session_shows_session_expired_status(self) -> None:
        """Test that dead session shows 'Session expired' status, not generic 'Error'."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionExpiredError(request=mock_request))
        manager.register("dead_session", MockFactory(client))

        with pytest.raises(SessionReauthRequiredError):
            await manager.connect("dead_session")

        info = manager.get_info("dead_session")
        assert info is not None
        assert info.state == SessionState.ERROR
        # Error message should mention session expiration, not generic error
        assert "expired" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_dead_session_revoked_shows_distinct_status(self) -> None:
        """Test that revoked session shows 'Session invalid' status distinct from temporary errors."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionRevokedError(request=mock_request))
        manager.register("dead_session", MockFactory(client))

        with pytest.raises(SessionInvalidError):
            await manager.connect("dead_session")

        info = manager.get_info("dead_session")
        assert info is not None
        assert info.state == SessionState.ERROR
        # Error message should indicate permanent session death
        assert "invalid" in info.error_message.lower()
        assert "new session" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_dead_session_banned_account_shows_permanent_status(self) -> None:
        """Test that banned account shows distinct permanent error status."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.PhoneNumberBannedError(request=mock_request))
        manager.register("banned_session", MockFactory(client))

        with pytest.raises(SessionInvalidError):
            await manager.connect("banned_session")

        info = manager.get_info("banned_session")
        assert info is not None
        assert info.state == SessionState.ERROR
        # Error message should indicate account is banned/deactivated
        assert "deactivated" in info.error_message.lower() or "banned" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_temporary_error_vs_permanent_session_death(self) -> None:
        """Test that temporary errors (network) are distinct from permanent session death."""
        manager = SessionManager()

        # Temporary error
        temp_client = MockClient(fail_connect=True)
        manager.register("temp_error", MockFactory(temp_client))

        # Permanent error
        mock_request = MagicMock()
        perm_client = MockClient(auth_error=errors.SessionRevokedError(request=mock_request))
        manager.register("perm_error", MockFactory(perm_client))

        # Temporary error should be SessionConnectError
        with pytest.raises(SessionConnectError):
            await manager.connect("temp_error")

        # Permanent error should be SessionInvalidError
        with pytest.raises(SessionInvalidError):
            await manager.connect("perm_error")

        temp_info = manager.get_info("temp_error")
        perm_info = manager.get_info("perm_error")

        assert temp_info is not None
        assert perm_info is not None

        # Both are in ERROR state, but messages should be distinct
        assert temp_info.state == SessionState.ERROR
        assert perm_info.state == SessionState.ERROR

        # Permanent error should mention needing new session
        assert "new session" in perm_info.error_message.lower()
        # Temporary error should mention connection failure
        assert ("connection" in temp_info.error_message.lower() or
                "connect" in temp_info.error_message.lower())

    @pytest.mark.asyncio
    async def test_session_recovery_preserves_session_id(self) -> None:
        """Test that session recovery preserves session ID during reconnection."""
        manager = SessionManager()
        client = MockClient()
        manager.register("test_session", MockFactory(client))

        # Connect initially
        await manager.connect("test_session")
        info_before = manager.get_info("test_session")
        session_id_before = info_before.session_id

        # Simulate recovery scenario: disconnect and reconnect
        await manager.disconnect("test_session")
        await manager.connect("test_session")
        info_after = manager.get_info("test_session")
        session_id_after = info_after.session_id

        # Session ID should be preserved
        assert session_id_before == session_id_after == "test_session"

    @pytest.mark.asyncio
    async def test_reauth_required_error_is_recoverable(self) -> None:
        """Test that SessionReauthRequiredError indicates session can be recovered via re-auth."""
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.SessionExpiredError(request=mock_request))
        manager.register("expired_session", MockFactory(client))

        with pytest.raises(SessionReauthRequiredError) as exc_info:
            await manager.connect("expired_session")

        # Error should clearly indicate re-authentication is possible
        error = exc_info.value
        assert "expired" in str(error).lower()

        # Session info should also indicate this is recoverable (vs SessionInvalidError)
        info = manager.get_info("expired_session")
        assert info is not None
        # Error message should not say "new session needed"
        assert "new session" not in info.error_message.lower()
        # But should indicate re-auth is needed
        assert "reauthentication" in info.error_message.lower() or "expired" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_reconnect_flow_same_session_id(self) -> None:
        """Test that reconnect button preserves same session ID for recovery flow."""
        manager = SessionManager()
        client = MockClient()
        manager.register("my_account", MockFactory(client))

        # Initial connection
        await manager.connect("my_account")
        original_info = manager.get_info("my_account")
        assert original_info is not None
        original_id = original_info.session_id

        # Simulate recovery: disconnect and reconnect
        await manager.disconnect("my_account")
        await manager.connect("my_account")

        recovered_info = manager.get_info("my_account")
        assert recovered_info is not None
        recovered_id = recovered_info.session_id

        # Session ID should be the same
        assert original_id == recovered_id == "my_account"


class TestAuthKeyUnregisteredAutoRecovery:
    """Tests for AuthKeyUnregistered detection and auto-recovery flow.

    When SessionManager detects AuthKeyUnregisteredError during connect():
    1. It sets session state to ERROR with appropriate message
    2. It raises SessionInvalidError to signal caller should handle recovery
    3. The caller (e.g., router) can then delete the invalid session file and retry

    These tests verify SessionManager correctly identifies AuthKeyUnregistered
    as a recoverable error that requires session file deletion and re-authentication.
    """

    @pytest.mark.asyncio
    async def test_connect_authkey_unregistered_auto_delete(self) -> None:
        """Test that AuthKeyUnregisteredError is correctly identified for auto-recovery.

        SessionManager should:
        - Raise SessionInvalidError (not SessionConnectError)
        - Set state to ERROR with recovery-oriented message
        - Allow the session to be unregistered and re-registered for recovery
        """
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.AuthKeyUnregisteredError(request=mock_request))
        manager.register("test_session", MockFactory(client))

        # Connect should raise SessionInvalidError
        with pytest.raises(SessionInvalidError) as exc_info:
            await manager.connect("test_session")

        # Verify error type and message indicate recovery is possible
        error = exc_info.value
        assert "permanently invalid" in str(error).lower()
        assert "AuthKeyUnregisteredError" in str(error)

        # Verify session state allows for recovery
        info = manager.get_info("test_session")
        assert info is not None
        assert info.state == SessionState.ERROR
        # Message should mention getting new session (i.e., recovery is possible)
        assert "new session" in info.error_message.lower()

    @pytest.mark.asyncio
    async def test_session_file_deletion_signaled_for_authkey_unregistered(self) -> None:
        """Verify SessionManager state indicates session file should be deleted.

        After AuthKeyUnregisteredError, the error message should clearly indicate
        that the session file is invalid and needs to be replaced.
        """
        manager = SessionManager()
        mock_request = MagicMock()
        client = MockClient(auth_error=errors.AuthKeyUnregisteredError(request=mock_request))
        manager.register("invalid_session", MockFactory(client))

        with pytest.raises(SessionInvalidError):
            await manager.connect("invalid_session")

        info = manager.get_info("invalid_session")
        assert info is not None
        # Error should mention "unregistered" or "revoked" - indicating file is corrupt/invalid
        error_lower = info.error_message.lower()
        assert "invalid" in error_lower or "unregistered" in error_lower or "revoked" in error_lower
        # Should mention need for new session file (signals deletion + re-auth needed)
        assert "new session" in error_lower or "session file" in error_lower

    @pytest.mark.asyncio
    async def test_reregister_after_authkey_unregistered_allows_recovery(self) -> None:
        """Test that session can be re-registered after AuthKeyUnregistered for recovery.

        After AuthKeyUnregisteredError:
        1. Session is in ERROR state
        2. Disconnect and unregister should work
        3. Re-registering with new client should allow fresh connection

        This simulates the recovery flow where session file is deleted and
        a new session file is created.
        """
        manager = SessionManager()
        mock_request = MagicMock()
        invalid_client = MockClient(auth_error=errors.AuthKeyUnregisteredError(request=mock_request))
        manager.register("recovering_session", MockFactory(invalid_client))

        # First connect fails with AuthKeyUnregistered
        with pytest.raises(SessionInvalidError):
            await manager.connect("recovering_session")

        # Verify session is in error state
        info = manager.get_info("recovering_session")
        assert info is not None
        assert info.state == SessionState.ERROR

        # Unregister the failed session (simulates cleanup before re-auth)
        manager.unregister("recovering_session")

        # Re-register with a new "valid" client (simulates new session file after send_code)
        valid_client = MockClient()
        manager.register("recovering_session", MockFactory(valid_client))

        # Now connection should succeed
        result = await manager.connect("recovering_session")
        assert result is valid_client
        assert valid_client.connected

        # Session should be connected
        info = manager.get_info("recovering_session")
        assert info is not None
        assert info.state == SessionState.CONNECTED

    @pytest.mark.asyncio
    async def test_authkey_unregistered_vs_other_auth_errors(self) -> None:
        """Verify AuthKeyUnregisteredError is handled same as SessionRevokedError.

        Both AuthKeyUnregisteredError and SessionRevokedError should:
        - Raise SessionInvalidError (not SessionReauthRequiredError)
        - Indicate permanent session invalidity
        - Require new session file (not just re-authentication)

        This is different from SessionExpiredError which raises SessionReauthRequiredError.
        """
        manager = SessionManager()
        mock_request = MagicMock()

        # Test AuthKeyUnregisteredError
        client1 = MockClient(auth_error=errors.AuthKeyUnregisteredError(request=mock_request))
        manager.register("unregistered", MockFactory(client1))

        with pytest.raises(SessionInvalidError):
            await manager.connect("unregistered")

        info1 = manager.get_info("unregistered")
        manager.unregister("unregistered")

        # Test SessionRevokedError - should behave the same
        client2 = MockClient(auth_error=errors.SessionRevokedError(request=mock_request))
        manager.register("revoked", MockFactory(client2))

        with pytest.raises(SessionInvalidError):
            await manager.connect("revoked")

        info2 = manager.get_info("revoked")

        # Both should have similar error handling
        assert info1.state == info2.state == SessionState.ERROR
        # Both should mention new session needed
        assert "new session" in info1.error_message.lower()
        assert "new session" in info2.error_message.lower()
