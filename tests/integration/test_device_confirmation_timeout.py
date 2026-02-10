"""Integration test for device confirmation timeout scenario.

Test Coverage:
- Device confirmation polling task behavior on timeout
- SSE event publication (disconnected)
- Auth state cleanup
- Client disconnection
- AuthKeyUnregisteredError retry behavior
- RPCError handling
- Successful confirmation flow
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.web.auth_state import AuthState, AuthStep


def _make_auth_state_with_client(
    session_name: str = "testsession",
    auth_id: str = "auth-timeout-test",
) -> AuthState:
    """Create a mock AuthState with connected client for polling.

    IMPORTANT: This is a synchronous helper - no await allowed.
    """
    # Create an AsyncMock for the client so that client(...) is properly awaitable
    client = AsyncMock()
    client.is_connected.return_value = True
    client.disconnect = AsyncMock()

    # Mock GetAuthorizationsRequest - returns unconfirmed state by default
    # Each test will override client.return_value as needed
    mock_result = MagicMock()
    mock_auth = MagicMock()
    mock_auth.current = True
    mock_auth.unconfirmed = True  # Still waiting for confirmation
    mock_result.authorizations = [mock_auth]

    # Set the return value for when client is called
    client.return_value = mock_result

    return AuthState(
        auth_id=auth_id,
        session_name=session_name,
        api_id=12345,
        api_hash="testhash",
        proxy_id="",
        phone="+79001234567",
        step=AuthStep.NEED_CONFIRMATION,
        phone_code_hash="test_hash",
        client=client,
    )


class TestDeviceConfirmationTimeout:
    """Integration tests for device confirmation timeout scenario."""

    @pytest.mark.asyncio
    async def test_polling_task_timeout_triggers_cleanup(self) -> None:
        """Device confirmation polling task should timeout after 5 minutes and clean up state.

        Scenario:
        1. Start device confirmation polling
        2. Mock time to simulate timeout (300s elapsed)
        3. Verify: client.disconnect() called
        4. Verify: auth_state removed
        5. Verify: SSE 'disconnected' event published
        """
        from chatfilter.web.routers.sessions import _poll_device_confirmation

        auth_state = _make_auth_state_with_client()
        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        # Mock auth manager
        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.remove_auth_state = AsyncMock()

        # Mock event bus
        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        # Mock time.time() to simulate timeout immediately
        initial_time = 1000.0
        timeout_time = initial_time + 301  # Just over 300s timeout

        def time_gen():
            yield initial_time  # Start time
            while True:
                yield timeout_time  # All subsequent calls return timeout

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
        ):
            # Run polling task (should timeout immediately)
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Verify cleanup happened
        auth_state.client.disconnect.assert_called_once()
        mock_auth_manager.remove_auth_state.assert_called_once_with(auth_id)
        mock_event_bus.publish.assert_called_once_with(safe_name, "disconnected")

    @pytest.mark.asyncio
    async def test_polling_task_timeout_with_disconnect_error(self) -> None:
        """Polling task should handle client.disconnect() errors gracefully during timeout cleanup."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation

        auth_state = _make_auth_state_with_client()

        # Make disconnect raise an error
        auth_state.client.disconnect = AsyncMock(side_effect=RuntimeError("Disconnect failed"))

        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.remove_auth_state = AsyncMock()

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        # Simulate timeout
        initial_time = 1000.0
        timeout_time = initial_time + 301

        def time_gen():
            yield initial_time
            while True:
                yield timeout_time

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
        ):
            # Should not raise despite disconnect error
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Cleanup should still complete
        mock_auth_manager.remove_auth_state.assert_called_once_with(auth_id)
        mock_event_bus.publish.assert_called_once_with(safe_name, "disconnected")

    @pytest.mark.asyncio
    async def test_polling_task_stops_if_auth_state_removed_externally(self) -> None:
        """Polling task should exit gracefully if auth_state is removed externally (e.g., user cancelled)."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation

        auth_state = _make_auth_state_with_client()
        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        # First call returns auth_state, second call returns None (state removed)
        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(side_effect=[auth_state, None])
        mock_auth_manager.remove_auth_state = AsyncMock()

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        # Mock time to NOT timeout yet
        initial_time = 1000.0
        still_within_timeout = initial_time + 10  # 10s elapsed, not timed out

        def time_gen():
            yield initial_time
            while True:
                yield still_within_timeout

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
        ):
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Should NOT publish event or call remove_auth_state (already removed externally)
        mock_event_bus.publish.assert_not_called()
        mock_auth_manager.remove_auth_state.assert_not_called()

    @pytest.mark.asyncio
    async def test_polling_task_handles_auth_key_unregistered_error(self) -> None:
        """Polling task should continue polling if GetAuthorizationsRequest raises AuthKeyUnregisteredError."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation
        from telethon.errors import AuthKeyUnregisteredError

        auth_state = _make_auth_state_with_client()

        # First call: AuthKeyUnregisteredError (expected during confirmation wait)
        # Second call: still unconfirmed
        # Third call: timeout
        call_count = 0

        async def mock_call_side_effect(*args):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise AuthKeyUnregisteredError(request=None)
            # Subsequent calls return unconfirmed state
            mock_result = MagicMock()
            mock_auth = MagicMock()
            mock_auth.current = True
            mock_auth.unconfirmed = True
            mock_result.authorizations = [mock_auth]
            return mock_result

        auth_state.client.side_effect = mock_call_side_effect

        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        mock_auth_manager = AsyncMock()
        # Return auth_state for first 3 checks, then trigger timeout
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.remove_auth_state = AsyncMock()

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        # Mock time: start, after first poll, then timeout
        initial_time = 1000.0
        timeout_time = initial_time + 301

        def time_gen():
            yield initial_time  # Start
            yield initial_time + 5  # After first poll (AuthKeyUnregisteredError)
            yield initial_time + 10  # After second poll (still unconfirmed)
            while True:
                yield timeout_time  # Timeout

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
            patch("asyncio.sleep", new_callable=AsyncMock),  # Skip actual sleep
        ):
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Should timeout and cleanup despite AuthKeyUnregisteredError
        auth_state.client.disconnect.assert_called_once()
        mock_auth_manager.remove_auth_state.assert_called_once_with(auth_id)
        mock_event_bus.publish.assert_called_once_with(safe_name, "disconnected")

    @pytest.mark.asyncio
    async def test_polling_task_cleanup_on_rpc_error(self) -> None:
        """Polling task should cleanup and publish error on Telegram RPC errors."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation
        from telethon.errors import RPCError

        auth_state = _make_auth_state_with_client()

        # GetAuthorizationsRequest raises RPCError
        rpc_error = RPCError(request=None, code=500, message="API error")
        auth_state.client.side_effect = rpc_error

        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.remove_auth_state = AsyncMock()

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        # Mock time: start, then one poll attempt
        initial_time = 1000.0

        def time_gen():
            yield initial_time
            while True:
                yield initial_time + 5

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
        ):
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Should cleanup on RPCError
        mock_auth_manager.remove_auth_state.assert_called_once_with(auth_id)
        mock_event_bus.publish.assert_called_once_with(safe_name, "error")

    @pytest.mark.asyncio
    async def test_polling_task_confirms_successfully_before_timeout(self) -> None:
        """Polling task should detect confirmation and finalize auth before timeout."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation

        auth_state = _make_auth_state_with_client()

        # First poll: still unconfirmed
        # Second poll: confirmed! (unconfirmed=False or missing)
        call_count = 0

        async def mock_call_side_effect(*args):
            nonlocal call_count
            call_count += 1
            mock_result = MagicMock()
            mock_auth = MagicMock()
            mock_auth.current = True
            if call_count == 1:
                mock_auth.unconfirmed = True  # Still waiting
            else:
                mock_auth.unconfirmed = False  # Confirmed!
            mock_result.authorizations = [mock_auth]
            return mock_result

        auth_state.client.side_effect = mock_call_side_effect

        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        mock_finalize = AsyncMock()

        # Mock time: start, first poll, second poll (confirmed)
        initial_time = 1000.0

        def time_gen():
            yield initial_time  # Start
            yield initial_time + 5  # First poll (unconfirmed)
            while True:
                yield initial_time + 10  # Second poll (confirmed) and beyond

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions._finalize_reconnect_auth", mock_finalize),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Should call finalize (NOT timeout cleanup)
        mock_finalize.assert_called_once()
        # Auth state NOT removed (finalize handles it)
        mock_auth_manager.remove_auth_state.assert_not_called()
        # No disconnected event published (finalize publishes 'connected')
        mock_event_bus.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_polling_task_handles_finalize_error(self) -> None:
        """Polling task should publish error event if _finalize_reconnect_auth fails."""
        from chatfilter.web.routers.sessions import _poll_device_confirmation

        auth_state = _make_auth_state_with_client()

        # Mock client to return confirmed state immediately
        async def mock_call_confirmed(*args):
            mock_result = MagicMock()
            mock_auth = MagicMock()
            mock_auth.current = True
            mock_auth.unconfirmed = False  # Confirmed
            mock_result.authorizations = [mock_auth]
            return mock_result

        auth_state.client.side_effect = mock_call_confirmed

        safe_name = "testsession"
        auth_id = "auth-timeout-test"

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        # Mock _finalize_reconnect_auth to raise an error
        mock_finalize = AsyncMock(side_effect=RuntimeError("Finalize failed"))

        initial_time = 1000.0

        def time_gen():
            yield initial_time
            while True:
                yield initial_time + 5

        with (
            patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus),
            patch("chatfilter.web.routers.sessions._finalize_reconnect_auth", mock_finalize),
            patch("chatfilter.web.routers.sessions.time.time", side_effect=time_gen()),
        ):
            await _poll_device_confirmation(safe_name, auth_id, mock_auth_manager)

        # Should call finalize and publish error on failure
        mock_finalize.assert_called_once()
        mock_event_bus.publish.assert_called_once_with(safe_name, "error")
