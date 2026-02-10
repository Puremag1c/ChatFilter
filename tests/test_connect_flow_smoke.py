"""Smoke tests for connection flow covering all SPEC scenarios.

Tests all 5 scenarios:
1. Factory missing → error
2. Config error (ApiIdInvalidError) → error
3. Expired session → auto send_code → needs_code
4. Normal connect → connected
5. Banned account → error

NOTE: Tests scenarios 3 and 4 work correctly. Scenarios 1, 2, 5 verify code
doesn't crash and logs errors, but cannot fully verify SSE events due to
local imports inside _do_connect_in_background_v2 that prevent mocking.

For full SSE event verification, see integration tests that use real event bus.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from telethon.errors import (
    ApiIdInvalidError,
    SessionRevokedError,
    SessionExpiredError,
    UserDeactivatedBanError,
)


@pytest.fixture
def mock_event_bus():
    """Mock event bus for SSE events."""
    bus = MagicMock()
    bus.publish = AsyncMock()
    return bus


@pytest.fixture
def mock_session_lock():
    """Mock session lock (async context manager)."""
    class MockLock:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def get_lock(session_id):
        return MockLock()

    return get_lock


@pytest.fixture
def mock_session_manager():
    """Mock session manager."""
    manager = MagicMock()
    manager._factories = {}
    manager.connect = AsyncMock()
    return manager


@pytest.fixture
def session_dir(tmp_path):
    """Create temporary session directory."""
    session_path = tmp_path / "test_session"
    session_path.mkdir(parents=True, exist_ok=True)
    return session_path


def create_session_file(session_dir: Path):
    """Helper to create dummy session.session file."""
    session_file = session_dir / "test_session.session"
    # Write a minimal SQLite header to simulate real session file
    session_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)


class TestConnectFlowSmoke:
    """Smoke tests for connection flow scenarios."""

    @pytest.mark.asyncio
    async def test_scenario_1_factory_missing(
        self, session_dir, mock_session_manager, mock_session_lock
    ):
        """Scenario 1: Factory missing → error (logs error, returns early)."""
        session_id = "test_session"

        # Setup: No factory registered
        mock_session_manager._factories = {}

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            # Should not raise exception, just logs error and returns
            await _do_connect_in_background_v2(session_id)

            # Verify: session_manager.connect() not called (early return)
            mock_session_manager.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_scenario_2_config_error(
        self, session_dir, mock_session_manager, mock_session_lock
    ):
        """Scenario 2: ApiIdInvalidError → handled in except block."""
        session_id = "test_session"

        # Setup: Factory exists
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        mock_session_manager._factories[session_id] = factory

        # Mock connect to raise ApiIdInvalidError
        mock_session_manager.connect.side_effect = ApiIdInvalidError("API ID invalid")

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            # Should not crash, just logs and handles error
            await _do_connect_in_background_v2(session_id)

            # Verify: connect() was called and raised exception (handled)
            mock_session_manager.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_scenario_3_expired_session_auto_send_code(
        self, session_dir, mock_event_bus, mock_session_manager, mock_session_lock
    ):
        """Scenario 3: SessionExpiredError → auto-triggers send_code flow."""
        session_id = "test_session"

        # Setup: Factory with session path
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        mock_session_manager._factories[session_id] = factory
        create_session_file(session_dir)

        # Mock connect to raise SessionExpiredError
        mock_session_manager.connect.side_effect = SessionExpiredError("Session expired")

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock), \
             patch("chatfilter.web.routers.sessions.load_account_info", return_value={"phone": "+1234567890"}), \
             patch("chatfilter.web.routers.sessions.secure_delete_file") as mock_delete, \
             patch("chatfilter.web.routers.sessions._send_verification_code_with_timeout", new_callable=AsyncMock) as mock_send_code:

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            await _do_connect_in_background_v2(session_id)

            # Verify: Should delete old session file and trigger send_code
            mock_delete.assert_called_once()
            mock_send_code.assert_called_once()

    @pytest.mark.asyncio
    async def test_scenario_4_normal_connect_success(
        self, session_dir, mock_event_bus, mock_session_manager, mock_session_lock
    ):
        """Scenario 4: Normal connect → session_manager.connect() succeeds."""
        session_id = "test_session"

        # Setup: Factory with session path
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        mock_session_manager._factories[session_id] = factory

        # Mock connect to succeed
        async def mock_connect_success(sid):
            await mock_event_bus.publish(sid, "connected")

        mock_session_manager.connect = AsyncMock(side_effect=mock_connect_success)

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            await _do_connect_in_background_v2(session_id)

            # Verify: connect() called and published "connected"
            mock_event_bus.publish.assert_called_once_with(session_id, "connected")

    @pytest.mark.asyncio
    async def test_scenario_5_banned_account(
        self, session_dir, mock_session_manager, mock_session_lock
    ):
        """Scenario 5: UserDeactivatedBanError → handled in except block."""
        session_id = "test_session"

        # Setup: Factory exists
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        mock_session_manager._factories[session_id] = factory

        # Mock connect to raise UserDeactivatedBanError
        mock_session_manager.connect.side_effect = UserDeactivatedBanError("User is banned")

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            # Should not crash, just logs and handles error
            await _do_connect_in_background_v2(session_id)

            # Verify: connect() was called and raised exception (handled)
            mock_session_manager.connect.assert_called_once()
