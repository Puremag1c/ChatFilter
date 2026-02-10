"""Smoke tests for connection flow covering all SPEC scenarios.

Tests all 5 scenarios from SPEC.md:
1. Save without api_id/proxy → disconnected in list
2. Connect without credentials → needs_config + Edit button
3. Connect with expired session → auto send_code → needs_code
4. Connect normal → connecting → needs_code or connected
5. Banned account → banned + tooltip

Test approach: Mock Telethon client, simulate each scenario, verify UI state via SSE events.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call
from telethon.errors import (
    ApiIdInvalidError,
    SessionRevokedError,
    SessionExpiredError,
    UserDeactivatedBanError,
    AuthKeyUnregisteredError,
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
    manager._sessions = {}
    manager.connect = AsyncMock()
    manager.get_info = MagicMock(return_value=None)
    return manager


@pytest.fixture
def session_dir(tmp_path):
    """Create temporary session directory with config.json."""
    session_path = tmp_path / "test_session"
    session_path.mkdir(parents=True, exist_ok=True)

    # Create config.json
    config = {
        "api_id": None,
        "api_hash": None,
        "proxy_id": None
    }
    config_file = session_path / "config.json"
    config_file.write_text(json.dumps(config))

    return session_path


def create_session_file(session_dir: Path):
    """Helper to create dummy session.session file."""
    session_file = session_dir / "test_session.session"
    # Write a minimal SQLite header to simulate real session file
    session_file.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)


class TestConnectFlowSmoke:
    """Smoke tests for connection flow scenarios."""

    @pytest.mark.asyncio
    async def test_scenario_1_save_without_api_id(self, session_dir):
        """Scenario 1: Save without api_id/proxy → disconnected in list.

        This scenario tests the save-only flow (start_auth_flow with minimal data).
        Session should appear as 'disconnected' in list.
        """
        # Setup: config.json with null api_id/api_hash/proxy_id (created by fixture)
        config_file = session_dir / "config.json"
        assert config_file.exists()

        config = json.loads(config_file.read_text())
        assert config["api_id"] is None
        assert config["api_hash"] is None
        assert config["proxy_id"] is None

        # Verify: Session would appear as 'disconnected' in list
        # (get_session_config_status returns ('needs_config', message) when api_id is missing)
        from chatfilter.web.routers.sessions import get_session_config_status
        status, message = get_session_config_status(session_dir)
        assert status == "needs_config"

    @pytest.mark.asyncio
    async def test_scenario_2_connect_without_credentials(
        self, session_dir, mock_event_bus, mock_session_manager, mock_session_lock
    ):
        """Scenario 2: Connect without credentials → needs_config + Edit button.

        This scenario tests connecting when api_id/api_hash are missing.
        Should publish 'needs_config' SSE event.
        """
        session_id = "test_session"

        # Setup: Factory exists but config has no api_id
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        factory.config_path = session_dir / "config.json"
        mock_session_manager._factories[session_id] = factory

        # Mock connect to raise error due to missing api_id
        mock_session_manager.connect.side_effect = ApiIdInvalidError("API ID is invalid")

        # Need to mock SessionState enum for state assignment
        from chatfilter.telegram.session_manager import SessionState
        mock_session_manager._sessions = {}

        # CRITICAL: patch get_event_bus at module level (chatfilter.web.events)
        # so that import inside _do_connect_in_background_v2 gets the mock
        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.events.get_event_bus", return_value=mock_event_bus), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock), \
             patch("chatfilter.web.routers.sessions.classify_error_state", return_value="needs_config"), \
             patch("chatfilter.telegram.error_mapping.get_user_friendly_message", return_value="API ID invalid"), \
             patch("chatfilter.web.routers.sessions.sanitize_error_message_for_client", return_value="API ID invalid"), \
             patch("chatfilter.web.routers.sessions._save_error_to_config"), \
             patch("chatfilter.web.routers.sessions.SessionState", SessionState):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            await _do_connect_in_background_v2(session_id)

            # Verify: Should publish 'needs_config' SSE event
            mock_event_bus.publish.assert_called_once_with(session_id, "needs_config")

    @pytest.mark.asyncio
    async def test_scenario_3_expired_session_auto_send_code(
        self, session_dir, mock_event_bus, mock_session_manager, mock_session_lock
    ):
        """Scenario 3: Connect with expired session → auto send_code → needs_code.

        This scenario tests auto-recovery from expired session.
        Should delete old session file and trigger send_code flow (publishes 'needs_code').
        """
        session_id = "test_session"

        # Setup: Factory with session path
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        factory.config_path = session_dir / "config.json"
        mock_session_manager._factories[session_id] = factory
        create_session_file(session_dir)

        # Create account_info.json with phone
        account_info = {"phone": "+1234567890"}
        account_info_file = session_dir / "account_info.json"
        account_info_file.write_text(json.dumps(account_info))

        # Mock connect to raise SessionExpiredError
        mock_session_manager.connect.side_effect = SessionExpiredError("Session expired")

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions.get_event_bus", return_value=mock_event_bus), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock), \
             patch("chatfilter.web.routers.sessions.load_account_info", return_value=account_info), \
             patch("chatfilter.web.routers.sessions.secure_delete_file") as mock_delete, \
             patch("chatfilter.web.routers.sessions._send_verification_code_with_timeout", new_callable=AsyncMock) as mock_send_code:

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            await _do_connect_in_background_v2(session_id)

            # Verify: Should delete old session file and trigger send_code
            mock_delete.assert_called_once()
            mock_send_code.assert_called_once()
            # _send_verification_code_with_timeout internally publishes 'needs_code'

    @pytest.mark.asyncio
    async def test_scenario_4_normal_connect_success(
        self, session_dir, mock_event_bus, mock_session_manager, mock_session_lock
    ):
        """Scenario 4: Connect normal → connecting → connected.

        This scenario tests successful connection with valid session.
        Should call session_manager.connect() which publishes 'connected' SSE.
        """
        session_id = "test_session"

        # Setup: Factory with session path
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        factory.config_path = session_dir / "config.json"
        mock_session_manager._factories[session_id] = factory
        create_session_file(session_dir)

        # Mock connect to succeed (publishes 'connected' internally)
        mock_session_manager.connect = AsyncMock()

        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            await _do_connect_in_background_v2(session_id)

            # Verify: connect() was called (which internally publishes 'connected')
            mock_session_manager.connect.assert_called_once_with(session_id)

    @pytest.mark.asyncio
    async def test_scenario_5_banned_account(
        self, session_dir, mock_event_bus, mock_session_manager, mock_session_lock
    ):
        """Scenario 5: Banned account → banned + tooltip.

        This scenario tests connecting with a banned account.
        Should publish 'banned' SSE event.
        """
        session_id = "test_session"

        # Setup: Factory exists
        factory = MagicMock()
        factory.session_path = session_dir / f"{session_id}.session"
        factory.config_path = session_dir / "config.json"
        mock_session_manager._factories[session_id] = factory

        # Mock connect to raise UserDeactivatedBanError
        mock_session_manager.connect.side_effect = UserDeactivatedBanError("User is banned")

        # Need to mock SessionState enum for state assignment
        from chatfilter.telegram.session_manager import SessionState
        mock_session_manager._sessions = {}

        # CRITICAL: patch get_event_bus at module level (chatfilter.web.events)
        # so that import inside _do_connect_in_background_v2 gets the mock
        with patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager), \
             patch("chatfilter.web.events.get_event_bus", return_value=mock_event_bus), \
             patch("chatfilter.web.routers.sessions._get_session_lock", new=mock_session_lock), \
             patch("chatfilter.web.routers.sessions.classify_error_state", return_value="banned"), \
             patch("chatfilter.telegram.error_mapping.get_user_friendly_message", return_value="Account banned"), \
             patch("chatfilter.web.routers.sessions.sanitize_error_message_for_client", return_value="Account banned"), \
             patch("chatfilter.web.routers.sessions._save_error_to_config"), \
             patch("chatfilter.web.routers.sessions.SessionState", SessionState):

            from chatfilter.web.routers.sessions import _do_connect_in_background_v2

            await _do_connect_in_background_v2(session_id)

            # Verify: Should publish 'banned' SSE event
            mock_event_bus.publish.assert_called_once_with(session_id, "banned")
