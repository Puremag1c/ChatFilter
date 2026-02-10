"""Tests for device confirmation ("Is this you?") handling.

Tests Bug 2 fix: Telegram requires device confirmation detection.
These are integration tests that verify the needs_confirmation state is properly
handled across verify-code and verify-2fa endpoints.
"""

import re
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.web.auth_state import AuthState, AuthStep


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag."""
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


@pytest.mark.asyncio
class TestDeviceConfirmation:
    """Test device confirmation detection and handling."""

    @pytest.fixture
    def mock_ensure_data_dir(self, isolated_tmp_dir: Path, monkeypatch):
        """Mock ensure_data_dir to return isolated tmp dir."""
        from unittest.mock import MagicMock

        mock_dir = MagicMock(return_value=isolated_tmp_dir)
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir", mock_dir
        )
        yield isolated_tmp_dir

    async def test_verify_code_needs_confirmation(
        self, fastapi_test_client, mock_ensure_data_dir: Path
    ) -> None:
        """Test verify_code detects device confirmation needed."""
        session_dir = mock_ensure_data_dir / "test_needs_confirmation"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create account_info.json
        account_info = {
            "user_id": 123456789,
            "phone": "+14385515736",
            "first_name": "Test",
            "last_name": "User",
        }
        from chatfilter.web.routers.sessions import save_account_info

        save_account_info(session_dir, account_info)

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True

        # Mock successful sign_in
        mock_client.sign_in = AsyncMock(return_value=MagicMock())

        # Mock GetAuthorizationsRequest to return unconfirmed session
        mock_authorization = MagicMock()
        mock_authorization.current = True
        mock_authorization.unconfirmed = True  # Device confirmation needed

        mock_authorizations = MagicMock()
        mock_authorizations.authorizations = [mock_authorization]

        async def mock_call(*args, **kwargs):
            return mock_authorizations

        mock_client.__call__ = mock_call

        mock_client.disconnect = AsyncMock()

        # Create auth state
        auth_state = AuthState(
            auth_id="test_auth_id",
            session_name="test_needs_confirmation",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.PHONE_SENT,
            client=mock_client,
        )

        # Get CSRF token from home page
        home_response = fastapi_test_client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        with (
            patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_get_mgr,
            patch("chatfilter.web.routers.sessions.get_event_bus") as mock_event_bus_fn,
            patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        ):
            mock_mgr = MagicMock()
            mock_mgr.get_auth_state = AsyncMock(return_value=auth_state)
            mock_mgr.update_auth_state = AsyncMock()
            mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_get_mgr.return_value = mock_mgr

            mock_event_bus = MagicMock()
            mock_event_bus.publish = AsyncMock()
            mock_event_bus_fn.return_value = mock_event_bus

            mock_sm = MagicMock()
            mock_sm._factories = {}
            mock_get_sm.return_value = mock_sm

            response = fastapi_test_client.post(
                "/api/sessions/test_needs_confirmation/verify-code",
                data={
                    "auth_id": "test_auth_id",
                    "code": "12345",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            html = response.text

            # Should show needs_confirmation state
            assert "needs_confirmation" in html
            assert "Awaiting Confirmation" in html

            # Should have updated auth state to NEED_CONFIRMATION
            mock_mgr.update_auth_state.assert_called()
            calls = mock_mgr.update_auth_state.call_args_list
            assert any(
                call.kwargs.get("step") == AuthStep.NEED_CONFIRMATION for call in calls
            )

            # Should have published needs_confirmation SSE event
            mock_event_bus.publish.assert_called_with(
                "test_needs_confirmation", "needs_confirmation"
            )

    async def test_verify_2fa_needs_confirmation(
        self, fastapi_test_client, mock_ensure_data_dir: Path
    ) -> None:
        """Test verify_2fa detects device confirmation needed."""
        session_dir = mock_ensure_data_dir / "test_2fa_needs_confirmation"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create account_info.json
        account_info = {
            "user_id": 123456789,
            "phone": "+14385515736",
            "first_name": "Test",
            "last_name": "User",
        }
        from chatfilter.web.routers.sessions import save_account_info

        save_account_info(session_dir, account_info)

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True

        # Mock successful sign_in with 2FA
        mock_client.sign_in = AsyncMock(return_value=MagicMock())

        # Mock GetAuthorizationsRequest to return unconfirmed session
        mock_authorization = MagicMock()
        mock_authorization.current = True
        mock_authorization.unconfirmed = True  # Device confirmation needed

        mock_authorizations = MagicMock()
        mock_authorizations.authorizations = [mock_authorization]

        async def mock_call(*args, **kwargs):
            return mock_authorizations

        mock_client.__call__ = mock_call

        mock_client.disconnect = AsyncMock()

        # Create auth state
        auth_state = AuthState(
            auth_id="test_auth_id_2fa",
            session_name="test_2fa_needs_confirmation",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.NEED_2FA,
            client=mock_client,
        )

        # Get CSRF token from home page
        home_response = fastapi_test_client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        with (
            patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_get_mgr,
            patch("chatfilter.web.routers.sessions.get_event_bus") as mock_event_bus_fn,
            patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        ):
            mock_mgr = MagicMock()
            mock_mgr.get_auth_state = AsyncMock(return_value=auth_state)
            mock_mgr.update_auth_state = AsyncMock()
            mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_get_mgr.return_value = mock_mgr

            mock_event_bus = MagicMock()
            mock_event_bus.publish = AsyncMock()
            mock_event_bus_fn.return_value = mock_event_bus

            mock_sm = MagicMock()
            mock_sm._factories = {}
            mock_get_sm.return_value = mock_sm

            response = fastapi_test_client.post(
                "/api/sessions/test_2fa_needs_confirmation/verify-2fa",
                data={
                    "auth_id": "test_auth_id_2fa",
                    "password": "test_password",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            html = response.text

            # Should show needs_confirmation state
            assert "needs_confirmation" in html
            assert "Awaiting Confirmation" in html

            # Should have updated auth state to NEED_CONFIRMATION
            mock_mgr.update_auth_state.assert_called()
            calls = mock_mgr.update_auth_state.call_args_list
            assert any(
                call.kwargs.get("step") == AuthStep.NEED_CONFIRMATION for call in calls
            )

            # Should have published needs_confirmation SSE event
            mock_event_bus.publish.assert_called_with(
                "test_2fa_needs_confirmation", "needs_confirmation"
            )
