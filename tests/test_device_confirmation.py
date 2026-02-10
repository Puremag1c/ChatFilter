"""Tests for device confirmation ("Is this you?") handling.

Tests Bug 2 fix: Telegram requires device confirmation detection.
These are integration tests that verify the needs_confirmation state is properly
handled across verify-code and verify-2fa endpoints, and that
list_stored_sessions maps NEED_CONFIRMATION auth step correctly.
"""

import json
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

        # Use AsyncMock for the client to handle all async operations
        mock_client = AsyncMock()
        mock_client.is_connected.return_value = True

        # Mock successful sign_in
        mock_client.sign_in = AsyncMock(return_value=MagicMock())

        # Mock GetAuthorizationsRequest to return unconfirmed session
        mock_authorization = MagicMock()
        mock_authorization.current = True
        mock_authorization.unconfirmed = True  # Device confirmation needed

        mock_authorizations = MagicMock()
        mock_authorizations.authorizations = [mock_authorization]

        # Make client(...) return an awaitable
        # AsyncMock's __call__ is already async-aware, just set return_value
        mock_client.return_value = mock_authorizations

        # Mock get_me() for account info retrieval
        mock_user = MagicMock()
        mock_user.id = 123456789
        mock_user.phone = "+14385515736"
        mock_user.first_name = "Test"
        mock_user.last_name = "User"
        mock_client.get_me = AsyncMock(return_value=mock_user)

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

        # Use AsyncMock for the client to handle all async operations
        mock_client = AsyncMock()
        mock_client.is_connected.return_value = True

        # Mock successful sign_in with 2FA
        mock_client.sign_in = AsyncMock(return_value=MagicMock())

        # Mock GetAuthorizationsRequest to return unconfirmed session
        mock_authorization = MagicMock()
        mock_authorization.current = True
        mock_authorization.unconfirmed = True  # Device confirmation needed

        mock_authorizations = MagicMock()
        mock_authorizations.authorizations = [mock_authorization]

        # Make client(...) return an awaitable
        # AsyncMock's __call__ is already async-aware, just set return_value
        mock_client.return_value = mock_authorizations

        # Mock get_me() for account info retrieval
        mock_user = MagicMock()
        mock_user.id = 123456789
        mock_user.phone = "+14385515736"
        mock_user.first_name = "Test"
        mock_user.last_name = "User"
        mock_client.get_me = AsyncMock(return_value=mock_user)

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

    async def test_list_stored_sessions_needs_confirmation_state(
        self, mock_ensure_data_dir: Path
    ) -> None:
        """Test list_stored_sessions maps NEED_CONFIRMATION auth step to needs_confirmation state."""
        from chatfilter.web.routers.sessions import list_stored_sessions, save_account_info

        session_name = "test_list_confirm"
        session_dir = mock_ensure_data_dir / session_name
        session_dir.mkdir(parents=True, exist_ok=True)

        save_account_info(session_dir, {
            "user_id": 123456789,
            "phone": "+14385515736",
            "first_name": "Test",
            "last_name": "User",
        })

        # Create config.json
        config = {"api_id": 12345, "api_hash": "abcdefghijklmnopqrstuvwxyzabcd"}
        (session_dir / "config.json").write_text(json.dumps(config))

        # Mock auth manager with NEED_CONFIRMATION state
        auth_state = AuthState(
            auth_id="auth_list_confirm",
            session_name=session_name,
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.NEED_CONFIRMATION,
        )

        mock_auth_manager = MagicMock()
        mock_auth_manager.get_auth_state_by_session.return_value = auth_state

        sessions = list_stored_sessions(
            session_manager=None, auth_manager=mock_auth_manager
        )

        confirm_sessions = [s for s in sessions if s.session_id == session_name]
        assert len(confirm_sessions) == 1
        assert confirm_sessions[0].state == "needs_confirmation"

    async def test_check_device_confirmation_auth_key_unregistered(self) -> None:
        """Test _check_device_confirmation returns True when AuthKeyUnregisteredError is raised."""
        from chatfilter.web.routers.sessions import _check_device_confirmation
        from telethon.errors import AuthKeyUnregisteredError

        # Mock client that raises AuthKeyUnregisteredError when calling GetAuthorizationsRequest
        mock_client = AsyncMock()
        # When called as a function (client(...)), raise AuthKeyUnregisteredError
        mock_client.side_effect = AuthKeyUnregisteredError("Auth key unregistered")

        # _check_device_confirmation should catch AuthKeyUnregisteredError and return True
        result = await _check_device_confirmation(mock_client)
        assert result is True

    async def test_verify_2fa_auth_key_unregistered_needs_confirmation(
        self, fastapi_test_client, mock_ensure_data_dir: Path
    ) -> None:
        """Test verify_2fa: sign_in succeeds, AuthKeyUnregisteredError → needs_confirmation (not error)."""
        from telethon.errors import AuthKeyUnregisteredError

        session_dir = mock_ensure_data_dir / "test_2fa_auth_key"
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

        mock_client = AsyncMock()
        mock_client.is_connected.return_value = True
        mock_client.sign_in = AsyncMock(return_value=MagicMock())

        # Mock GetAuthorizationsRequest to raise AuthKeyUnregisteredError
        mock_client.side_effect = AuthKeyUnregisteredError("Auth key unregistered")

        mock_client.get_me = AsyncMock(return_value=MagicMock(
            id=123456789,
            phone="+14385515736",
            first_name="Test",
            last_name="User",
        ))
        mock_client.disconnect = AsyncMock()

        auth_state = AuthState(
            auth_id="test_auth_2fa_key",
            session_name="test_2fa_auth_key",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.NEED_2FA,
            client=mock_client,
        )

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
            mock_mgr.remove_auth_state = AsyncMock()  # Must mock remove_auth_state
            mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_get_mgr.return_value = mock_mgr

            mock_event_bus = MagicMock()
            mock_event_bus.publish = AsyncMock()
            mock_event_bus_fn.return_value = mock_event_bus

            mock_sm = MagicMock()
            mock_sm._factories = {}
            mock_get_sm.return_value = mock_sm

            response = fastapi_test_client.post(
                "/api/sessions/test_2fa_auth_key/verify-2fa",
                data={
                    "auth_id": "test_auth_2fa_key",
                    "password": "test_password",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            html = response.text

            # Should show needs_confirmation, NOT error about deleting session
            assert "needs_confirmation" in html
            assert "Awaiting Confirmation" in html
            assert "delete" not in html.lower() or "recreate" not in html.lower()

            # Should have transitioned to NEED_CONFIRMATION step
            mock_mgr.update_auth_state.assert_called()
            calls = mock_mgr.update_auth_state.call_args_list
            assert any(
                call.kwargs.get("step") == AuthStep.NEED_CONFIRMATION for call in calls
            )

    async def test_verify_code_auth_key_unregistered_needs_confirmation(
        self, fastapi_test_client, mock_ensure_data_dir: Path
    ) -> None:
        """Test verify_code: sign_in succeeds, AuthKeyUnregisteredError → needs_confirmation (not error)."""
        from telethon.errors import AuthKeyUnregisteredError

        session_dir = mock_ensure_data_dir / "test_code_auth_key"
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

        mock_client = AsyncMock()
        mock_client.is_connected.return_value = True
        mock_client.sign_in = AsyncMock(return_value=MagicMock())

        # Mock GetAuthorizationsRequest to raise AuthKeyUnregisteredError
        mock_client.side_effect = AuthKeyUnregisteredError("Auth key unregistered")

        mock_client.get_me = AsyncMock(return_value=MagicMock(
            id=123456789,
            phone="+14385515736",
            first_name="Test",
            last_name="User",
        ))
        mock_client.disconnect = AsyncMock()

        auth_state = AuthState(
            auth_id="test_auth_code_key",
            session_name="test_code_auth_key",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.PHONE_SENT,
            client=mock_client,
        )

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
                "/api/sessions/test_code_auth_key/verify-code",
                data={
                    "auth_id": "test_auth_code_key",
                    "code": "12345",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            html = response.text

            # Should show needs_confirmation, NOT error about deleting session
            assert "needs_confirmation" in html
            assert "Awaiting Confirmation" in html
            assert "delete" not in html.lower() or "recreate" not in html.lower()

            # Should have transitioned to NEED_CONFIRMATION step
            mock_mgr.update_auth_state.assert_called()
            calls = mock_mgr.update_auth_state.call_args_list
            assert any(
                call.kwargs.get("step") == AuthStep.NEED_CONFIRMATION for call in calls
            )

    async def test_auto_2fa_auth_key_unregistered_needs_confirmation(
        self, fastapi_test_client, mock_ensure_data_dir: Path
    ) -> None:
        """Test auto-2FA path: sign_in(code) → 2FA → sign_in(password) succeeds, AuthKeyUnregisteredError → needs_confirmation."""
        from telethon.errors import SessionPasswordNeededError, AuthKeyUnregisteredError

        session_dir = mock_ensure_data_dir / "test_auto_2fa_key"
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

        # Store 2FA password for auto-login
        from chatfilter.security import SecureCredentialManager
        manager = SecureCredentialManager(session_dir)
        manager.store_2fa("test_auto_2fa_key", "stored_password")

        mock_client = AsyncMock()
        mock_client.is_connected.return_value = True

        # First sign_in(code) raises SessionPasswordNeededError
        # Second sign_in(password) succeeds
        sign_in_call_count = [0]
        async def mock_sign_in(*args, **kwargs):
            sign_in_call_count[0] += 1
            if sign_in_call_count[0] == 1:
                # First call (with code) triggers 2FA
                raise SessionPasswordNeededError("2FA required")
            # Second call (with password) succeeds
            return MagicMock()

        mock_client.sign_in = mock_sign_in

        # Mock GetAuthorizationsRequest to raise AuthKeyUnregisteredError
        mock_client.side_effect = AuthKeyUnregisteredError("Auth key unregistered")

        mock_client.get_me = AsyncMock(return_value=MagicMock(
            id=123456789,
            phone="+14385515736",
            first_name="Test",
            last_name="User",
        ))
        mock_client.disconnect = AsyncMock()

        auth_state = AuthState(
            auth_id="test_auth_auto_2fa",
            session_name="test_auto_2fa_key",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.PHONE_SENT,
            client=mock_client,
        )

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
                "/api/sessions/test_auto_2fa_key/verify-code",
                data={
                    "auth_id": "test_auth_auto_2fa",
                    "code": "12345",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            html = response.text

            # Auto-2FA succeeded → needs_confirmation (not error)
            assert "needs_confirmation" in html
            assert "Awaiting Confirmation" in html
            assert "delete" not in html.lower() or "recreate" not in html.lower()

            # Should have transitioned to NEED_CONFIRMATION step
            mock_mgr.update_auth_state.assert_called()
            calls = mock_mgr.update_auth_state.call_args_list
            assert any(
                call.kwargs.get("step") == AuthStep.NEED_CONFIRMATION for call in calls
            )

            # Verify sign_in was called twice (code, then password)
            assert sign_in_call_count[0] == 2
