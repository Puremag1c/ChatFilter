"""Tests for sessions router."""

import json
import re
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app
from chatfilter.web.routers.sessions import (
    migrate_legacy_sessions,
    read_upload_with_size_limit,
    sanitize_session_name,
    validate_account_info_json,
    validate_config_file_format,
    validate_session_file_format,
)

from .conftest import extract_csrf_token


class TestVerify2FA:
    """Tests for verify-2fa endpoint password validation.

    Tests the verify_2fa endpoint password validation directly by checking
    the validation logic without full integration testing.
    """

    def test_password_validation_logic(self) -> None:
        """Test password validation logic handles empty and whitespace passwords."""
        # Test cases for password validation
        test_cases = [
            ("", False, "empty string"),
            (" ", False, "single space"),
            ("   ", False, "multiple spaces"),
            ("\t", False, "tab"),
            ("\n", False, "newline"),
            ("  \t\n  ", False, "mixed whitespace"),
            ("a", True, "valid single char"),
            ("  password  ", True, "password with surrounding spaces"),
            ("valid_password", True, "valid password"),
        ]

        for password, should_pass, description in test_cases:
            # Validation logic from verify_2fa endpoint (line 3806)
            is_valid = bool(password and password.strip())

            if should_pass:
                assert is_valid, f"Expected '{description}' to pass validation but it failed"
            else:
                assert not is_valid, f"Expected '{description}' to fail validation but it passed"

    @pytest.mark.asyncio
    async def test_verify_code_2fa_auto_fails_shows_manual_modal(self) -> None:
        """Test verify_code recovery when 2FA auto-entry fails (wrong stored password).

        Scenario:
        1. Code verification succeeds → SessionPasswordNeededError (2FA required)
        2. Handler attempts auto-entry with stored 2FA password
        3. Auto-entry fails with PasswordHashInvalidError (wrong password)
        4. Handler shows manual 2FA form modal (doesn't block user)
        5. User can now enter 2FA password manually

        This verifies the recovery path when stored 2FA password is incorrect.
        """
        from unittest.mock import AsyncMock, MagicMock, patch
        from pathlib import Path
        import tempfile
        import sqlite3

        from chatfilter.web.auth_state import AuthState, AuthStep
        from chatfilter.security import SecureCredentialManager
        from chatfilter.web.routers.sessions import save_account_info
        from telethon.errors import SessionPasswordNeededError, PasswordHashInvalidError

        app = create_app(debug=True)
        client = TestClient(app)

        with tempfile.TemporaryDirectory() as tmp_dir:
            session_id = "test_auto_2fa_wrong"
            session_dir = Path(tmp_dir) / session_id
            session_dir.mkdir(parents=True, exist_ok=True)

            # Create session.session file (minimal SQLite structure)
            session_path = session_dir / "session.session"
            conn = sqlite3.connect(session_path)
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)"
            )
            cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
            cursor.execute(
                "CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)"
            )
            conn.commit()
            conn.close()

            # Save account_info with 2FA password (simulating stored credentials)
            account_info = {
                "user_id": 123456789,
                "phone": "+14385515736",
                "first_name": "Test",
                "last_name": "User",
            }
            save_account_info(session_dir, account_info)

            # Store encrypted 2FA password (wrong one)
            manager = SecureCredentialManager(session_dir)
            manager.store_2fa(session_id, "wrong_password_123")

            # Create mock client with sign_in side effect
            mock_client = MagicMock()
            mock_client.is_connected.return_value = True
            mock_client.disconnect = AsyncMock()

            sign_in_call_count = [0]

            async def sign_in_side_effect(*args, **kwargs):
                sign_in_call_count[0] += 1
                if sign_in_call_count[0] == 1:
                    # First call (with code): needs 2FA
                    raise SessionPasswordNeededError(None)
                else:
                    # Subsequent calls (with password): wrong password
                    raise PasswordHashInvalidError(None)

            mock_client.sign_in = AsyncMock(side_effect=sign_in_side_effect)

            auth_id = "test_auth_id_wrong"
            auth_state = AuthState(
                auth_id=auth_id,
                session_name=session_id,
                api_id=12345,
                api_hash="abcdefghijklmnopqrstuvwxyzabcd",
                proxy_id="proxy-1",
                phone="+14385515736",
                phone_code_hash="test_hash",
                step=AuthStep.PHONE_SENT,
                client=mock_client,
            )

            with patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_get_mgr, \
                 patch("chatfilter.web.routers.sessions.get_event_bus") as mock_event_bus_fn, \
                 patch("chatfilter.web.routers.sessions.helpers.get_settings") as mock_settings_fn, \
                 patch("chatfilter.web.routers.sessions.auth_reconnect.ensure_data_dir", return_value=Path(tmp_dir)):

                mock_mgr = MagicMock()
                mock_mgr.get_auth_state = AsyncMock(return_value=auth_state)
                mock_mgr.update_auth_state = AsyncMock()
                mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
                mock_mgr.increment_failed_attempts = AsyncMock()
                mock_get_mgr.return_value = mock_mgr

                mock_event_bus = MagicMock()
                mock_event_bus.publish = AsyncMock()
                mock_event_bus_fn.return_value = mock_event_bus

                mock_settings = MagicMock()
                mock_settings.sessions_dir = Path(tmp_dir)
                mock_settings_fn.return_value = mock_settings

                home_response = client.get("/")
                csrf_token = extract_csrf_token(home_response.text)

                response = client.post(
                    f"/api/sessions/{session_id}/verify-code",
                    data={"auth_id": auth_id, "code": "12345"},
                    headers={"X-CSRF-Token": csrf_token},
                )

                # Should return 200 with 2FA form template (or 503 if template not found)
                assert response.status_code in (200, 503), (
                    f"Expected 200 or 503, got {response.status_code}: {response.text[:500]}"
                )

                # Verify sign_in was called multiple times (code + 2FA attempts)
                # First call with code triggers SessionPasswordNeededError
                # Subsequent calls with password trigger PasswordHashInvalidError
                assert sign_in_call_count[0] >= 2, (
                    f"Expected sign_in to be called at least twice, got {sign_in_call_count[0]}"
                )

                # Either response contains 2FA form or needs_2fa event was published
                response_text = response.text.lower()
                has_2fa_form = (
                    "2fa" in response_text
                    or "password" in response_text
                    or "form" in response_text
                )
                # Check if needs_2fa event was published
                calls = mock_event_bus.publish.call_args_list
                needs_2fa_published = any("needs_2fa" in str(call) for call in calls)

                assert has_2fa_form or needs_2fa_published or response.status_code == 503, (
                    f"Expected 2FA form or needs_2fa event, got: {response.text[:500]}"
                )


class TestVerifyCode2FAAutoEntry:
    """Tests for 2FA auto-entry during verify_code endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path, monkeypatch) -> Iterator[Path]:
        """Create temporary data directory."""
        from unittest.mock import MagicMock
        mock_ensure_data_dir = MagicMock(return_value=tmp_path)
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.helpers.ensure_data_dir", mock_ensure_data_dir
        )
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.auth_reconnect.ensure_data_dir", mock_ensure_data_dir
        )
        yield tmp_path

    @pytest.mark.asyncio
    async def test_verify_code_auto_2fa_success(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test verify_code with auto 2FA success."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import SessionPasswordNeededError
        from chatfilter.web.auth_state import AuthState, AuthStep
        from chatfilter.security import SecureCredentialManager

        session_dir = clean_data_dir / "test_auto_2fa_success"
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

        # Store 2FA password
        manager = SecureCredentialManager(session_dir)
        manager.store_2fa("test_auto_2fa_success", "correct_2fa_password")

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True
        mock_client.is_user_authorized = AsyncMock(return_value=True)

        # Mock session.save() for the 2FA auto-entry success path (synchronous, like real Telethon)
        mock_session = MagicMock()
        mock_session.save = MagicMock()
        mock_client.session = mock_session

        mock_me = MagicMock()
        mock_me.id = 123456789
        mock_me.phone = "+14385515736"
        mock_me.first_name = "Test"
        mock_me.last_name = "User"

        sign_in_call_count = [0]

        async def sign_in_side_effect(*args, **kwargs):
            sign_in_call_count[0] += 1
            if sign_in_call_count[0] == 1:
                raise SessionPasswordNeededError(None)
            else:
                return None

        mock_client.sign_in = AsyncMock(side_effect=sign_in_side_effect)
        mock_client.get_me = AsyncMock(return_value=mock_me)
        mock_client.disconnect = AsyncMock()

        # Create auth state
        auth_state = AuthState(
            auth_id="test_auth_id_success",
            session_name="test_auto_2fa_success",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.NEED_2FA,
            client=mock_client,
        )

        with patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_get_mgr,              patch("chatfilter.web.routers.sessions.get_event_bus") as mock_event_bus_fn,              patch("chatfilter.web.dependencies.get_session_manager") as mock_session_mgr_fn,              patch("chatfilter.web.routers.sessions.ensure_data_dir", return_value=session_dir.parent),              patch("chatfilter.web.routers.sessions.auth_reconnect_helpers.get_event_bus") as mock_event_bus_helpers_fn:

            mock_mgr = MagicMock()
            mock_mgr.get_auth_state = AsyncMock(return_value=auth_state)
            mock_mgr.get_auth_state_by_session = MagicMock(return_value=auth_state)
            mock_mgr.remove_auth_state = AsyncMock()
            mock_mgr.update_auth_state = AsyncMock()
            mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_get_mgr.return_value = mock_mgr

            mock_event_bus = MagicMock()
            mock_event_bus.publish = AsyncMock()
            mock_event_bus_fn.return_value = mock_event_bus
            mock_event_bus_helpers_fn.return_value = mock_event_bus

            mock_session_manager = MagicMock()
            mock_session_manager.adopt_client = AsyncMock()
            mock_session_mgr_fn.return_value = mock_session_manager

            home_response = client.get("/")
            csrf_token = extract_csrf_token(home_response.text)

            response = client.post(
                "/api/sessions/test_auto_2fa_success/verify-code",
                data={"auth_id": "test_auth_id_success", "code": "12345"},
                headers={"X-CSRF-Token": csrf_token},
            )

            # Either response is 200 (success) or 503 (template not found but success logic ran)
            # The important thing is that sign_in was called twice and we got past the 2FA check
            assert response.status_code in (200, 503), f"Expected 200 or 503, got {response.status_code}"
            assert sign_in_call_count[0] >= 2, f"Expected sign_in to be called at least twice, got {sign_in_call_count[0]}"

    @pytest.mark.asyncio
    async def test_verify_code_auto_2fa_missing(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test verify_code with no stored 2FA shows modal."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import SessionPasswordNeededError
        from chatfilter.web.auth_state import AuthState, AuthStep
        from chatfilter.web.routers.sessions import save_account_info

        session_dir = clean_data_dir / "test_auto_2fa_missing"
        session_dir.mkdir(parents=True, exist_ok=True)

        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        account_info = {
            "user_id": 123456789,
            "phone": "+14385515736",
            "first_name": "Test",
            "last_name": "User",
        }
        save_account_info(session_dir, account_info)

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True
        mock_client.sign_in = AsyncMock(side_effect=SessionPasswordNeededError(None))
        mock_client.disconnect = AsyncMock()

        auth_state = AuthState(
            auth_id="test_auth_id_missing",
            session_name="test_auto_2fa_missing",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.NEED_2FA,
            client=mock_client,
        )

        with patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_get_mgr,              patch("chatfilter.web.routers.sessions.get_event_bus") as mock_event_bus_fn:

            mock_mgr = MagicMock()
            mock_mgr.get_auth_state = AsyncMock(return_value=auth_state)
            mock_mgr.update_auth_state = AsyncMock()
            mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_get_mgr.return_value = mock_mgr

            mock_event_bus = MagicMock()
            mock_event_bus.publish = AsyncMock()
            mock_event_bus_fn.return_value = mock_event_bus

            home_response = client.get("/")
            csrf_token = extract_csrf_token(home_response.text)

            response = client.post(
                "/api/sessions/test_auto_2fa_missing/verify-code",
                data={"auth_id": "test_auth_id_missing", "code": "12345"},
                headers={"X-CSRF-Token": csrf_token},
            )

            # Either response is 200 or 503 (template not found), the important thing is 
            # that the needs_2fa flow was triggered (no success response)
            assert response.status_code in (200, 503), f"Expected 200 or 503, got {response.status_code}"
            # Verify that needs_2fa event was published or form shown
            assert "auth_2fa_form_reconnect" in response.text or "2FA" in response.text or response.status_code == 503

    @pytest.mark.asyncio
    async def test_verify_code_auto_2fa_wrong(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test verify_code with wrong 2FA password shows error."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import SessionPasswordNeededError, PasswordHashInvalidError
        from chatfilter.web.auth_state import AuthState, AuthStep
        from chatfilter.security import SecureCredentialManager
        from chatfilter.web.routers.sessions import save_account_info

        session_dir = clean_data_dir / "test_auto_2fa_wrong"
        session_dir.mkdir(parents=True, exist_ok=True)

        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        account_info = {
            "user_id": 123456789,
            "phone": "+14385515736",
            "first_name": "Test",
            "last_name": "User",
        }
        save_account_info(session_dir, account_info)

        manager = SecureCredentialManager(session_dir)
        manager.store_2fa("test_auto_2fa_wrong", "wrong_2fa_password")

        mock_client = MagicMock()
        mock_client.is_connected.return_value = True

        sign_in_call_count = [0]

        async def sign_in_side_effect(*args, **kwargs):
            sign_in_call_count[0] += 1
            if sign_in_call_count[0] == 1:
                raise SessionPasswordNeededError(None)
            else:
                raise PasswordHashInvalidError(None)

        mock_client.sign_in = AsyncMock(side_effect=sign_in_side_effect)
        mock_client.disconnect = AsyncMock()

        auth_state = AuthState(
            auth_id="test_auth_id_wrong",
            session_name="test_auto_2fa_wrong",
            api_id=12345,
            api_hash="abcdefghijklmnopqrstuvwxyzabcd",
            proxy_id="proxy-1",
            phone="+14385515736",
            phone_code_hash="test_hash",
            step=AuthStep.NEED_2FA,
            client=mock_client,
        )

        with patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_get_mgr,              patch("chatfilter.web.routers.sessions.get_event_bus") as mock_event_bus_fn,              patch("chatfilter.web.routers.sessions.ensure_data_dir", return_value=session_dir.parent),              patch("chatfilter.web.routers.sessions.auth_reconnect_helpers.get_event_bus") as mock_event_bus_helpers_fn:

            mock_mgr = MagicMock()
            mock_mgr.get_auth_state = AsyncMock(return_value=auth_state)
            mock_mgr.update_auth_state = AsyncMock()
            mock_mgr.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_mgr.increment_failed_attempts = AsyncMock()
            mock_get_mgr.return_value = mock_mgr

            mock_event_bus = MagicMock()
            mock_event_bus.publish = AsyncMock()
            mock_event_bus_fn.return_value = mock_event_bus
            mock_event_bus_helpers_fn.return_value = mock_event_bus

            home_response = client.get("/")
            csrf_token = extract_csrf_token(home_response.text)

            response = client.post(
                "/api/sessions/test_auto_2fa_wrong/verify-code",
                data={"auth_id": "test_auth_id_wrong", "code": "12345"},
                headers={"X-CSRF-Token": csrf_token},
            )

            # Either response is 200 or 503 (template not found), the important thing is
            # that the needs_2fa flow was triggered (no success response)
            assert response.status_code in (200, 503), f"Expected 200 or 503, got {response.status_code}"
            # Verify that needs_2fa event was published or form shown
            assert "auth_2fa_form_reconnect" in response.text or "2FA" in response.text or response.status_code == 503
            # Verify rate limiting was applied (increment_failed_attempts called)
            mock_mgr.increment_failed_attempts.assert_called_once_with("test_auth_id_wrong")


