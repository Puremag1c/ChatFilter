"""Tests for SPEC requirement #1: Save != Connect.

These tests verify that the Save button in the form ONLY saves data to disk
(.account_info.json + .credentials.enc) without attempting to connect to Telegram.

SPEC Requirement:
- Save in form ONLY saves data on disk
- Does NOT create Telethon client
- Does NOT send code
- Does NOT connect
- After Save, account appears in list with status disconnected
"""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app


@pytest.fixture
def app(monkeypatch):
    """Create app with mocked CSRF middleware."""
    monkeypatch.setattr(
        "chatfilter.web.app.CSRFProtectionMiddleware",
        lambda app: app,  # No-op middleware
    )
    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestSaveNotConnect:
    """Test that Save button only saves data without connecting.

    Tests cover the 4 missing test cases from task requirements:
    1. test_save_account_only_name_phone
    2. test_save_account_appears_disconnected
    3. test_save_validates_credentials_before_connect (replaces import test)
    4. test_start_auth_flow_no_telethon_call
    """

    def test_save_account_only_name_phone(self, client, tmp_path, monkeypatch):
        """Test Save with just name + phone (no api_id/proxy).

        Verifies that start_auth_flow saves data without requiring api_id/api_hash.
        This is the minimal save scenario from SPEC.
        """
        # Mock ensure_data_dir to use tmp_path
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        # Mock TelegramClient to verify it's NOT called
        mock_telethon_client = MagicMock()
        with patch("telethon.TelegramClient", mock_telethon_client):
            response = client.post(
                "/api/sessions/auth/start",
                data={
                    "session_name": "minimal_session",
                    "phone": "+1234567890",
                    # No api_id, no api_hash, no proxy_id
                },
            )

            # Verify response is success
            assert response.status_code == 200
            assert b"saved successfully" in response.content

            # CRITICAL: Verify TelegramClient was NOT instantiated
            mock_telethon_client.assert_not_called()

        # Verify files created on disk
        session_dir = tmp_path / "minimal_session"
        assert session_dir.exists()
        assert (session_dir / ".account_info.json").exists()
        assert (session_dir / "config.json").exists()

        # Verify .credentials.enc was NOT created (no credentials provided)
        assert not (tmp_path / ".credentials.enc").exists()

        # Verify account_info contains phone and disconnected status
        with open(session_dir / ".account_info.json", "r") as f:
            account_info = json.load(f)
            assert account_info["phone"] == "+1234567890"
            assert account_info["status"] == "disconnected"

        # Verify config.json has null api_id/api_hash/proxy_id
        with open(session_dir / "config.json", "r") as f:
            config = json.load(f)
            assert config["api_id"] is None
            assert config["api_hash"] is None
            assert config["proxy_id"] is None
            assert config["source"] == "phone"

    def test_save_account_appears_disconnected(self, client, tmp_path, monkeypatch):
        """Test that saved account appears as disconnected in list.

        Verifies that after Save, get_session_config_status returns 'needs_config'
        (which is displayed as disconnected/needs config in UI).
        """
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        # Save minimal session
        with patch("telethon.TelegramClient"):
            response = client.post(
                "/api/sessions/auth/start",
                data={
                    "session_name": "check_status_session",
                    "phone": "+1234567890",
                },
            )
            assert response.status_code == 200

        # Verify session status is 'needs_config'
        from chatfilter.web.routers.sessions import get_session_config_status

        session_dir = tmp_path / "check_status_session"
        status, message = get_session_config_status(session_dir)
        assert status == "needs_config"
        # Message contains "API credentials required" or similar
        assert "api" in message.lower() and ("credentials" in message.lower() or "id" in message.lower())

    def test_save_validates_credentials_before_connect(self, client, tmp_path, monkeypatch):
        """Test that Save validates credentials but does NOT connect.

        Verifies that credential validation happens during Save (api_id format check)
        but no connection to Telegram is attempted.
        """
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        # Mock TelegramClient to verify it's NOT called
        mock_telethon_client = MagicMock()

        with patch("telethon.TelegramClient", mock_telethon_client):
            # Test 1: Valid credentials should save without connecting
            response = client.post(
                "/api/sessions/auth/start",
                data={
                    "session_name": "valid_creds",
                    "phone": "+1234567890",
                    "api_id": "123456",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                },
            )
            assert response.status_code == 200
            assert b"saved successfully" in response.content
            mock_telethon_client.assert_not_called()

            # Test 2: Invalid api_hash should be rejected WITHOUT connecting
            response2 = client.post(
                "/api/sessions/auth/start",
                data={
                    "session_name": "invalid_hash",
                    "phone": "+1234567890",
                    "api_id": "123456",
                    "api_hash": "not-a-valid-hash",
                },
            )
            assert response2.status_code == 200
            assert b"Invalid API hash format" in response2.content
            # CRITICAL: Even validation errors should NOT trigger Telegram connection
            mock_telethon_client.assert_not_called()

        # Verify valid session was saved
        session_dir = tmp_path / "valid_creds"
        assert session_dir.exists()
        with open(session_dir / ".account_info.json", "r") as f:
            account_info = json.load(f)
            assert account_info["status"] == "disconnected"

    def test_start_auth_flow_no_telethon_call(self, client, tmp_path, monkeypatch):
        """Test that start_auth_flow doesn't create Telethon client.

        Verifies that the entire start_auth_flow function completes without
        any calls to telethon.TelegramClient or any Telegram API calls.
        """
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        # Mock all Telegram-related modules
        mock_telethon_client = MagicMock()
        mock_client_loader = MagicMock()
        mock_session_manager = MagicMock()

        with patch("telethon.TelegramClient", mock_telethon_client), \
             patch("chatfilter.telegram.client.TelegramClientLoader", mock_client_loader), \
             patch("chatfilter.web.dependencies.get_session_manager", return_value=mock_session_manager):

            response = client.post(
                "/api/sessions/auth/start",
                data={
                    "session_name": "no_telethon_session",
                    "phone": "+1234567890",
                    "api_id": "123456",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                },
            )

            # Verify response is success
            assert response.status_code == 200
            assert b"saved successfully" in response.content

            # CRITICAL: Verify NO Telegram API calls were made
            mock_telethon_client.assert_not_called()
            mock_client_loader.assert_not_called()
            mock_session_manager.connect.assert_not_called()

            # Verify session_manager methods that trigger connection were NOT called
            if hasattr(mock_session_manager, "send_code"):
                mock_session_manager.send_code.assert_not_called()
            if hasattr(mock_session_manager, "sign_in"):
                mock_session_manager.sign_in.assert_not_called()

        # Verify session exists and has disconnected status
        session_dir = tmp_path / "no_telethon_session"
        with open(session_dir / ".account_info.json", "r") as f:
            account_info = json.load(f)
            assert account_info["status"] == "disconnected"

    def test_save_with_credentials_no_connect(self, client, tmp_path, monkeypatch):
        """Test that Save with full credentials still doesn't connect.

        Even when user provides api_id, api_hash, and proxy_id, the Save
        button should only save to disk without connecting.
        """
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        # Mock TelegramClient to verify it's NOT called
        mock_telethon_client = MagicMock()

        with patch("telethon.TelegramClient", mock_telethon_client):
            response = client.post(
                "/api/sessions/auth/start",
                data={
                    "session_name": "full_creds_session",
                    "phone": "+1234567890",
                    "api_id": "123456",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": "my_proxy",
                },
            )

            # Verify response is success
            assert response.status_code == 200
            assert b"saved successfully" in response.content

            # CRITICAL: Even with full credentials, Save should NOT connect
            mock_telethon_client.assert_not_called()

        # Verify credentials were saved
        session_dir = tmp_path / "full_creds_session"
        assert (session_dir / "config.json").exists()

        with open(session_dir / "config.json", "r") as f:
            config = json.load(f)
            assert config["api_id"] == 123456
            assert config["api_hash"] == "0123456789abcdef0123456789abcdef"
            assert config["proxy_id"] == "my_proxy"

        # Verify .credentials.enc was created (credentials stored securely)
        # Note: SecureCredentialManager creates .credentials.enc at data_dir level
        assert (tmp_path / ".credentials.enc").exists()

        # Verify status is still disconnected
        with open(session_dir / ".account_info.json", "r") as f:
            account_info = json.load(f)
            assert account_info["status"] == "disconnected"
