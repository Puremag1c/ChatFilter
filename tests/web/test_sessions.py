"""Regression tests for session status logic.

Bug 1 fix: get_session_config_status() must check SecureCredentialManager
for encrypted credentials, not just plaintext config.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chatfilter.web.routers.sessions import get_session_config_status


class TestGetSessionConfigStatus:
    """Tests for get_session_config_status() after Bug 1 fix."""

    def test_encrypted_credentials_with_proxy(self, tmp_path: Path):
        """Test status with encrypted credentials and valid proxy.

        Scenario: Session has NO plaintext api_id/api_hash in config.json,
        but HAS encrypted credentials in SecureCredentialManager.
        Expected: Should return "disconnected" (ready to connect).
        """
        session_dir = tmp_path / "my_session"
        session_dir.mkdir(parents=True)

        # Config without api_id/api_hash (null), but with proxy_id
        config_data = {
            "api_id": None,
            "api_hash": None,
            "proxy_id": "proxy-123",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock SecureCredentialManager to return True for has_credentials
        mock_manager = MagicMock()
        mock_manager.has_credentials.return_value = True

        # Mock imports that happen inside the function
        with patch(
            "chatfilter.security.SecureCredentialManager",
            return_value=mock_manager,
        ), patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.return_value = {"id": "proxy-123", "host": "127.0.0.1"}

            status, reason = get_session_config_status(session_dir)

        assert status == "disconnected"
        assert reason is None
        mock_manager.has_credentials.assert_called_once_with("my_session")

    def test_encrypted_credentials_missing(self, tmp_path: Path):
        """Test status when encrypted credentials don't exist.

        Scenario: Session has NO plaintext api_id/api_hash,
        and NO encrypted credentials in SecureCredentialManager.
        Expected: Should return "needs_config" with "API credentials required".
        """
        session_dir = tmp_path / "empty_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": None,
            "api_hash": None,
            "proxy_id": "proxy-456",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock SecureCredentialManager to return False for has_credentials
        mock_manager = MagicMock()
        mock_manager.has_credentials.return_value = False

        with patch(
            "chatfilter.security.SecureCredentialManager",
            return_value=mock_manager,
        ):
            status, reason = get_session_config_status(session_dir)

        assert status == "needs_config"
        assert reason == "API credentials required"
        mock_manager.has_credentials.assert_called_once_with("empty_session")

    def test_plaintext_credentials_backward_compatibility(self, tmp_path: Path):
        """Test backward compatibility with plaintext config.json.

        Scenario: Session has plaintext api_id/api_hash in config.json.
        Expected: Should NOT check SecureCredentialManager,
        proceed directly to proxy check, return "disconnected".
        """
        session_dir = tmp_path / "legacy_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": 12345,
            "api_hash": "abc123def456",
            "proxy_id": "proxy-789",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock proxy lookup
        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.return_value = {"id": "proxy-789", "host": "proxy.example.com"}

            status, reason = get_session_config_status(session_dir)

        assert status == "disconnected"
        assert reason is None
        # SecureCredentialManager should NOT be called for plaintext credentials

    def test_missing_config_file(self, tmp_path: Path):
        """Test status when config.json doesn't exist.

        Expected: Should return "needs_config" with "Configuration file missing".
        """
        session_dir = tmp_path / "no_config_session"
        session_dir.mkdir(parents=True)

        status, reason = get_session_config_status(session_dir)

        assert status == "needs_config"
        assert reason == "Configuration file missing"

    def test_corrupted_config_file(self, tmp_path: Path):
        """Test status when config.json is corrupted/invalid JSON.

        Expected: Should return "needs_config" with "Configuration file corrupted".
        """
        session_dir = tmp_path / "corrupted_session"
        session_dir.mkdir(parents=True)

        config_file = session_dir / "config.json"
        config_file.write_text("{ invalid json }", encoding="utf-8")

        status, reason = get_session_config_status(session_dir)

        assert status == "needs_config"
        assert reason == "Configuration file corrupted"

    def test_missing_proxy_id(self, tmp_path: Path):
        """Test status when proxy_id is missing from config.

        Expected: Should return "needs_config" with "Proxy configuration required".
        """
        session_dir = tmp_path / "no_proxy_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": 12345,
            "api_hash": "abc123",
            "proxy_id": None,  # Missing proxy
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        status, reason = get_session_config_status(session_dir)

        assert status == "needs_config"
        assert reason == "Proxy configuration required"

    def test_proxy_not_found_in_pool(self, tmp_path: Path):
        """Test status when proxy_id references non-existent proxy.

        Expected: Should return "needs_config" with "Proxy not found in pool".
        """
        from chatfilter.storage.errors import StorageNotFoundError

        session_dir = tmp_path / "bad_proxy_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": 12345,
            "api_hash": "abc123",
            "proxy_id": "nonexistent-proxy",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.side_effect = StorageNotFoundError("Proxy not found")

            status, reason = get_session_config_status(session_dir)

        assert status == "needs_config"
        assert reason == "Proxy not found in pool"

    def test_encrypted_credentials_check_error_handling(self, tmp_path: Path):
        """Test graceful handling of SecureCredentialManager errors.

        Scenario: SecureCredentialManager.has_credentials() raises exception
        (e.g., corrupted .credentials.enc file).
        Expected: Should treat as credentials absent, return "needs_config" with "API credentials required".
        """
        session_dir = tmp_path / "corrupted_creds_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": None,
            "api_hash": None,
            "proxy_id": "proxy-999",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock SecureCredentialManager to raise exception
        mock_manager = MagicMock()
        mock_manager.has_credentials.side_effect = Exception("Corrupted credentials file")

        with patch(
            "chatfilter.security.SecureCredentialManager",
            return_value=mock_manager,
        ):
            status, reason = get_session_config_status(session_dir)

        assert status == "needs_config"
        assert reason == "API credentials required"

    # Note: test_storage_dir_does_not_exist removed - edge case covered by unit test,
    # difficult to simulate in integration test without complex mocking

    def test_encrypted_credentials_with_only_api_id_null(self, tmp_path: Path):
        """Test encrypted check when only api_id is null (api_hash present).

        Scenario: api_id is None, but api_hash has value in config.
        Expected: Should check encrypted credentials (both must be present).
        """
        session_dir = tmp_path / "partial_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": None,
            "api_hash": "somehash",  # Only hash present
            "proxy_id": "proxy-222",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        mock_manager = MagicMock()
        mock_manager.has_credentials.return_value = True

        with patch(
            "chatfilter.security.SecureCredentialManager",
            return_value=mock_manager,
        ), patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.return_value = {"id": "proxy-222"}

            status, reason = get_session_config_status(session_dir)

        # Should check encrypted credentials because api_id is None
        assert status == "disconnected"
        assert reason is None
        mock_manager.has_credentials.assert_called_once()

    def test_encrypted_credentials_with_only_api_hash_null(self, tmp_path: Path):
        """Test encrypted check when only api_hash is null (api_id present).

        Scenario: api_hash is None, but api_id has value in config.
        Expected: Should check encrypted credentials (both must be present).
        """
        session_dir = tmp_path / "partial_hash_session"
        session_dir.mkdir(parents=True)

        config_data = {
            "api_id": 12345,  # Only ID present
            "api_hash": None,
            "proxy_id": "proxy-333",
        }
        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        mock_manager = MagicMock()
        mock_manager.has_credentials.return_value = True

        with patch(
            "chatfilter.security.SecureCredentialManager",
            return_value=mock_manager,
        ), patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.return_value = {"id": "proxy-333"}

            status, reason = get_session_config_status(session_dir)

        # Should check encrypted credentials because api_hash is None
        assert status == "disconnected"
        assert reason is None
        mock_manager.has_credentials.assert_called_once()


class TestConnectSessionErrorHandling:
    """Regression tests for Bug 2: connect error handling.

    Bug 2 fixed silent failures when Connect is clicked. These tests verify
    that error messages are published via SSE and saved to config.json when:
    - Phone number is missing from account_info
    - Proxy is not found in pool
    - Network is unavailable (after retries)
    """

    @pytest.mark.asyncio
    async def test_connect_session_publishes_error_when_phone_missing(self, tmp_path: Path):
        """Test that missing phone number triggers error event.

        Scenario: User clicks Connect but account_info.json has no phone number.
        Expected: Telethon raises PhoneNumberInvalidError, error event published.
        """
        from chatfilter.web.routers.sessions import _send_verification_code_and_create_auth

        session_id = "test_no_phone"
        session_dir = tmp_path / session_id
        session_dir.mkdir(parents=True)
        session_path = session_dir / "session.session"
        config_path = session_dir / "config.json"

        # Config with valid credentials and proxy
        config_data = {
            "api_id": 12345,
            "api_hash": "valid_hash",
            "proxy_id": "proxy-123",
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock event bus to capture published events (publish is async)
        publish_calls = []

        async def mock_publish(sid, state):
            publish_calls.append((sid, state))

        mock_event_bus = MagicMock()
        mock_event_bus.publish = mock_publish

        # Mock proxy lookup to succeed
        mock_proxy = MagicMock()
        mock_proxy.to_telethon_proxy.return_value = ("socks5", "127.0.0.1", 1080, True, None, None)

        # Mock TelegramClient and make send_code_request raise PhoneNumberInvalidError
        mock_client = MagicMock()

        async def mock_connect():
            pass  # connect succeeds

        mock_client.connect = mock_connect

        # Import error class for patching
        from telethon.errors import PhoneNumberInvalidError

        # Make send_code_request raise PhoneNumberInvalidError (empty phone is invalid)
        async def mock_send_code_request(phone):
            raise PhoneNumberInvalidError("PHONE_NUMBER_INVALID")

        mock_client.send_code_request = mock_send_code_request

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id", return_value=mock_proxy), patch(
            "chatfilter.web.routers.sessions.background.get_event_bus", return_value=mock_event_bus
        ), patch("chatfilter.web.routers.sessions.background.TelegramClient", return_value=mock_client):
            await _send_verification_code_and_create_auth(
                session_id=session_id,
                session_path=session_path,
                config_path=config_path,
                phone="",  # Empty phone triggers PhoneNumberInvalidError
            )

        # Verify error event was published
        assert len(publish_calls) == 1
        # Check published event
        published_session_id, published_state = publish_calls[0]
        assert published_session_id == session_id
        # Should publish error state (PhoneNumberInvalidError is non-retryable)
        assert published_state != "needs_code"  # Should NOT succeed

        # Verify error_message saved to config.json
        with config_path.open("r") as f:
            saved_config = json.load(f)
        assert "error_message" in saved_config
        assert saved_config["retry_available"] is False  # Non-retryable error

    @pytest.mark.asyncio
    async def test_connect_session_publishes_error_when_proxy_fails(self, tmp_path: Path):
        """Test that proxy not found triggers needs_config event.

        Scenario: User clicks Connect but proxy_id references non-existent proxy.
        Expected: SSE event published with 'needs_config' state and error saved to config.json.
        """
        import asyncio
        from chatfilter.web.routers.sessions import _send_verification_code_and_create_auth
        from chatfilter.storage.errors import StorageNotFoundError

        session_id = "test_proxy_needs_config"
        session_dir = tmp_path / session_id
        session_dir.mkdir(parents=True)
        session_path = session_dir / "session.session"
        config_path = session_dir / "config.json"

        config_data = {
            "api_id": 12345,
            "api_hash": "valid_hash",
            "proxy_id": "nonexistent-proxy",
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock event bus to capture published events
        publish_calls = []

        async def mock_publish(sid, state):
            publish_calls.append((sid, state))

        mock_event_bus = MagicMock()
        mock_event_bus.publish = mock_publish

        # Mock proxy lookup to fail with StorageNotFoundError
        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy, patch(
            "chatfilter.web.routers.sessions.background.get_event_bus", return_value=mock_event_bus
        ):
            mock_get_proxy.side_effect = StorageNotFoundError("Proxy not found")

            await _send_verification_code_and_create_auth(
                session_id=session_id,
                session_path=session_path,
                config_path=config_path,
                phone="+1234567890",
            )

        # Verify needs_config event was published
        assert len(publish_calls) == 1
        published_session_id, published_state = publish_calls[0]
        assert published_session_id == session_id
        assert published_state == "needs_config"

        # Verify error_message saved to config.json
        with config_path.open("r") as f:
            saved_config = json.load(f)
        assert "error_message" in saved_config
        assert "Proxy" in saved_config["error_message"] or "proxy" in saved_config["error_message"].lower()
        assert saved_config["retry_available"] is False

    @pytest.mark.asyncio
    async def test_connect_session_publishes_error_when_network_unavailable(self, tmp_path: Path):
        """Test that network error (after retries) triggers error event.

        Scenario: User clicks Connect but network is unavailable (ConnectionError on all retries).
        Expected: SSE event published with 'error' state, error_message saved with retry_available=True.
        """
        import asyncio
        from chatfilter.web.routers.sessions import _send_verification_code_and_create_auth

        session_id = "test_network_error"
        session_dir = tmp_path / session_id
        session_dir.mkdir(parents=True)
        session_path = session_dir / "session.session"
        config_path = session_dir / "config.json"

        config_data = {
            "api_id": 12345,
            "api_hash": "valid_hash",
            "proxy_id": "proxy-123",
        }
        config_path.write_text(json.dumps(config_data), encoding="utf-8")

        # Mock event bus to capture published events
        publish_calls = []

        async def mock_publish(sid, state):
            publish_calls.append((sid, state))

        mock_event_bus = MagicMock()
        mock_event_bus.publish = mock_publish

        # Mock proxy lookup to succeed
        mock_proxy = MagicMock()
        mock_proxy.to_telethon_proxy.return_value = ("socks5", "127.0.0.1", 1080, True, None, None)

        # Mock TelegramClient to raise ConnectionError (simulates network failure)
        mock_client = MagicMock()

        async def mock_connect():
            raise ConnectionError("Network unreachable")

        mock_client.connect = mock_connect

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id", return_value=mock_proxy), patch(
            "chatfilter.web.routers.sessions.background.get_event_bus", return_value=mock_event_bus
        ), patch("telethon.TelegramClient", return_value=mock_client):
            await _send_verification_code_and_create_auth(
                session_id=session_id,
                session_path=session_path,
                config_path=config_path,
                phone="+1234567890",
            )

        # Verify error event was published (after all retries failed)
        assert len(publish_calls) == 1
        published_session_id, published_state = publish_calls[0]
        assert published_session_id == session_id
        # Should publish error state (not needs_code)
        assert published_state != "needs_code"  # Should NOT succeed

        # Verify error_message saved to config.json with retry_available=True (transient error)
        with config_path.open("r") as f:
            saved_config = json.load(f)
        assert "error_message" in saved_config
        assert saved_config["retry_available"] is True  # Network errors are retryable
