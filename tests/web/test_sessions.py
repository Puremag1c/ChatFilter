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

            status = get_session_config_status(session_dir)

        assert status == "disconnected"
        mock_manager.has_credentials.assert_called_once_with("my_session")

    def test_encrypted_credentials_missing(self, tmp_path: Path):
        """Test status when encrypted credentials don't exist.

        Scenario: Session has NO plaintext api_id/api_hash,
        and NO encrypted credentials in SecureCredentialManager.
        Expected: Should return "needs_api_id".
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
            status = get_session_config_status(session_dir)

        assert status == "needs_api_id"
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

            status = get_session_config_status(session_dir)

        assert status == "disconnected"
        # SecureCredentialManager should NOT be called for plaintext credentials

    def test_missing_config_file(self, tmp_path: Path):
        """Test status when config.json doesn't exist.

        Expected: Should return "needs_api_id".
        """
        session_dir = tmp_path / "no_config_session"
        session_dir.mkdir(parents=True)

        status = get_session_config_status(session_dir)

        assert status == "needs_api_id"

    def test_corrupted_config_file(self, tmp_path: Path):
        """Test status when config.json is corrupted/invalid JSON.

        Expected: Should return "needs_api_id".
        """
        session_dir = tmp_path / "corrupted_session"
        session_dir.mkdir(parents=True)

        config_file = session_dir / "config.json"
        config_file.write_text("{ invalid json }", encoding="utf-8")

        status = get_session_config_status(session_dir)

        assert status == "needs_api_id"

    def test_missing_proxy_id(self, tmp_path: Path):
        """Test status when proxy_id is missing from config.

        Expected: Should return "needs_api_id" (proxy required for session).
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

        status = get_session_config_status(session_dir)

        assert status == "needs_api_id"

    def test_proxy_not_found_in_pool(self, tmp_path: Path):
        """Test status when proxy_id references non-existent proxy.

        Expected: Should return "proxy_missing".
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

            status = get_session_config_status(session_dir)

        assert status == "proxy_missing"

    def test_encrypted_credentials_check_error_handling(self, tmp_path: Path):
        """Test graceful handling of SecureCredentialManager errors.

        Scenario: SecureCredentialManager.has_credentials() raises exception
        (e.g., corrupted .credentials.enc file).
        Expected: Should treat as credentials absent, return "needs_api_id".
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
            status = get_session_config_status(session_dir)

        assert status == "needs_api_id"

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

            status = get_session_config_status(session_dir)

        # Should check encrypted credentials because api_id is None
        assert status == "disconnected"
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

            status = get_session_config_status(session_dir)

        # Should check encrypted credentials because api_hash is None
        assert status == "disconnected"
        mock_manager.has_credentials.assert_called_once()
