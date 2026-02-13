"""
Backend logic tests for v0.8.2 bugfixes.

Tests verify:
1. Bug 1: Session shows "Setup Required" when credentials exist in .credentials.enc
2. Bug 2: Connect failure shows error message to user
3. Bug 3: All session statuses are translated to Russian
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from starlette.testclient import TestClient


class TestBug1_SessionConfigStatusWithEncryptedCredentials:
    """Test that get_session_config_status checks encrypted credentials."""

    def test_encrypted_credentials_return_valid_status(self, tmp_path: Path):
        """Session with encrypted credentials should NOT return 'needs_api_id'."""
        from chatfilter.web.routers.sessions import get_session_config_status

        # Create session directory structure
        session_dir = tmp_path / "test_session"
        session_dir.mkdir()

        # Create config.json with null api_id/api_hash (Pattern A)
        config = {
            "api_id": None,
            "api_hash": None,
            "proxy_id": "test-proxy",
            "source": "phone",
        }
        with (session_dir / "config.json").open("w") as f:
            json.dump(config, f)

        # Mock SecureCredentialManager to simulate encrypted credentials
        with patch("chatfilter.web.routers.sessions.SecureCredentialManager") as mock_scm:
            mock_manager = MagicMock()
            mock_manager.has_credentials.return_value = True  # Credentials exist
            mock_scm.return_value = mock_manager

            # Mock proxy lookup to succeed
            with patch("chatfilter.web.routers.sessions.get_proxy_by_id") as mock_proxy:
                mock_proxy.return_value = Mock()

                status = get_session_config_status(session_dir)

                # Bug 1 verification: Should NOT return "needs_api_id"
                assert status != "needs_api_id"
                assert status == "disconnected"  # Valid config

                # Verify SecureCredentialManager was checked
                mock_scm.assert_called_once()
                mock_manager.has_credentials.assert_called_once_with("test_session")

    def test_plaintext_config_still_works(self, tmp_path: Path):
        """Backward compatibility: plaintext config.json should still work."""
        from chatfilter.web.routers.sessions import get_session_config_status

        session_dir = tmp_path / "test_session"
        session_dir.mkdir()

        # Create config.json with plaintext credentials
        config = {
            "api_id": 12345,
            "api_hash": "test_hash",
            "proxy_id": "test-proxy",
            "source": "file",
        }
        with (session_dir / "config.json").open("w") as f:
            json.dump(config, f)

        # Mock proxy lookup
        with patch("chatfilter.web.routers.sessions.get_proxy_by_id") as mock_proxy:
            mock_proxy.return_value = Mock()

            status = get_session_config_status(session_dir)

            assert status == "disconnected"  # Valid config

    def test_no_credentials_anywhere_returns_needs_api_id(self, tmp_path: Path):
        """Session without credentials in config or encrypted storage should return needs_api_id."""
        from chatfilter.web.routers.sessions import get_session_config_status

        session_dir = tmp_path / "test_session"
        session_dir.mkdir()

        # Create config.json without credentials
        config = {
            "api_id": None,
            "api_hash": None,
            "proxy_id": "test-proxy",
            "source": "phone",
        }
        with (session_dir / "config.json").open("w") as f:
            json.dump(config, f)

        # Mock SecureCredentialManager to simulate NO encrypted credentials
        with patch("chatfilter.web.routers.sessions.SecureCredentialManager") as mock_scm:
            mock_manager = MagicMock()
            mock_manager.has_credentials.return_value = False  # No credentials
            mock_scm.return_value = mock_manager

            status = get_session_config_status(session_dir)

            assert status == "needs_api_id"


class TestBug2_ConnectFailureShowsError:
    """Test that connect failure shows error message to user."""

    @pytest.mark.asyncio
    async def test_connect_missing_phone_shows_error(self, client: TestClient, clean_data_dir: Path):
        """Connect without phone number should show clear error."""
        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.storage.proxy_pool import add_proxy_to_pool

        # Create session without account_info (no phone)
        session_dir = clean_data_dir / "sessions" / "test_session"
        session_dir.mkdir(parents=True)

        # Create valid config
        config = {
            "api_id": 12345,
            "api_hash": "test_hash",
            "proxy_id": "test-proxy",
            "source": "file",
        }
        with (session_dir / "config.json").open("w") as f:
            json.dump(config, f)

        # Create proxy
        proxy = ProxyEntry(
            id="test-proxy",
            host="proxy.example.com",
            port=1080,
            username="user",
            password="pass",
        )
        add_proxy_to_pool(proxy)

        # No account_info.json created (missing phone)

        # Attempt to connect
        response = client.post("/sessions/test_session/connect")

        # Bug 2 verification: Should show error message, not silent fail
        assert response.status_code in [200, 400, 500]

        # Response should contain error message about missing phone
        response_text = response.text.lower()
        assert any(
            keyword in response_text
            for keyword in ["phone", "account_info", "error", "required", "missing"]
        ), f"Expected error message about missing phone, got: {response.text[:200]}"

    @pytest.mark.asyncio
    async def test_connect_network_error_shows_error(
        self, client: TestClient, clean_data_dir: Path
    ):
        """Connect with network error should show clear error."""
        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.storage.proxy_pool import add_proxy_to_pool

        # Create session with account_info
        session_dir = clean_data_dir / "sessions" / "test_session"
        session_dir.mkdir(parents=True)

        config = {
            "api_id": 12345,
            "api_hash": "test_hash",
            "proxy_id": "test-proxy",
            "source": "file",
        }
        with (session_dir / "config.json").open("w") as f:
            json.dump(config, f)

        account_info = {"phone": "+1234567890"}
        with (session_dir / "account_info.json").open("w") as f:
            json.dump(account_info, f)

        # Create proxy
        proxy = ProxyEntry(
            id="test-proxy",
            host="proxy.example.com",
            port=1080,
            username="user",
            password="pass",
        )
        add_proxy_to_pool(proxy)

        # Mock TelegramClient to fail with network error
        with patch("chatfilter.web.routers.sessions.TelegramClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.connect.side_effect = ConnectionError("Network unreachable")
            mock_client_cls.return_value = mock_client

            response = client.post("/sessions/test_session/connect")

            # Bug 2 verification: Should show error, not silent spinner disappear
            assert response.status_code in [200, 400, 500]

            response_text = response.text.lower()
            # Should mention network/connection/error
            assert any(
                keyword in response_text
                for keyword in ["network", "connection", "error", "failed", "unreachable"]
            ), f"Expected network error message, got: {response.text[:200]}"


class TestBug3_SessionStatusesTranslatedToRussian:
    """Test that all session statuses are translated to Russian."""

    def test_all_session_statuses_have_russian_translations(self):
        """All session status strings should exist in Russian .po file."""
        from pathlib import Path

        # Read Russian .po file
        po_file = Path("src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po")
        assert po_file.exists(), "Russian .po file not found"

        po_content = po_file.read_text()

        # Session statuses that should be translated
        statuses = [
            "disconnected",
            "connecting",
            "connected",
            "needs_api_id",
            "proxy_missing",
            "session_expired",
            "error",
            # Setup states
            "Setup Required",
            "Needs API ID",
            "Proxy Missing",
            "Connect",
            "Disconnect",
            "Connecting...",
        ]

        missing_translations = []
        for status in statuses:
            # Check if msgid exists in .po file
            if f'msgid "{status}"' not in po_content:
                missing_translations.append(status)

        assert not missing_translations, (
            f"Missing Russian translations for statuses: {missing_translations}\n"
            "Bug 3: Add these to messages.po"
        )

    def test_po_file_compiled_to_mo(self):
        """Russian .po file should be compiled to .mo file."""
        from pathlib import Path

        mo_file = Path("src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.mo")
        assert mo_file.exists(), ".mo file not compiled. Run: msgfmt messages.po -o messages.mo"

    def test_javascript_and_python_translations_match(self):
        """JavaScript ru.json and Python messages.po should have matching translations."""
        import json
        from pathlib import Path

        # Read JavaScript translations
        js_file = Path("src/chatfilter/static/i18n/ru.json")
        if not js_file.exists():
            pytest.skip("JavaScript translations file not found")

        js_translations = json.loads(js_file.read_text())

        # Read Python .po file
        po_file = Path("src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po")
        po_content = po_file.read_text()

        # Check that common keys exist in both
        common_keys = ["disconnected", "connecting", "connected", "error"]

        for key in common_keys:
            if key in js_translations:
                # Should also exist in .po
                assert f'msgid "{key}"' in po_content, (
                    f"Key '{key}' exists in ru.json but not in messages.po. "
                    "Bug 3: Synchronize translations"
                )
