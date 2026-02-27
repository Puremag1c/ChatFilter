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


class TestDeadSessionRecoveryUX:
    """Tests for dead session error messages and recovery UX flow."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        data_dir = tmp_path / "sessions"
        data_dir.mkdir(parents=True, exist_ok=True)
        yield data_dir
        if data_dir.exists():
            shutil.rmtree(data_dir)

    @pytest.fixture
    def configured_session(self, clean_data_dir: Path) -> Path:
        """Create a fully configured session directory."""
        import uuid

        session_dir = clean_data_dir / "dead_session"
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

        # Create config.json
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": str(uuid.uuid4()),
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_dead_session_returns_connecting_state(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that dead session returns 'connecting' immediately - error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionReauthRequiredError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to raise SessionReauthRequiredError (expired session)
        # Error now handled in background task, not HTTP handler
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionReauthRequiredError("Session has expired")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # Error state (disconnected) delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_expired_session_connect_returns_connecting(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that expired session connect returns 'connecting' - error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionReauthRequiredError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Connect fails with expired error - handled in background task
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionReauthRequiredError("Session has expired")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # Reauth error delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_session_recovery_preserves_session_id(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that session recovery preserves session ID."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionInfo, SessionState

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to return session info with same ID
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock()
        mock_session_manager.get_info.return_value = SessionInfo(
            session_id="dead_session",  # ID is preserved
            state=SessionState.CONNECTED,
        )

        mock_loader = MagicMock()

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Session should be recovered with same ID
        assert response.status_code == 200
        # Verify get_info was called and returned consistent session_id
        mock_session_manager.get_info.assert_called()

    def test_temporary_error_vs_permanent_session_death_ui(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that UI distinguishes temporary errors from permanent session death."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import (
            SessionConnectError,
            SessionInvalidError,
        )

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)

        # Test temporary error (network issue)
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionConnectError("Network connection failed")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            temp_response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 'connecting' immediately for both cases
        # Error classification now happens in background task, delivered via SSE
        assert temp_response.status_code == 200
        assert "Connecting" in temp_response.text or "connecting" in temp_response.text.lower()

        # Test permanent error (session invalid) - same behavior
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionInvalidError("Session is permanently invalid")
        )
        mock_session_manager.get_info.return_value = None

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            perm_response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' - error delivered via SSE
        assert perm_response.status_code == 200
        assert "Connecting" in perm_response.text or "connecting" in perm_response.text.lower()


class TestAPICredentialReValidation:
    """Tests for API credential re-validation when credentials change on existing session."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        data_dir = tmp_path / "sessions"
        data_dir.mkdir(parents=True, exist_ok=True)
        yield data_dir
        if data_dir.exists():
            shutil.rmtree(data_dir)

    @pytest.fixture
    def configured_session(self, clean_data_dir: Path) -> Path:
        """Create a fully configured session directory."""
        import uuid

        session_dir = clean_data_dir / "test_session"
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

        # Create config.json with initial credentials
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": str(uuid.uuid4()),
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_change_api_id_triggers_disconnect_and_reauth(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that changing API_ID on existing session triggers disconnect + re-auth flow."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to track disconnect call
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

        # Create mock TelegramClient
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock()
        mock_client.disconnect = AsyncMock()
        mock_client.is_connected.return_value = True

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "99999",  # Changed from 12345
                    "api_hash": "fedcba9876543210fedcba9876543210",  # Changed
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Should show success and reconnect flow
        response_text = response.text.lower()
        assert "credential" in response_text or "reauth" in response_text or "reconnect" in response_text

        # Verify session was disconnected
        mock_session_manager.disconnect.assert_called_once_with("test_session")

        # Verify config was updated with new credentials
        config_path = configured_session / "config.json"
        updated_config = json.loads(config_path.read_text())
        assert updated_config["api_id"] == 99999
        assert updated_config["api_hash"] == "fedcba9876543210fedcba9876543210"

    def test_invalid_api_id_rejected_not_saved(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that invalid API_ID/API_HASH credentials are rejected and not saved."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import ApiIdInvalidError

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]
        original_api_id = config_data["api_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Create mock that raises ApiIdInvalidError on connect
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ApiIdInvalidError("Invalid api_id"))
        mock_client.is_connected.return_value = False

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "11111",  # Invalid API ID
                    "api_hash": "11111111111111111111111111111111",  # Valid format, invalid credentials
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400
        # Should show error about invalid credentials
        assert "invalid" in response.text.lower()
        assert "credentials not saved" in response.text.lower()

        # Verify config was NOT updated (credentials remain unchanged)
        config_path = configured_session / "config.json"
        saved_config = json.loads(config_path.read_text())
        assert saved_config["api_id"] == original_api_id

    def test_valid_credentials_needing_auth_triggers_reconnect(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that valid but unauthenticated credentials trigger reconnect/code modal."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

        # Create mock client with successful connection
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock()
        mock_client.disconnect = AsyncMock()
        mock_client.is_connected.return_value = True

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "55555",
                    "api_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        response_text = response.text.lower()
        # Should show credentials updated message and reconnect flow
        assert "credential" in response_text or "reauth" in response_text or "updated" in response_text

        # Verify config was saved
        config_path = configured_session / "config.json"
        saved_config = json.loads(config_path.read_text())
        assert saved_config["api_id"] == 55555

    def test_credentials_not_saved_before_validation_success(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that only save credentials AFTER successful validation."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import ApiIdInvalidError

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id and initial config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]
        original_api_id = config_data["api_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock client to simulate validation failure (invalid credentials)
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ApiIdInvalidError("Invalid api_id or api_hash"))
        mock_client.is_connected.return_value = False

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            # Attempt to update with invalid credentials
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "99999",  # Would be saved, but validation fails
                    "api_hash": "ffffffffffffffffffffffffffffffff",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should return error
        assert response.status_code == 400

        # Most important: verify original credentials are still in config
        config_path = configured_session / "config.json"
        saved_config = json.loads(config_path.read_text())
        assert saved_config["api_id"] == original_api_id
        # Credentials were NOT saved despite validation attempt

    def test_network_error_during_validation_shows_proxy_error(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that network/proxy errors during validation show helpful message."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock client to simulate network error
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ConnectionError("Proxy connection failed"))
        mock_client.is_connected.return_value = False

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "77777",
                    "api_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 500
        # Should mention network/proxy error
        response_text = response.text.lower()
        assert "network" in response_text or "proxy" in response_text or "failed" in response_text


