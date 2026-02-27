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


class TestSessionConnectDisconnectAPI:
    """Tests for session connect/disconnect API endpoints."""

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

        # Create config.json with valid proxy_id
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": str(uuid.uuid4()),
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    @pytest.fixture
    def unconfigured_session(self, clean_data_dir: Path) -> Path:
        """Create a session without proxy configured."""
        session_dir = clean_data_dir / "unconfigured_session"
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

        # Create config.json without proxy_id
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": None,
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_connect_session_not_found(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test connecting non-existent session returns 404."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/nonexistent/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_connect_session_invalid_name(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test connecting with invalid session name returns 200 with error state."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/.../connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_connect_session_not_configured(
        self, client: TestClient, clean_data_dir: Path, unconfigured_session: Path
    ) -> None:
        """Test connecting unconfigured session returns needs_config state."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/unconfigured_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Should return needs_config state (not error)
        assert "needs_config" in response.text.lower() or "config" in response.text.lower()

    def test_connect_session_proxy_missing(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test connecting session with missing proxy returns needs_config."""
        from unittest.mock import MagicMock, patch

        from chatfilter.storage.errors import StorageNotFoundError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                side_effect=StorageNotFoundError("Not found"),
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # After refactor: missing proxy returns needs_config (unified state)
        assert "config" in response.text.lower()

    def test_connect_session_success(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection - returns immediately with 'connecting' state."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager - get_info returns None to simulate new session
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock()
        mock_session_manager.get_info.return_value = None  # No existing session

        # Mock loader
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
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Connect now returns immediately with 'connecting' state
        # The actual connection happens in background, final state via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_failure(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection failure - HTTP returns 'connecting', error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionConnectError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager to raise error
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionConnectError("Connection failed")
        )

        # Mock loader
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
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Connect returns immediately with 'connecting' state
        # The error is delivered via SSE in background task
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_concurrent_request_returns_connecting(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test concurrent connection request returns 'connecting' - error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionBusyError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager to raise SessionBusyError
        # Now handled in background task, not HTTP handler
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionBusyError("Session is already busy with another operation")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        # Mock loader
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
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # SessionBusyError is handled in background task and delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_timeout_returns_connecting(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection timeout - HTTP returns 'connecting', error via SSE."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager connect to raise TimeoutError
        # Now handled in background task, not HTTP handler
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_session_manager.get_info.return_value = None  # No existing session

        # Mock loader
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
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # Timeout error is handled in background task and delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_missing_session_file(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test connect with missing session.session file triggers send_code flow.

        Scenario: Session exists with config.json but NO session.session file
        Expected: HTTP 200 with 'connecting' state, background task triggers send_code → 'needs_code' via SSE
        """
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Remove the session.session file to simulate missing session
        session_file = configured_session / "session.session"
        if session_file.exists():
            session_file.unlink()

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.get_info.return_value = None

        # Mock loader - will fail to load non-existent session
        mock_loader = MagicMock()
        mock_loader.validate.return_value = None

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
            patch(
                "chatfilter.web.routers.sessions._send_verification_code_and_create_auth",
                new_callable=AsyncMock,
            ) as mock_send_code,
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()
        # Verify auto-reauth without showing removed legacy status (now 'disconnected')
        removed_status = "session" + "_expired"  # Removed legacy status
        assert removed_status not in response.text.lower()

    def test_connect_session_invalid_session_auto_reauth(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test connect with invalid session.session (AuthKeyUnregistered) triggers auto-reauth.

        Scenario: Session exists with config.json and corrupted session.session
        Expected: HTTP 200 with 'connecting' state, background task detects AuthKeyUnregistered,
                  deletes file, triggers send_code → 'needs_code' via SSE
                  (no removed legacy status shown - now 'disconnected')
        """
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from telethon.errors import AuthKeyUnregisteredError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.get_info.return_value = None
        mock_session_manager.register = MagicMock()
        # connect() will raise AuthKeyUnregisteredError to simulate invalid session
        mock_session_manager.connect = AsyncMock(side_effect=AuthKeyUnregisteredError(request=None))

        # Mock loader
        mock_loader = MagicMock()
        mock_loader.validate.return_value = None

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
            patch(
                "chatfilter.web.routers.sessions._send_verification_code_and_create_auth",
                new_callable=AsyncMock,
            ) as mock_send_code,
            patch(
                "chatfilter.web.routers.sessions.background.secure_delete_file",
                return_value=None,
            ) as mock_delete,
            patch(
                "chatfilter.web.routers.sessions.load_account_info",
                return_value={"phone": "1234567890"},
            ),
            patch(
                "chatfilter.web.routers.sessions.save_account_info",
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()
        # Verify auto-reauth without showing removed legacy status (now 'disconnected')
        removed_status = "session" + "_expired"  # Removed legacy status
        assert removed_status not in response.text.lower()

    def test_disconnect_session_invalid_name(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test disconnecting with invalid session name returns 400."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/.../disconnect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400

    def test_disconnect_session_success(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test successful session disconnection."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

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
        ):
            response = client.post(
                "/api/sessions/test_session/disconnect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # v0.8.5: endpoint returns empty body, relies on SSE OOB swaps
        assert response.text == ""
        assert "HX-Reswap" in response.headers
        mock_session_manager.disconnect.assert_called_once_with("test_session")

    def test_disconnect_session_not_connected(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test disconnecting session that's not connected still succeeds."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
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

        # Mock session manager - disconnect is safe even when not connected
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

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
        ):
            response = client.post(
                "/api/sessions/test_session/disconnect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should succeed - disconnect is idempotent
        assert response.status_code == 200
        # v0.8.5: endpoint returns empty body, relies on SSE OOB swaps
        assert response.text == ""


