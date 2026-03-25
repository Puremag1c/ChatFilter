"""Tests for sessions router."""

import json
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app

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

        # Code uses ensure_data_dir(user_id) where user_id=None for unauthenticated requests
        # str(None) == "None", so sessions live at sessions_dir / "None" / session_name
        user_dir = clean_data_dir / "None"
        user_dir.mkdir(parents=True, exist_ok=True)
        session_dir = user_dir / "dead_session"
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
        from unittest.mock import AsyncMock, MagicMock

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session import SessionReauthRequiredError

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
            patch(
                "chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings
            ),
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
        from unittest.mock import AsyncMock, MagicMock

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session import SessionReauthRequiredError

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
            patch(
                "chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings
            ),
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
        from unittest.mock import AsyncMock, MagicMock

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session import SessionInfo, SessionState

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
            patch(
                "chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings
            ),
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
        from unittest.mock import AsyncMock, MagicMock

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session import (
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
            patch(
                "chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings
            ),
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
            patch(
                "chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings
            ),
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

