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


class TestSessionConfigAPI:
    """Tests for session configuration API endpoints."""

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
    def session_with_config(self, clean_data_dir: Path) -> Path:
        """Create a session directory with config file."""
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

        # Create config.json
        config_data = {
            "api_id": 12345,
            "api_hash": "test_hash_abcdef1234567890123456",
            "proxy_id": None,
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_get_session_config_success(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test getting session configuration form."""
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with (
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
            patch("chatfilter.storage.proxy_pool.load_proxy_pool", return_value=[]),
        ):
            response = client.get("/api/sessions/test_session/config")

        assert response.status_code == 200
        assert "proxy_id" in response.text or "Proxy" in response.text

    def test_get_session_config_not_found(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test getting config for non-existent session.

        Edit button should always return config form, even if files are missing.
        This allows users to fix configuration issues via the Edit form.
        """
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.get("/api/sessions/nonexistent/config")

        # Returns 200 OK with config form (not an error)
        assert response.status_code == 200
        # Config form should be present
        assert "session_config" in response.text or "api_id" in response.text or "api_hash" in response.text

    def test_get_session_config_invalid_name(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test getting config with invalid session name."""
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Use URL-encoded invalid characters that won't break URL parsing
        # After sanitization, "..." becomes empty, which raises ValueError
        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.get("/api/sessions/.../config")

        # Returns 200 OK with HTML error to prevent HTMX from destroying session list
        assert response.status_code == 200
        assert "Invalid session name" in response.text

    def test_update_session_config_success(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test updating session proxy configuration."""
        import uuid
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Create a mock proxy with valid UUID
        test_proxy_id = str(uuid.uuid4())
        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Create mock TelegramClient for credential validation
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
            patch("chatfilter.security.SecureCredentialManager"),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "success" in response.text.lower() or "saved" in response.text.lower()

        # Verify config was updated
        config_path = session_with_config / "config.json"
        config_data = json.loads(config_path.read_text())
        assert config_data["proxy_id"] == test_proxy_id
        assert config_data["api_id"] == 12345678
        assert config_data["api_hash"] == "0123456789abcdef0123456789abcdef"

    def test_update_session_config_proxy_required(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test that proxy selection is required."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": "",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # FastAPI returns 422 for validation errors (empty required field)
        # or 400 if our custom validation catches it first
        assert response.status_code in (400, 422)
        # Check error message present (varies by validation layer)
        assert "required" in response.text.lower() or "proxy" in response.text.lower()

    def test_update_session_config_proxy_not_found(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test updating with non-existent proxy ID."""
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
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": "nonexistent-proxy",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400
        assert "not found" in response.text.lower()

    def test_update_session_config_session_not_found(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test updating config for non-existent session."""
        import uuid
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        test_proxy_id = str(uuid.uuid4())

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            response = client.put(
                "/api/sessions/nonexistent/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 404


