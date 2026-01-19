"""Tests for chats router."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from chatfilter.models.chat import Chat, ChatType
from chatfilter.web.app import create_app


class TestChatsPage:
    """Tests for chats page."""

    def test_chats_page_loads(self) -> None:
        """Test that chats page loads successfully."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/chats")

        assert response.status_code == 200
        assert "Select Chats" in response.text


class TestChatsAPI:
    """Tests for chats API endpoints."""

    def test_get_chats_no_session_selected(self) -> None:
        """Test getting chats with no session selected."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/chats?session-select=")

        assert response.status_code == 200
        # Should return empty list, no error

    def test_get_chats_session_not_found(self) -> None:
        """Test getting chats from non-existent session returns 404."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/chats?session-select=nonexistent")

        # Session not found returns 404
        assert response.status_code == 404

    def test_get_chats_success(self) -> None:
        """Test getting chats successfully from a mock session."""
        # Mock data
        mock_chats = [
            Chat(id=1, title="Test Group", chat_type=ChatType.GROUP),
            Chat(id=2, title="Test Channel", chat_type=ChatType.CHANNEL, username="testchan"),
        ]

        app = create_app()
        client = TestClient(app)

        # We need to mock several things:
        # 1. The session path check
        # 2. The TelegramClientLoader
        # 3. The SessionManager connection
        # 4. The get_dialogs call

        with patch("chatfilter.web.routers.chats.get_session_paths") as mock_paths, \
             patch("chatfilter.web.routers.chats.TelegramClientLoader") as mock_loader_cls, \
             patch("chatfilter.web.routers.chats.get_session_manager") as mock_get_manager, \
             patch("chatfilter.web.routers.chats.get_dialogs") as mock_get_dialogs:

            from pathlib import Path

            mock_paths.return_value = (Path("/tmp/test.session"), Path("/tmp/config.json"))

            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_manager = mock_get_manager.return_value
            mock_client = AsyncMock()

            # Create an async context manager mock
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            mock_manager.session.return_value = mock_session_ctx

            mock_get_dialogs.return_value = mock_chats

            response = client.get("/api/chats?session-select=test_session")

        assert response.status_code == 200
        assert "Test Group" in response.text
        assert "Test Channel" in response.text
        assert "@testchan" in response.text
