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
        from chatfilter.service.chat_analysis import SessionNotFoundError

        app = create_app()
        client = TestClient(app)

        # Mock the service to raise SessionNotFoundError
        with patch("chatfilter.web.routers.chats.get_chat_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats = AsyncMock(
                side_effect=SessionNotFoundError("Session 'nonexistent' not found")
            )

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

        # Mock the service layer instead of the low-level components
        with patch("chatfilter.web.routers.chats.get_chat_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats = AsyncMock(return_value=mock_chats)

            response = client.get("/api/chats?session-select=test_session")

        assert response.status_code == 200
        assert "Test Group" in response.text
        assert "Test Channel" in response.text
        assert "@testchan" in response.text

        # Verify the service was called correctly
        mock_service.get_chats.assert_awaited_once_with("test_session")
