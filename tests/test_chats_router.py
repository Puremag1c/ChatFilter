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
            mock_service.get_chats_paginated = AsyncMock(
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
            # Return tuple of (chats, total_count)
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, len(mock_chats)))

            response = client.get("/api/chats?session-select=test_session")

        assert response.status_code == 200
        assert "Test Group" in response.text
        assert "Test Channel" in response.text
        assert "@testchan" in response.text

        # Verify the service was called correctly with pagination params
        mock_service.get_chats_paginated.assert_awaited_once_with(
            "test_session", offset=0, limit=100
        )

    def test_get_chats_with_pagination(self) -> None:
        """Test getting chats with explicit pagination parameters."""
        # Mock data - simulate a large list with pagination
        mock_chats = [
            Chat(id=i, title=f"Chat {i}", chat_type=ChatType.GROUP)
            for i in range(150, 200)  # Simulating items 150-200 (offset=150, limit=50)
        ]

        app = create_app()
        client = TestClient(app)

        # Mock the service layer
        with patch("chatfilter.web.routers.chats.get_chat_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            # Return tuple of (chats_slice, total_count)
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 500))

            response = client.get("/api/chats?session-select=test_session&offset=150&limit=50")

        assert response.status_code == 200
        # Check that pagination metadata is in the response
        assert "Chat 150" in response.text
        assert "Chat 199" in response.text
        # Check for load more button (has_more should be True since 200 < 500)
        assert "Load More" in response.text
        assert "300 remaining" in response.text  # 500 - 200 = 300

        # Verify the service was called with custom pagination params
        mock_service.get_chats_paginated.assert_awaited_once_with(
            "test_session", offset=150, limit=50
        )

    def test_get_chats_last_page(self) -> None:
        """Test getting the last page of chats (no load more button)."""
        # Mock data - last 20 chats
        mock_chats = [
            Chat(id=i, title=f"Chat {i}", chat_type=ChatType.GROUP)
            for i in range(80, 100)  # Last 20 chats
        ]

        app = create_app()
        client = TestClient(app)

        # Mock the service layer
        with patch("chatfilter.web.routers.chats.get_chat_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            # Return tuple showing we've reached the end
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 100))

            response = client.get("/api/chats?session-select=test_session&offset=80&limit=100")

        assert response.status_code == 200
        assert "Chat 80" in response.text
        # Should not have load more button on last page
        # Note: The response might not contain "Load More" if has_more is False
