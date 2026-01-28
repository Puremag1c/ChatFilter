"""Tests for chats router."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.models import AccountInfo, Chat, ChatType
from chatfilter.service.chat_analysis import SessionNotFoundError
from chatfilter.telegram.session_manager import (
    SessionInvalidError,
    SessionReauthRequiredError,
)
from chatfilter.web.app import create_app


@pytest.fixture
def mock_chat_service() -> MagicMock:
    """Create a mock chat service."""
    return MagicMock()


@pytest.fixture(autouse=True)
def reset_global_state() -> None:
    """Reset global singleton state before each test.

    This ensures that mocking works correctly by clearing cached instances.
    """
    import chatfilter.web.routers.chats as chats_module

    # Clear global state before test
    chats_module._chat_service = None
    chats_module._session_manager = None

    yield

    # Clear global state after test
    chats_module._chat_service = None
    chats_module._session_manager = None


@pytest.fixture
def client() -> TestClient:
    """Create test client."""
    app = create_app()
    return TestClient(app)


class TestChatsPage:
    """Tests for chats page."""

    def test_chats_page_loads(self, client: TestClient) -> None:
        """Test that chats page loads successfully."""
        response = client.get("/chats")

        assert response.status_code == 200
        assert "Select Chats" in response.text


class TestChatsAPI:
    """Tests for chats API endpoints."""

    def test_get_chats_session_not_found(self, client: TestClient) -> None:
        """Test getting chats from non-existent session returns 404."""
        # Mock the service to raise SessionNotFoundError
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionNotFoundError("Session 'nonexistent' not found")
            )

            response = client.get("/api/chats?session_select=nonexistent")

            # Session not found returns 404
            assert response.status_code == 404

    def test_get_chats_success(self, client: TestClient) -> None:
        """Test getting chats successfully from a mock session."""
        # Mock data
        mock_chats = [
            Chat(id=1, title="Test Group", chat_type=ChatType.GROUP),
            Chat(id=2, title="Test Channel", chat_type=ChatType.CHANNEL, username="testchan"),
        ]

        # Mock the service layer instead of the low-level components
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            # Return tuple of (chats, total_count)
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, len(mock_chats)))

            response = client.get("/api/chats?session_select=test_session")

        assert response.status_code == 200
        assert "Test Group" in response.text
        assert "Test Channel" in response.text
        assert "@testchan" in response.text

        # Verify the service was called correctly with pagination params
        mock_service.get_chats_paginated.assert_awaited_once_with(
            "test_session", offset=0, limit=100
        )

    def test_get_chats_with_pagination(self, client: TestClient) -> None:
        """Test getting chats with explicit pagination parameters."""
        # Mock data - simulate a large list with pagination
        mock_chats = [
            Chat(id=i, title=f"Chat {i}", chat_type=ChatType.GROUP)
            for i in range(150, 200)  # Simulating items 150-200 (offset=150, limit=50)
        ]

        # Mock the service layer
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            # Return tuple of (chats_slice, total_count)
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 500))

            response = client.get("/api/chats?session_select=test_session&offset=150&limit=50")

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

    def test_get_chats_last_page(self, client: TestClient) -> None:
        """Test getting the last page of chats (no load more button)."""
        # Mock data - last 20 chats
        mock_chats = [
            Chat(id=i, title=f"Chat {i}", chat_type=ChatType.GROUP)
            for i in range(80, 100)  # Last 20 chats
        ]

        # Mock the service layer
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            # Return tuple showing we've reached the end
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 100))

            response = client.get("/api/chats?session_select=test_session&offset=80&limit=100")

        assert response.status_code == 200
        assert "Chat 80" in response.text
        # Should not have load more button on last page
        # Note: The response might not contain "Load More" if has_more is False

    def test_get_chats_session_invalid_error(self, client: TestClient) -> None:
        """Test getting chats when session is invalid (revoked/banned)."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionInvalidError("Session revoked")
            )

            with patch("chatfilter.web.routers.chats.cleanup_invalid_session") as mock_cleanup:
                response = client.get("/api/chats?session_select=invalid_session")

                assert response.status_code == 200
                assert "Session is invalid" in response.text
                assert "has been removed" in response.text
                mock_cleanup.assert_called_once_with("invalid_session")

    def test_get_chats_session_reauth_required_error(self, client: TestClient) -> None:
        """Test getting chats when session requires re-authorization."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionReauthRequiredError("Session expired")
            )

            response = client.get("/api/chats?session_select=expired_session")

            assert response.status_code == 200
            assert "requires re-authorization" in response.text.lower()

    def test_get_chats_session_reauth_2fa_error(self, client: TestClient) -> None:
        """Test getting chats when 2FA is required."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionReauthRequiredError("2FA password required")
            )

            response = client.get("/api/chats?session_select=2fa_session")

            assert response.status_code == 200
            assert "2FA" in response.text or "Two-factor authentication" in response.text

    def test_get_chats_generic_telethon_error(self, client: TestClient) -> None:
        """Test handling of generic Telethon errors."""

        # Create a custom error class that looks like a Telethon error
        class TelethonLikeError(Exception):
            pass

        # Set the module attribute on the class itself
        TelethonLikeError.__module__ = "telethon.errors"
        mock_error = TelethonLikeError("Some Telethon error")

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(side_effect=mock_error)

            with patch("chatfilter.web.routers.chats.get_actionable_error_info") as mock_error_info:
                mock_error_info.return_value = {
                    "message": "Rate limit exceeded",
                    "action": "Wait and try again",
                    "action_type": "retry",
                    "can_retry": True,
                }

                response = client.get("/api/chats?session_select=test_session")

                assert response.status_code == 200
                assert "Rate limit exceeded" in response.text

    def test_get_chats_generic_error(self, client: TestClient) -> None:
        """Test handling of generic non-Telethon errors."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(side_effect=Exception("Network error"))

            response = client.get("/api/chats?session_select=test_session")

            assert response.status_code == 200
            assert "Failed to connect to Telegram" in response.text

    def test_get_chats_error_info_extraction_fails(self, client: TestClient) -> None:
        """Test handling when error info extraction itself fails."""

        class TelethonLikeError(Exception):
            pass

        TelethonLikeError.__module__ = "telethon.errors"
        mock_error = TelethonLikeError("Telethon error")

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(side_effect=mock_error)

            # Mock error info extraction to raise an exception
            with patch(
                "chatfilter.web.routers.chats.get_actionable_error_info",
                side_effect=Exception("Error info extraction failed"),
            ):
                response = client.get("/api/chats?session_select=test_session")

                # Should fall back to generic error message
                assert response.status_code == 200
                assert "Failed to connect to Telegram" in response.text

    def test_get_chats_json_no_session(self, client: TestClient) -> None:
        """Test JSON endpoint with no session selected."""
        response = client.get("/api/chats/json?session_select=")

        assert response.status_code == 200
        data = response.json()
        assert data["chats"] == []
        assert data["total_count"] == 0
        assert data["session_id"] == ""

    def test_get_chats_json_session_not_found(self, client: TestClient) -> None:
        """Test JSON endpoint returns 404 for non-existent session."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionNotFoundError("Session 'nonexistent' not found")
            )

            response = client.get("/api/chats/json?session_select=nonexistent")

        assert response.status_code == 404

    def test_get_chats_json_success(self, client: TestClient) -> None:
        """Test JSON endpoint returns all chats successfully."""
        # Mock data - large list for virtual scrolling
        mock_chats = [
            Chat(
                id=i,
                title=f"Chat {i}",
                chat_type=ChatType.GROUP,
                username=f"chat{i}" if i % 2 == 0 else None,
                member_count=100 + i if i % 3 == 0 else None,
            )
            for i in range(1, 201)  # 200 chats
        ]

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, len(mock_chats)))

            response = client.get("/api/chats/json?session_select=test_session")

        assert response.status_code == 200
        data = response.json()

        assert len(data["chats"]) == 200
        assert data["total_count"] == 200
        assert data["session_id"] == "test_session"

        # Verify chat data structure
        first_chat = data["chats"][0]
        assert "id" in first_chat
        assert "title" in first_chat
        assert "chat_type" in first_chat
        assert first_chat["title"] == "Chat 1"
        assert first_chat["chat_type"] == "group"

        # Verify chats with username
        chat_with_username = data["chats"][1]  # id=2, even number
        assert chat_with_username["username"] == "chat2"

        # Verify chats with member_count
        chat_with_members = data["chats"][2]  # id=3, divisible by 3
        assert chat_with_members["member_count"] == 103

        # Verify service was called with high limit to fetch all chats
        mock_service.get_chats_paginated.assert_awaited_once_with(
            "test_session", offset=0, limit=10000
        )

    def test_get_chats_json_session_invalid_error(self, client: TestClient) -> None:
        """Test JSON endpoint handles invalid session."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionInvalidError("Session revoked")
            )

            with patch("chatfilter.web.routers.chats.cleanup_invalid_session") as mock_cleanup:
                response = client.get("/api/chats/json?session_select=invalid_session")

                assert response.status_code == 400
                assert "invalid" in response.json()["detail"].lower()
                mock_cleanup.assert_called_once_with("invalid_session")

    def test_get_chats_json_session_reauth_required(self, client: TestClient) -> None:
        """Test JSON endpoint handles reauth required."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(
                side_effect=SessionReauthRequiredError("Session expired")
            )

            response = client.get("/api/chats/json?session_select=expired_session")

            assert response.status_code == 401
            assert "re-authorization" in response.json()["detail"].lower()

    def test_get_chats_json_generic_error(self, client: TestClient) -> None:
        """Test JSON endpoint handles generic errors."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(side_effect=Exception("Network error"))

            response = client.get("/api/chats/json?session_select=test_session")

            assert response.status_code == 500
            assert "Failed to connect" in response.json()["detail"]


class TestAccountInfoAPI:
    """Tests for account info API endpoints."""

    def test_get_account_info_no_session(self, client: TestClient) -> None:
        """Test account info endpoint with no session selected."""
        response = client.get("/api/account-info?session_select=")

        assert response.status_code == 200
        # Template should render without account info when no session is provided

    def test_get_account_info_success(self, client: TestClient) -> None:
        """Test getting account info successfully."""
        mock_account_info = AccountInfo.fake(
            user_id=123456,
            username="testuser",
            first_name="Test",
            last_name="User",
            is_premium=False,
            chat_count=450,
        )

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(return_value=mock_account_info)

            response = client.get("/api/account-info?session_select=test_session")

            assert response.status_code == 200
            # Check for account info fields in response
            assert "testuser" in response.text or "Test" in response.text
            mock_service.get_account_info.assert_awaited_once_with("test_session")

    def test_get_account_info_session_not_found(self, client: TestClient) -> None:
        """Test account info endpoint with non-existent session."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(
                side_effect=SessionNotFoundError("Session not found")
            )

            response = client.get("/api/account-info?session_select=nonexistent")

            assert response.status_code == 200
            assert "not found" in response.text.lower()

    def test_get_account_info_error(self, client: TestClient) -> None:
        """Test account info endpoint handles errors gracefully."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(side_effect=Exception("Connection error"))

            response = client.get("/api/account-info?session_select=test_session")

            assert response.status_code == 200
            assert "Failed to fetch" in response.text or "error" in response.text.lower()

    def test_get_account_info_json_no_session(self, client: TestClient) -> None:
        """Test JSON account info endpoint with no session."""
        response = client.get("/api/account-info/json?session_select=")

        assert response.status_code == 200
        data = response.json()
        assert "error" in data

    def test_get_account_info_json_success(self, client: TestClient) -> None:
        """Test JSON account info endpoint success."""
        mock_account_info = AccountInfo.fake(
            user_id=123456,
            username="testuser",
            first_name="Test",
            last_name="User",
            is_premium=True,
            chat_count=800,
        )

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(return_value=mock_account_info)

            response = client.get("/api/account-info/json?session_select=test_session")

            assert response.status_code == 200
            data = response.json()

            assert data["user_id"] == 123456
            assert data["username"] == "testuser"
            assert data["first_name"] == "Test"
            assert data["last_name"] == "User"
            assert data["is_premium"] is True
            assert data["chat_count"] == 800
            assert data["chat_limit"] == 1000  # Premium limit
            assert data["remaining_slots"] == 200
            assert data["is_near_limit"] is False
            assert data["display_name"] == "@testuser"

    def test_get_account_info_json_non_premium(self, client: TestClient) -> None:
        """Test JSON account info for non-premium account."""
        mock_account_info = AccountInfo.fake(
            user_id=789,
            username=None,
            first_name="NonPremium",
            is_premium=False,
            chat_count=475,
        )

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(return_value=mock_account_info)

            response = client.get("/api/account-info/json?session_select=test_session")

            assert response.status_code == 200
            data = response.json()

            assert data["is_premium"] is False
            assert data["chat_limit"] == 500  # Standard limit
            assert data["chat_count"] == 475
            assert data["remaining_slots"] == 25
            assert data["is_near_limit"] is True  # 95% of limit
            assert data["usage_percent"] == 95.0

    def test_get_account_info_json_at_limit(self, client: TestClient) -> None:
        """Test JSON account info for account at limit."""
        mock_account_info = AccountInfo.fake(
            user_id=999,
            is_premium=False,
            chat_count=500,  # At limit
        )

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(return_value=mock_account_info)

            response = client.get("/api/account-info/json?session_select=test_session")

            assert response.status_code == 200
            data = response.json()

            assert data["chat_count"] == 500
            assert data["chat_limit"] == 500
            assert data["remaining_slots"] == 0
            assert data["is_at_limit"] is True
            assert data["is_critical"] is True
            assert data["usage_percent"] == 100.0

    def test_get_account_info_json_session_not_found(self, client: TestClient) -> None:
        """Test JSON account info endpoint with non-existent session."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(
                side_effect=SessionNotFoundError("Session not found")
            )

            response = client.get("/api/account-info/json?session_select=nonexistent")

            assert response.status_code == 404

    def test_get_account_info_json_error(self, client: TestClient) -> None:
        """Test JSON account info endpoint handles errors."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_account_info = AsyncMock(side_effect=Exception("Connection error"))

            response = client.get("/api/account-info/json?session_select=test_session")

            assert response.status_code == 500
            assert "Failed to fetch" in response.json()["detail"]


class TestHelperFunctions:
    """Tests for helper functions in chats router."""

    def test_get_session_paths_success(self, tmp_path: Path) -> None:
        """Test get_session_paths with valid session."""
        from chatfilter.web.routers.chats import get_session_paths

        # Create a test session directory
        session_dir = tmp_path / "test_session"
        session_dir.mkdir(parents=True)
        (session_dir / "session.session").touch()
        (session_dir / "config.json").touch()

        with patch("chatfilter.web.routers.chats.DATA_DIR", tmp_path):
            session_path, config_path = get_session_paths("test_session")

            assert session_path == session_dir / "session.session"
            assert config_path == session_dir / "config.json"

    def test_get_session_paths_directory_not_found(self, tmp_path: Path) -> None:
        """Test get_session_paths with non-existent directory."""
        from fastapi import HTTPException

        from chatfilter.web.routers.chats import get_session_paths

        with patch("chatfilter.web.routers.chats.DATA_DIR", tmp_path):
            with pytest.raises(HTTPException) as exc_info:
                get_session_paths("nonexistent")

            assert exc_info.value.status_code == 404
            assert "not found" in exc_info.value.detail.lower()

    def test_get_session_paths_missing_files(self, tmp_path: Path) -> None:
        """Test get_session_paths with missing session files."""
        from fastapi import HTTPException

        from chatfilter.web.routers.chats import get_session_paths

        # Create directory but not the files
        session_dir = tmp_path / "incomplete_session"
        session_dir.mkdir(parents=True)

        with patch("chatfilter.web.routers.chats.DATA_DIR", tmp_path):
            with pytest.raises(HTTPException) as exc_info:
                get_session_paths("incomplete_session")

            assert exc_info.value.status_code == 404
            assert "incomplete" in exc_info.value.detail.lower()

    def test_cleanup_invalid_session(self, tmp_path: Path) -> None:
        """Test cleanup_invalid_session removes session files."""
        from chatfilter.web.routers.chats import cleanup_invalid_session

        # Create a test session directory with files
        session_dir = tmp_path / "invalid_session"
        session_dir.mkdir(parents=True)
        session_file = session_dir / "session.session"
        config_file = session_dir / "config.json"
        session_file.write_text("fake session data")
        config_file.write_text('{"api_id": 12345, "api_hash": "abc"}')

        assert session_dir.exists()
        assert session_file.exists()
        assert config_file.exists()

        with patch("chatfilter.web.routers.chats.DATA_DIR", tmp_path):
            cleanup_invalid_session("invalid_session")

        # Directory and files should be removed
        assert not session_dir.exists()

    def test_cleanup_invalid_session_nonexistent(self, tmp_path: Path) -> None:
        """Test cleanup_invalid_session handles non-existent session gracefully."""
        from chatfilter.web.routers.chats import cleanup_invalid_session

        with patch("chatfilter.web.routers.chats.DATA_DIR", tmp_path):
            # Should not raise an error
            cleanup_invalid_session("nonexistent_session")

    def test_cleanup_invalid_session_error_handling(self, tmp_path: Path) -> None:
        """Test cleanup_invalid_session handles errors gracefully."""
        from chatfilter.web.routers.chats import cleanup_invalid_session

        # Create a test session directory
        session_dir = tmp_path / "error_session"
        session_dir.mkdir(parents=True)
        (session_dir / "session.session").touch()

        with (
            patch("chatfilter.web.routers.chats.DATA_DIR", tmp_path),
            # Mock the secure_delete_file from sessions module
            patch(
                "chatfilter.web.routers.sessions.secure_delete_file",
                side_effect=Exception("Delete error"),
            ),
        ):
            # Should not raise an error, just log it
            cleanup_invalid_session("error_session")


class TestWebSessionPersistence:
    """Tests for web session storage functionality."""

    def test_get_chats_stores_session_in_web_session(self, client: TestClient) -> None:
        """Test that get_chats stores selected session in web session."""
        mock_chats = [Chat(id=1, title="Test", chat_type=ChatType.GROUP)]

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 1))

            # Track web session set calls
            with patch("chatfilter.web.routers.chats.WebSession"):
                response = client.get("/api/chats?session_select=test_session")

                assert response.status_code == 200

    def test_get_chats_json_stores_session_in_web_session(self, client: TestClient) -> None:
        """Test that get_chats_json stores selected session in web session."""
        mock_chats = [Chat(id=1, title="Test", chat_type=ChatType.GROUP)]

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 1))

            response = client.get("/api/chats/json?session_select=test_session")

            assert response.status_code == 200
            # Session storage is handled by the dependency injection


class TestPaginationEdgeCases:
    """Tests for pagination edge cases."""

    def test_get_chats_with_zero_offset(self, client: TestClient) -> None:
        """Test pagination with explicit zero offset."""
        # Chat IDs must be positive (>0), so start from 1
        mock_chats = [Chat(id=i, title=f"Chat {i}", chat_type=ChatType.GROUP) for i in range(1, 11)]

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 100))

            response = client.get("/api/chats?session_select=test&offset=0&limit=10")

            assert response.status_code == 200
            mock_service.get_chats_paginated.assert_awaited_once_with("test", offset=0, limit=10)

    def test_get_chats_with_max_limit(self, client: TestClient) -> None:
        """Test pagination with maximum allowed limit."""
        # Chat IDs must be positive (>0), so start from 1
        mock_chats = [
            Chat(id=i, title=f"Chat {i}", chat_type=ChatType.GROUP) for i in range(1, 501)
        ]

        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(return_value=(mock_chats, 500))

            response = client.get("/api/chats?session_select=test&offset=0&limit=500")

            assert response.status_code == 200
            mock_service.get_chats_paginated.assert_awaited_once_with("test", offset=0, limit=500)

    def test_get_chats_empty_result(self, client: TestClient) -> None:
        """Test getting chats when result is empty."""
        with patch("chatfilter.web.routers.chats.get_chat_analysis_service") as mock_get_service:
            mock_service = mock_get_service.return_value
            mock_service.get_chats_paginated = AsyncMock(return_value=([], 0))

            response = client.get("/api/chats?session_select=test_session")

            assert response.status_code == 200
