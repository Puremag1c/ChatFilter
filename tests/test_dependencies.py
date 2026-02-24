"""Tests for FastAPI dependency injection helpers.

Tests cover:
- get_web_session: web session dependency
- get_session_manager: Telegram session manager
- get_chat_analysis_service: chat analysis service
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from starlette.requests import Request

from chatfilter.web.dependencies import (
    get_chat_analysis_service,
    get_session_manager,
    get_web_session,
)


class TestGetWebSession:
    """Tests for get_web_session dependency."""

    def test_returns_session(self) -> None:
        """Should return session from get_session."""
        request = MagicMock(spec=Request)

        with patch("chatfilter.web.dependencies.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session

            result = get_web_session(request)

            assert result is mock_session
            mock_get_session.assert_called_once_with(request)


class TestGetSessionManager:
    """Tests for get_session_manager function."""

    def test_creates_session_manager(self) -> None:
        """Should create SessionManager instance."""
        # Reset global
        import chatfilter.web.dependencies as deps
        from chatfilter.telegram.session_manager import SessionManager

        deps._session_manager = None

        result = get_session_manager()

        assert isinstance(result, SessionManager)

    def test_returns_cached_instance(self) -> None:
        """Should return cached instance on subsequent calls."""
        import chatfilter.web.dependencies as deps

        mock_manager = MagicMock()
        deps._session_manager = mock_manager

        result = get_session_manager()

        assert result is mock_manager


class TestGetChatAnalysisService:
    """Tests for get_chat_analysis_service function."""

    def test_creates_service(self) -> None:
        """Should create ChatAnalysisService instance."""
        import chatfilter.web.dependencies as deps
        from chatfilter.service import ChatAnalysisService

        deps._chat_service = None

        result = get_chat_analysis_service()

        assert isinstance(result, ChatAnalysisService)

    def test_returns_cached_instance(self) -> None:
        """Should return cached instance on subsequent calls."""
        import chatfilter.web.dependencies as deps

        mock_service = MagicMock()
        deps._chat_service = mock_service

        result = get_chat_analysis_service()

        assert result is mock_service
