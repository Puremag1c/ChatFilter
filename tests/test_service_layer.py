"""Tests for the service layer."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.models import Chat, ChatMetrics, ChatType, Message
from chatfilter.service.chat_analysis import ChatAnalysisService, SessionNotFoundError
from chatfilter.telegram.session_manager import SessionManager


@pytest.fixture
def mock_session_manager() -> SessionManager:
    """Provide a mock session manager."""
    return MagicMock(spec=SessionManager)


@pytest.fixture
def test_data_dir(tmp_path: Path) -> Path:
    """Provide a temporary data directory."""
    data_dir = tmp_path / "data" / "sessions"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


@pytest.fixture
def service(
    mock_session_manager: SessionManager,
    test_data_dir: Path,
) -> ChatAnalysisService:
    """Provide a ChatAnalysisService instance for testing."""
    return ChatAnalysisService(
        session_manager=mock_session_manager,
        data_dir=test_data_dir,
    )


class TestChatAnalysisServiceInit:
    """Tests for ChatAnalysisService initialization."""

    def test_service_initialization(
        self,
        mock_session_manager: SessionManager,
        test_data_dir: Path,
    ) -> None:
        """Test that service initializes correctly with dependencies."""
        service = ChatAnalysisService(
            session_manager=mock_session_manager,
            data_dir=test_data_dir,
        )

        assert service._session_manager is mock_session_manager
        assert service._data_dir == test_data_dir
        assert service._loaders == {}
        assert service._chat_cache == {}


class TestGetSessionPaths:
    """Tests for _get_session_paths method."""

    def test_get_session_paths_success(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
    ) -> None:
        """Test getting session paths for valid session."""
        # Create a test session directory
        session_dir = test_data_dir / "test_session"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").touch()

        session_path, config_path = service._get_session_paths("test_session")

        assert session_path == session_dir / "session.session"
        assert config_path == session_dir / "config.json"

    def test_get_session_paths_nonexistent_session(
        self,
        service: ChatAnalysisService,
    ) -> None:
        """Test getting paths for non-existent session raises error."""
        with pytest.raises(SessionNotFoundError) as exc_info:
            service._get_session_paths("nonexistent")

        assert "not found" in str(exc_info.value).lower()

    def test_get_session_paths_incomplete_session(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
    ) -> None:
        """Test getting paths for incomplete session raises error."""
        # Create session dir but missing files
        session_dir = test_data_dir / "incomplete"
        session_dir.mkdir()

        with pytest.raises(SessionNotFoundError) as exc_info:
            service._get_session_paths("incomplete")

        assert "incomplete" in str(exc_info.value).lower()


class TestGetChats:
    """Tests for get_chats method."""

    @pytest.mark.asyncio
    async def test_get_chats_success(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
        mock_session_manager: SessionManager,
    ) -> None:
        """Test getting chats successfully."""
        # Setup test session
        session_dir = test_data_dir / "test_session"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')

        # Mock data
        mock_chats = [
            Chat(id=1, title="Test Group", chat_type=ChatType.GROUP),
            Chat(id=2, title="Test Channel", chat_type=ChatType.CHANNEL),
        ]

        # Mock the loader and get_dialogs
        with (
            patch("chatfilter.service.chat_analysis.TelegramClientLoader") as mock_loader_cls,
            patch("chatfilter.service.chat_analysis.get_dialogs") as mock_get_dialogs,
        ):
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            mock_session_manager.session.return_value = mock_session_ctx

            mock_get_dialogs.return_value = mock_chats

            result = await service.get_chats("test_session")

        assert result == mock_chats
        assert "test_session" in service._chat_cache
        assert service._chat_cache["test_session"][1] == mock_chats[0]
        assert service._chat_cache["test_session"][2] == mock_chats[1]


class TestGetChatInfo:
    """Tests for get_chat_info method."""

    @pytest.mark.asyncio
    async def test_get_chat_info_from_cache(
        self,
        service: ChatAnalysisService,
    ) -> None:
        """Test getting cached chat info."""
        # Pre-populate cache
        test_chat = Chat(id=123, title="Cached Chat", chat_type=ChatType.GROUP)
        service._chat_cache["session1"] = {123: test_chat}

        result = await service.get_chat_info("session1", 123)

        assert result == test_chat

    @pytest.mark.asyncio
    async def test_get_chat_info_not_in_cache(
        self,
        service: ChatAnalysisService,
    ) -> None:
        """Test getting chat info returns None if not cached."""
        result = await service.get_chat_info("session1", 999)

        assert result is None


class TestAnalyzeChat:
    """Tests for analyze_chat method."""

    @pytest.mark.asyncio
    async def test_analyze_chat_success(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
        mock_session_manager: SessionManager,
    ) -> None:
        """Test analyzing a chat successfully."""
        # Setup test session
        session_dir = test_data_dir / "test_session"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')

        # Pre-cache chat info
        cached_chat = Chat(id=456, title="Test Chat", chat_type=ChatType.SUPERGROUP)
        service._chat_cache["test_session"] = {456: cached_chat}

        # Mock messages
        mock_messages = [
            Message(
                id=1,
                chat_id=456,
                author_id=100,
                text="Hello",
                timestamp=datetime.now(UTC),
            ),
            Message(
                id=2,
                chat_id=456,
                author_id=101,
                text="Hi",
                timestamp=datetime.now(UTC),
            ),
        ]

        # Mock the loader, get_messages, and compute_metrics
        with (
            patch("chatfilter.service.chat_analysis.TelegramClientLoader") as mock_loader_cls,
            patch("chatfilter.service.chat_analysis.get_messages") as mock_get_messages,
            patch("chatfilter.service.chat_analysis.compute_metrics") as mock_compute_metrics,
        ):
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            mock_session_manager.session.return_value = mock_session_ctx

            mock_get_messages.return_value = mock_messages

            mock_metrics = ChatMetrics(
                message_count=2,
                unique_authors=2,
                history_hours=1.0,
                first_message_at=mock_messages[0].timestamp,
                last_message_at=mock_messages[1].timestamp,
            )
            mock_compute_metrics.return_value = mock_metrics

            result = await service.analyze_chat("test_session", 456, message_limit=1000)

        assert result.chat == cached_chat
        assert result.metrics == mock_metrics
        assert result.analyzed_at is not None
        mock_get_messages.assert_awaited_once_with(mock_client, 456, limit=1000)

    @pytest.mark.asyncio
    async def test_analyze_chat_without_cached_info(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
        mock_session_manager: SessionManager,
    ) -> None:
        """Test analyzing chat creates minimal chat info if not cached."""
        # Setup test session
        session_dir = test_data_dir / "test_session"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')

        # Mock the dependencies
        with (
            patch("chatfilter.service.chat_analysis.TelegramClientLoader") as mock_loader_cls,
            patch("chatfilter.service.chat_analysis.get_messages") as mock_get_messages,
            patch("chatfilter.service.chat_analysis.compute_metrics") as mock_compute_metrics,
        ):
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            mock_session_manager.session.return_value = mock_session_ctx

            mock_get_messages.return_value = []
            mock_compute_metrics.return_value = ChatMetrics(
                message_count=0,
                unique_authors=0,
                history_hours=0.0,
                first_message_at=datetime.now(UTC),
                last_message_at=datetime.now(UTC),
            )

            result = await service.analyze_chat("test_session", 789)

        # Should create minimal chat info
        assert result.chat.id == 789
        assert result.chat.title == "Chat 789"
        assert result.chat.chat_type == ChatType.GROUP


class TestValidateSession:
    """Tests for validate_session method."""

    @pytest.mark.asyncio
    async def test_validate_session_success(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
    ) -> None:
        """Test validating a valid session."""
        # Setup test session
        session_dir = test_data_dir / "valid_session"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')

        with patch("chatfilter.service.chat_analysis.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            result = await service.validate_session("valid_session")

        assert result is True

    @pytest.mark.asyncio
    async def test_validate_session_not_found(
        self,
        service: ChatAnalysisService,
    ) -> None:
        """Test validating non-existent session returns False."""
        result = await service.validate_session("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_validate_session_validation_error(
        self,
        service: ChatAnalysisService,
        test_data_dir: Path,
    ) -> None:
        """Test validating session with validation error returns False."""
        # Setup test session
        session_dir = test_data_dir / "invalid_session"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')

        with patch("chatfilter.service.chat_analysis.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.side_effect = ValueError("Invalid config")

            result = await service.validate_session("invalid_session")

        assert result is False
