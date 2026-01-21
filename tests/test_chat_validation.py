"""Tests for chat ID validation (ChatFilter-9526).

This module tests the validate_chat_ids functionality that prevents
stale chat state when chats are added/deleted between selection and analysis.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from chatfilter.models import Chat, ChatType
from chatfilter.service.chat_analysis import ChatAnalysisService


@pytest.fixture
def mock_session_manager():
    """Provide a mock session manager."""
    manager = MagicMock()
    return manager


@pytest.fixture
def service(mock_session_manager, tmp_path):
    """Provide a ChatAnalysisService with mocked dependencies."""
    return ChatAnalysisService(
        session_manager=mock_session_manager,
        data_dir=tmp_path,
    )


class TestChatIdValidation:
    """Tests for validate_chat_ids method."""

    @pytest.mark.asyncio
    async def test_validate_all_valid_ids(self, service, monkeypatch):
        """Test validation when all selected chat IDs are valid."""
        # Mock get_chats to return a list of chats
        mock_chats = [
            Chat(id=123, title="Chat 1", chat_type=ChatType.GROUP),
            Chat(id=456, title="Chat 2", chat_type=ChatType.GROUP),
            Chat(id=789, title="Chat 3", chat_type=ChatType.GROUP),
        ]

        async def mock_get_chats(session_id):
            return mock_chats

        monkeypatch.setattr(service, "get_chats", mock_get_chats)

        # Validate chat IDs that all exist
        valid_ids, invalid_ids = await service.validate_chat_ids("test_session", [123, 456, 789])

        assert valid_ids == [123, 456, 789]
        assert invalid_ids == []

    @pytest.mark.asyncio
    async def test_validate_some_invalid_ids(self, service, monkeypatch):
        """Test validation when some selected chat IDs are stale/invalid."""
        # Mock get_chats to return a list of chats
        mock_chats = [
            Chat(id=123, title="Chat 1", chat_type=ChatType.GROUP),
            Chat(id=456, title="Chat 2", chat_type=ChatType.GROUP),
        ]

        async def mock_get_chats(session_id):
            return mock_chats

        monkeypatch.setattr(service, "get_chats", mock_get_chats)

        # Validate chat IDs where 789 and 999 don't exist (were deleted)
        valid_ids, invalid_ids = await service.validate_chat_ids(
            "test_session", [123, 456, 789, 999]
        )

        assert valid_ids == [123, 456]
        assert invalid_ids == [789, 999]

    @pytest.mark.asyncio
    async def test_validate_all_invalid_ids(self, service, monkeypatch):
        """Test validation when all selected chat IDs are invalid."""
        # Mock get_chats to return a list of chats
        mock_chats = [
            Chat(id=123, title="Chat 1", chat_type=ChatType.GROUP),
            Chat(id=456, title="Chat 2", chat_type=ChatType.GROUP),
        ]

        async def mock_get_chats(session_id):
            return mock_chats

        monkeypatch.setattr(service, "get_chats", mock_get_chats)

        # Validate chat IDs that don't exist at all
        valid_ids, invalid_ids = await service.validate_chat_ids("test_session", [789, 999, 111])

        assert valid_ids == []
        assert invalid_ids == [789, 999, 111]

    @pytest.mark.asyncio
    async def test_validate_clears_cache(self, service, monkeypatch):
        """Test that validation clears cache to fetch fresh data."""
        # Pre-populate cache with stale data
        service._chat_cache["test_session"] = {
            999: Chat(id=999, title="Deleted Chat", chat_type=ChatType.GROUP)
        }

        # Mock get_chats to return current (fresh) list
        mock_chats = [
            Chat(id=123, title="Chat 1", chat_type=ChatType.GROUP),
            Chat(id=456, title="Chat 2", chat_type=ChatType.GROUP),
        ]

        call_count = 0

        async def mock_get_chats(session_id):
            nonlocal call_count
            call_count += 1
            return mock_chats

        monkeypatch.setattr(service, "get_chats", mock_get_chats)

        # Validate - should clear cache and fetch fresh data
        valid_ids, invalid_ids = await service.validate_chat_ids("test_session", [123, 999])

        # 999 should be invalid because it's not in the fresh fetch
        assert valid_ids == [123]
        assert invalid_ids == [999]

        # Verify get_chats was called (cache was bypassed)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_validate_empty_list(self, service, monkeypatch):
        """Test validation with empty chat ID list."""
        mock_chats = [
            Chat(id=123, title="Chat 1", chat_type=ChatType.GROUP),
        ]

        async def mock_get_chats(session_id):
            return mock_chats

        monkeypatch.setattr(service, "get_chats", mock_get_chats)

        valid_ids, invalid_ids = await service.validate_chat_ids("test_session", [])

        assert valid_ids == []
        assert invalid_ids == []
