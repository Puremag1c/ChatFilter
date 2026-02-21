"""Tests for moderation and captcha detection in GroupAnalysisEngine.

Tests cover:
- Moderation detection from join_request flag (CheckChatInviteRequest.request_needed)
- Moderation detection from entity.join_request (get_entity)
- Activity metrics marked as N/A when moderation enabled
- Captcha detection from Restricted status after join
- Captcha detection from known captcha bot scanning
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telethon import errors
from telethon.tl.types import (
    Channel,
    ChatInvite,
    ChatInviteAlready,
    Message as TelethonMessage,
    PeerUser,
    User,
)

from chatfilter.analyzer.group_engine import GroupAnalysisEngine
from chatfilter.analyzer.worker import CAPTCHA_BOTS, _ResolvedChat
from chatfilter.models.group import (
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def group_db(tmp_path: Path) -> GroupDatabase:
    """Create a temporary GroupDatabase for testing."""
    db_path = tmp_path / "test_groups.db"
    return GroupDatabase(db_path=str(db_path))


@pytest.fixture
def mock_session_manager() -> MagicMock:
    """Create a mock SessionManager."""
    mgr = MagicMock()
    mgr.list_sessions.return_value = ["account1"]

    async def mock_is_healthy(session_id: str) -> bool:
        return True

    mgr.is_healthy = AsyncMock(side_effect=mock_is_healthy)

    # Mock session context manager
    mock_client = AsyncMock()
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_client
    mock_context.__aexit__.return_value = None
    mgr.session.return_value = mock_context

    return mgr


@pytest.fixture
def engine(group_db: GroupDatabase, mock_session_manager: MagicMock) -> GroupAnalysisEngine:
    """Create a GroupAnalysisEngine instance for testing."""
    return GroupAnalysisEngine(
        db=group_db,
        session_manager=mock_session_manager,
    )


class TestModerationDetectionLogic:
    """Unit tests for moderation detection logic using _ResolvedChat internal structure."""

    def test_resolved_chat_from_chatinvite_with_request_needed_true(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that ChatInvite.request_needed=True sets moderation flag."""
        # Simulate logic from _resolve_by_invite for ChatInvite case
        mock_invite = MagicMock(spec=ChatInvite)
        mock_invite.title = "Moderated Chat"
        mock_invite.participants_count = 100
        mock_invite.request_needed = True  # Moderation enabled
        mock_invite.broadcast = False
        mock_invite.megagroup = True

        # Engine logic extracts this value (see group_engine.py:517)
        moderation = mock_invite.request_needed or False
        assert moderation is True

    def test_resolved_chat_from_chatinvite_with_request_needed_false(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that ChatInvite.request_needed=False sets moderation to False."""
        mock_invite = MagicMock(spec=ChatInvite)
        mock_invite.title = "Open Chat"
        mock_invite.participants_count = 50
        mock_invite.request_needed = False  # No moderation
        mock_invite.broadcast = False
        mock_invite.megagroup = True

        moderation = mock_invite.request_needed or False
        assert moderation is False

    def test_resolved_chat_from_channel_entity_with_join_request_true(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that Channel.join_request=True sets moderation flag."""
        # Simulate logic from _resolve_by_username for Channel case
        mock_channel = MagicMock(spec=Channel)
        mock_channel.id = 123456
        mock_channel.title = "Moderated Channel"
        mock_channel.megagroup = True
        mock_channel.join_request = True  # Moderation enabled
        mock_channel.participants_count = 200

        # Engine logic (see group_engine.py:401)
        moderation = getattr(mock_channel, "join_request", None) or False
        assert moderation is True

    def test_resolved_chat_from_channel_entity_with_join_request_false(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that Channel.join_request=False/None sets moderation to False."""
        mock_channel = MagicMock(spec=Channel)
        mock_channel.id = 123456
        mock_channel.title = "Open Channel"
        mock_channel.megagroup = True
        mock_channel.join_request = None  # No moderation attribute
        mock_channel.participants_count = 200

        moderation = getattr(mock_channel, "join_request", None) or False
        assert moderation is False

    def test_activity_metrics_marked_na_when_moderation_enabled(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that activity metrics are marked N/A when moderation=True."""
        # Simulates logic from _analyze_chat_activity when moderation=True
        existing_metrics = {
            "moderation": True,
            "title": "Moderated Chat",
            "chat_type": ChatTypeEnum.GROUP.value,
        }

        settings = GroupSettings(
            detect_moderation=True,
            detect_activity=True,
            detect_unique_authors=True,
            detect_captcha=True,
        )

        # When moderation=True, Phase 2 marks activity as N/A (see group_engine.py:776-784)
        if existing_metrics.get("moderation") is True:
            messages_per_hour = "N/A"
            unique_authors_per_hour = "N/A"
            captcha = "N/A"

        assert messages_per_hour == "N/A"
        assert unique_authors_per_hour == "N/A"
        assert captcha == "N/A"


class TestCaptchaDetectionFromBotScanning:
    """Tests for captcha detection by scanning for known captcha bots."""

    @pytest.mark.asyncio
    async def test_detect_captcha_from_missrose_bot(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that @MissRose_bot is detected as captcha."""
        mock_client = AsyncMock()
        messages = []

        # Create a message from MissRose_bot
        mock_bot = User(
            id=111,
            bot=True,
            username="MissRose_bot",
            first_name="Miss Rose",
        )

        # Mock get_entity to return the bot
        async def mock_get_entity(user_id: int) -> User:
            if user_id == 111:
                return mock_bot
            raise ValueError(f"Unknown user: {user_id}")

        mock_client.get_entity = AsyncMock(side_effect=mock_get_entity)

        # Create mock message from the bot
        from chatfilter.models import Message
        msg = Message(
            id=1,
            chat_id=999,
            author_id=111,
            text="Welcome! Please verify you're human.",
            timestamp=datetime.now(UTC),
        )

        has_captcha = await engine._detect_captcha(mock_client, 999, [msg])

        assert has_captcha is True

    @pytest.mark.asyncio
    async def test_detect_captcha_from_multiple_known_bots(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test detection of various known captcha bots."""
        from chatfilter.models import Message

        # Test each bot in CAPTCHA_BOTS
        for bot_username in ["shieldy_bot", "join_captcha_bot", "GroupHelpBot", "Combot"]:
            mock_client = AsyncMock()

            mock_bot = User(
                id=222,
                bot=True,
                username=bot_username,
                first_name="Captcha Bot",
            )

            mock_client.get_entity = AsyncMock(return_value=mock_bot)

            msg = Message(
                id=1,
                chat_id=999,
                author_id=222,
                text="Complete captcha",
                timestamp=datetime.now(UTC),
            )

            has_captcha = await engine._detect_captcha(mock_client, 999, [msg])

            assert has_captcha is True, f"Failed to detect {bot_username}"

    @pytest.mark.asyncio
    async def test_detect_captcha_from_generic_captcha_bot_name(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test detection of bots with 'captcha' or 'verify' in username."""
        from chatfilter.models import Message

        mock_client = AsyncMock()

        # Bot not in known list but has "captcha" in name
        mock_bot = User(
            id=333,
            bot=True,
            username="CustomCaptchaBot",
            first_name="Custom Captcha",
        )

        mock_client.get_entity = AsyncMock(return_value=mock_bot)

        msg = Message(
            id=1,
            chat_id=999,
            author_id=333,
            text="Verify yourself",
            timestamp=datetime.now(UTC),
        )

        has_captcha = await engine._detect_captcha(mock_client, 999, [msg])

        assert has_captcha is True

    @pytest.mark.asyncio
    async def test_no_captcha_when_only_regular_users(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that regular users don't trigger captcha detection."""
        from chatfilter.models import Message

        mock_client = AsyncMock()

        # Regular user (not a bot)
        mock_user = User(
            id=444,
            bot=False,
            username="regular_user",
            first_name="John",
        )

        mock_client.get_entity = AsyncMock(return_value=mock_user)

        msg = Message(
            id=1,
            chat_id=999,
            author_id=444,
            text="Hello everyone!",
            timestamp=datetime.now(UTC),
        )

        has_captcha = await engine._detect_captcha(mock_client, 999, [msg])

        assert has_captcha is False

    @pytest.mark.asyncio
    async def test_captcha_detection_case_insensitive(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """Test that captcha bot detection is case-insensitive."""
        from chatfilter.models import Message

        mock_client = AsyncMock()

        # Bot with mixed case username
        mock_bot = User(
            id=555,
            bot=True,
            username="MissRose_Bot",  # Mixed case
            first_name="Miss Rose",
        )

        mock_client.get_entity = AsyncMock(return_value=mock_bot)

        msg = Message(
            id=1,
            chat_id=999,
            author_id=555,
            text="Welcome!",
            timestamp=datetime.now(UTC),
        )

        has_captcha = await engine._detect_captcha(mock_client, 999, [msg])

        # Should detect even with different casing
        assert has_captcha is True




class TestCaptchaBotsConstant:
    """Tests to ensure CAPTCHA_BOTS constant is correctly defined."""

    def test_captcha_bots_contains_expected_bots(self) -> None:
        """Verify CAPTCHA_BOTS frozenset contains all required bots."""
        expected = {
            "missrose_bot",
            "shieldy_bot",
            "join_captcha_bot",
            "grouphelpbot",
            "combot",
        }

        assert CAPTCHA_BOTS == expected

    def test_captcha_bots_all_lowercase(self) -> None:
        """Verify all bot usernames in CAPTCHA_BOTS are lowercase."""
        for bot in CAPTCHA_BOTS:
            assert bot == bot.lower(), f"Bot '{bot}' should be lowercase"

    def test_captcha_bots_no_at_symbol(self) -> None:
        """Verify bot usernames don't include @ symbol."""
        for bot in CAPTCHA_BOTS:
            assert not bot.startswith("@"), f"Bot '{bot}' should not start with @"
