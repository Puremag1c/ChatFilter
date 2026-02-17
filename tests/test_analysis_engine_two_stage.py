"""Integration tests for two-stage group analysis logic.

Tests the core business logic from SPEC.md v0.11.0 Must Have #2:
- Stage 1: Resolve without joining (get_entity, CheckChatInviteRequest)
- Stage 2: Join only when needed (settings.needs_join())
- Hybrid time window logic (max 500 messages within X hour window)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telethon import errors
from telethon.tl.functions.messages import CheckChatInviteRequest

from chatfilter.analyzer.group_engine import GroupAnalysisEngine, _ResolvedChat
from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupSettings, GroupStatus
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.session_manager import SessionManager


@pytest.fixture
def mock_db(isolated_tmp_dir):
    """Create a GroupDatabase instance with isolated storage."""
    db = GroupDatabase(str(isolated_tmp_dir / "groups.db"))
    return db


@pytest.fixture
def mock_session_manager():
    """Create a mock SessionManager."""
    mgr = MagicMock(spec=SessionManager)
    mgr.list_sessions = MagicMock(return_value=["account1"])

    # Mock is_healthy as async
    async def mock_is_healthy(session_id):
        return True
    mgr.is_healthy = mock_is_healthy

    return mgr


@pytest.fixture
def engine(mock_db, mock_session_manager):
    """Create GroupAnalysisEngine with mocked dependencies."""
    return GroupAnalysisEngine(db=mock_db, session_manager=mock_session_manager)


def create_mock_channel(**kwargs):
    """Create a mock Channel object that works with isinstance checks.

    Args:
        **kwargs: Channel attributes (id, title, broadcast, megagroup, etc.)

    Returns:
        Mock object that behaves like a Telethon Channel.
    """
    from telethon.tl.types import Channel

    mock = MagicMock(spec=Channel)
    for key, value in kwargs.items():
        setattr(mock, key, value)
    return mock


def create_mock_chat_invite(**kwargs):
    """Create a mock ChatInvite object that works with isinstance checks.

    Args:
        **kwargs: ChatInvite attributes (title, participants_count, etc.)

    Returns:
        Mock object that behaves like a Telethon ChatInvite.
    """
    from telethon.tl.types import ChatInvite

    mock = MagicMock(spec=ChatInvite)
    for key, value in kwargs.items():
        setattr(mock, key, value)
    return mock


class TestStage1ResolveWithoutJoin:
    """Tests for Stage 1: Resolve metadata without joining.

    Stage 1 should:
    - Use get_entity() for public chats (username-based)
    - Use CheckChatInviteRequest for invite links
    - Extract: chat type, subscribers, moderation flag
    - NOT join the chat
    """

    @pytest.mark.asyncio
    async def test_resolve_public_channel_via_username(self, engine, mock_db, mock_session_manager):
        """Test Stage 1: Resolve public channel using get_entity(username)."""
        # Setup: Create group with one public channel
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/test_channel",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock TelegramClient.get_entity() to return a public channel
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=123456,
            title="Test Channel",
            username="test_channel",
            broadcast=True,
            megagroup=False,
            participants_count=5000,
            join_request=False,  # No moderation
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        # Mock session context
        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute: Start analysis (Phase 1 only, no join)
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=False,  # Disable activity -> no join needed
            detect_unique_authors=False,
            detect_captcha=False,
        )
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )

        await engine.start_analysis(group_id)

        # Verify: get_entity was called (Phase 1)
        mock_client.get_entity.assert_called_once_with("test_channel")

        # Verify: Chat metadata was saved without joining
        result = mock_db.load_result(group_id, "https://t.me/test_channel")
        assert result is not None
        metrics = result["metrics_data"]
        assert metrics["chat_type"] == ChatTypeEnum.CHANNEL_NO_COMMENTS.value
        assert metrics["title"] == "Test Channel"
        assert metrics["subscribers"] == 5000
        assert metrics["moderation"] is False
        assert "messages_per_hour" not in metrics  # Activity not requested

        # Verify: Chat status is DONE (Phase 1 complete)
        chats = mock_db.load_chats(group_id=group_id)
        assert len(chats) == 1
        assert chats[0]["status"] == GroupChatStatus.DONE.value

    @pytest.mark.asyncio
    async def test_resolve_invite_link_via_check_chat_invite(self, engine, mock_db, mock_session_manager):
        """Test Stage 1: Resolve invite link using CheckChatInviteRequest."""
        # Setup: Create group with one invite link
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/+AbCdEf123456",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock TelegramClient(CheckChatInviteRequest) to return invite info
        mock_client = AsyncMock()
        mock_invite = create_mock_chat_invite(
            title="Private Group",
            participants_count=250,
            megagroup=True,
            broadcast=False,
            request_needed=True,  # Moderation enabled
        )

        async def mock_call_request(request):
            if isinstance(request, CheckChatInviteRequest):
                return mock_invite
            raise ValueError(f"Unexpected request: {request}")

        mock_client.side_effect = mock_call_request

        # Mock session context
        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute: Start analysis (Phase 1 only)
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=False,
            detect_unique_authors=False,
            detect_captcha=False,
        )
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )

        await engine.start_analysis(group_id)

        # Verify: CheckChatInviteRequest was called
        mock_client.assert_called_once()
        call_args = mock_client.call_args[0][0]
        assert isinstance(call_args, CheckChatInviteRequest)
        assert call_args.hash == "AbCdEf123456"

        # Verify: Invite metadata was saved without joining
        result = mock_db.load_result(group_id, "https://t.me/+AbCdEf123456")
        assert result is not None
        metrics = result["metrics_data"]
        assert metrics["chat_type"] == ChatTypeEnum.GROUP.value
        assert metrics["title"] == "Private Group"
        assert metrics["subscribers"] == 250
        assert metrics["moderation"] is True  # request_needed=True

    @pytest.mark.asyncio
    async def test_stage1_extracts_all_required_fields(self, engine, mock_db, mock_session_manager):
        """Test Stage 1: Extracts chat type, subscribers, moderation flag."""
        # Setup
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/test_group",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock: Megagroup with moderation enabled
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=789,
            title="Moderated Group",
            username="test_group",
            broadcast=False,
            megagroup=True,
            participants_count=1500,
            join_request=True,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=False,
            detect_unique_authors=False,
            detect_captcha=False,
        )
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )

        await engine.start_analysis(group_id)

        # Verify: All Stage 1 fields extracted
        result = mock_db.load_result(group_id, "https://t.me/test_group")
        metrics = result["metrics_data"]

        # chat_type: GROUP (megagroup=True, not forum)
        assert metrics["chat_type"] == ChatTypeEnum.GROUP.value

        # subscribers: participants_count
        assert metrics["subscribers"] == 1500

        # moderation: join_request flag
        assert metrics["moderation"] is True


class TestStage2JoinOnlyWhenNeeded:
    """Tests for Stage 2: Join only when settings.needs_join() == True.

    Stage 2 should:
    - Check settings.needs_join() -> True if activity/unique_authors/captcha requested
    - Skip join if moderation=True (approval required)
    - Only join chats that passed Stage 1 (status=DONE)
    - ALWAYS leave after analysis
    """

    @pytest.mark.asyncio
    async def test_skip_stage2_when_needs_join_false(self, engine, mock_db, mock_session_manager):
        """Test: Stage 2 is skipped when settings.needs_join() == False."""
        # Setup: Group with no activity metrics requested
        group_id = "test-group"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=False,  # No activity
            detect_unique_authors=False,  # No authors
            detect_captcha=False,  # No captcha
        )
        assert settings.needs_join() is False  # Precondition

        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/test_channel",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock client for Stage 1
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=123,
            title="Test Channel",
            username="test_channel",
            broadcast=True,
            megagroup=False,
            participants_count=1000,
            join_request=False,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute
        await engine.start_analysis(group_id)

        # Verify: get_entity was called (Stage 1)
        assert mock_client.get_entity.called

        # Verify: iter_messages was NOT called (Stage 2 skipped)
        assert not mock_client.iter_messages.called

        # Verify: Result contains Stage 1 data only
        result = mock_db.load_result(group_id, "https://t.me/test_channel")
        metrics = result["metrics_data"]
        assert "subscribers" in metrics
        assert "messages_per_hour" not in metrics  # Activity not requested

    @pytest.mark.asyncio
    async def test_stage2_joins_when_needs_join_true(self, engine, mock_db, mock_session_manager):
        """Test: Stage 2 joins chat when settings.needs_join() == True."""
        # Setup: Group with activity metrics requested
        group_id = "test-group"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=True,  # Requires join
            detect_unique_authors=True,  # Requires join
            detect_captcha=False,
            time_window=24,
        )
        assert settings.needs_join() is True  # Precondition

        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/test_group",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock client
        mock_client = AsyncMock()

        # Stage 1: get_entity
        mock_channel = create_mock_channel(
            id=456,
            title="Active Group",
            username="test_group",
            broadcast=False,
            megagroup=True,
            participants_count=500,
            join_request=False,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        # Stage 2: join and fetch messages
        mock_client.iter_messages = AsyncMock()

        # Create async iterator for messages
        async def mock_iter_messages(*args, **kwargs):
            # Return empty list (no messages in time window)
            for _ in []:
                yield _

        mock_client.iter_messages.return_value = mock_iter_messages()

        # Mock join/leave
        with patch("chatfilter.analyzer.group_engine.join_chat") as mock_join, \
             patch("chatfilter.analyzer.group_engine.leave_chat") as mock_leave:

            mock_joined = MagicMock()
            mock_joined.id = 456
            mock_join.return_value = mock_joined

            mock_session_manager.session = MagicMock()
            mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

            # Execute
            await engine.start_analysis(group_id)

            # Verify: join_chat was called (Stage 2)
            mock_join.assert_called_once()

            # Verify: leave_chat was called (cleanup)
            mock_leave.assert_called_once_with(mock_client, 456)

        # Verify: Activity metrics were calculated
        result = mock_db.load_result(group_id, "https://t.me/test_group")
        metrics = result["metrics_data"]
        assert "messages_per_hour" in metrics
        assert "unique_authors_per_hour" in metrics

    @pytest.mark.asyncio
    async def test_skip_join_when_approval_required(self, engine, mock_db, mock_session_manager):
        """Test: Stage 2 skips join if moderation=True (approval required)."""
        # Setup
        group_id = "test-group"
        settings = GroupSettings(
            detect_activity=True,  # Would normally require join
            detect_unique_authors=True,
            detect_moderation=True,
            time_window=24,
        )
        assert settings.needs_join() is True

        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/moderated_group",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock client: Stage 1 shows moderation=True
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=789,
            title="Moderated Group",
            username="moderated_group",
            broadcast=False,
            megagroup=True,
            participants_count=300,
            join_request=True,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute
        with patch("chatfilter.analyzer.group_engine.join_chat") as mock_join:
            await engine.start_analysis(group_id)

            # Verify: join_chat was NOT called (moderation=True)
            mock_join.assert_not_called()

        # Verify: Activity metrics marked as "N/A"
        result = mock_db.load_result(group_id, "https://t.me/moderated_group")
        metrics = result["metrics_data"]
        assert metrics["moderation"] is True
        assert metrics["messages_per_hour"] == "N/A"
        assert metrics["unique_authors_per_hour"] == "N/A"


class TestHybridTimeWindowLogic:
    """Tests for hybrid time window logic.

    Should:
    - Load max 500 messages within time_window hours
    - Calculate metrics based on actual time covered (not full window)
    - Handle cases where <500 messages exist
    """

    @pytest.mark.asyncio
    async def test_time_window_limits_message_fetch(self, engine, mock_db, mock_session_manager):
        """Test: Messages are fetched within time_window, max 500."""
        # Setup
        group_id = "test-group"
        settings = GroupSettings(
            detect_activity=True,
            detect_unique_authors=True,
            time_window=6,  # 6 hour window
        )
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/active_group",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock client
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=111,
            title="Active Group",
            username="active_group",
            broadcast=False,
            megagroup=True,
            participants_count=1000,
            join_request=False,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        # Track iter_messages call
        iter_messages_kwargs = {}

        async def mock_iter_messages(*args, **kwargs):
            iter_messages_kwargs.update(kwargs)
            # Return empty iterator
            for _ in []:
                yield _

        mock_client.iter_messages = mock_iter_messages

        with patch("chatfilter.analyzer.group_engine.join_chat") as mock_join, \
             patch("chatfilter.analyzer.group_engine.leave_chat"):

            mock_joined = MagicMock()
            mock_joined.id = 111
            mock_join.return_value = mock_joined

            mock_session_manager.session = MagicMock()
            mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

            # Execute
            await engine.start_analysis(group_id)

            # Verify: iter_messages called with limit=500 and offset_date
            assert "limit" in iter_messages_kwargs
            assert iter_messages_kwargs["limit"] == 500

            assert "offset_date" in iter_messages_kwargs
            offset = iter_messages_kwargs["offset_date"]
            now = datetime.now(UTC)
            expected_offset = now - timedelta(hours=6)
            # Allow 1 minute tolerance for execution time
            assert abs((offset - expected_offset).total_seconds()) < 60

    @pytest.mark.asyncio
    async def test_metrics_based_on_actual_time_covered(self, engine, mock_db, mock_session_manager):
        """Test: Metrics calculated from actual message timestamps, not full window."""
        # Setup
        group_id = "test-group"
        settings = GroupSettings(
            detect_activity=True,
            detect_unique_authors=True,
            time_window=24,  # 24 hour window
        )
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/sparse_group",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock client
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=222,
            title="Sparse Group",
            username="sparse_group",
            broadcast=False,
            megagroup=True,
            participants_count=100,
            join_request=False,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        # Mock messages: Only 2 messages in last 2 hours (not 24)
        from chatfilter.models.message import Message
        now = datetime.now(UTC)

        mock_msg1 = MagicMock()
        mock_msg1.id = 1
        mock_msg1.date = now - timedelta(hours=2)
        mock_msg1.sender_id = 100
        mock_msg1.message = "Test 1"

        mock_msg2 = MagicMock()
        mock_msg2.id = 2
        mock_msg2.date = now
        mock_msg2.sender_id = 200
        mock_msg2.message = "Test 2"

        async def mock_iter_messages(*args, **kwargs):
            yield mock_msg2
            yield mock_msg1

        mock_client.iter_messages = mock_iter_messages

        with patch("chatfilter.analyzer.group_engine.join_chat") as mock_join, \
             patch("chatfilter.analyzer.group_engine.leave_chat"), \
             patch("chatfilter.analyzer.group_engine._telethon_message_to_model") as mock_convert:

            mock_joined = MagicMock()
            mock_joined.id = 222
            mock_join.return_value = mock_joined

            # Mock message conversion
            def convert_msg(msg, chat_id):
                if msg.id == 1:
                    return Message.fake(
                        id=1,
                        chat_id=chat_id,
                        author_id=100,
                        timestamp=now - timedelta(hours=2),
                        text="Test 1",
                    )
                elif msg.id == 2:
                    return Message.fake(
                        id=2,
                        chat_id=chat_id,
                        author_id=200,
                        timestamp=now,
                        text="Test 2",
                    )
                return None

            mock_convert.side_effect = convert_msg

            mock_session_manager.session = MagicMock()
            mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

            # Execute
            await engine.start_analysis(group_id)

            # Verify: Metrics based on time_window (24 hours), not actual span
            result = mock_db.load_result(group_id, "https://t.me/sparse_group")
            metrics = result["metrics_data"]

            # 2 messages over 24 hour window = 0.08 messages/hour
            # Note: Implementation divides by settings.time_window, not actual message span
            assert metrics["messages_per_hour"] == round(2 / 24, 2)

            # 2 unique authors over 24 hour window = 0.08 authors/hour
            assert metrics["unique_authors_per_hour"] == round(2 / 24, 2)

    @pytest.mark.asyncio
    async def test_handles_fewer_than_500_messages(self, engine, mock_db, mock_session_manager):
        """Test: Handles chats with <500 messages gracefully."""
        # Setup
        group_id = "test-group"
        settings = GroupSettings(
            detect_activity=True,
            detect_unique_authors=True,
            time_window=24,
        )
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status=GroupStatus.PENDING.value,
        )
        mock_db.save_chat(
            group_id=group_id,
            chat_ref="https://t.me/small_group",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Mock client
        mock_client = AsyncMock()
        mock_channel = create_mock_channel(
            id=333,
            title="Small Group",
            username="small_group",
            broadcast=False,
            megagroup=True,
            participants_count=10,
            join_request=False,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        # Mock: Only 3 messages total
        from chatfilter.models.message import Message
        now = datetime.now(UTC)

        messages = []
        for i in range(3):
            msg = MagicMock()
            msg.id = i + 1
            msg.date = now - timedelta(hours=i)
            msg.sender_id = 100 + i
            msg.message = f"Test {i}"
            messages.append(msg)

        async def mock_iter_messages(*args, **kwargs):
            for msg in reversed(messages):
                yield msg

        mock_client.iter_messages = mock_iter_messages

        with patch("chatfilter.analyzer.group_engine.join_chat") as mock_join, \
             patch("chatfilter.analyzer.group_engine.leave_chat"), \
             patch("chatfilter.analyzer.group_engine._telethon_message_to_model") as mock_convert:

            mock_joined = MagicMock()
            mock_joined.id = 333
            mock_join.return_value = mock_joined

            def convert_msg(msg, chat_id):
                return Message.fake(
                    id=msg.id,
                    chat_id=chat_id,
                    author_id=msg.sender_id,
                    timestamp=msg.date,
                    text=msg.message,
                )

            mock_convert.side_effect = convert_msg

            mock_session_manager.session = MagicMock()
            mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

            # Execute
            await engine.start_analysis(group_id)

            # Verify: All 3 messages processed correctly
            result = mock_db.load_result(group_id, "https://t.me/small_group")
            metrics = result["metrics_data"]

            # Metrics should be calculated from 3 messages
            assert metrics["messages_per_hour"] > 0


class TestIncrementalModeSkipLogic:
    """Tests for INCREMENT mode skip logic.

    Tests that in INCREMENT mode, chats with existing metrics are skipped
    and only missing metrics are fetched.
    """

    @pytest.mark.asyncio
    async def test_phase1_skip_when_all_metrics_exist(self, engine, mock_db, mock_session_manager):
        """Test Phase 1: Skip chat when all Phase 1 metrics already exist."""
        # Setup: Create group with one chat
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings(
                detect_subscribers=True,
                detect_moderation=True,
                detect_activity=False,
                detect_unique_authors=False,
                detect_captcha=False,
                time_window=24,
            ).model_dump(),
            status=GroupStatus.PENDING.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        chat_ref = "https://t.me/existing_chat"
        mock_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Pre-populate result with Phase 1 metrics
        mock_db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data={
                "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
                "title": "Existing Channel",
                "subscribers": 1000,
                "moderation": False,
                "status": "done",
            },
        )

        # Setup mock client (should NOT be called)
        mock_client = MagicMock()
        mock_client.get_entity = AsyncMock(side_effect=Exception("Should not call get_entity"))

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute with INCREMENT mode
        from chatfilter.models.group import AnalysisMode
        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

        # Verify: get_entity NOT called (chat was skipped)
        assert mock_client.get_entity.call_count == 0

        # Verify: Chat marked as DONE
        chats = mock_db.load_chats(group_id=group_id)
        assert len(chats) == 1
        assert chats[0]["status"] == GroupChatStatus.DONE.value

        # Verify: Existing result unchanged
        result = mock_db.load_result(group_id, chat_ref)
        assert result["metrics_data"]["subscribers"] == 1000
        assert result["metrics_data"]["title"] == "Existing Channel"

    @pytest.mark.asyncio
    async def test_phase1_resolve_when_partial_metrics_exist(self, engine, mock_db, mock_session_manager):
        """Test Phase 1: Re-resolve chat when only SOME Phase 1 metrics exist."""
        # Setup: Create group with one chat
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings(
                detect_subscribers=True,
                detect_moderation=True,
                detect_activity=False,
                detect_unique_authors=False,
                detect_captcha=False,
                time_window=24,
            ).model_dump(),
            status=GroupStatus.PENDING.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        chat_ref = "https://t.me/partial_chat"
        mock_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Pre-populate result with PARTIAL Phase 1 metrics (missing subscribers)
        mock_db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data={
                "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
                "title": "Partial Channel",
                "moderation": False,
                "status": "done",
                # subscribers missing!
            },
        )

        # Setup mock client
        mock_client = MagicMock()
        mock_channel = create_mock_channel(
            id=123456,
            title="Updated Channel",
            broadcast=True,
            megagroup=False,
            participants_count=2000,
            join_request=False,
        )
        mock_client.get_entity = AsyncMock(return_value=mock_channel)

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute with INCREMENT mode
        from chatfilter.models.group import AnalysisMode
        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

        # Verify: get_entity WAS called (chat was re-resolved)
        assert mock_client.get_entity.call_count == 1

        # Verify: Result updated with complete metrics
        result = mock_db.load_result(group_id, chat_ref)
        assert result["metrics_data"]["subscribers"] == 2000  # Now present

    @pytest.mark.asyncio
    async def test_phase2_skip_when_all_metrics_exist(self, engine, mock_db, mock_session_manager):
        """Test Phase 2: Skip chat when all Phase 2 metrics already exist."""
        # Setup: Create group with one chat
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings(
                detect_subscribers=False,
                detect_moderation=False,
                detect_activity=True,
                detect_unique_authors=True,
                detect_captcha=True,
                time_window=24,
            ).model_dump(),
            status=GroupStatus.PENDING.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        chat_ref = "https://t.me/existing_activity"
        chat_id = mock_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type=ChatTypeEnum.GROUP.value,
            status=GroupChatStatus.DONE.value,  # Already processed in Phase 1
        )

        # Pre-populate result with Phase 1 + Phase 2 metrics
        mock_db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data={
                "chat_type": ChatTypeEnum.GROUP.value,
                "title": "Existing Group",
                "moderation": False,
                "status": "done",
                "messages_per_hour": 10.5,
                "unique_authors_per_hour": 3.2,
                "captcha": False,
            },
        )

        # Setup mock client (join_chat should NOT be called)
        mock_client = MagicMock()

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute with INCREMENT mode (skip Phase 1, only Phase 2)
        from chatfilter.models.group import AnalysisMode
        with patch("chatfilter.analyzer.group_engine.join_chat") as mock_join:
            await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

            # Verify: join_chat NOT called (chat was skipped)
            assert mock_join.call_count == 0

        # Verify: Existing result unchanged
        result = mock_db.load_result(group_id, chat_ref)
        assert result["metrics_data"]["messages_per_hour"] == 10.5
        assert result["metrics_data"]["unique_authors_per_hour"] == 3.2

    @pytest.mark.asyncio
    async def test_skip_respects_settings(self, engine, mock_db, mock_session_manager):
        """Test that skip logic respects settings (doesn't require disabled metrics)."""
        # Setup: Create group with detect_subscribers=False
        group_id = "test-group"
        mock_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings(
                detect_subscribers=False,  # Disabled
                detect_moderation=True,
                detect_activity=False,
                detect_unique_authors=False,
                detect_captcha=False,
                time_window=24,
            ).model_dump(),
            status=GroupStatus.PENDING.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        chat_ref = "https://t.me/no_subs_chat"
        mock_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        # Pre-populate result WITHOUT subscribers (not required by settings)
        mock_db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data={
                "chat_type": ChatTypeEnum.GROUP.value,
                "title": "Group Without Subs",
                "moderation": False,
                "status": "done",
                # subscribers not present, but not required
            },
        )

        # Setup mock client (should NOT be called)
        mock_client = MagicMock()
        mock_client.get_entity = AsyncMock(side_effect=Exception("Should not call get_entity"))

        mock_session_manager.session = MagicMock()
        mock_session_manager.session.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        mock_session_manager.session.return_value.__aexit__ = AsyncMock(return_value=None)

        # Execute with INCREMENT mode
        from chatfilter.models.group import AnalysisMode
        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

        # Verify: get_entity NOT called (chat was skipped)
        assert mock_client.get_entity.call_count == 0

        # Verify: Chat marked as DONE
        chats = mock_db.load_chats(group_id=group_id)
        assert chats[0]["status"] == GroupChatStatus.DONE.value
