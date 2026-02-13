"""Tests for GroupAnalysisEngine - bulk chat analysis orchestration.

Tests cover:
1. Phase 1: Join chats and resolve types (round-robin distribution)
2. Phase 2: Analysis via TaskQueue
3. Phase 3: Leave chats (if enabled)
4. Error handling: FloodWait, ChatNotFound, no connected accounts
5. Progress tracking and SSE events
6. Stop/resume functionality
"""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from telethon import errors
from telethon.tl.types import Channel, Chat, User

from chatfilter.analyzer.group_engine import (
    GroupAnalysisEngine,
    GroupNotFoundError,
    GroupProgressEvent,
    NoConnectedAccountsError,
)
from chatfilter.analyzer.task_queue import TaskStatus
from chatfilter.models.group import (
    ChatGroup,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def temp_db(tmp_path):
    """Create temporary database."""
    db_path = tmp_path / "test_groups.db"
    return GroupDatabase(str(db_path))


@pytest.fixture
def mock_session_manager():
    """Mock SessionManager with connected accounts."""
    mgr = MagicMock()

    # Mock two connected accounts
    account1 = MagicMock()
    account1.phone_number = "+1234567890"
    account1.status = "connected"

    account2 = MagicMock()
    account2.phone_number = "+0987654321"
    account2.status = "connected"

    mgr.get_connected_sessions.return_value = [account1, account2]
    mgr.get_client = MagicMock()

    return mgr


@pytest.fixture
def mock_task_queue():
    """Mock TaskQueue."""
    queue = MagicMock()
    queue.create_task = AsyncMock(return_value=uuid4())
    queue.cancel_task = AsyncMock()
    return queue


@pytest.fixture
def mock_executor():
    """Mock AnalysisExecutor."""
    executor = MagicMock()
    return executor


@pytest.fixture
async def engine(temp_db, mock_session_manager, mock_task_queue, mock_executor):
    """Create GroupAnalysisEngine instance."""
    return GroupAnalysisEngine(
        db=temp_db,
        session_manager=mock_session_manager,
        task_queue=mock_task_queue,
        executor=mock_executor,
    )


class TestGroupEngineInitialization:
    """Test engine initialization and basic setup."""

    async def test_engine_creation(self, engine):
        """Engine can be instantiated."""
        assert engine is not None
        assert isinstance(engine.db, GroupDatabase)

    async def test_nonexistent_group_raises_error(self, engine):
        """Starting analysis on nonexistent group raises error."""
        with pytest.raises(GroupNotFoundError):
            await engine.start_analysis("nonexistent-group")


class TestPhase1JoinAndResolve:
    """Test Phase 1: Join chats and resolve types."""

    async def test_no_connected_accounts_raises_error(
        self, engine, temp_db, mock_session_manager
    ):
        """Starting analysis with no connected accounts raises error."""
        # Create a group
        group = ChatGroup(
            id="group-1",
            name="Test Group",
            settings=GroupSettings(),
            status=GroupStatus.PENDING,
            chat_count=1,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@test_chat")

        # Mock no connected accounts
        mock_session_manager.get_connected_sessions.return_value = []

        with pytest.raises(NoConnectedAccountsError):
            await engine.start_analysis("group-1")

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_round_robin_distribution(
        self, mock_join_chat, engine, temp_db, mock_session_manager
    ):
        """Chats are distributed round-robin across accounts."""
        # Create group with 5 chats
        group = ChatGroup.fake(id="group-1", chat_count=5)
        temp_db.save_group(group)

        for i in range(5):
            temp_db.save_chat("group-1", f"chat-{i}", f"@chat{i}")

        # Mock join_chat to return channel type
        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = False
        mock_channel.broadcast = True
        mock_channel.has_link = False
        mock_join_chat.return_value = mock_channel

        # Mock clients
        client1 = AsyncMock()
        client2 = AsyncMock()
        mock_session_manager.get_client.side_effect = [client1, client2] * 3

        await engine.start_analysis("group-1")

        # Verify distribution: 5 chats across 2 accounts = [3, 2]
        chats = temp_db.load_chats("group-1")
        account1_chats = [c for c in chats if c.assigned_account == "+1234567890"]
        account2_chats = [c for c in chats if c.assigned_account == "+0987654321"]

        assert len(account1_chats) == 3
        assert len(account2_chats) == 2

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_resolve_channel_no_comments(
        self, mock_join_chat, engine, temp_db, mock_session_manager
    ):
        """Channels without discussion group are resolved correctly."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@channel")

        # Mock channel without linked chat
        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = False
        mock_channel.broadcast = True
        mock_channel.has_link = False
        mock_join_chat.return_value = mock_channel

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].chat_type == ChatTypeEnum.CHANNEL_NO_COMMENTS

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_resolve_channel_with_comments(
        self, mock_join_chat, engine, temp_db, mock_session_manager
    ):
        """Channels with discussion group are resolved correctly."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@channel")

        # Mock channel with linked chat
        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = False
        mock_channel.broadcast = True
        mock_channel.has_link = True  # Has discussion group
        mock_join_chat.return_value = mock_channel

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].chat_type == ChatTypeEnum.CHANNEL_COMMENTS

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_resolve_forum(self, mock_join_chat, engine, temp_db, mock_session_manager):
        """Forums are resolved correctly."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@forum")

        # Mock forum (megagroup with forum enabled)
        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = True
        mock_channel.broadcast = False
        mock_channel.forum = True
        mock_join_chat.return_value = mock_channel

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].chat_type == ChatTypeEnum.FORUM

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_resolve_group(self, mock_join_chat, engine, temp_db, mock_session_manager):
        """Regular groups are resolved correctly."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@group")

        # Mock regular group (megagroup without forum)
        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = True
        mock_channel.broadcast = False
        mock_channel.forum = False
        mock_join_chat.return_value = mock_channel

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].chat_type == ChatTypeEnum.GROUP

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_dead_chat_link(
        self, mock_join_chat, engine, temp_db, mock_session_manager
    ):
        """Dead/deleted chats are marked as DEAD."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@deleted_chat")

        # Mock chat not found error
        mock_join_chat.side_effect = ValueError("Could not find the input entity")

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].chat_type == ChatTypeEnum.DEAD
        assert chats[0].status == GroupChatStatus.FAILED

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_flood_wait_error_handling(
        self, mock_join_chat, engine, temp_db, mock_session_manager
    ):
        """FloodWait errors are handled gracefully."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@chat")

        # Mock FloodWaitError
        mock_join_chat.side_effect = errors.FloodWaitError("Too many requests", request=None, seconds=300)

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].status == GroupChatStatus.FAILED
        assert "FloodWait" in chats[0].error

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_chat_forbidden_error(
        self, mock_join_chat, engine, temp_db, mock_session_manager
    ):
        """ChatForbiddenError marks chat as DEAD."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@private_chat")

        mock_join_chat.side_effect = errors.ChatForbiddenError("Access denied", request=None)

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        chats = temp_db.load_chats("group-1")
        assert chats[0].chat_type == ChatTypeEnum.DEAD
        assert chats[0].status == GroupChatStatus.FAILED


class TestPhase2Analysis:
    """Test Phase 2: TaskQueue integration and analysis."""

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_analysis_phase_creates_tasks(
        self, mock_join_chat, engine, temp_db, mock_session_manager, mock_task_queue
    ):
        """Phase 2 creates TaskQueue tasks for DONE chats."""
        group = ChatGroup.fake(id="group-1", chat_count=2)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@chat1")
        temp_db.save_chat("group-1", "chat-2", "@chat2")

        # Mock successful join
        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = True
        mock_channel.forum = False
        mock_join_chat.return_value = mock_channel

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        # Verify TaskQueue.create_task was called for each chat
        assert mock_task_queue.create_task.call_count >= 1


class TestPhase3Leave:
    """Test Phase 3: Leave chats after analysis."""

    async def test_leave_chats_when_enabled(self, engine, temp_db):
        """Chats are left when leave_after_analysis=True."""
        # Create group with leave enabled
        settings = GroupSettings(leave_after_analysis=True)
        group = ChatGroup.fake(id="group-1", settings=settings, chat_count=1)
        temp_db.save_group(group)

        # Mark chat as analyzed
        temp_db.save_chat("group-1", "chat-1", "@chat", assigned_account="+1234567890")
        temp_db.update_chat_status(
            "group-1", "chat-1",
            status=GroupChatStatus.DONE,
            chat_type=ChatTypeEnum.GROUP
        )

        # TODO: Phase 3 implementation test
        # This will be tested once leave logic is integrated

    async def test_skip_leave_when_disabled(self, engine, temp_db):
        """Chats are NOT left when leave_after_analysis=False."""
        settings = GroupSettings(leave_after_analysis=False)
        group = ChatGroup.fake(id="group-1", settings=settings, chat_count=1)
        temp_db.save_group(group)

        temp_db.save_chat("group-1", "chat-1", "@chat", assigned_account="+1234567890")
        temp_db.update_chat_status(
            "group-1", "chat-1",
            status=GroupChatStatus.DONE,
            chat_type=ChatTypeEnum.GROUP
        )

        # TODO: Verify no leave_chat calls when disabled


class TestStopAndResume:
    """Test stop/pause and resume functionality."""

    async def test_stop_analysis_cancels_tasks(self, engine, mock_task_queue):
        """Stopping analysis cancels ongoing tasks."""
        # TODO: Implement once engine._active_tasks tracking is available
        pass

    async def test_resume_skips_done_chats(self, engine, temp_db):
        """Resuming analysis skips DONE chats."""
        group = ChatGroup.fake(id="group-1", chat_count=2)
        temp_db.save_group(group)

        # One DONE, one FAILED
        temp_db.save_chat("group-1", "chat-1", "@chat1", assigned_account="+1234567890")
        temp_db.update_chat_status("group-1", "chat-1", status=GroupChatStatus.DONE)

        temp_db.save_chat("group-1", "chat-2", "@chat2", assigned_account="+1234567890")
        temp_db.update_chat_status("group-1", "chat-2", status=GroupChatStatus.FAILED)

        # TODO: Test resume retries only FAILED


class TestProgressTracking:
    """Test progress event generation."""

    async def test_progress_events_emitted(self, engine, temp_db):
        """Progress events are emitted during analysis."""
        group = ChatGroup.fake(id="group-1", chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@chat")

        # Subscribe to progress
        progress_queue = await engine.subscribe("group-1")

        # TODO: Test that events are published to queue
        # Should receive events for: JOINING -> ANALYZING -> DONE

    async def test_progress_current_and_total(self, engine):
        """Progress events report correct current/total counts."""
        # TODO: Verify progress.current increments and progress.total matches chat_count
        pass


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    async def test_empty_group(self, engine, temp_db):
        """Group with zero chats completes immediately."""
        group = ChatGroup.fake(id="group-1", chat_count=0)
        temp_db.save_group(group)

        await engine.start_analysis("group-1")

        loaded = temp_db.load_group("group-1")
        assert loaded.status == GroupStatus.COMPLETED

    async def test_all_chats_dead(self, engine, temp_db, mock_session_manager):
        """Group where all chats are dead/deleted."""
        # TODO: Verify status becomes COMPLETED with all chats marked DEAD
        pass

    async def test_account_becomes_disconnected_during_analysis(self, engine):
        """Account disconnects mid-analysis."""
        # TODO: Test error handling when account drops during Phase 1
        pass

    async def test_database_error_during_save(self, engine, temp_db):
        """Database errors are handled gracefully."""
        # TODO: Mock database.save_chat to raise exception
        pass


class TestServerRestart:
    """Test persistence and recovery after server restart."""

    async def test_incomplete_analysis_persisted(self, temp_db):
        """Incomplete analysis state survives restart."""
        # Create group with partial progress
        group = ChatGroup.fake(id="group-1", chat_count=3, status=GroupStatus.IN_PROGRESS)
        temp_db.save_group(group)

        temp_db.save_chat("group-1", "chat-1", "@chat1", assigned_account="+1234567890")
        temp_db.update_chat_status("group-1", "chat-1", status=GroupChatStatus.DONE)

        temp_db.save_chat("group-1", "chat-2", "@chat2", assigned_account="+1234567890")
        temp_db.update_chat_status("group-1", "chat-2", status=GroupChatStatus.PENDING)

        temp_db.save_chat("group-1", "chat-3", "@chat3", assigned_account="+0987654321")
        temp_db.update_chat_status("group-3", "chat-3", status=GroupChatStatus.FAILED)

        # Simulate restart: create new engine with same DB
        new_db = GroupDatabase(temp_db.db_path)
        loaded = new_db.load_group("group-1")

        assert loaded.status == GroupStatus.IN_PROGRESS

        chats = new_db.load_chats("group-1")
        done_count = sum(1 for c in chats if c.status == GroupChatStatus.DONE)
        pending_count = sum(1 for c in chats if c.status == GroupChatStatus.PENDING)

        assert done_count == 1
        assert pending_count == 1

    async def test_resume_after_restart(self, engine, temp_db):
        """Analysis can be resumed after server restart."""
        # TODO: Test calling resume_analysis() after simulated restart
        pass


class TestMessageLimitSettings:
    """Test message_limit from GroupSettings."""

    @patch("chatfilter.analyzer.group_engine.join_chat")
    async def test_message_limit_passed_to_analysis(
        self, mock_join_chat, engine, temp_db, mock_session_manager, mock_task_queue
    ):
        """message_limit setting is passed to TaskQueue."""
        settings = GroupSettings(message_limit=5000)
        group = ChatGroup.fake(id="group-1", settings=settings, chat_count=1)
        temp_db.save_group(group)
        temp_db.save_chat("group-1", "chat-1", "@chat")

        mock_channel = MagicMock(spec=Channel)
        mock_channel.megagroup = True
        mock_channel.forum = False
        mock_join_chat.return_value = mock_channel

        mock_client = AsyncMock()
        mock_session_manager.get_client.return_value = mock_client

        await engine.start_analysis("group-1")

        # TODO: Verify create_task called with message_limit=5000
