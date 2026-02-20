"""Tests for _prepare_increment() logic in GroupAnalysisEngine.

Covers:
- Incomplete DONE chats (missing metrics) are marked PENDING
- Complete DONE chats are kept as DONE
- Initial progress event is published BEFORE _prepare_increment (correct count)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.analyzer.group_engine import GroupAnalysisEngine
from chatfilter.models.group import (
    AnalysisMode,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.session_manager import SessionManager


@pytest.fixture
def mock_db(isolated_tmp_dir):
    """Create a GroupDatabase instance with isolated storage."""
    return GroupDatabase(str(isolated_tmp_dir / "groups.db"))


@pytest.fixture
def mock_session_manager():
    """Create a mock SessionManager."""
    mgr = MagicMock(spec=SessionManager)
    mgr.list_sessions = MagicMock(return_value=["account1"])

    async def mock_is_healthy(session_id):
        return True

    mgr.is_healthy = mock_is_healthy
    return mgr


@pytest.fixture
def engine(mock_db, mock_session_manager):
    """Create GroupAnalysisEngine with mocked dependencies."""
    return GroupAnalysisEngine(db=mock_db, session_manager=mock_session_manager)


def _create_group_with_chats(db, group_id, settings_dict, chat_refs, chat_statuses, results):
    """Helper: create group, chats, and results in DB.

    Args:
        db: GroupDatabase instance
        group_id: Group ID
        settings_dict: Settings as dict
        chat_refs: List of chat references
        chat_statuses: List of statuses for each chat
        results: Dict of chat_ref -> metrics_data (only for chats with results)
    """
    db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=settings_dict,
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    for ref, status in zip(chat_refs, chat_statuses):
        db.save_chat(
            group_id=group_id,
            chat_ref=ref,
            chat_type=ChatTypeEnum.GROUP.value,
            status=status,
        )
    for ref, metrics in results.items():
        db.save_result(
            group_id=group_id,
            chat_ref=ref,
            metrics_data=metrics,
        )


class TestPrepareIncrement:
    """Tests for _prepare_increment() method."""

    def test_incomplete_done_chats_marked_pending(self, engine, mock_db):
        """DONE chats missing required metrics should be marked PENDING."""
        settings = GroupSettings(
            detect_activity=True,
            detect_subscribers=True,
            detect_moderation=False,
            detect_captcha=False,
            detect_unique_authors=False,
        )
        group_id = "g1"

        _create_group_with_chats(
            mock_db,
            group_id,
            settings.model_dump(),
            chat_refs=["chat_a", "chat_b", "chat_c"],
            chat_statuses=[
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
            ],
            results={
                # chat_a: complete (has chat_type + subscribers + activity)
                "chat_a": {
                    "chat_type": "group",
                    "subscribers": 100,
                    "messages_per_hour": 5.0,
                },
                # chat_b: missing activity (messages_per_hour)
                "chat_b": {
                    "chat_type": "group",
                    "subscribers": 50,
                },
                # chat_c: no result at all
            },
        )

        count = engine._prepare_increment(group_id, settings)

        assert count == 2, "Should mark 2 incomplete chats as PENDING"

        chats = mock_db.load_chats(group_id=group_id)
        status_map = {c["chat_ref"]: c["status"] for c in chats}
        assert status_map["chat_a"] == GroupChatStatus.DONE.value
        assert status_map["chat_b"] == GroupChatStatus.PENDING.value
        assert status_map["chat_c"] == GroupChatStatus.PENDING.value

    def test_all_complete_no_changes(self, engine, mock_db):
        """When all DONE chats have all metrics, none should be marked PENDING."""
        settings = GroupSettings(
            detect_activity=False,
            detect_subscribers=True,
            detect_moderation=False,
            detect_captcha=False,
            detect_unique_authors=False,
        )
        group_id = "g2"

        _create_group_with_chats(
            mock_db,
            group_id,
            settings.model_dump(),
            chat_refs=["chat_x", "chat_y"],
            chat_statuses=[
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
            ],
            results={
                "chat_x": {"chat_type": "group", "subscribers": 100},
                "chat_y": {"chat_type": "group", "subscribers": 200},
            },
        )

        count = engine._prepare_increment(group_id, settings)

        assert count == 0, "All chats complete, none should change"

        chats = mock_db.load_chats(group_id=group_id)
        for c in chats:
            assert c["status"] == GroupChatStatus.DONE.value

    def test_no_chats_returns_zero(self, engine, mock_db):
        """Empty group should return 0."""
        settings = GroupSettings()
        group_id = "g3"

        mock_db.save_group(
            group_id=group_id,
            name="Empty Group",
            settings=settings.model_dump(),
            status=GroupStatus.COMPLETED.value,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

        count = engine._prepare_increment(group_id, settings)
        assert count == 0

    def test_settings_change_detects_missing_metric(self, engine, mock_db):
        """When user enables a new metric, previously DONE chats should be re-analyzed."""
        # Original analysis with detect_activity=False
        old_settings = GroupSettings(detect_activity=False)
        group_id = "g4"

        _create_group_with_chats(
            mock_db,
            group_id,
            old_settings.model_dump(),
            chat_refs=["chat1", "chat2", "chat3"],
            chat_statuses=[
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
            ],
            results={
                "chat1": {"chat_type": "group", "subscribers": 10},
                "chat2": {"chat_type": "group", "subscribers": 20},
                "chat3": {"chat_type": "group", "subscribers": 30},
            },
        )

        # Now user enables detect_activity
        new_settings = GroupSettings(detect_activity=True)
        count = engine._prepare_increment(group_id, new_settings)

        # All 3 chats should be marked PENDING (missing messages_per_hour)
        assert count == 3

        chats = mock_db.load_chats(group_id=group_id)
        for c in chats:
            assert c["status"] == GroupChatStatus.PENDING.value


class TestIncrementInitialProgress:
    """Test that initial progress is published BEFORE _prepare_increment."""

    @pytest.mark.asyncio
    async def test_initial_progress_shows_original_count(self, engine, mock_db):
        """Initial progress event should show count BEFORE incomplete chats are reset."""
        settings = GroupSettings(
            detect_activity=True,
            detect_subscribers=True,
            detect_moderation=False,
            detect_captcha=False,
            detect_unique_authors=False,
        )
        group_id = "g5"

        _create_group_with_chats(
            mock_db,
            group_id,
            settings.model_dump(),
            chat_refs=["done1", "done2", "incomplete1"],
            chat_statuses=[
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
                GroupChatStatus.DONE.value,
            ],
            results={
                "done1": {"chat_type": "group", "subscribers": 100, "messages_per_hour": 5.0},
                "done2": {"chat_type": "group", "subscribers": 200, "messages_per_hour": 10.0},
                # incomplete1: missing messages_per_hour
                "incomplete1": {"chat_type": "group", "subscribers": 50},
            },
        )

        # Track published events
        published_events = []
        original_publish = engine._publish_event

        def capture_event(event):
            published_events.append(event)
            original_publish(event)

        engine._publish_event = capture_event

        # Patch _phase1_resolve_account to avoid actual Telegram calls
        async def mock_phase1(*args, **kwargs):
            pass

        engine._phase1_resolve_account = mock_phase1

        # Also patch _run_phase2 to avoid actual Telegram calls
        async def mock_phase2(*args, **kwargs):
            pass

        engine._run_phase2 = mock_phase2

        # Run start_analysis in INCREMENT mode
        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

        # Find the initial progress event (first IN_PROGRESS event)
        initial_events = [
            e for e in published_events
            if e.status == GroupStatus.IN_PROGRESS.value
        ]

        assert len(initial_events) >= 1, "Should have at least one initial progress event"

        first_event = initial_events[0]
        # Key assertion: initial progress should show 3/3 (all were DONE before _prepare_increment)
        # because count_processed_chats counts done+failed+dead
        assert first_event.current == 3, (
            f"Initial progress should show 3 (all originally DONE), got {first_event.current}"
        )
        assert first_event.total == 3
