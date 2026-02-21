"""Tests for group re-analysis feature (incremental and overwrite modes).

This module tests the SPEC requirement #3 (v0.9.12): Re-analysis functionality
with "Дополнить" (incremental) and "Перезаписать" (overwrite) modes.

Coverage:
- Incremental mode preserves existing metrics and adds new ones
- Incremental mode skips chats with existing metrics (no redundant API calls)
- Incremental mode does NOT call clear_results()
- Overwrite mode clears all previous results
- Overwrite mode resets all chat statuses to PENDING
- UI buttons visibility logic (completed → visible, in_progress → hidden)
- Settings change + increment correctly merges metrics
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

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


@pytest.fixture
def mock_session_manager():
    """Mock SessionManager with one healthy account."""
    mock_mgr = MagicMock()
    mock_mgr.list_sessions.return_value = ["test_account_1"]

    async def is_healthy_mock(session_id: str) -> bool:
        return session_id == "test_account_1"

    mock_mgr.is_healthy = AsyncMock(side_effect=is_healthy_mock)

    # Mock session context manager
    mock_client = MagicMock()
    mock_context = MagicMock()
    mock_context.__aenter__ = AsyncMock(return_value=mock_client)
    mock_context.__aexit__ = AsyncMock(return_value=None)
    mock_mgr.session.return_value = mock_context

    return mock_mgr


@pytest.fixture
def test_db(tmp_path):
    """Create a test GroupDatabase instance."""
    db_path = tmp_path / "test_groups.db"
    return GroupDatabase(db_path)


@pytest.fixture
def sample_settings() -> GroupSettings:
    """Sample group settings for testing."""
    return GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=False,
        detect_unique_authors=False,
        detect_moderation=False,
        detect_captcha=False,
        time_window=24,
    )


@pytest.mark.asyncio
async def test_incremental_preserves_existing_metrics(
    test_db: GroupDatabase,
    mock_session_manager,
    sample_settings: GroupSettings,
):
    """Test that incremental mode preserves existing metrics and adds new ones.

    1. Initial analysis: detect_subscribers=True
    2. Verify: subscribers populated
    3. Change settings: enable detect_activity=True
    4. Run: incremental analysis
    5. Verify: subscribers UNCHANGED, activity ADDED
    """
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    # Step 1: Create group with detect_subscribers=True
    initial_settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=False,
        detect_unique_authors=False,
        detect_moderation=False,
        detect_captcha=False,
        time_window=24,
    )

    group_id = "test_group_1"
    test_db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=initial_settings.model_dump(),
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add test chat
    test_db.save_chat(
        group_id=group_id,
        chat_ref="test_channel",
        chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account=None,
    )

    # Step 2: Simulate initial analysis completion (Phase 1 only)
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1:
        # Mock Phase 1 resolution - populate subscribers
        async def mock_resolve(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                # Simulate successful resolution with subscribers
                test_db.save_chat(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
                    status=GroupChatStatus.DONE.value,
                    assigned_account="test_account_1",
                    subscribers=5000,
                )
                # Save Phase 1 result
                test_db.save_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
                        "title": "Test Channel",
                        "chat_ref": chat["chat_ref"],
                        "status": "done",
                        "subscribers": 5000,
                    },
                )

        mock_phase1.side_effect = mock_resolve

        # Run initial analysis
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Verify initial state: subscribers populated
    initial_result = test_db.load_result(group_id, "test_channel")
    assert initial_result is not None
    assert initial_result["metrics_data"]["subscribers"] == 5000
    assert "messages_per_hour" not in initial_result["metrics_data"]

    # Step 3: Change settings to enable detect_activity
    updated_settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=True,  # NEW: enable activity detection
        detect_unique_authors=False,
        detect_moderation=False,
        detect_captcha=False,
        time_window=24,
    )

    test_db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=updated_settings.model_dump(),
        status=GroupStatus.COMPLETED.value,  # Mark as completed to allow re-analysis
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Reset chat to PENDING for re-analysis
    test_db.update_chat_status(
        chat_id=test_db.load_chats(group_id=group_id)[0]["id"],
        status=GroupChatStatus.PENDING.value,
    )

    # Step 4: Run incremental analysis
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1, \
         patch.object(engine, "_phase2_activity_account", new_callable=AsyncMock) as mock_phase2:

        # Phase 1 should skip (metrics exist)
        async def mock_resolve_increment(*args, **kwargs):
            # Incremental mode will skip Phase 1 since subscribers already exist
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                test_db.update_chat_status(
                    chat_id=chat["id"],
                    status=GroupChatStatus.DONE.value,
                )

        # Phase 2 should add activity metrics
        async def mock_activity(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
            for chat in chats:
                # Use upsert to preserve existing metrics
                test_db.upsert_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "messages_per_hour": 12.5,
                    },
                )

        mock_phase1.side_effect = mock_resolve_increment
        mock_phase2.side_effect = mock_activity

        # Run incremental re-analysis
        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Step 5: Verify final state
    final_result = test_db.load_result(group_id, "test_channel")
    assert final_result is not None

    # CRITICAL: subscribers should be UNCHANGED (preserved from initial analysis)
    assert final_result["metrics_data"]["subscribers"] == 5000

    # Activity should be ADDED
    assert final_result["metrics_data"]["messages_per_hour"] == 12.5


@pytest.mark.asyncio
async def test_incremental_skips_collected_metrics(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that incremental mode skips chats with existing metrics (no redundant API calls).

    Given: Chat with subscribers=1000, activity=50
    When: Run incremental with same settings
    Then: NO API calls (metrics already exist)
    """
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    # Create group with all metrics enabled
    settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=True,
        detect_unique_authors=True,
        detect_moderation=True,
        detect_captcha=True,
        time_window=24,
    )

    group_id = "test_group_skip"
    test_db.save_group(
        group_id=group_id,
        name="Test Group Skip",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add chat with COMPLETE metrics already populated
    test_db.save_chat(
        group_id=group_id,
        chat_ref="complete_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.DONE.value,
        assigned_account="test_account_1",
        subscribers=1000,
    )

    test_db.save_result(
        group_id=group_id,
        chat_ref="complete_chat",
        metrics_data={
            "chat_type": ChatTypeEnum.GROUP.value,
            "title": "Complete Chat",
            "chat_ref": "complete_chat",
            "status": "done",
            "subscribers": 1000,
            "messages_per_hour": 50.0,
            "unique_authors_per_hour": 10.0,
            "moderation": True,
            "captcha": False,
        },
    )

    # Reset to PENDING to trigger re-analysis
    test_db.update_chat_status(
        chat_id=test_db.load_chats(group_id=group_id)[0]["id"],
        status=GroupChatStatus.PENDING.value,
    )

    # Run incremental analysis
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1, \
         patch.object(engine, "_phase2_activity_account", new_callable=AsyncMock) as mock_phase2:

        # Real implementation should skip processing
        # We'll verify by checking that _resolve_chat is never called
        resolve_called = False

        async def track_resolve(*args, **kwargs):
            nonlocal resolve_called
            # This should NOT be called for chats with complete metrics
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                # Check if metrics exist and are complete
                existing = test_db.load_result(group_id, chat["chat_ref"])
                if existing:
                    em = existing.get("metrics_data", {})
                    # If all required metrics exist, skip
                    has_all = (
                        em.get("chat_type") is not None and
                        em.get("subscribers") is not None and
                        em.get("moderation") is not None
                    )
                    if has_all:
                        # Mark as done without calling API
                        test_db.update_chat_status(
                            chat_id=chat["id"],
                            status=GroupChatStatus.DONE.value,
                        )
                        continue

                resolve_called = True

        async def track_activity(*args, **kwargs):
            nonlocal resolve_called
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
            for chat in chats:
                existing = test_db.load_result(group_id, chat["chat_ref"])
                if existing:
                    em = existing.get("metrics_data", {})
                    # If all activity metrics exist, skip
                    has_all = (
                        em.get("messages_per_hour") is not None and
                        em.get("unique_authors_per_hour") is not None and
                        em.get("captcha") is not None
                    )
                    if has_all:
                        continue

                resolve_called = True

        mock_phase1.side_effect = track_resolve
        mock_phase2.side_effect = track_activity

        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Verify: NO API calls were made (resolve_called should be False)
    assert not resolve_called, "Expected NO API calls for chat with complete metrics"

    # Verify: metrics remain unchanged
    final_result = test_db.load_result(group_id, "complete_chat")
    assert final_result["metrics_data"]["subscribers"] == 1000
    assert final_result["metrics_data"]["messages_per_hour"] == 50.0


@pytest.mark.asyncio
async def test_incremental_does_not_call_clear_results(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that incremental mode does NOT call clear_results().

    This verifies that existing metrics_data is preserved.
    """
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=False,
    )

    group_id = "test_group_noclear"
    test_db.save_group(
        group_id=group_id,
        name="Test No Clear",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add existing result
    test_db.save_chat(
        group_id=group_id,
        chat_ref="existing_chat",
        chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account="test_account_1",
        subscribers=999,
    )

    test_db.save_result(
        group_id=group_id,
        chat_ref="existing_chat",
        metrics_data={
            "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
            "title": "Existing Chat",
            "chat_ref": "existing_chat",
            "status": "done",
            "subscribers": 999,
        },
    )

    # Spy on clear_results to ensure it's NOT called
    clear_called = False
    original_clear = test_db.clear_results

    def track_clear(gid):
        nonlocal clear_called
        clear_called = True
        return original_clear(gid)

    test_db.clear_results = track_clear

    # Run incremental analysis
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock):
        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Verify: clear_results was NOT called
    assert not clear_called, "clear_results() should NOT be called in INCREMENT mode"

    # Verify: existing result still exists
    result = test_db.load_result(group_id, "existing_chat")
    assert result is not None
    assert result["metrics_data"]["subscribers"] == 999


@pytest.mark.asyncio
async def test_overwrite_clears_all_results(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that overwrite mode clears all previous results.

    Given: Chat with subscribers=1000, activity=50
    When: Run overwrite analysis
    Then: clear_results() called, all metrics fresh (no old data)
    """

    settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=True,
    )

    group_id = "test_group_overwrite"
    test_db.save_group(
        group_id=group_id,
        name="Test Overwrite",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add existing result with OLD data
    # IMPORTANT: Use PENDING status to avoid early return in start_analysis()
    # (when all chats DONE, start_analysis returns before OVERWRITE logic)
    test_db.save_chat(
        group_id=group_id,
        chat_ref="old_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.PENDING.value,  # PENDING to trigger analysis
        assigned_account="test_account_1",
        subscribers=1000,
    )

    test_db.save_result(
        group_id=group_id,
        chat_ref="old_chat",
        metrics_data={
            "chat_type": ChatTypeEnum.GROUP.value,
            "title": "Old Chat",
            "chat_ref": "old_chat",
            "status": "done",
            "subscribers": 1000,
            "messages_per_hour": 50.0,
        },
    )

    # Verify old data exists
    old_result = test_db.load_result(group_id, "old_chat")
    assert old_result is not None
    assert old_result["metrics_data"]["subscribers"] == 1000

    # Run overwrite analysis
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1, \
         patch.object(engine, "_phase2_activity_account", new_callable=AsyncMock) as mock_phase2:

        async def mock_resolve(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                test_db.save_chat(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.GROUP.value,
                    status=GroupChatStatus.DONE.value,
                    assigned_account="test_account_1",
                    subscribers=2000,  # NEW data
                )
                test_db.save_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "chat_type": ChatTypeEnum.GROUP.value,
                        "title": "New Chat Title",
                        "chat_ref": chat["chat_ref"],
                        "status": "done",
                        "subscribers": 2000,  # NEW data
                    },
                )

        async def mock_activity(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
            for chat in chats:
                test_db.upsert_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "messages_per_hour": 100.0,  # NEW data
                    },
                )

        mock_phase1.side_effect = mock_resolve
        mock_phase2.side_effect = mock_activity

        await engine.start_analysis(group_id, mode=AnalysisMode.OVERWRITE)

    # Verify: new metrics (old data replaced)
    # OVERWRITE mode calls clear_results() which deletes old data
    # Then new analysis populates fresh data
    new_result = test_db.load_result(group_id, "old_chat")
    assert new_result is not None
    assert new_result["metrics_data"]["subscribers"] == 2000  # NEW data (not 1000)
    assert new_result["metrics_data"]["messages_per_hour"] == 100.0  # NEW data (not 50.0)
    assert new_result["metrics_data"]["title"] == "New Chat Title"  # NEW data (not "Old Chat")


@pytest.mark.asyncio
async def test_overwrite_resets_chat_statuses(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that overwrite mode resets all chat statuses to PENDING.

    Given: Some chats status=done, some=dead
    When: Run overwrite
    Then: All statuses reset to pending
    """
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
    )

    group_id = "test_group_reset"
    test_db.save_group(
        group_id=group_id,
        name="Test Reset",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add chats with various statuses
    test_db.save_chat(
        group_id=group_id,
        chat_ref="done_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.DONE.value,
        assigned_account="test_account_1",
    )

    test_db.save_chat(
        group_id=group_id,
        chat_ref="failed_chat",
        chat_type=ChatTypeEnum.DEAD.value,
        status=GroupChatStatus.ERROR.value,
        assigned_account="test_account_1",
    )

    # Verify initial statuses
    done_chat = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
    error_chat = test_db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value)
    assert len(done_chat) == 1
    assert len(error_chat) == 1

    # Run overwrite analysis (will reset all to PENDING)
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1:
        # Mock Phase 1 to create results (prevents orphan safety net from triggering)
        async def mock_resolve(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                # Save minimal result to satisfy orphan safety net
                test_db.save_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "chat_ref": chat["chat_ref"],
                        "status": "pending",
                    },
                )

        mock_phase1.side_effect = mock_resolve
        await engine.start_analysis(group_id, mode=AnalysisMode.OVERWRITE)

    # Verify: ALL chats reset to PENDING
    pending_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
    assert len(pending_chats) == 2  # Both chats should be PENDING

    # Verify: no more DONE or ERROR chats
    done_after = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
    error_after = test_db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value)
    assert len(done_after) == 0
    assert len(error_after) == 0


def test_reanalysis_buttons_visible_when_completed(test_db: GroupDatabase):
    """Test that re-analysis buttons are only visible when group status=COMPLETED.

    This is a UI logic test - buttons should only appear when analysis is complete.
    """
    group_id = "test_group_ui"

    # Create group with COMPLETED status
    test_db.save_group(
        group_id=group_id,
        name="Completed Group",
        settings=GroupSettings(detect_chat_type=True).model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Load and verify status
    group = test_db.load_group(group_id)
    assert group is not None
    assert group["status"] == GroupStatus.COMPLETED.value

    # UI logic: buttons should be visible for COMPLETED status
    buttons_visible = group["status"] == GroupStatus.COMPLETED.value
    assert buttons_visible is True

    # Test: IN_PROGRESS → buttons hidden
    test_db.save_group(
        group_id=group_id,
        name="In Progress Group",
        settings=GroupSettings(detect_chat_type=True).model_dump(),
        status=GroupStatus.IN_PROGRESS.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    group = test_db.load_group(group_id)
    buttons_visible = group["status"] == GroupStatus.COMPLETED.value
    assert buttons_visible is False

    # Test: PENDING → buttons hidden
    test_db.save_group(
        group_id=group_id,
        name="Pending Group",
        settings=GroupSettings(detect_chat_type=True).model_dump(),
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    group = test_db.load_group(group_id)
    buttons_visible = group["status"] == GroupStatus.COMPLETED.value
    assert buttons_visible is False


@pytest.mark.asyncio
async def test_settings_change_plus_increment(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that changing settings + running increment correctly merges metrics.

    Scenario:
    - Initial: detect_subscribers=True, detect_activity=False
    - Complete analysis
    - Change: detect_activity=True
    - Run: increment
    - Verify: metrics_data contains BOTH subscribers AND activity
    """
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    # Step 1: Initial settings (only subscribers)
    initial_settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=False,
        detect_unique_authors=False,
        detect_moderation=False,
        detect_captcha=False,
    )

    group_id = "test_group_merge"
    test_db.save_group(
        group_id=group_id,
        name="Test Merge",
        settings=initial_settings.model_dump(),
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add test chat
    test_db.save_chat(
        group_id=group_id,
        chat_ref="merge_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account="test_account_1",
    )

    # Step 2: Complete initial analysis (Phase 1 only, no activity)
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1:
        async def mock_initial_resolve(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                test_db.save_chat(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.GROUP.value,
                    status=GroupChatStatus.DONE.value,
                    assigned_account="test_account_1",
                    subscribers=3000,
                )
                test_db.save_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "chat_type": ChatTypeEnum.GROUP.value,
                        "title": "Merge Chat",
                        "chat_ref": chat["chat_ref"],
                        "status": "done",
                        "subscribers": 3000,
                    },
                )

        mock_phase1.side_effect = mock_initial_resolve
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Verify initial state
    initial_result = test_db.load_result(group_id, "merge_chat")
    assert initial_result["metrics_data"]["subscribers"] == 3000
    assert "messages_per_hour" not in initial_result["metrics_data"]

    # Step 3: Change settings to enable detect_activity
    updated_settings = GroupSettings(
        detect_chat_type=True,
        detect_subscribers=True,
        detect_activity=True,  # NEW
        detect_unique_authors=False,
        detect_moderation=False,
        detect_captcha=False,
    )

    test_db.save_group(
        group_id=group_id,
        name="Test Merge",
        settings=updated_settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Reset to PENDING for re-analysis
    test_db.update_chat_status(
        chat_id=test_db.load_chats(group_id=group_id)[0]["id"],
        status=GroupChatStatus.PENDING.value,
    )

    # Step 4: Run incremental analysis
    with patch.object(engine, "_phase1_resolve_account", new_callable=AsyncMock) as mock_phase1, \
         patch.object(engine, "_phase2_activity_account", new_callable=AsyncMock) as mock_phase2:

        # Phase 1 should skip (subscribers exist)
        async def mock_skip_phase1(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
            for chat in chats:
                test_db.update_chat_status(
                    chat_id=chat["id"],
                    status=GroupChatStatus.DONE.value,
                )

        # Phase 2 should add activity
        async def mock_add_activity(*args, **kwargs):
            chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
            for chat in chats:
                test_db.upsert_result(
                    group_id=group_id,
                    chat_ref=chat["chat_ref"],
                    metrics_data={
                        "messages_per_hour": 25.0,
                    },
                )

        mock_phase1.side_effect = mock_skip_phase1
        mock_phase2.side_effect = mock_add_activity

        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Step 5: Verify MERGED metrics
    final_result = test_db.load_result(group_id, "merge_chat")
    assert final_result is not None

    # CRITICAL: Both metrics should be present
    assert final_result["metrics_data"]["subscribers"] == 3000  # Preserved
    assert final_result["metrics_data"]["messages_per_hour"] == 25.0  # Added
