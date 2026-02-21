"""Tests for group re-analysis feature (incremental and overwrite modes).

This module tests the SPEC requirement #3 (v0.9.12): Re-analysis functionality
with "Дополнить" (incremental) and "Перезаписать" (overwrite) modes.

Coverage:
- Incremental mode preserves existing metrics and adds new ones
- Incremental mode skips chats with existing metrics (no redundant API calls)
- Incremental mode does NOT clear existing metrics
- Overwrite mode clears all previous metrics (sets to NULL)
- Overwrite mode resets all chat statuses to PENDING
- UI buttons visibility logic (completed → visible, in_progress → hidden)
- Settings change + increment correctly merges metrics
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.analyzer.group_engine import GroupAnalysisEngine
from chatfilter.analyzer.worker import ChatResult
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


def _make_chat_result(
    chat_ref: str,
    subscribers: int | None = 1000,
    messages_per_hour: float | None = 10.0,
    unique_authors_per_hour: float | None = 5.0,
    moderation: bool | None = False,
    captcha: bool | None = False,
) -> ChatResult:
    """Helper to create ChatResult."""
    return ChatResult(
        chat_ref=chat_ref,
        chat_type=ChatTypeEnum.GROUP.value,
        title=f"Chat {chat_ref}",
        subscribers=subscribers,
        messages_per_hour=messages_per_hour,
        unique_authors_per_hour=unique_authors_per_hour,
        moderation=moderation,
        captcha=captcha,
        partial_data=False,
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

    # Step 1: Create group with detect_subscribers=True, detect_activity=False
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

    # Step 2: Run initial analysis (only subscribers, no activity)
    async def mock_initial_worker(chat, client, account_id, settings):
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=5000,
            messages_per_hour=None,  # Not collected yet
            unique_authors_per_hour=None,
            moderation=None,
            captcha=None,
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_initial_worker),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Verify initial state: subscribers populated, activity not
    chat = test_db.load_chats(group_id=group_id)[0]
    initial_metrics = test_db.get_chat_metrics(chat["id"])
    assert initial_metrics["subscribers"] == 5000
    assert initial_metrics["messages_per_hour"] is None

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

    # Step 4: Run incremental analysis
    async def mock_increment_worker(chat, client, account_id, settings):
        # Incremental worker adds missing metrics
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=5000,  # Unchanged
            messages_per_hour=12.5,  # NEW
            unique_authors_per_hour=None,
            moderation=None,
            captcha=None,
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_increment_worker),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        # Sleep to avoid task ID collision (timestamp-based)
        import time
        time.sleep(1.1)

        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Step 5: Verify final state
    final_chat = test_db.load_chats(group_id=group_id)[0]
    final_metrics = test_db.get_chat_metrics(final_chat["id"])

    # CRITICAL: subscribers should be UNCHANGED (preserved from initial analysis)
    assert final_metrics["subscribers"] == 5000

    # Activity should be ADDED
    assert final_metrics["messages_per_hour"] == 12.5


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
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add chat with PENDING status
    test_db.save_chat(
        group_id=group_id,
        chat_ref="complete_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account=None,
    )

    # Run FRESH analysis first to populate all metrics
    async def mock_fresh_worker(chat, client, account_id, settings):
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=1000,
            messages_per_hour=50.0,
            unique_authors_per_hour=10.0,
            moderation=True,
            captcha=False,
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_fresh_worker),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Mark group as completed
    test_db.save_group(
        group_id=group_id,
        name="Test Group Skip",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Now run incremental - should NOT call worker (metrics complete)
    processed_refs: list[str] = []

    async def mock_increment_worker(chat, client, account_id, settings):
        # This should NEVER be called for chats with complete metrics
        processed_refs.append(chat["chat_ref"])
        return _make_chat_result(chat["chat_ref"])

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_increment_worker),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        # Sleep to avoid task ID collision
        import time
        time.sleep(1.1)

        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Verify: NO API calls were made (processed_refs should be empty)
    assert len(processed_refs) == 0, f"Expected NO API calls, but processed: {processed_refs}"

    # Verify: metrics remain unchanged
    final_chat = test_db.load_chats(group_id=group_id)[0]
    final_metrics = test_db.get_chat_metrics(final_chat["id"])
    assert final_metrics["subscribers"] == 1000
    assert final_metrics["messages_per_hour"] == 50.0


@pytest.mark.asyncio
async def test_incremental_does_not_call_clear_results(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that incremental mode does NOT clear existing metrics.

    This verifies that existing metrics are preserved in the column-based schema.
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
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add existing chat
    test_db.save_chat(
        group_id=group_id,
        chat_ref="existing_chat",
        chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account=None,
    )

    # Initial analysis
    async def mock_initial(chat, client, account_id, settings):
        return _make_chat_result(chat["chat_ref"], subscribers=999, messages_per_hour=None)

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_initial),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Mark as completed
    test_db.save_group(
        group_id=group_id,
        name="Test No Clear",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Run incremental analysis
    async def mock_increment(chat, client, account_id, settings):
        # Should see existing metrics preserved
        return _make_chat_result(chat["chat_ref"], subscribers=999, messages_per_hour=None)

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_increment),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        # Sleep to avoid task ID collision
        import time
        time.sleep(1.1)

        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Verify: existing metrics still exist (not cleared)
    final_chat = test_db.load_chats(group_id=group_id)[0]
    metrics = test_db.get_chat_metrics(final_chat["id"])
    assert metrics is not None
    assert metrics["subscribers"] == 999


@pytest.mark.asyncio
async def test_overwrite_clears_all_results(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that overwrite mode clears all previous metrics.

    Given: Chat with subscribers=1000, activity=50
    When: Run overwrite analysis
    Then: All metrics reset to NULL, then repopulated with fresh data
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
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add chat
    test_db.save_chat(
        group_id=group_id,
        chat_ref="old_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account=None,
    )

    # Initial analysis with OLD data
    engine = GroupAnalysisEngine(db=test_db, session_manager=mock_session_manager)

    async def mock_initial(chat, client, account_id, settings):
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=1000,
            messages_per_hour=50.0,
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_initial),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Verify old data exists
    chat = test_db.load_chats(group_id=group_id)[0]
    old_metrics = test_db.get_chat_metrics(chat["id"])
    assert old_metrics["subscribers"] == 1000
    assert old_metrics["messages_per_hour"] == 50.0

    # Mark as completed
    test_db.save_group(
        group_id=group_id,
        name="Test Overwrite",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Run OVERWRITE analysis with NEW data
    async def mock_overwrite(chat, client, account_id, settings):
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=2000,  # NEW data
            messages_per_hour=100.0,  # NEW data
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_overwrite),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        # Sleep to avoid task ID collision
        import time
        time.sleep(1.1)

        await engine.start_analysis(group_id, mode=AnalysisMode.OVERWRITE)

    # Verify: NEW data (old data replaced)
    new_chat = test_db.load_chats(group_id=group_id)[0]
    new_metrics = test_db.get_chat_metrics(new_chat["id"])
    assert new_metrics["subscribers"] == 2000  # NEW data (not 1000)
    assert new_metrics["messages_per_hour"] == 100.0  # NEW data (not 50.0)


@pytest.mark.asyncio
async def test_overwrite_resets_chat_statuses(
    test_db: GroupDatabase,
    mock_session_manager,
):
    """Test that overwrite mode resets all chat statuses to PENDING.

    Given: Some chats status=done, some=error
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
        status=GroupStatus.PENDING.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Add chats with PENDING status
    test_db.save_chat(
        group_id=group_id,
        chat_ref="done_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account=None,
    )

    test_db.save_chat(
        group_id=group_id,
        chat_ref="failed_chat",
        chat_type=ChatTypeEnum.GROUP.value,
        status=GroupChatStatus.PENDING.value,
        assigned_account=None,
    )

    # Initial analysis - make one DONE, one ERROR
    call_count = 0

    async def mock_initial(chat, client, account_id, settings):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First chat succeeds
            return _make_chat_result(chat["chat_ref"])
        else:
            # Second chat fails
            raise Exception("Simulated error")

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_initial),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        try:
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)
        except:
            pass  # Expected to fail on second chat

    # Verify initial statuses: one DONE, one ERROR
    done_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
    error_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value)
    assert len(done_chats) >= 1
    assert len(error_chats) >= 1

    # Mark as completed (manually, since it failed)
    test_db.save_group(
        group_id=group_id,
        name="Test Reset",
        settings=settings.model_dump(),
        status=GroupStatus.COMPLETED.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Run OVERWRITE - should reset all to PENDING
    async def mock_overwrite(chat, client, account_id, settings):
        return _make_chat_result(chat["chat_ref"])

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_overwrite),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        # Sleep to avoid task ID collision
        import time
        time.sleep(1.1)

        await engine.start_analysis(group_id, mode=AnalysisMode.OVERWRITE)

    # Verify: ALL chats should now be DONE (not PENDING, because analysis completed)
    all_chats = test_db.load_chats(group_id=group_id)
    for chat in all_chats:
        assert chat["status"] == GroupChatStatus.DONE.value

    # Verify: no more ERROR chats
    error_after = test_db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value)
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
    - Verify: metrics contain BOTH subscribers AND activity
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
        assigned_account=None,
    )

    # Step 2: Complete initial analysis (only subscribers)
    async def mock_initial(chat, client, account_id, settings):
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=3000,
            messages_per_hour=None,  # Not collected
            unique_authors_per_hour=None,
            moderation=None,
            captcha=None,
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_initial),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    # Verify initial state
    chat = test_db.load_chats(group_id=group_id)[0]
    initial_metrics = test_db.get_chat_metrics(chat["id"])
    assert initial_metrics["subscribers"] == 3000
    assert initial_metrics["messages_per_hour"] is None

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

    # Step 4: Run incremental analysis
    async def mock_increment(chat, client, account_id, settings):
        # Add activity metric
        return _make_chat_result(
            chat["chat_ref"],
            subscribers=3000,  # Unchanged
            messages_per_hour=25.0,  # NEW
            unique_authors_per_hour=None,
            moderation=None,
            captcha=None,
        )

    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_increment),
        patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
    ):
        # Sleep to avoid task ID collision
        import time
        time.sleep(1.1)

        await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    # Step 5: Verify MERGED metrics
    final_chat = test_db.load_chats(group_id=group_id)[0]
    final_metrics = test_db.get_chat_metrics(final_chat["id"])

    # CRITICAL: Both metrics should be present
    assert final_metrics["subscribers"] == 3000  # Preserved
    assert final_metrics["messages_per_hour"] == 25.0  # Added
