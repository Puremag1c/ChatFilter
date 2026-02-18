"""Integration tests for group analysis retry mechanism and re-analysis modes.

Test Scenarios:
1. test_retry_on_floodwait — simulate FloodWait → verify retry → 3 failures → chat marked dead
2. test_incremental_analysis_skips_existing — analyze with subscribers → add activity → verify subscribers unchanged, activity added
3. test_full_reanalysis_clears_old_data — analyze → overwrite → verify all data fresh
4. test_all_chats_get_results — 10 chats, 2 fail → verify 10 rows in group_results (8 done + 2 dead)
5. test_export_filters_work_without_exclude_dead — verify dead type checkbox removes dead chats from CSV
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telethon.errors import FloodWaitError

from chatfilter.models.group import AnalysisMode, GroupChatStatus, GroupSettings
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.web.routers.groups import _apply_export_filters


@pytest.fixture
def test_db(tmp_path: Path) -> GroupDatabase:
    """Create isolated test database."""
    db_path = tmp_path / "test_groups.db"
    db = GroupDatabase(str(db_path))
    yield db


class TestRetryMechanism:
    """Test 1: FloodWait retry mechanism."""

    @pytest.mark.asyncio
    async def test_retry_on_errors_marks_dead_after_3_failures(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that general errors trigger retry, and 3 failures mark chat as dead.

        This tests the retry mechanism from lines 609-671 in group_engine.py,
        which handles non-FloodWait exceptions with MAX_RETRIES=3.
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        # Setup: Create group with 1 chat
        group_id = "test-group-retry"
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status="pending",
        )

        chat_ref = "https://t.me/retry_test_chat"
        test_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type="pending",
            assigned_account="test-account",
            status=GroupChatStatus.PENDING.value,
        )

        # Mock engine dependencies
        mock_session_manager = MagicMock()

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Track retry attempts
        retry_count = 0

        # Mock _resolve_chat to raise a generic Exception (not FloodWait)
        # This will trigger the retry logic at lines 609-671
        async def mock_resolve_chat(*args, **kwargs):
            nonlocal retry_count
            retry_count += 1
            # Simulate a network error or API error
            raise ConnectionError("Simulated connection error")

        # Mock session manager context (proper async context manager)
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Patch _resolve_chat to raise ConnectionError
        with patch.object(
            engine,
            "_resolve_chat",
            side_effect=mock_resolve_chat,
        ):
            # Run Phase 1 (should handle retries internally)
            await engine._phase1_resolve_account(
                group_id=group_id,
                account_id="test-account",
                settings=GroupSettings(),
                mode=AnalysisMode.FRESH,
            )

        # Verify: Chat should be marked as FAILED after 3 retries
        failed_chats = test_db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.FAILED.value,
        )
        assert len(failed_chats) == 1, f"Expected 1 failed chat after 3 retries, got {len(failed_chats)}"

        # Verify: Result should be saved as 'dead'
        result = test_db.load_result(group_id, chat_ref)
        assert result is not None, "Dead chat should have result row"
        assert result["metrics_data"]["status"] == "dead", "Status should be 'dead'"
        assert result["metrics_data"]["chat_type"] == "dead", "Chat type should be 'dead'"

        # Error reason should mention retry limit and error type
        error_reason = result["metrics_data"].get("error_reason", "")
        assert "Failed after 3 retries" in error_reason, (
            f"Error reason should mention retry limit, got: {error_reason}"
        )
        assert "ConnectionError" in error_reason, (
            f"Error reason should mention error type, got: {error_reason}"
        )

        # Verify: Retry was attempted 3 times (MAX_RETRIES)
        assert retry_count == 3, f"Expected 3 retry attempts, got {retry_count}"


class TestIncrementalAnalysisDatabase:
    """Test 2: Incremental analysis with database upsert."""

    def test_incremental_upsert_preserves_existing_metrics(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that upsert_result() preserves existing metrics and adds new ones."""
        # Setup: Create group
        group_id = "test-group-incremental"
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status="pending",
        )
        chat_ref = "https://t.me/test_chat"

        # Phase 1: Save initial result with only subscribers
        initial_metrics = {
            "chat_type": "group",
            "subscribers": 500,
            "messages_per_hour": None,
            "unique_authors_per_hour": None,
            "moderation": False,
            "captcha": False,
            "status": "done",
            "title": "Test Chat",
            "chat_ref": chat_ref,
        }
        test_db.save_result(group_id, chat_ref, initial_metrics)

        # Verify initial result
        initial_result = test_db.load_result(group_id, chat_ref)
        assert initial_result is not None
        assert initial_result["metrics_data"]["subscribers"] == 500
        assert initial_result["metrics_data"]["messages_per_hour"] is None

        # Wait a bit to ensure timestamp difference
        import time

        time.sleep(0.1)

        # Phase 2: Upsert with activity metrics (INCREMENT mode simulation)
        incremental_metrics = {
            "chat_type": "group",
            "subscribers": None,  # Null to preserve existing
            "messages_per_hour": 15.5,
            "unique_authors_per_hour": 8.3,
            "moderation": None,
            "captcha": None,
            "status": "done",
            "title": "Test Chat",
            "chat_ref": chat_ref,
        }
        test_db.upsert_result(group_id, chat_ref, incremental_metrics)

        # Verify: subscribers preserved, activity added
        final_result = test_db.load_result(group_id, chat_ref)
        assert final_result is not None
        final_metrics = final_result["metrics_data"]

        # Key assertion: subscribers unchanged from initial
        assert final_metrics["subscribers"] == 500, "Upsert should preserve existing subscribers"

        # Activity should now be present
        assert final_metrics["messages_per_hour"] == 15.5, "Should have new activity metric"
        assert final_metrics["unique_authors_per_hour"] == 8.3, "Should have new unique authors"

        # Timestamp should be updated
        assert final_result["analyzed_at"] > initial_result["analyzed_at"]


class TestFullReanalysisDatabase:
    """Test 3: Full re-analysis clears old data."""

    def test_full_reanalysis_clears_results(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that clear_results() removes all old data for OVERWRITE mode."""
        # Setup: Create group with 3 chats
        group_id = "test-group-overwrite"
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status="completed",
        )

        # Add 3 results from "old" analysis
        for i in range(3):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_result(
                group_id,
                chat_ref,
                {
                    "chat_type": "group",
                    "subscribers": 100 * (i + 1),
                    "messages_per_hour": 10.0,
                    "unique_authors_per_hour": 5.0,
                    "moderation": False,
                    "captcha": False,
                    "status": "done",
                    "title": f"Old Chat {i}",
                    "chat_ref": chat_ref,
                },
            )

        # Verify old results exist
        old_results = test_db.load_results(group_id)
        assert len(old_results) == 3

        # OVERWRITE mode: Clear all results before new analysis
        test_db.clear_results(group_id)

        # Verify: All old results removed
        cleared_results = test_db.load_results(group_id)
        assert len(cleared_results) == 0, "clear_results() should remove all old data"

        # Simulate new analysis with fresh data
        for i in range(3):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_result(
                group_id,
                chat_ref,
                {
                    "chat_type": "forum",  # Changed type
                    "subscribers": 500 * (i + 1),  # Different count
                    "messages_per_hour": 20.0,
                    "unique_authors_per_hour": 10.0,
                    "moderation": True,
                    "captcha": True,
                    "status": "done",
                    "title": f"New Chat {i}",  # Different title
                    "chat_ref": chat_ref,
                },
            )

        # Verify: New results are completely fresh (not merged)
        new_results = test_db.load_results(group_id)
        assert len(new_results) == 3

        for result in new_results:
            metrics = result["metrics_data"]
            assert metrics["chat_type"] == "forum", "Should have new chat type"
            assert metrics["title"].startswith("New"), "Should have new title"
            assert metrics["subscribers"] >= 500, "Should have new subscriber counts"


class TestAllChatsGetResults:
    """Test 4: All chats get results (done or dead)."""

    def test_all_chats_saved_including_dead(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that both successful and dead chats are saved to group_results."""
        # Setup: Create group
        group_id = "test-group-all-results"
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status="pending",
        )

        # Simulate analysis results: 8 successful + 2 dead
        for i in range(8):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_result(
                group_id,
                chat_ref,
                {
                    "chat_type": "group",
                    "subscribers": 100 * (i + 1),
                    "messages_per_hour": 10.0,
                    "unique_authors_per_hour": 5.0,
                    "moderation": False,
                    "captcha": False,
                    "status": "done",
                    "title": f"Active Chat {i}",
                    "chat_ref": chat_ref,
                },
            )

        # Add 2 dead chats with errors
        for i in [8, 9]:
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_result(
                group_id,
                chat_ref,
                {
                    "chat_type": "dead",
                    "subscribers": None,
                    "messages_per_hour": None,
                    "unique_authors_per_hour": None,
                    "moderation": None,
                    "captcha": None,
                    "status": "dead",
                    "title": None,
                    "chat_ref": chat_ref,
                    "error_reason": "ChannelPrivateError: Channel is private",
                },
            )

        # Verify: ALL 10 chats have results
        results = test_db.load_results(group_id)
        assert len(results) == 10, f"Expected 10 result rows, got {len(results)}"

        # Count done vs dead
        done_results = [r for r in results if r["metrics_data"]["status"] == "done"]
        dead_results = [r for r in results if r["metrics_data"]["status"] == "dead"]

        assert len(done_results) == 8, f"Expected 8 done chats, got {len(done_results)}"
        assert len(dead_results) == 2, f"Expected 2 dead chats, got {len(dead_results)}"

        # Verify dead chats have error reasons
        for result in dead_results:
            metrics = result["metrics_data"]
            assert metrics["chat_type"] == "dead", "Dead chat should have type=dead"
            assert "error_reason" in metrics, "Dead chat should have error_reason"
            assert "ChannelPrivateError" in metrics["error_reason"], "Should include error type"


class TestExportFiltersWithoutExcludeDead:
    """Test 5: Export filters work with dead type checkbox."""

    def test_export_filters_exclude_dead_via_chat_type(self) -> None:
        """Verify dead type checkbox removes dead chats from export results."""
        # Setup: Create mock results with mixed chat types
        results_data = [
            {
                "chat_ref": "https://t.me/chat1",
                "metrics_data": {
                    "chat_type": "group",
                    "subscribers": 500,
                    "messages_per_hour": 10.5,
                    "unique_authors_per_hour": 5.2,
                    "status": "done",
                    "title": "Active Group",
                },
            },
            {
                "chat_ref": "https://t.me/chat2",
                "metrics_data": {
                    "chat_type": "channel_no_comments",
                    "subscribers": 1000,
                    "messages_per_hour": None,
                    "unique_authors_per_hour": None,
                    "status": "done",
                    "title": "Channel",
                },
            },
            {
                "chat_ref": "https://t.me/chat3",
                "metrics_data": {
                    "chat_type": "dead",
                    "subscribers": None,
                    "messages_per_hour": None,
                    "unique_authors_per_hour": None,
                    "status": "dead",
                    "title": "Dead Chat",
                    "error_reason": "ChannelPrivateError: Channel is private",
                },
            },
            {
                "chat_ref": "https://t.me/chat4",
                "metrics_data": {
                    "chat_type": "dead",
                    "subscribers": None,
                    "messages_per_hour": None,
                    "unique_authors_per_hour": None,
                    "status": "dead",
                    "title": "Another Dead",
                    "error_reason": "FloodWaitError: Retry limit exceeded",
                },
            },
            {
                "chat_ref": "https://t.me/chat5",
                "metrics_data": {
                    "chat_type": "forum",
                    "subscribers": 300,
                    "messages_per_hour": 20.0,
                    "unique_authors_per_hour": 8.5,
                    "status": "done",
                    "title": "Forum",
                },
            },
        ]

        # Test 1: Filter WITH dead type (should include dead chats)
        filtered_with_dead = _apply_export_filters(
            results_data,
            chat_types="group,channel_no_comments,forum,dead",
        )
        assert len(filtered_with_dead) == 5, "Should include all chats when 'dead' is in chat_types"

        # Test 2: Filter WITHOUT dead type (should exclude dead chats)
        filtered_without_dead = _apply_export_filters(
            results_data,
            chat_types="group,channel_no_comments,forum",  # No 'dead'
        )
        assert len(filtered_without_dead) == 3, "Should exclude dead chats when 'dead' not in chat_types"

        # Verify only non-dead chats remain
        for result in filtered_without_dead:
            assert result["metrics_data"]["chat_type"] != "dead", "Dead chats should be filtered out"

        # Test 3: Filter ONLY dead chats
        filtered_only_dead = _apply_export_filters(
            results_data,
            chat_types="dead",
        )
        assert len(filtered_only_dead) == 2, "Should include only dead chats"

        for result in filtered_only_dead:
            assert result["metrics_data"]["chat_type"] == "dead", "Should only have dead chats"

    def test_export_filters_with_multiple_criteria(self) -> None:
        """Test combined filters: chat types + subscribers + activity."""
        results_data = [
            {
                "chat_ref": "https://t.me/chat1",
                "metrics_data": {
                    "chat_type": "group",
                    "subscribers": 500,
                    "messages_per_hour": 15.0,
                    "unique_authors_per_hour": 7.0,
                    "status": "done",
                },
            },
            {
                "chat_ref": "https://t.me/chat2",
                "metrics_data": {
                    "chat_type": "group",
                    "subscribers": 200,  # Below min
                    "messages_per_hour": 5.0,
                    "unique_authors_per_hour": 2.0,
                    "status": "done",
                },
            },
            {
                "chat_ref": "https://t.me/chat3",
                "metrics_data": {
                    "chat_type": "forum",
                    "subscribers": 1000,
                    "messages_per_hour": 25.0,
                    "unique_authors_per_hour": 12.0,
                    "status": "done",
                },
            },
            {
                "chat_ref": "https://t.me/chat4",
                "metrics_data": {
                    "chat_type": "dead",
                    "subscribers": None,
                    "messages_per_hour": None,
                    "unique_authors_per_hour": None,
                    "status": "dead",
                },
            },
        ]

        # Filter: group/forum + subscribers >= 300 + activity >= 10
        filtered = _apply_export_filters(
            results_data,
            chat_types="group,forum",
            subscribers_min=300,
            activity_min=10.0,
        )

        # Should match: chat1 (group, 500 subs, 15 msg/h) and chat3 (forum, 1000 subs, 25 msg/h)
        # Should exclude: chat2 (200 subs < 300), chat4 (dead)
        assert len(filtered) == 2, "Should match 2 chats with all criteria"

        refs = [r["chat_ref"] for r in filtered]
        assert "https://t.me/chat1" in refs
        assert "https://t.me/chat3" in refs


class TestAllChatsGetResultsGuarantee:
    """Integration tests for SPEC requirement: all chats get results (done or dead).

    SPEC v0.9.12 Must Have #1: Group with 143 chats → 143 results in group_results.
    No silent skips allowed.
    """

    @pytest.mark.asyncio
    async def test_all_chats_get_results_pass_or_dead(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that 143 chats produce 143 results (done or dead).

        Simulates mixed success/failure scenario:
        - 100 chats succeed
        - 43 chats fail (various errors: FloodWait timeout, network errors, etc.)
        - Verify: ALL 143 appear in group_results (status=done OR dead)
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine, _ResolvedChat
        from chatfilter.models.group import ChatTypeEnum

        # Setup: Create group with 143 chats
        group_id = "test-group-143"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=False,  # Phase 1 only
        )
        test_db.save_group(
            group_id=group_id,
            name="Test Group 143",
            settings=settings.model_dump(),
            status="pending",
        )

        # Add 143 chats to database
        for i in range(143):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type="pending",
                assigned_account="test-account",
                status=GroupChatStatus.PENDING.value,
            )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["test-account"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Track call count
        call_count = 0

        # Mock _resolve_chat to simulate mixed results:
        # - First 100 chats succeed
        # - Next 43 chats fail with various errors
        async def mock_resolve_chat(client, chat, account_id):
            nonlocal call_count
            call_count += 1
            chat_index = int(chat["chat_ref"].split("chat")[1])

            if chat_index < 100:
                # Success
                return _ResolvedChat(
                    db_chat_id=chat["id"],
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.GROUP.value,
                    title=f"Chat {chat_index}",
                    subscribers=100 + chat_index,
                    moderation=False,
                    numeric_id=1000000 + chat_index,
                    status="done",
                )
            else:
                # Fail with error
                error_types = [
                    "ChannelPrivateError: Channel is private",
                    "InviteHashExpiredError: Invite link expired",
                    "ConnectionError: Network error",
                ]
                error = error_types[chat_index % 3]
                return _ResolvedChat(
                    db_chat_id=chat["id"],
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.DEAD.value,
                    title=None,
                    subscribers=None,
                    moderation=None,
                    numeric_id=None,
                    status="dead",
                    error=error,
                )

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        # CRITICAL: __aexit__ must be async (returns awaitable), not None
        mock_session_context.__aexit__.return_value = asyncio.Future()
        mock_session_context.__aexit__.return_value.set_result(None)
        mock_session_manager.session.return_value = mock_session_context

        # Patch _resolve_chat AND asyncio.sleep to make test fast
        with (
            patch.object(engine, "_resolve_chat", side_effect=mock_resolve_chat),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            # Run Phase 1 analysis
            await engine._phase1_resolve_account(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                mode=AnalysisMode.FRESH,
            )

        # CRITICAL ASSERTION: ALL 143 chats must have results
        results = test_db.load_results(group_id)
        assert len(results) == 143, (
            f"SPEC VIOLATION: Expected 143 results for 143 chats, got {len(results)}. "
            f"Silent skips detected!"
        )

        # Verify status distribution
        done_results = [r for r in results if r["metrics_data"]["status"] == "done"]
        dead_results = [r for r in results if r["metrics_data"]["status"] == "dead"]

        assert len(done_results) == 100, f"Expected 100 successful chats, got {len(done_results)}"
        assert len(dead_results) == 43, f"Expected 43 dead chats, got {len(dead_results)}"

        # Verify all results have required fields
        for result in results:
            metrics = result["metrics_data"]
            assert "chat_type" in metrics, "Missing chat_type"
            assert "status" in metrics, "Missing status"
            assert metrics["status"] in ("done", "dead"), f"Invalid status: {metrics['status']}"

        # Verify dead chats have error_reason
        for result in dead_results:
            metrics = result["metrics_data"]
            assert "error_reason" in metrics, "Dead chat missing error_reason"
            assert metrics["chat_type"] == "dead", "Dead chat should have type=dead"

        # Verify _resolve_chat was called 143 times (no skips)
        assert call_count == 143, f"Expected 143 _resolve_chat calls, got {call_count}"

    @pytest.mark.asyncio
    async def test_floodwait_continues_processing_remaining_chats(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that FloodWait on chat #50 doesn't break the loop.

        Scenario:
        - 100 chats in group
        - Chat #50 triggers FloodWait (10s wait)
        - Verify: Remaining 50 chats processed after wait
        - Verify: No break from loop — all 100 get results
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine, _ResolvedChat
        from chatfilter.models.group import ChatTypeEnum

        # Setup: Create group with 100 chats
        group_id = "test-group-floodwait"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_moderation=False,
            detect_activity=False,
        )
        test_db.save_group(
            group_id=group_id,
            name="Test FloodWait Recovery",
            settings=settings.model_dump(),
            status="pending",
        )

        for i in range(100):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type="pending",
                assigned_account="test-account",
                status=GroupChatStatus.PENDING.value,
            )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["test-account"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Track calls
        call_count = 0
        floodwait_hit = False

        # Mock _resolve_chat to raise FloodWait on chat #50
        async def mock_resolve_chat(client, chat, account_id):
            nonlocal call_count, floodwait_hit
            call_count += 1
            chat_index = int(chat["chat_ref"].split("chat")[1])

            # Chat #50: Trigger FloodWait on FIRST attempt only
            if chat_index == 50 and not floodwait_hit:
                floodwait_hit = True
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 2  # 2 seconds wait (use low value for fast test)
                raise error

            # All others succeed
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                title=f"Chat {chat_index}",
                subscribers=100 + chat_index,
                moderation=False,
                numeric_id=1000000 + chat_index,
                status="done",
            )

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        # CRITICAL: __aexit__ must be async (returns awaitable), not None
        mock_session_context.__aexit__.return_value = asyncio.Future()
        mock_session_context.__aexit__.return_value.set_result(None)
        mock_session_manager.session.return_value = mock_session_context

        # Patch _resolve_chat AND asyncio.sleep to make test fast
        with (
            patch.object(engine, "_resolve_chat", side_effect=mock_resolve_chat),
            patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            # Run Phase 1 analysis
            await engine._phase1_resolve_account(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                mode=AnalysisMode.FRESH,
            )

            # Verify sleep was called with FloodWait duration
            assert mock_sleep.called, "FloodWait should trigger sleep"
            # sleep called with 2s + 10% buffer = 2.2s
            sleep_calls = [call.args[0] for call in mock_sleep.call_args_list]
            assert any(2.0 <= s <= 2.5 for s in sleep_calls), (
                f"Expected sleep(~2.2s) for FloodWait, got: {sleep_calls}"
            )

        # CRITICAL ASSERTION: ALL 100 chats processed despite FloodWait
        results = test_db.load_results(group_id)
        assert len(results) == 100, (
            f"FloodWait broke the loop! Expected 100 results, got {len(results)}. "
            f"Remaining chats were silently skipped."
        )

        # Verify all succeeded (including chat #50 after retry)
        done_results = [r for r in results if r["metrics_data"]["status"] == "done"]
        assert len(done_results) == 100, (
            f"Expected all 100 chats to succeed after FloodWait, got {len(done_results)}"
        )

        # Verify chat #50 is in results
        chat50_result = test_db.load_result(group_id, "https://t.me/chat50")
        assert chat50_result is not None, "Chat #50 missing from results after FloodWait"
        assert chat50_result["metrics_data"]["status"] == "done", (
            "Chat #50 should succeed after FloodWait retry"
        )

        # Verify FloodWait was hit
        assert floodwait_hit, "FloodWait scenario should have been triggered"

        # Verify _resolve_chat called 101 times (100 chats + 1 retry for chat #50)
        assert call_count == 101, (
            f"Expected 101 _resolve_chat calls (100 chats + 1 FloodWait retry), got {call_count}"
        )

    @pytest.mark.asyncio
    async def test_chat_saved_as_dead_after_max_retries(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that chat failing 3x is saved as status=dead with error_reason.

        Scenario:
        - Chat fails with network error
        - Retry 3x (MAX_RETRIES)
        - Verify: Saved as status=dead
        - Verify: error_reason populated
        - Verify: Result exists in group_results
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        # Setup: Create group with 1 chat
        group_id = "test-group-dead-after-retry"
        settings = GroupSettings(detect_subscribers=True, detect_activity=False)
        test_db.save_group(
            group_id=group_id,
            name="Test Dead After Retry",
            settings=settings.model_dump(),
            status="pending",
        )

        chat_ref = "https://t.me/failing_chat"
        test_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type="pending",
            assigned_account="test-account",
            status=GroupChatStatus.PENDING.value,
        )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["test-account"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Track retry attempts
        retry_count = 0

        # Mock _resolve_chat to ALWAYS fail with network error
        async def mock_resolve_chat(client, chat, account_id):
            nonlocal retry_count
            retry_count += 1
            raise ConnectionError("Network unreachable")

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        # CRITICAL: __aexit__ must be async (returns awaitable), not None
        mock_session_context.__aexit__.return_value = asyncio.Future()
        mock_session_context.__aexit__.return_value.set_result(None)
        mock_session_manager.session.return_value = mock_session_context

        # Patch _resolve_chat
        with patch.object(
            engine,
            "_resolve_chat",
            side_effect=mock_resolve_chat,
        ):
            # Run Phase 1 analysis
            await engine._phase1_resolve_account(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                mode=AnalysisMode.FRESH,
            )

        # Verify: Chat marked as FAILED in database
        failed_chats = test_db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.FAILED.value,
        )
        assert len(failed_chats) == 1, f"Expected 1 failed chat, got {len(failed_chats)}"

        # CRITICAL ASSERTION: Result exists in group_results (dead chat NOT skipped)
        result = test_db.load_result(group_id, chat_ref)
        assert result is not None, (
            "SPEC VIOLATION: Dead chat missing from group_results! "
            "All chats MUST have results."
        )

        # Verify result fields
        metrics = result["metrics_data"]
        assert metrics["status"] == "dead", f"Expected status=dead, got {metrics['status']}"
        assert metrics["chat_type"] == "dead", f"Expected chat_type=dead, got {metrics['chat_type']}"

        # Verify error_reason populated
        assert "error_reason" in metrics, "Dead chat missing error_reason field"
        error_reason = metrics["error_reason"]
        assert "Failed after 3 retries" in error_reason, (
            f"Error reason should mention retry limit: {error_reason}"
        )
        assert "ConnectionError" in error_reason, (
            f"Error reason should mention error type: {error_reason}"
        )

        # Verify retry count
        assert retry_count == 3, f"Expected 3 retry attempts, got {retry_count}"

    @pytest.mark.asyncio
    async def test_sse_progress_shows_retry_attempt(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that SSE progress events show retry attempt number.

        Scenario:
        - Chat fails, triggers retry
        - Verify: SSE message contains 'Retry 2/3 for @channel_name'
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        # Setup: Create group with 1 chat
        group_id = "test-group-sse-retry"
        settings = GroupSettings(detect_subscribers=True, detect_activity=False)
        test_db.save_group(
            group_id=group_id,
            name="Test SSE Retry",
            settings=settings.model_dump(),
            status="pending",
        )

        chat_ref = "https://t.me/retry_chat"
        test_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type="pending",
            assigned_account="test-account",
            status=GroupChatStatus.PENDING.value,
        )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["test-account"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Subscribe to SSE events
        event_queue = engine.subscribe(group_id)

        # Track retry attempts
        retry_count = 0

        # Mock _resolve_chat to fail 2x then succeed
        async def mock_resolve_chat(client, chat, account_id):
            nonlocal retry_count
            retry_count += 1
            if retry_count < 3:
                raise ConnectionError("Temporary network error")

            # Success on 3rd attempt
            from chatfilter.analyzer.group_engine import _ResolvedChat
            from chatfilter.models.group import ChatTypeEnum
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                title="Retry Chat",
                subscribers=500,
                moderation=False,
                numeric_id=1000001,
                status="done",
            )

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        # CRITICAL: __aexit__ must be async (returns awaitable), not None
        mock_session_context.__aexit__.return_value = asyncio.Future()
        mock_session_context.__aexit__.return_value.set_result(None)
        mock_session_manager.session.return_value = mock_session_context

        # Patch _resolve_chat
        with patch.object(
            engine,
            "_resolve_chat",
            side_effect=mock_resolve_chat,
        ):
            # Run Phase 1 analysis
            await engine._phase1_resolve_account(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                mode=AnalysisMode.FRESH,
            )

        # Collect all SSE events
        events = []
        while not event_queue.empty():
            events.append(await event_queue.get())

        # Verify: At least one retry event exists
        retry_events = [
            e for e in events
            if e.message and "Retry" in e.message
        ]
        assert len(retry_events) >= 1, (
            f"Expected at least 1 retry event in SSE, got {len(retry_events)}. "
            f"Events: {[e.message for e in events]}"
        )

        # Verify retry message format: "Retry X/3 for @channel_name"
        retry_messages = [e.message for e in retry_events]
        assert any("Retry 2/3" in msg for msg in retry_messages), (
            f"Expected 'Retry 2/3' in SSE messages, got: {retry_messages}"
        )
        assert any("retry_chat" in msg for msg in retry_messages), (
            f"Expected chat_ref in retry message, got: {retry_messages}"
        )

        # Verify final success
        assert retry_count == 3, f"Expected 3 attempts, got {retry_count}"
        result = test_db.load_result(group_id, chat_ref)
        assert result is not None, "Chat should have result after retry success"
        assert result["metrics_data"]["status"] == "done", "Chat should succeed after retries"




class TestExceptionRecoveryPaths:
    """Tests for the 3 exception recovery paths added in ChatFilter-dpfke.

    Recovery Path 1: Outer exception handler in _phase1_resolve_account (lines 744-776)
    Recovery Path 2: Account task exception handler in start_analysis (lines 307-341)
    Recovery Path 3: Orphan safety net after Phase 1 (lines 343-383)
    """

    @pytest.mark.asyncio
    async def test_outer_exception_handler_saves_remaining_chats(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test outer exception handler: session context manager raises exception.

        Scenario:
        - Group with 5 chats assigned to account
        - Mock session context manager to raise exception  
        - Verify: Outer exception handler saves dead records for ALL remaining PENDING chats

        This tests lines 744-776 in group_engine.py (Feature 1).
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        # Setup: Create group with 5 chats
        group_id = "test-group-outer-exception"
        settings = GroupSettings(detect_subscribers=True, detect_activity=False)
        test_db.save_group(
            group_id=group_id,
            name="Test Outer Exception Handler",
            settings=settings.model_dump(),
            status="pending",
        )

        # Add 5 chats
        for i in range(5):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type="pending",
                assigned_account="test-account",
                status=GroupChatStatus.PENDING.value,
            )

        # Mock session manager
        mock_session_manager = MagicMock()

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Mock session context manager to raise exception in __aenter__
        # This will be caught by the outer exception handler (lines 744-776)
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.side_effect = RuntimeError("Session context error")
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Run _phase1_resolve_account (should catch exception in outer handler)
        await engine._phase1_resolve_account(
            group_id=group_id,
            account_id="test-account",
            settings=settings,
            mode=AnalysisMode.FRESH,
        )

        # CRITICAL ASSERTION: ALL 5 chats must have results
        results = test_db.load_results(group_id)
        assert len(results) == 5, (
            f"Outer exception handler failed! Expected 5 results for 5 chats, got {len(results)}. "
            f"Remaining chats were not saved."
        )

        # Verify: All chats are dead with "Account error" message
        dead_results = [r for r in results if r["metrics_data"]["status"] == "dead"]
        assert len(dead_results) == 5, f"Expected 5 dead chats from outer handler, got {len(dead_results)}"

        # Verify dead chats have proper error message
        for result in dead_results:
            metrics = result["metrics_data"]
            assert metrics["chat_type"] == "dead", "Dead chat should have type=dead"
            assert "error_reason" in metrics, "Dead chat missing error_reason"
            assert "Account error" in metrics["error_reason"], (
                f"Error reason should mention 'Account error', got: {metrics['error_reason']}"
            )
            assert "Session context error" in metrics["error_reason"], (
                f"Error reason should include original error message, got: {metrics['error_reason']}"
            )

        # Verify chats marked as FAILED
        failed_chats = test_db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.FAILED.value,
        )
        assert len(failed_chats) == 5, f"Expected 5 failed chats, got {len(failed_chats)}"


    @pytest.mark.asyncio
    async def test_account_task_exception_saves_dead_results(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test account task exception handler: _phase1_resolve_account raises immediately.

        Scenario:
        - Group with 5 chats assigned to account
        - Mock _phase1_resolve_account to raise exception directly
        - Verify: start_analysis() safety net saves dead records for all account chats

        This tests lines 307-341 in group_engine.py.
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        # Setup: Create group with 5 chats
        group_id = "test-group-account-task-exception"
        settings = GroupSettings(detect_subscribers=True, detect_activity=False)
        test_db.save_group(
            group_id=group_id,
            name="Test Account Task Exception",
            settings=settings.model_dump(),
            status="pending",
        )

        # Add 5 chats
        for i in range(5):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type="pending",
                assigned_account="test-account",
                status=GroupChatStatus.PENDING.value,
            )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["test-account"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Mock _phase1_resolve_account to raise exception immediately
        async def mock_phase1_exception(*args, **kwargs):
            raise ValueError("Account task failed immediately")

        # Patch _phase1_resolve_account to raise exception
        with patch.object(
            engine,
            "_phase1_resolve_account",
            side_effect=mock_phase1_exception,
        ):
            # Run start_analysis (should handle exception via account task handler)
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # CRITICAL ASSERTION: ALL 5 chats must have results
        results = test_db.load_results(group_id)
        assert len(results) == 5, (
            f"Account task exception handler failed! Expected 5 results for 5 chats, got {len(results)}. "
            f"Safety net did not save dead records."
        )

        # Verify: All chats are dead with "Account task exception" message
        dead_results = [r for r in results if r["metrics_data"]["status"] == "dead"]
        assert len(dead_results) == 5, f"Expected 5 dead chats from account task handler, got {len(dead_results)}"

        # Verify dead chats have proper error message
        for result in dead_results:
            metrics = result["metrics_data"]
            assert metrics["chat_type"] == "dead", "Dead chat should have type=dead"
            assert "error_reason" in metrics, "Dead chat missing error_reason"
            assert "Account task exception" in metrics["error_reason"], (
                f"Error reason should mention 'Account task exception', got: {metrics['error_reason']}"
            )
            assert "Account task failed immediately" in metrics["error_reason"], (
                f"Error reason should include original error message, got: {metrics['error_reason']}"
            )

    @pytest.mark.asyncio
    async def test_orphan_safety_net_fills_missing_results(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test orphan safety net: detects chats without results after Phase 1.

        Scenario:
        - Group with 8 chats
        - After Phase 1, manually delete 3 group_results records
        - Verify: Safety net detects and fills missing results with dead records

        This tests lines 343-383 in group_engine.py.
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine, _ResolvedChat
        from chatfilter.models.group import ChatTypeEnum

        # Setup: Create group with 8 chats
        group_id = "test-group-orphan-safety-net"
        settings = GroupSettings(detect_subscribers=True, detect_activity=False)
        test_db.save_group(
            group_id=group_id,
            name="Test Orphan Safety Net",
            settings=settings.model_dump(),
            status="pending",
        )

        # Add 8 chats
        for i in range(8):
            chat_ref = f"https://t.me/chat{i}"
            test_db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type="pending",
                assigned_account="test-account",
                status=GroupChatStatus.PENDING.value,
            )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["test-account"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Mock _resolve_chat to succeed for all chats
        async def mock_resolve_chat(client, chat, account_id):
            chat_index = int(chat["chat_ref"].split("chat")[1])
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                title=f"Chat {chat_index}",
                subscribers=100 + chat_index,
                moderation=False,
                numeric_id=1000000 + chat_index,
                status="done",
            )

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        # CRITICAL: __aexit__ must be async (returns awaitable), not None
        mock_session_context.__aexit__.return_value = asyncio.Future()
        mock_session_context.__aexit__.return_value.set_result(None)
        mock_session_manager.session.return_value = mock_session_context

        # First: Run Phase 1 normally (all chats get results)
        # CRITICAL: Mock asyncio.sleep to avoid rate-limiting delays (tests would timeout)
        with patch.object(
            engine,
            "_resolve_chat",
            side_effect=mock_resolve_chat,
        ), patch("asyncio.sleep", return_value=asyncio.Future()):
            # Set mock sleep to complete immediately
            asyncio.sleep.return_value.set_result(None)

            await engine._phase1_resolve_account(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                mode=AnalysisMode.FRESH,
            )

        # Verify all 8 chats have results
        results_before = test_db.load_results(group_id)
        assert len(results_before) == 8, f"Expected 8 results after Phase 1, got {len(results_before)}"

        # SIMULATE ORPHAN SCENARIO: Delete 3 group_results records manually
        # This simulates a bug where some results didn't get saved
        orphan_chat_refs = ["https://t.me/chat2", "https://t.me/chat5", "https://t.me/chat7"]
        with test_db._connection() as conn:
            for chat_ref in orphan_chat_refs:
                # Delete result from group_results table (simulating missing result)
                conn.execute(
                    "DELETE FROM group_results WHERE group_id = ? AND chat_ref = ?",
                    (group_id, chat_ref),
                )
            conn.commit()

        # Verify orphans created
        results_after_delete = test_db.load_results(group_id)
        assert len(results_after_delete) == 5, (
            f"Expected 5 results after deleting 3, got {len(results_after_delete)}"
        )

        # Mark one chat as FAILED so start_analysis continues past early return
        all_chats = test_db.load_chats(group_id=group_id)
        chat0 = [c for c in all_chats if c["chat_ref"] == "https://t.me/chat0"][0]
        test_db.update_chat_status(
            chat_id=chat0["id"],
            status=GroupChatStatus.FAILED.value,
            error="Simulated failure for test",
        )

        # Now run start_analysis again to trigger orphan safety net
        # There's 1 FAILED chat, so start_analysis will continue and safety net will run
        # IMPORTANT: Mock _phase1_resolve_account to avoid hanging on real telethon calls
        async def mock_phase1_no_op(group_id, account_id, settings, mode):
            """No-op Phase 1 — we already have 1 FAILED chat (chat0) that will be reset.

            start_analysis will:
            1. Reset FAILED→PENDING (chat0)
            2. Call _phase1_resolve_account (this mock — does nothing)
            3. Run safety net which fills missing results for orphans
            """
            pass

        with patch.object(
            engine,
            "_phase1_resolve_account",
            side_effect=mock_phase1_no_op,
        ), patch("asyncio.sleep", return_value=asyncio.Future()):
            # Mock sleep for second invocation too
            asyncio.sleep.return_value.set_result(None)
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # CRITICAL ASSERTION: ALL 8 chats must have results again
        results_after_safety_net = test_db.load_results(group_id)
        assert len(results_after_safety_net) == 8, (
            f"Orphan safety net failed! Expected 8 results for 8 chats, got {len(results_after_safety_net)}. "
            f"Safety net did not detect or fill orphans."
        )

        # Verify: Orphaned chats have dead records with "Orphan safety net" message
        for chat_ref in orphan_chat_refs:
            result = test_db.load_result(group_id, chat_ref)
            assert result is not None, f"Orphan chat {chat_ref} still missing result"

            metrics = result["metrics_data"]
            assert metrics["status"] == "dead", (
                f"Orphan chat {chat_ref} should be marked as dead, got {metrics['status']}"
            )
            assert metrics["chat_type"] == "dead", (
                f"Orphan chat {chat_ref} should have type=dead, got {metrics['chat_type']}"
            )
            assert "error_reason" in metrics, f"Orphan chat {chat_ref} missing error_reason"
            assert "Orphan safety net" in metrics["error_reason"], (
                f"Error reason should mention 'Orphan safety net', got: {metrics['error_reason']}"
            )
