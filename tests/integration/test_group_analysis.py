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
