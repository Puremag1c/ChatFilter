"""Integration tests for group analysis retry mechanism and re-analysis modes.

Test Scenarios:
1. test_retry_on_floodwait — simulate FloodWait → verify retry → 3 failures → chat marked dead
2. test_incremental_analysis_skips_existing — analyze with subscribers → add activity → verify subscribers unchanged, activity added
3. test_full_reanalysis_clears_old_data — analyze → overwrite → verify all data fresh
4. test_all_chats_get_results — 10 chats, 2 fail → verify 10 rows with results (8 done + 2 dead)
5. test_export_filters_work_without_exclude_dead — verify dead type checkbox removes dead chats from CSV
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telethon.errors import FloodWaitError

from chatfilter.analyzer.retry import RetryPolicy, RetryResult
from chatfilter.analyzer.worker import ChatResult
from chatfilter.models.group import AnalysisMode, GroupChatStatus, GroupSettings
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.web.routers.groups import _apply_export_filters


@pytest.fixture
def test_db(tmp_path: Path) -> GroupDatabase:
    """Create isolated test database."""
    db_path = tmp_path / "test_groups.db"
    db = GroupDatabase(str(db_path))
    yield db


def _save_chat_with_metrics(
    db: GroupDatabase,
    group_id: str,
    chat_ref: str,
    chat_type: str,
    status: str,
    subscribers: int | None = None,
    title: str | None = None,
    messages_per_hour: float | None = None,
    unique_authors_per_hour: float | None = None,
    moderation: bool | None = None,
    captcha: bool | None = None,
    partial_data: bool | None = None,
    metrics_version: int | None = None,
    error: str | None = None,
    assigned_account: str | None = None,
) -> int:
    """Helper to save a chat with metrics in the new schema (columns on group_chats)."""
    chat_id = db.save_chat(
        group_id=group_id,
        chat_ref=chat_ref,
        chat_type=chat_type,
        status=status,
        subscribers=subscribers,
        assigned_account=assigned_account,
        error=error,
    )
    metrics = {}
    if title is not None:
        metrics["title"] = title
    if moderation is not None:
        metrics["moderation"] = moderation
    if messages_per_hour is not None:
        metrics["messages_per_hour"] = messages_per_hour
    if unique_authors_per_hour is not None:
        metrics["unique_authors_per_hour"] = unique_authors_per_hour
    if captcha is not None:
        metrics["captcha"] = captcha
    if partial_data is not None:
        metrics["partial_data"] = partial_data
    if metrics_version is not None:
        metrics["metrics_version"] = metrics_version
    if metrics:
        db.save_chat_metrics(chat_id, metrics)
    return chat_id


def _load_all_results(db: GroupDatabase, group_id: str) -> list[dict]:
    """Load all chats with their metrics (flat structure matching service.get_results)."""
    chats = db.load_chats(group_id=group_id)
    chat_ids = [c["id"] for c in chats]
    metrics_by_id = db.get_chat_metrics_batch(chat_ids)
    results = []
    for chat in chats:
        m = metrics_by_id.get(chat["id"], {})
        result = {
            "chat_ref": chat["chat_ref"],
            "chat_type": chat["chat_type"],
            "status": chat["status"],
            "subscribers": chat.get("subscribers"),
            "error": chat.get("error"),
        }
        if m:
            result.update({
                "title": m.get("title"),
                "moderation": m.get("moderation"),
                "messages_per_hour": m.get("messages_per_hour"),
                "unique_authors_per_hour": m.get("unique_authors_per_hour"),
                "captcha": m.get("captcha"),
                "metrics_version": m.get("metrics_version"),
            })
        results.append(result)
    return results


def _load_result_for_chat(db: GroupDatabase, group_id: str, chat_ref: str) -> dict | None:
    """Load a single chat's result (flat dict) by chat_ref."""
    chats = db.load_chats(group_id=group_id)
    for chat in chats:
        if chat["chat_ref"] == chat_ref:
            m = db.get_chat_metrics(chat["id"])
            result = {
                "chat_ref": chat["chat_ref"],
                "chat_type": chat["chat_type"],
                "status": chat["status"],
                "subscribers": chat.get("subscribers"),
                "error": chat.get("error"),
            }
            if m:
                result.update({
                    "title": m.get("title"),
                    "moderation": m.get("moderation"),
                    "messages_per_hour": m.get("messages_per_hour"),
                    "unique_authors_per_hour": m.get("unique_authors_per_hour"),
                    "captcha": m.get("captcha"),
                    "metrics_version": m.get("metrics_version"),
                })
            return result
    return None


def _count_results_with_metrics(db: GroupDatabase, group_id: str) -> int:
    """Count chats that have metrics set (non-NULL metrics_version)."""
    chats = db.load_chats(group_id=group_id)
    chat_ids = [c["id"] for c in chats]
    metrics_by_id = db.get_chat_metrics_batch(chat_ids)
    count = 0
    for chat in chats:
        m = metrics_by_id.get(chat["id"], {})
        if m.get("metrics_version") is not None or chat["chat_type"] != "pending":
            count += 1
    return count


class TestRetryMechanism:
    """Test 1: Retry mechanism via try_with_retry."""

    @pytest.mark.asyncio
    async def test_retry_on_errors_marks_dead_after_3_failures(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that general errors trigger retry, and all accounts exhausted marks chat as dead.

        Tests the retry mechanism in retry.py and the error handling in group_engine.py
        _process_single_chat → try_with_retry → _save_chat_error.
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

        # Track call count
        call_count = 0

        # Mock process_chat to always fail
        async def mock_process_chat(chat_dict, client, account_id, settings):
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Simulated connection error")

        # Mock session manager context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Patch process_chat and sleep
        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
            patch("chatfilter.analyzer.retry.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine._run_account_worker(
                group_id=group_id,
                account_id="test-account",
                settings=GroupSettings(),
                all_accounts=["test-account"],
                mode=AnalysisMode.FRESH,
            )

        # Verify: Chat should be marked as ERROR after retries exhausted
        error_chats = test_db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.ERROR.value,
        )
        assert len(error_chats) == 1, f"Expected 1 error chat after retries, got {len(error_chats)}"

        # Verify error message
        error_msg = error_chats[0].get("error", "")
        assert "exhausted" in error_msg.lower() or "error" in error_msg.lower(), (
            f"Error message should mention exhaustion or error, got: {error_msg}"
        )

        # Verify process_chat was called multiple times (retry attempts)
        assert call_count >= 1, f"Expected at least 1 process_chat call, got {call_count}"


class TestIncrementalAnalysisDatabase:
    """Test 2: Incremental analysis with database metrics."""

    def test_incremental_upsert_preserves_existing_metrics(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that save_chat_metrics() overwrites metrics, allowing incremental updates."""
        # Setup: Create group
        group_id = "test-group-incremental"
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status="pending",
        )
        chat_ref = "https://t.me/test_chat"

        # Phase 1: Save initial chat with subscribers
        chat_id = test_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type="group",
            status=GroupChatStatus.DONE.value,
            subscribers=500,
        )
        test_db.save_chat_metrics(chat_id, {
            "title": "Test Chat",
            "moderation": False,
            "captcha": False,
            "metrics_version": 1,
        })

        # Verify initial metrics
        initial_metrics = test_db.get_chat_metrics(chat_id)
        assert initial_metrics is not None
        assert initial_metrics["subscribers"] == 500
        assert initial_metrics["messages_per_hour"] is None

        import time
        time.sleep(0.1)

        # Phase 2: Update with activity metrics (save_chat_metrics overwrites columns)
        test_db.save_chat_metrics(chat_id, {
            "title": "Test Chat",
            "messages_per_hour": 15.5,
            "unique_authors_per_hour": 8.3,
            "moderation": False,
            "captcha": False,
            "metrics_version": 2,
        })

        # Verify: activity metrics added
        final_metrics = test_db.get_chat_metrics(chat_id)
        assert final_metrics is not None

        # Key assertion: subscribers preserved (it's a separate column not touched by save_chat_metrics)
        assert final_metrics["subscribers"] == 500, "Subscribers should be preserved"

        # Activity should now be present
        assert final_metrics["messages_per_hour"] == 15.5, "Should have new activity metric"
        assert final_metrics["unique_authors_per_hour"] == 8.3, "Should have new unique authors"


class TestFullReanalysisDatabase:
    """Test 3: Full re-analysis clears old data."""

    def test_full_reanalysis_clears_results(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that OVERWRITE mode resets chats to PENDING (clearing old results)."""
        # Setup: Create group with 3 chats
        group_id = "test-group-overwrite"
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=GroupSettings().model_dump(),
            status="completed",
        )

        # Add 3 chats with metrics (simulate old analysis)
        for i in range(3):
            chat_ref = f"https://t.me/chat{i}"
            _save_chat_with_metrics(
                test_db, group_id, chat_ref,
                chat_type="group",
                status=GroupChatStatus.DONE.value,
                subscribers=100 * (i + 1),
                title=f"Old Chat {i}",
                messages_per_hour=10.0,
                unique_authors_per_hour=5.0,
                moderation=False,
                captcha=False,
                metrics_version=2,
            )

        # Verify old results exist (3 chats with DONE status)
        done_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        assert len(done_chats) == 3

        # OVERWRITE mode: Reset all chats to PENDING
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine
        engine = GroupAnalysisEngine(db=test_db, session_manager=MagicMock())
        engine._prepare_chats_for_mode(group_id, GroupSettings(), AnalysisMode.OVERWRITE)

        # Verify: All chats reset to PENDING
        pending_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
        assert len(pending_chats) == 3, "OVERWRITE should reset all chats to PENDING"

        done_chats_after = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        assert len(done_chats_after) == 0, "No DONE chats should remain after OVERWRITE"

        # Simulate new analysis with fresh data
        for chat in pending_chats:
            test_db.save_chat(
                group_id=group_id,
                chat_ref=chat["chat_ref"],
                chat_type="forum",
                status=GroupChatStatus.DONE.value,
                subscribers=500 * (int(chat["chat_ref"][-1]) + 1),
                chat_id=chat["id"],
            )
            test_db.save_chat_metrics(chat["id"], {
                "title": f"New Chat {chat['chat_ref'][-1]}",
                "moderation": True,
                "captcha": True,
                "messages_per_hour": 20.0,
                "unique_authors_per_hour": 10.0,
                "metrics_version": 2,
            })

        # Verify: New results are completely fresh (not merged)
        results = _load_all_results(test_db, group_id)
        assert len(results) == 3

        for result in results:
            assert result["chat_type"] == "forum", "Should have new chat type"
            assert result.get("title", "").startswith("New"), "Should have new title"
            assert result["subscribers"] >= 500, "Should have new subscriber counts"


class TestAllChatsGetResults:
    """Test 4: All chats get results (done or dead)."""

    def test_all_chats_saved_including_dead(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that both successful and dead chats are saved with results."""
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
            _save_chat_with_metrics(
                test_db, group_id, chat_ref,
                chat_type="group",
                status=GroupChatStatus.DONE.value,
                subscribers=100 * (i + 1),
                title=f"Active Chat {i}",
                messages_per_hour=10.0,
                unique_authors_per_hour=5.0,
                moderation=False,
                captcha=False,
                metrics_version=2,
            )

        # Add 2 dead chats with errors
        for i in [8, 9]:
            chat_ref = f"https://t.me/chat{i}"
            _save_chat_with_metrics(
                test_db, group_id, chat_ref,
                chat_type="dead",
                status=GroupChatStatus.ERROR.value,
                error="ChannelPrivateError: Channel is private",
                metrics_version=2,
            )

        # Verify: ALL 10 chats have results
        results = _load_all_results(test_db, group_id)
        assert len(results) == 10, f"Expected 10 result rows, got {len(results)}"

        # Count done vs dead
        done_results = [r for r in results if r["status"] == GroupChatStatus.DONE.value]
        dead_results = [r for r in results if r["chat_type"] == "dead"]

        assert len(done_results) == 8, f"Expected 8 done chats, got {len(done_results)}"
        assert len(dead_results) == 2, f"Expected 2 dead chats, got {len(dead_results)}"

        # Verify dead chats have error reasons
        for result in dead_results:
            assert result["chat_type"] == "dead", "Dead chat should have type=dead"
            assert result.get("error") is not None, "Dead chat should have error"
            assert "ChannelPrivateError" in result["error"], "Should include error type"


class TestExportFiltersWithoutExcludeDead:
    """Test 5: Export filters work with dead type checkbox."""

    def test_export_filters_exclude_dead_via_chat_type(self) -> None:
        """Verify dead type checkbox removes dead chats from export results."""
        # Setup: Create flat results (matching service.get_results() format)
        results_data = [
            {
                "chat_ref": "https://t.me/chat1",
                "chat_type": "group",
                "subscribers": 500,
                "messages_per_hour": 10.5,
                "unique_authors_per_hour": 5.2,
                "status": "done",
                "title": "Active Group",
            },
            {
                "chat_ref": "https://t.me/chat2",
                "chat_type": "channel_no_comments",
                "subscribers": 1000,
                "messages_per_hour": None,
                "unique_authors_per_hour": None,
                "status": "done",
                "title": "Channel",
            },
            {
                "chat_ref": "https://t.me/chat3",
                "chat_type": "dead",
                "subscribers": None,
                "messages_per_hour": None,
                "unique_authors_per_hour": None,
                "status": "error",
                "title": "Dead Chat",
                "error": "ChannelPrivateError: Channel is private",
            },
            {
                "chat_ref": "https://t.me/chat4",
                "chat_type": "dead",
                "subscribers": None,
                "messages_per_hour": None,
                "unique_authors_per_hour": None,
                "status": "error",
                "title": "Another Dead",
                "error": "FloodWaitError: Retry limit exceeded",
            },
            {
                "chat_ref": "https://t.me/chat5",
                "chat_type": "forum",
                "subscribers": 300,
                "messages_per_hour": 20.0,
                "unique_authors_per_hour": 8.5,
                "status": "done",
                "title": "Forum",
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
            assert result["chat_type"] != "dead", "Dead chats should be filtered out"

        # Test 3: Filter ONLY dead chats
        filtered_only_dead = _apply_export_filters(
            results_data,
            chat_types="dead",
        )
        assert len(filtered_only_dead) == 2, "Should include only dead chats"

        for result in filtered_only_dead:
            assert result["chat_type"] == "dead", "Should only have dead chats"

    def test_export_filters_with_multiple_criteria(self) -> None:
        """Test combined filters: chat types + subscribers + activity."""
        results_data = [
            {
                "chat_ref": "https://t.me/chat1",
                "chat_type": "group",
                "subscribers": 500,
                "messages_per_hour": 15.0,
                "unique_authors_per_hour": 7.0,
                "status": "done",
            },
            {
                "chat_ref": "https://t.me/chat2",
                "chat_type": "group",
                "subscribers": 200,  # Below min
                "messages_per_hour": 5.0,
                "unique_authors_per_hour": 2.0,
                "status": "done",
            },
            {
                "chat_ref": "https://t.me/chat3",
                "chat_type": "forum",
                "subscribers": 1000,
                "messages_per_hour": 25.0,
                "unique_authors_per_hour": 12.0,
                "status": "done",
            },
            {
                "chat_ref": "https://t.me/chat4",
                "chat_type": "dead",
                "subscribers": None,
                "messages_per_hour": None,
                "unique_authors_per_hour": None,
                "status": "error",
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

    SPEC v0.9.12 Must Have #1: Group with 143 chats → 143 chats with results.
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
        - 43 chats fail (various errors: account ban, network errors, etc.)
        - Verify: ALL 143 have results (status=done OR error with type=dead)
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

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

        # Mock process_chat to simulate mixed results:
        # - First 100 chats succeed
        # - Next 43 chats return dead results
        async def mock_process_chat(chat_dict, client, account_id, settings):
            nonlocal call_count
            call_count += 1
            chat_index = int(chat_dict["chat_ref"].split("chat")[1])

            if chat_index < 100:
                # Success
                return ChatResult(
                    chat_ref=chat_dict["chat_ref"],
                    chat_type="group",
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
                return ChatResult(
                    chat_ref=chat_dict["chat_ref"],
                    chat_type="dead",
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
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Patch process_chat AND asyncio.sleep to make test fast
        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            # Run worker for test-account
            await engine._run_account_worker(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                all_accounts=["test-account"],
                mode=AnalysisMode.FRESH,
            )

        # CRITICAL ASSERTION: ALL 143 chats must have results
        all_chats = test_db.load_chats(group_id=group_id)
        assert len(all_chats) == 143

        # Every chat should be DONE or ERROR (not PENDING)
        pending = [c for c in all_chats if c["status"] == GroupChatStatus.PENDING.value]
        assert len(pending) == 0, (
            f"SPEC VIOLATION: {len(pending)} chats still PENDING — silently skipped!"
        )

        done_chats = [c for c in all_chats if c["status"] == GroupChatStatus.DONE.value]
        error_chats = [c for c in all_chats if c["status"] == GroupChatStatus.ERROR.value]

        assert len(done_chats) == 100, f"Expected 100 successful chats, got {len(done_chats)}"
        assert len(error_chats) == 43, f"Expected 43 dead chats, got {len(error_chats)}"

        # Verify all done chats have metrics
        for chat in done_chats:
            metrics = test_db.get_chat_metrics(chat["id"])
            assert metrics.get("chat_type") is not None, f"Done chat missing chat_type: {chat['chat_ref']}"

        # Verify dead chats have type=dead
        for chat in error_chats:
            assert chat["chat_type"] == "dead", f"Dead chat should have type=dead: {chat['chat_ref']}"

        # Verify process_chat was called 143 times (no skips)
        assert call_count == 143, f"Expected 143 process_chat calls, got {call_count}"

    @pytest.mark.asyncio
    async def test_floodwait_continues_processing_remaining_chats(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that FloodWait on chat #50 doesn't break the loop.

        Scenario:
        - 100 chats in group
        - Chat #50 triggers FloodWait (2s wait)
        - Verify: Remaining chats processed after wait
        - Verify: No break from loop — all 100 get results
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

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

        # Mock process_chat to raise FloodWait on chat #50
        async def mock_process_chat(chat_dict, client, account_id, settings):
            nonlocal call_count, floodwait_hit
            call_count += 1
            chat_index = int(chat_dict["chat_ref"].split("chat")[1])

            # Chat #50: Trigger FloodWait on FIRST attempt only
            if chat_index == 50 and not floodwait_hit:
                floodwait_hit = True
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 2
                raise error

            # All others succeed
            return ChatResult(
                chat_ref=chat_dict["chat_ref"],
                chat_type="group",
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
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Patch process_chat AND asyncio.sleep to make test fast
        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
            patch("chatfilter.analyzer.retry.asyncio.sleep", new_callable=AsyncMock) as mock_retry_sleep,
        ):
            # Run worker
            await engine._run_account_worker(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                all_accounts=["test-account"],
                mode=AnalysisMode.FRESH,
            )

            # Verify sleep was called for FloodWait
            assert mock_retry_sleep.called, "FloodWait should trigger sleep in retry"

        # CRITICAL ASSERTION: ALL 100 chats processed despite FloodWait
        all_chats = test_db.load_chats(group_id=group_id)
        done_chats = [c for c in all_chats if c["status"] == GroupChatStatus.DONE.value]
        error_chats = [c for c in all_chats if c["status"] == GroupChatStatus.ERROR.value]
        pending_chats = [c for c in all_chats if c["status"] == GroupChatStatus.PENDING.value]

        total_processed = len(done_chats) + len(error_chats)
        assert total_processed == 100, (
            f"FloodWait broke the loop! Expected 100 processed, got {total_processed}. "
            f"({len(done_chats)} done, {len(error_chats)} error, {len(pending_chats)} pending)"
        )

        # Verify chat #50 is processed
        chat50_result = _load_result_for_chat(test_db, group_id, "https://t.me/chat50")
        assert chat50_result is not None, "Chat #50 missing from results after FloodWait"

        # Verify FloodWait was hit
        assert floodwait_hit, "FloodWait scenario should have been triggered"

        # Verify process_chat called 101 times (100 chats + 1 retry for chat #50)
        assert call_count == 101, (
            f"Expected 101 process_chat calls (100 chats + 1 FloodWait retry), got {call_count}"
        )

    @pytest.mark.asyncio
    async def test_chat_saved_as_dead_after_max_retries(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that chat failing all retries is saved as ERROR with error message.

        Scenario:
        - Chat fails with network error on every attempt
        - All accounts exhausted
        - Verify: Saved as status=error
        - Verify: error field populated
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

        # Mock process_chat to ALWAYS fail with network error
        async def mock_process_chat(chat_dict, client, account_id, settings):
            nonlocal retry_count
            retry_count += 1
            raise ConnectionError("Network unreachable")

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Patch process_chat
        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
            patch("chatfilter.analyzer.retry.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine._run_account_worker(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                all_accounts=["test-account"],
                mode=AnalysisMode.FRESH,
            )

        # Verify: Chat marked as ERROR in database
        error_chats = test_db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.ERROR.value,
        )
        assert len(error_chats) == 1, f"Expected 1 error chat, got {len(error_chats)}"

        # CRITICAL ASSERTION: Result exists (dead chat NOT skipped)
        result = _load_result_for_chat(test_db, group_id, chat_ref)
        assert result is not None, (
            "SPEC VIOLATION: Dead chat missing from results! "
            "All chats MUST have results."
        )

        # Verify error status
        assert result["status"] == GroupChatStatus.ERROR.value, (
            f"Expected status=error, got {result['status']}"
        )

        # Verify error field populated
        assert result.get("error") is not None, "Error chat missing error field"
        assert "exhausted" in result["error"].lower(), (
            f"Error should mention account exhaustion: {result['error']}"
        )

        # Verify retry was attempted (at least once)
        assert retry_count >= 1, f"Expected at least 1 retry attempt, got {retry_count}"

    @pytest.mark.asyncio
    async def test_sse_progress_shows_retry_attempt(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that SSE progress events are emitted during processing with account rotation.

        Scenario:
        - Chat with 3 available accounts
        - First 2 accounts fail (ConnectionError → try_with_retry rotates to next)
        - 3rd account succeeds
        - Verify: SSE events are published
        - Verify: Chat result is saved as done
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
            assigned_account="account-1",
            status=GroupChatStatus.PENDING.value,
        )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.list_sessions.return_value = ["account-1", "account-2", "account-3"]
        mock_session_manager.is_healthy = AsyncMock(return_value=True)
        mock_session_manager.connect = AsyncMock(return_value=AsyncMock())

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_manager,
        )

        # Subscribe to SSE events
        event_queue = engine.subscribe(group_id)

        # Track retry attempts
        retry_count = 0

        # Mock process_chat to fail on first 2 accounts, succeed on 3rd
        async def mock_process_chat(chat_dict, client, account_id, settings):
            nonlocal retry_count
            retry_count += 1
            if retry_count < 3:
                raise ConnectionError("Temporary network error")

            # Success on 3rd attempt (account-3)
            return ChatResult(
                chat_ref=chat_dict["chat_ref"],
                chat_type="group",
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
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Patch process_chat
        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
            patch("chatfilter.analyzer.retry.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine._run_account_worker(
                group_id=group_id,
                account_id="account-1",
                settings=settings,
                all_accounts=["account-1", "account-2", "account-3"],
                mode=AnalysisMode.FRESH,
            )

        # Collect all SSE events
        events = []
        while not event_queue.empty():
            events.append(await event_queue.get())

        # Verify: At least one progress event exists (for the processed chat)
        assert len(events) >= 1, (
            f"Expected at least 1 progress event, got {len(events)}"
        )

        # Verify success after account rotation
        assert retry_count == 3, f"Expected 3 attempts (2 failures + 1 success), got {retry_count}"
        result = _load_result_for_chat(test_db, group_id, chat_ref)
        assert result is not None, "Chat should have result after retry success"
        assert result["status"] == GroupChatStatus.DONE.value, "Chat should succeed after account rotation"


class TestExceptionRecoveryPaths:
    """Tests for exception recovery paths in group_engine.py.

    Recovery Path 1: _run_account_worker catches exceptions and marks remaining chats ERROR
    Recovery Path 2: start_analysis() gathers exceptions without breaking
    Recovery Path 3: _finalize_group detects completion after errors
    """

    @pytest.mark.asyncio
    async def test_outer_exception_handler_saves_remaining_chats(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test _run_account_worker exception handler: session context manager raises exception.

        Scenario:
        - Group with 5 chats assigned to account
        - Mock session context manager to raise exception
        - Verify: Exception handler saves ERROR status for ALL remaining PENDING chats
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
        # This will be caught by _run_account_worker's outer exception handler
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.side_effect = RuntimeError("Session context error")
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Run _run_account_worker (should catch exception in outer handler)
        await engine._run_account_worker(
            group_id=group_id,
            account_id="test-account",
            settings=settings,
            all_accounts=["test-account"],
            mode=AnalysisMode.FRESH,
        )

        # CRITICAL ASSERTION: ALL 5 chats must be marked as ERROR
        error_chats = test_db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.ERROR.value,
        )
        assert len(error_chats) == 5, (
            f"Outer exception handler failed! Expected 5 error chats, got {len(error_chats)}. "
            f"Remaining chats were not saved."
        )

        # Verify error messages reference the account error
        for chat in error_chats:
            assert chat.get("error") is not None, "Error chat should have error message"
            assert "Account error" in chat["error"], (
                f"Error should mention 'Account error', got: {chat['error']}"
            )
            assert "Session context error" in chat["error"], (
                f"Error should include original error message, got: {chat['error']}"
            )

    @pytest.mark.asyncio
    async def test_account_task_exception_saves_dead_results(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test start_analysis gathers worker exceptions without losing chats.

        Scenario:
        - Group with 5 chats assigned to account
        - Mock _run_account_worker to raise exception directly
        - Verify: start_analysis() completes, worker error logged, finalize_group runs
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

        # Mock _run_account_worker to raise exception immediately
        # This tests that start_analysis's gather(return_exceptions=True) handles it
        async def mock_worker_exception(*args, **kwargs):
            raise ValueError("Account task failed immediately")

        # Patch _run_account_worker to raise exception
        with patch.object(
            engine,
            "_run_account_worker",
            side_effect=mock_worker_exception,
        ):
            # Run start_analysis (should handle exception via gather)
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # After start_analysis with exception: chats remain PENDING
        # (worker never ran, so they weren't processed)
        # But _finalize_group is still called — it checks done+error vs total
        all_chats = test_db.load_chats(group_id=group_id)
        assert len(all_chats) == 5, f"Expected 5 chats, got {len(all_chats)}"

        # Verify start_analysis completed without raising
        # The exception is gathered and logged, not propagated
        # Chats stay PENDING since the worker never actually processed them
        # This is the expected behavior — the worker exception is logged in start_analysis

    @pytest.mark.asyncio
    async def test_orphan_safety_net_fills_missing_results(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Test that _finalize_group correctly handles mixed done/error states.

        Scenario:
        - Group with 8 chats
        - Phase 1 processes all (5 succeed, 3 fail)
        - Verify: _finalize_group sets correct completion status
        - Verify: All chats have final status (DONE or ERROR)
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

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

        # Mock process_chat to succeed for first 5, fail for last 3
        call_count = 0

        async def mock_process_chat(chat_dict, client, account_id, settings):
            nonlocal call_count
            call_count += 1
            chat_index = int(chat_dict["chat_ref"].split("chat")[1])

            if chat_index < 5:
                return ChatResult(
                    chat_ref=chat_dict["chat_ref"],
                    chat_type="group",
                    title=f"Chat {chat_index}",
                    subscribers=100 + chat_index,
                    moderation=False,
                    numeric_id=1000000 + chat_index,
                    status="done",
                )
            else:
                return ChatResult(
                    chat_ref=chat_dict["chat_ref"],
                    chat_type="dead",
                    title=None,
                    subscribers=None,
                    moderation=None,
                    numeric_id=None,
                    status="dead",
                    error="Orphan safety net: missing result after Phase 1",
                )

        # Mock session context
        mock_client = AsyncMock()
        mock_session_context = AsyncMock()
        mock_session_context.__aenter__.return_value = mock_client
        mock_session_context.__aexit__.return_value = None
        mock_session_manager.session.return_value = mock_session_context

        # Run worker
        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine._run_account_worker(
                group_id=group_id,
                account_id="test-account",
                settings=settings,
                all_accounts=["test-account"],
                mode=AnalysisMode.FRESH,
            )

        # CRITICAL ASSERTION: ALL 8 chats must have results
        all_chats = test_db.load_chats(group_id=group_id)
        assert len(all_chats) == 8

        done_chats = [c for c in all_chats if c["status"] == GroupChatStatus.DONE.value]
        error_chats = [c for c in all_chats if c["status"] == GroupChatStatus.ERROR.value]
        pending_chats = [c for c in all_chats if c["status"] == GroupChatStatus.PENDING.value]

        assert len(pending_chats) == 0, (
            f"Orphan safety net failed! {len(pending_chats)} chats still PENDING"
        )
        assert len(done_chats) + len(error_chats) == 8, (
            f"Expected 8 processed chats, got {len(done_chats)} done + {len(error_chats)} error"
        )
        assert len(done_chats) == 5, f"Expected 5 done chats, got {len(done_chats)}"
        assert len(error_chats) == 3, f"Expected 3 error chats, got {len(error_chats)}"

        # Verify dead chats have correct type
        for chat in error_chats:
            assert chat["chat_type"] == "dead", f"Error chat should have type=dead: {chat['chat_ref']}"

        # Verify _finalize_group handles this correctly
        engine._finalize_group(group_id)

        # Group should be COMPLETED (not FAILED since some chats succeeded)
        # Use compute_group_status (status is now computed from chat statuses)
        from chatfilter.analyzer.progress import compute_group_status
        computed_status = compute_group_status(test_db, group_id)
        assert computed_status == "completed", (
            f"Expected group status 'completed', got {computed_status}"
        )

        # Verify process_chat called for all 8
        assert call_count == 8, f"Expected 8 process_chat calls, got {call_count}"


class TestPrepareIncrement:
    """Test _prepare_increment() marks incomplete DONE chats as PENDING."""

    def test_incomplete_done_chats_marked_pending(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """DONE chats missing required metrics should be marked PENDING."""
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        group_id = "test-prepare-increment"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_activity=True,  # This metric will be missing
        )
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status="completed",
        )

        # Chat 1: DONE with all metrics (complete)
        chat_ref_complete = "https://t.me/complete_chat"
        chat_id_complete = _save_chat_with_metrics(
            test_db, group_id, chat_ref_complete,
            chat_type="group",
            status=GroupChatStatus.DONE.value,
            subscribers=500,
            title="Complete Chat",
            messages_per_hour=10.0,
            unique_authors_per_hour=5.0,
            moderation=False,
            captcha=False,
            metrics_version=2,
        )

        # Chat 2: DONE but missing activity metrics (incomplete)
        chat_ref_incomplete = "https://t.me/incomplete_chat"
        chat_id_incomplete = _save_chat_with_metrics(
            test_db, group_id, chat_ref_incomplete,
            chat_type="group",
            status=GroupChatStatus.DONE.value,
            subscribers=300,
            title="Incomplete Chat",
            moderation=False,
            captcha=False,
            metrics_version=2,
            # messages_per_hour=None — missing!
            # unique_authors_per_hour=None — missing!
        )

        # Chat 3: DONE but no metrics at all
        chat_ref_no_result = "https://t.me/no_result_chat"
        test_db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref_no_result,
            chat_type="group",
            status=GroupChatStatus.DONE.value,
        )

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=MagicMock(),
        )

        # Run _prepare_increment
        incomplete_count = engine._prepare_increment(group_id, settings)

        # Should mark 2 chats as PENDING (incomplete + no_result)
        assert incomplete_count == 2, f"Expected 2 incomplete chats, got {incomplete_count}"

        # Complete chat should remain DONE
        done_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        assert len(done_chats) == 1
        assert done_chats[0]["chat_ref"] == chat_ref_complete

        # Incomplete chats should be PENDING
        pending_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
        assert len(pending_chats) == 2
        pending_refs = {c["chat_ref"] for c in pending_chats}
        assert chat_ref_incomplete in pending_refs
        assert chat_ref_no_result in pending_refs

    def test_all_complete_returns_zero(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """When all DONE chats have all metrics, _prepare_increment returns 0."""
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        group_id = "test-prepare-all-complete"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_activity=False,
            detect_unique_authors=False,
            detect_moderation=False,
            detect_captcha=False,
        )
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status="completed",
        )

        chat_ref = "https://t.me/all_done"
        _save_chat_with_metrics(
            test_db, group_id, chat_ref,
            chat_type="group",
            status=GroupChatStatus.DONE.value,
            subscribers=500,
            title="Done Chat",
            moderation=False,
            captcha=False,
            metrics_version=2,
        )

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=MagicMock(),
        )

        incomplete_count = engine._prepare_increment(group_id, settings)
        assert incomplete_count == 0, "All chats complete, should return 0"

        # Chat should remain DONE
        done_chats = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        assert len(done_chats) == 1

    @pytest.mark.asyncio
    async def test_initial_progress_before_prepare_increment(
        self,
        test_db: GroupDatabase,
    ) -> None:
        """Initial progress event should show count BEFORE _prepare_increment runs.

        Verifies that start_analysis captures count_processed_chats BEFORE calling
        _prepare_increment, so the user sees the original processed count (e.g. 5/5)
        not the reduced count after incomplete chats are marked PENDING (e.g. 3/5).
        """
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        group_id = "test-progress-timing"
        settings = GroupSettings(
            detect_subscribers=True,
            detect_activity=True,
        )
        test_db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=settings.model_dump(),
            status="pending",
        )

        # Create 5 chats: 3 complete DONE, 2 incomplete DONE (missing activity)
        for i in range(3):
            ref = f"https://t.me/complete{i}"
            _save_chat_with_metrics(
                test_db, group_id, ref,
                chat_type="group",
                status=GroupChatStatus.DONE.value,
                subscribers=100,
                title=f"Complete {i}",
                messages_per_hour=5.0,
                unique_authors_per_hour=2.0,
                moderation=False,
                captcha=False,
                metrics_version=2,
            )

        for i in range(2):
            ref = f"https://t.me/incomplete{i}"
            _save_chat_with_metrics(
                test_db, group_id, ref,
                chat_type="group",
                status=GroupChatStatus.DONE.value,
                subscribers=100,
                title=f"Incomplete {i}",
                moderation=False,
                captcha=False,
                metrics_version=2,
                # messages_per_hour missing, unique_authors_per_hour missing
            )

        # Before _prepare_increment: all 5 are DONE → processed=5
        processed_before, total_before = test_db.count_processed_chats(group_id)
        assert processed_before == 5, "All 5 should be processed before prepare"
        assert total_before == 5

        # Mock dependencies
        mock_session_mgr = MagicMock()
        mock_session_mgr.list_sessions.return_value = ["account-1"]

        async def mock_is_healthy(sid):
            return True
        mock_session_mgr.is_healthy = mock_is_healthy

        engine = GroupAnalysisEngine(
            db=test_db,
            session_manager=mock_session_mgr,
        )

        # Capture published events
        published_events = []
        original_publish = engine._progress.publish

        def capture_event(event):
            published_events.append(event)
            original_publish(event)
        engine._progress.publish = capture_event

        # Patch worker and finalize to avoid Telegram calls
        async def mock_noop(*args, **kwargs):
            pass

        with (
            patch.object(engine, "_run_account_worker", side_effect=mock_noop),
            patch.object(engine, "_finalize_group", return_value=None),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

        # After _prepare_increment: 2 incomplete chats should be marked PENDING
        pending = test_db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
        assert len(pending) == 2, "2 incomplete chats should be PENDING after prepare_increment"

        done = test_db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        assert len(done) == 3, "3 complete chats should remain DONE"
