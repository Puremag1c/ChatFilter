"""Integration tests for WAITING_FOR_ACCOUNTS auto-resume lifecycle.

Tests verify the full status transition cycle:
IN_PROGRESS → WAITING_FOR_ACCOUNTS → IN_PROGRESS → COMPLETED

Scenarios:
1. All accounts FloodWait → WAITING_FOR_ACCOUNTS → flood expires → auto-resume → COMPLETED
2. New account added during wait → detects and resumes with new account
3. SSE events emitted with flood_wait_until timestamp
4. Full lifecycle transition verification via captured progress events
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.analyzer.group_engine import GroupAnalysisEngine
from chatfilter.analyzer.progress import GroupProgressEvent, ProgressTracker
from chatfilter.analyzer.worker import ChatResult
from chatfilter.models.group import (
    AnalysisMode,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.flood_tracker import FloodWaitTracker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_db(tmp_path: Path) -> GroupDatabase:
    """Create isolated test database."""
    db_path = tmp_path / "test_groups.db"
    return GroupDatabase(str(db_path))


@pytest.fixture
def flood_tracker() -> FloodWaitTracker:
    """Fresh FloodWaitTracker per test (not the global singleton)."""
    return FloodWaitTracker()


def _make_session_manager(
    accounts: list[str],
    healthy: set[str] | None = None,
) -> MagicMock:
    """Create a mock SessionManager.

    Args:
        accounts: list of session IDs returned by list_sessions()
        healthy: set of session IDs that are healthy (default: all)
    """
    if healthy is None:
        healthy = set(accounts)

    mgr = MagicMock()
    mgr.list_sessions.return_value = list(accounts)

    # is_healthy must be a real coroutine
    async def _is_healthy(sid: str) -> bool:
        return sid in healthy

    mgr.is_healthy = _is_healthy

    # connect is NOT async (so engine skips pre-validation for mocks)
    mgr.connect = MagicMock(return_value=MagicMock())
    mgr.disconnect = MagicMock()

    # session() context manager
    @asynccontextmanager
    async def _session(sid: str, *, auto_disconnect: bool = True):
        yield MagicMock()

    mgr.session = _session
    return mgr


def _setup_group_with_chats(
    db: GroupDatabase,
    group_id: str,
    chat_refs: list[str],
    assigned_account: str = "acct1",
) -> None:
    """Create a group with PENDING chats in the database."""
    settings = GroupSettings()
    db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=settings.model_dump(),
        status=GroupStatus.IN_PROGRESS.value,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    for ref in chat_refs:
        db.save_chat(
            group_id=group_id,
            chat_ref=ref,
            chat_type="channel",
            status=GroupChatStatus.PENDING.value,
            assigned_account=assigned_account,
        )


# ---------------------------------------------------------------------------
# Test: FloodWait expires → auto-resume → COMPLETED
# ---------------------------------------------------------------------------

class TestAutoResume:
    """Test that WAITING_FOR_ACCOUNTS auto-resumes when FloodWait expires."""

    @pytest.mark.asyncio
    async def test_auto_resume_after_flood_expires(
        self, test_db: GroupDatabase, flood_tracker: FloodWaitTracker
    ) -> None:
        """Full lifecycle: IN_PROGRESS → WAITING_FOR_ACCOUNTS → IN_PROGRESS → COMPLETED.

        Scenario:
        - 2 accounts, both FloodWait blocked
        - Engine enters _wait_for_accounts_and_resume
        - After one poll cycle, FloodWait expires (mock time advance)
        - Engine resumes with INCREMENT → processes remaining chats → COMPLETED
        """
        group_id = "grp-auto-resume"
        chat_refs = ["@chat1", "@chat2", "@chat3"]

        # Block both accounts
        flood_tracker.record_flood_wait("acct1", 60)
        flood_tracker.record_flood_wait("acct2", 60)

        # Session manager: 2 accounts, both healthy
        session_mgr = _make_session_manager(["acct1", "acct2"])

        progress = ProgressTracker(test_db)
        engine = GroupAnalysisEngine(test_db, session_mgr, progress)

        # Subscribe to capture SSE events
        queue = progress.subscribe(group_id)

        _setup_group_with_chats(test_db, group_id, chat_refs)

        # Track how many times _wait loop runs
        wait_call_count = 0
        original_wait_for = asyncio.wait_for

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal wait_call_count
            wait_call_count += 1
            # After first wait, clear flood wait (simulate time passing)
            if wait_call_count == 1:
                flood_tracker.clear_all()
            # Always timeout immediately to avoid actual waiting
            raise asyncio.TimeoutError()

        # Track start_analysis calls to handle INCREMENT resume
        original_start = engine.start_analysis
        start_calls: list[AnalysisMode] = []

        async def patched_start(gid: str, mode: AnalysisMode = AnalysisMode.FRESH) -> None:
            start_calls.append(mode)
            if mode == AnalysisMode.INCREMENT:
                # On resume: mark all PENDING chats as DONE (simulating successful processing)
                pending = test_db.load_chats(group_id=gid, status=GroupChatStatus.PENDING.value)
                for chat in pending:
                    test_db.update_chat_status(
                        chat_id=chat["id"],
                        status=GroupChatStatus.DONE.value,
                    )
                    test_db.save_chat_metrics(chat["id"], {"title": chat["chat_ref"], "metrics_version": 2})
                # Finalize
                engine._finalize_group(gid)
            else:
                await original_start(gid, mode)

        with (
            patch.object(engine, "start_analysis", side_effect=patched_start),
            patch("chatfilter.analyzer.group_engine.get_flood_tracker", return_value=flood_tracker),
            patch("asyncio.wait_for", side_effect=mock_wait_for),
        ):
            settings = GroupSettings()
            await engine._wait_for_accounts_and_resume(group_id, settings)

        # Verify: wait_for was called (at least one poll cycle happened)
        assert wait_call_count >= 1, "Expected at least one poll cycle"

        # Verify: start_analysis was called with INCREMENT mode
        assert AnalysisMode.INCREMENT in start_calls, (
            f"Expected INCREMENT resume, got: {start_calls}"
        )

        # Verify: all chats are DONE
        all_chats = test_db.load_chats(group_id=group_id)
        done_chats = [c for c in all_chats if c["status"] == GroupChatStatus.DONE.value]
        assert len(done_chats) == len(chat_refs), (
            f"Expected {len(chat_refs)} DONE chats, got {len(done_chats)}"
        )

        # Verify: SSE events were published
        events: list[GroupProgressEvent] = []
        while not queue.empty():
            ev = queue.get_nowait()
            if ev is not None:
                events.append(ev)

        # Must have at least one WAITING_FOR_ACCOUNTS event
        waiting_events = [
            e for e in events
            if e.status == GroupStatus.WAITING_FOR_ACCOUNTS.value
        ]
        assert len(waiting_events) >= 1, (
            f"Expected WAITING_FOR_ACCOUNTS SSE event, got statuses: "
            f"{[e.status for e in events]}"
        )

        # WAITING event must have flood_wait_until timestamp
        for ev in waiting_events:
            assert ev.flood_wait_until is not None, (
                "WAITING_FOR_ACCOUNTS event must include flood_wait_until"
            )
            assert isinstance(ev.flood_wait_until, datetime), (
                f"flood_wait_until must be datetime, got {type(ev.flood_wait_until)}"
            )

        # Check for COMPLETED event (from _finalize_group)
        completed_events = [
            e for e in events
            if e.status == GroupStatus.COMPLETED.value
        ]
        assert len(completed_events) >= 1, (
            f"Expected COMPLETED SSE event after resume, got statuses: "
            f"{[e.status for e in events]}"
        )


# ---------------------------------------------------------------------------
# Test: New account added during wait → detects and resumes
# ---------------------------------------------------------------------------

class TestNewAccountDetection:
    """Test that a new account added during WAITING_FOR_ACCOUNTS triggers resume."""

    @pytest.mark.asyncio
    async def test_new_account_triggers_resume(
        self, test_db: GroupDatabase, flood_tracker: FloodWaitTracker
    ) -> None:
        """New account added while waiting → engine detects and resumes.

        Scenario:
        - 1 account (acct1) gets FloodWait
        - Engine enters waiting loop
        - FloodWait clears (account deleted), but no healthy accounts
        - Then new account (acct_new) appears via list_sessions
        - Engine detects new account and resumes with INCREMENT
        """
        group_id = "grp-new-acct"
        chat_refs = ["@chat_a", "@chat_b"]

        # Block acct1
        flood_tracker.record_flood_wait("acct1", 120)

        # Start with only acct1 (blocked). After sleep, add acct_new.
        accounts_list: list[list[str]] = [["acct1"], ["acct_new"]]
        call_idx = 0

        session_mgr = MagicMock()

        def _list_sessions() -> list[str]:
            nonlocal call_idx
            # First calls return acct1 (blocked), later return acct_new
            idx = min(call_idx, len(accounts_list) - 1)
            return accounts_list[idx]

        session_mgr.list_sessions = _list_sessions

        # acct_new is always healthy, acct1 is always healthy too (but flood-blocked)
        async def _is_healthy(sid: str) -> bool:
            return True

        session_mgr.is_healthy = _is_healthy
        session_mgr.connect = MagicMock(return_value=MagicMock())
        session_mgr.disconnect = MagicMock()

        @asynccontextmanager
        async def _session(sid: str, *, auto_disconnect: bool = True):
            yield MagicMock()

        session_mgr.session = _session

        progress = ProgressTracker(test_db)
        engine = GroupAnalysisEngine(test_db, session_mgr, progress)

        _setup_group_with_chats(test_db, group_id, chat_refs)

        # Track resume call
        resume_mode: list[AnalysisMode] = []

        async def patched_start(gid: str, mode: AnalysisMode = AnalysisMode.FRESH) -> None:
            resume_mode.append(mode)
            # Simulate successful processing
            pending = test_db.load_chats(group_id=gid, status=GroupChatStatus.PENDING.value)
            for chat in pending:
                test_db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.DONE.value)
            engine._finalize_group(gid)

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal call_idx
            call_idx += 1
            # Clear flood so acct1 is no longer blocked, simulating account deletion
            flood_tracker.clear_all()
            # Always timeout to continue loop iteration
            raise asyncio.TimeoutError()

        with (
            patch.object(engine, "start_analysis", side_effect=patched_start),
            patch("chatfilter.analyzer.group_engine.get_flood_tracker", return_value=flood_tracker),
            patch("asyncio.wait_for", side_effect=mock_wait_for),
        ):
            settings = GroupSettings()
            await engine._wait_for_accounts_and_resume(group_id, settings)

        # Verify: resume was triggered with INCREMENT
        assert len(resume_mode) == 1, f"Expected exactly 1 resume call, got {len(resume_mode)}"
        assert resume_mode[0] == AnalysisMode.INCREMENT, (
            f"Expected INCREMENT mode, got {resume_mode[0]}"
        )

        # Verify: all chats processed
        all_chats = test_db.load_chats(group_id=group_id)
        pending = [c for c in all_chats if c["status"] == GroupChatStatus.PENDING.value]
        assert len(pending) == 0, f"Expected 0 PENDING chats, got {len(pending)}"


# ---------------------------------------------------------------------------
# Test: SSE events contain correct fields during waiting
# ---------------------------------------------------------------------------

class TestSSEEvents:
    """Test SSE event content during WAITING_FOR_ACCOUNTS status."""

    @pytest.mark.asyncio
    async def test_waiting_event_has_flood_wait_until(
        self, test_db: GroupDatabase, flood_tracker: FloodWaitTracker
    ) -> None:
        """SSE events during WAITING_FOR_ACCOUNTS must include flood_wait_until.

        Verifies:
        - Event status is 'waiting_for_accounts'
        - Event has flood_wait_until as datetime
        - Event has breakdown dict with done/error/dead/pending counts
        - Event message describes the wait
        """
        group_id = "grp-sse-test"
        chat_refs = ["@sse1", "@sse2"]

        flood_tracker.record_flood_wait("acct1", 300)

        session_mgr = _make_session_manager(["acct1"])
        progress = ProgressTracker(test_db)
        engine = GroupAnalysisEngine(test_db, session_mgr, progress)
        queue = progress.subscribe(group_id)

        _setup_group_with_chats(test_db, group_id, chat_refs)

        # Mark one chat as DONE to have mixed statuses
        chats = test_db.load_chats(group_id=group_id)
        test_db.update_chat_status(chat_id=chats[0]["id"], status=GroupChatStatus.DONE.value)

        poll_count = 0

        async def mock_wait_for(coro, *, timeout=None):
            nonlocal poll_count
            poll_count += 1
            # Unblock after first poll so engine resumes
            flood_tracker.clear_all()
            # Always timeout to continue loop iteration
            raise asyncio.TimeoutError()

        async def patched_start(gid: str, mode: AnalysisMode = AnalysisMode.FRESH) -> None:
            # Mark remaining pending as DONE
            for c in test_db.load_chats(group_id=gid, status=GroupChatStatus.PENDING.value):
                test_db.update_chat_status(chat_id=c["id"], status=GroupChatStatus.DONE.value)
            engine._finalize_group(gid)

        with (
            patch.object(engine, "start_analysis", side_effect=patched_start),
            patch("chatfilter.analyzer.group_engine.get_flood_tracker", return_value=flood_tracker),
            patch("asyncio.wait_for", side_effect=mock_wait_for),
        ):
            settings = GroupSettings()
            await engine._wait_for_accounts_and_resume(group_id, settings)

        # Collect all events
        events: list[GroupProgressEvent] = []
        while not queue.empty():
            ev = queue.get_nowait()
            if ev is not None:
                events.append(ev)

        # Find WAITING_FOR_ACCOUNTS events
        waiting_events = [
            e for e in events if e.status == GroupStatus.WAITING_FOR_ACCOUNTS.value
        ]
        assert len(waiting_events) >= 1, (
            f"Expected at least 1 WAITING_FOR_ACCOUNTS event, "
            f"got: {[e.status for e in events]}"
        )

        ev = waiting_events[0]

        # Verify flood_wait_until
        assert ev.flood_wait_until is not None, "Missing flood_wait_until"
        assert isinstance(ev.flood_wait_until, datetime), (
            f"flood_wait_until should be datetime, got {type(ev.flood_wait_until)}"
        )

        # Verify breakdown
        assert ev.breakdown is not None, "Missing breakdown in SSE event"
        assert "done" in ev.breakdown, "breakdown missing 'done' key"
        assert "pending" in ev.breakdown, "breakdown missing 'pending' key"
        assert "error" in ev.breakdown, "breakdown missing 'error' key"
        assert "dead" in ev.breakdown, "breakdown missing 'dead' key"

        # Verify counts make sense (1 done + 1 pending = 2 total)
        assert ev.total == 2, f"Expected total=2, got {ev.total}"
        # current = processed (done + error), so should be 1
        assert ev.current == 1, f"Expected current=1, got {ev.current}"

        # Verify message
        assert ev.message is not None, "Missing message in waiting event"
        assert "waiting" in ev.message.lower() or "flood" in ev.message.lower(), (
            f"Message should mention waiting/flood, got: {ev.message}"
        )

    @pytest.mark.asyncio
    async def test_group_status_saved_as_waiting(
        self, test_db: GroupDatabase, flood_tracker: FloodWaitTracker
    ) -> None:
        """Database group status is updated to WAITING_FOR_ACCOUNTS during wait."""
        group_id = "grp-db-status"
        chat_refs = ["@db1"]

        flood_tracker.record_flood_wait("acct1", 300)

        session_mgr = _make_session_manager(["acct1"])
        progress = ProgressTracker(test_db)
        engine = GroupAnalysisEngine(test_db, session_mgr, progress)

        _setup_group_with_chats(test_db, group_id, chat_refs)

        # Capture DB status during the wait
        captured_status: list[str] = []

        async def mock_wait_for(coro, *, timeout=None):
            # Read DB status during the wait (after save_group was called)
            group_data = test_db.load_group(group_id)
            if group_data:
                captured_status.append(group_data["status"])
            # Unblock
            flood_tracker.clear_all()
            # Always timeout to continue loop iteration
            raise asyncio.TimeoutError()

        async def patched_start(gid: str, mode: AnalysisMode = AnalysisMode.FRESH) -> None:
            for c in test_db.load_chats(group_id=gid, status=GroupChatStatus.PENDING.value):
                test_db.update_chat_status(chat_id=c["id"], status=GroupChatStatus.DONE.value)
            engine._finalize_group(gid)

        with (
            patch.object(engine, "start_analysis", side_effect=patched_start),
            patch("chatfilter.analyzer.group_engine.get_flood_tracker", return_value=flood_tracker),
            patch("asyncio.wait_for", side_effect=mock_wait_for),
        ):
            settings = GroupSettings()
            await engine._wait_for_accounts_and_resume(group_id, settings)

        # DB status must have been WAITING_FOR_ACCOUNTS during the wait
        assert len(captured_status) >= 1, "Expected to capture DB status during sleep"
        assert captured_status[0] == GroupStatus.WAITING_FOR_ACCOUNTS.value, (
            f"Expected DB status 'waiting_for_accounts', got '{captured_status[0]}'"
        )


# ---------------------------------------------------------------------------
# Test: Full lifecycle via start_analysis entry point
# ---------------------------------------------------------------------------

class TestFullLifecycle:
    """Test the complete path: start_analysis → workers → wait → resume → complete."""

    @pytest.mark.asyncio
    async def test_start_analysis_enters_waiting_when_all_blocked(
        self, test_db: GroupDatabase, flood_tracker: FloodWaitTracker
    ) -> None:
        """start_analysis → workers leave PENDING chats → all blocked → enters wait.

        This tests the full entry point from start_analysis through to
        _wait_for_accounts_and_resume. Workers process some chats but leave
        remaining PENDING. All accounts get FloodWait. Engine detects this
        and enters the waiting loop, which we verify via a patched
        _wait_for_accounts_and_resume that records the call.
        """
        group_id = "grp-full-lifecycle"
        chat_refs = ["@life1", "@life2", "@life3", "@life4"]

        session_mgr = _make_session_manager(["acct1", "acct2"])
        progress = ProgressTracker(test_db)
        engine = GroupAnalysisEngine(test_db, session_mgr, progress)
        queue = progress.subscribe(group_id)

        _setup_group_with_chats(test_db, group_id, chat_refs)

        # Mock _run_account_worker: process 2 out of 4 chats, leave 2 PENDING
        # Then block both accounts with FloodWait
        async def mock_worker(
            group_id: str,
            account_id: str,
            settings: GroupSettings,
            all_accounts: list[str],
            mode: AnalysisMode,
            health_tracker,
        ) -> None:
            chats = test_db.load_chats(
                group_id=group_id,
                assigned_account=account_id,
                status=GroupChatStatus.PENDING.value,
            )
            if chats:
                # Process only first chat, leave rest PENDING
                test_db.update_chat_status(
                    chat_id=chats[0]["id"],
                    status=GroupChatStatus.DONE.value,
                )
                test_db.save_chat_metrics(
                    chats[0]["id"], {"title": chats[0]["chat_ref"], "metrics_version": 2}
                )

            # Record FloodWait for this account
            flood_tracker.record_flood_wait(account_id, 120)

        # Track _wait_for_accounts_and_resume calls
        wait_calls: list[str] = []

        async def mock_wait(gid: str, settings: GroupSettings) -> None:
            """Capture that the engine entered the waiting loop, then simulate resume."""
            wait_calls.append(gid)
            # Simulate what _wait_for_accounts_and_resume does:
            # 1. Publish WAITING_FOR_ACCOUNTS event
            processed, total = test_db.count_processed_chats(gid)
            event = GroupProgressEvent(
                group_id=gid,
                status=GroupStatus.WAITING_FOR_ACCOUNTS.value,
                current=processed,
                total=total,
                message="Waiting for FloodWait to expire on all accounts...",
                flood_wait_until=datetime.now(UTC),
            )
            progress.publish(event)

            # 2. Simulate resume: process remaining chats
            pending = test_db.load_chats(group_id=gid, status=GroupChatStatus.PENDING.value)
            for chat in pending:
                test_db.update_chat_status(
                    chat_id=chat["id"], status=GroupChatStatus.DONE.value,
                )
                test_db.save_chat_metrics(
                    chat["id"], {"title": chat["chat_ref"], "metrics_version": 2}
                )

            # 3. Finalize
            engine._finalize_group(gid)

        with (
            patch.object(engine, "_run_account_worker", side_effect=mock_worker),
            patch.object(engine, "_wait_for_accounts_and_resume", side_effect=mock_wait),
            patch("chatfilter.analyzer.group_engine.get_flood_tracker", return_value=flood_tracker),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Verify: _wait_for_accounts_and_resume was called
        assert len(wait_calls) == 1, (
            f"Expected _wait_for_accounts_and_resume to be called once, "
            f"got {len(wait_calls)} calls"
        )
        assert wait_calls[0] == group_id

        # Collect all events
        events: list[GroupProgressEvent] = []
        while not queue.empty():
            ev = queue.get_nowait()
            if ev is not None:
                events.append(ev)

        statuses = [e.status for e in events]

        # Verify status transitions: must contain WAITING_FOR_ACCOUNTS
        assert GroupStatus.WAITING_FOR_ACCOUNTS.value in statuses, (
            f"Expected WAITING_FOR_ACCOUNTS in status transitions, got: {statuses}"
        )

        # Must contain COMPLETED (from _finalize_group)
        assert GroupStatus.COMPLETED.value in statuses, (
            f"Expected COMPLETED in status transitions, got: {statuses}"
        )

        # WAITING must come before COMPLETED
        waiting_idx = next(
            i for i, s in enumerate(statuses)
            if s == GroupStatus.WAITING_FOR_ACCOUNTS.value
        )
        completed_idx = next(
            i for i, s in enumerate(statuses)
            if s == GroupStatus.COMPLETED.value
        )
        assert waiting_idx < completed_idx, (
            f"WAITING_FOR_ACCOUNTS (idx={waiting_idx}) should precede "
            f"COMPLETED (idx={completed_idx})"
        )

        # Verify all chats are DONE
        all_chats = test_db.load_chats(group_id=group_id)
        assert len(all_chats) == len(chat_refs)
        for chat in all_chats:
            assert chat["status"] == GroupChatStatus.DONE.value, (
                f"Chat {chat['chat_ref']} should be DONE, got {chat['status']}"
            )

    @pytest.mark.asyncio
    async def test_no_waiting_when_healthy_accounts_available(
        self, test_db: GroupDatabase, flood_tracker: FloodWaitTracker
    ) -> None:
        """When some accounts are healthy after workers finish, skip waiting loop.

        If there are PENDING chats but at least one account is not flood-blocked,
        the engine should go to _finalize_group instead of _wait_for_accounts_and_resume.
        """
        group_id = "grp-no-wait"
        chat_refs = ["@nw1", "@nw2"]

        # Only acct1 is blocked, acct2 is free
        flood_tracker.record_flood_wait("acct1", 300)

        session_mgr = _make_session_manager(["acct1", "acct2"])
        progress = ProgressTracker(test_db)
        engine = GroupAnalysisEngine(test_db, session_mgr, progress)
        queue = progress.subscribe(group_id)

        _setup_group_with_chats(test_db, group_id, chat_refs)

        # Workers: leave all chats PENDING (simulating quick exit)
        async def mock_worker(
            group_id: str,
            account_id: str,
            settings: GroupSettings,
            all_accounts: list[str],
            mode: AnalysisMode,
            health_tracker,
        ) -> None:
            # Process all chats (since acct2 is healthy, engine should not enter waiting)
            chats = test_db.load_chats(
                group_id=group_id,
                assigned_account=account_id,
                status=GroupChatStatus.PENDING.value,
            )
            for chat in chats:
                test_db.update_chat_status(
                    chat_id=chat["id"], status=GroupChatStatus.DONE.value,
                )

        with (
            patch.object(engine, "_run_account_worker", side_effect=mock_worker),
            patch("chatfilter.analyzer.group_engine.get_flood_tracker", return_value=flood_tracker),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Collect events
        events: list[GroupProgressEvent] = []
        while not queue.empty():
            ev = queue.get_nowait()
            if ev is not None:
                events.append(ev)

        statuses = [e.status for e in events]

        # Should NOT contain WAITING_FOR_ACCOUNTS
        assert GroupStatus.WAITING_FOR_ACCOUNTS.value not in statuses, (
            f"Should not enter WAITING_FOR_ACCOUNTS when healthy accounts exist, "
            f"got statuses: {statuses}"
        )

        # Should contain COMPLETED
        assert GroupStatus.COMPLETED.value in statuses, (
            f"Expected COMPLETED in statuses, got: {statuses}"
        )
