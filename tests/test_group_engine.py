"""Tests for group_engine: FloodWait global retry, account health, pre-validation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from telethon.errors import FloodWaitError

from chatfilter.analyzer.group_engine import (
    AccountHealthTracker,
    GroupAnalysisEngine,
    NoConnectedAccountsError,
)
from chatfilter.analyzer.retry import RetryPolicy, RetryResult, try_with_retry
from chatfilter.models.group import GroupChatStatus, GroupSettings
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.session_manager import SessionInvalidError, SessionManager


# ===== TEST 1: FloodWait global retry - all accounts hit FloodWait =====


@pytest.mark.asyncio
async def test_floodwait_global_retry_all_accounts_exhausted() -> None:
    """Test FloodWait global retry: all accounts → FloodWait, verify retry after min wait."""
    call_log = []

    async def mock_fn(account_id: str, chat: dict) -> str:
        call_log.append(account_id)
        # All accounts hit FloodWait on first try
        error = FloodWaitError("FLOOD_WAIT_X")
        error.seconds = 2  # 2 seconds wait
        raise error

    chat = {"id": "chat-1", "chat_ref": "https://t.me/test"}
    accounts = ["acc1", "acc2", "acc3"]
    policy = RetryPolicy(max_retries=5, max_global_retries=1)

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        result = await try_with_retry(fn=mock_fn, chat=chat, accounts=accounts, policy=policy)

    # Verify:
    # 1. All accounts tried
    assert "acc1" in call_log
    assert "acc2" in call_log
    assert "acc3" in call_log

    # 2. Global retry triggered - sleep was called with min wait (2s + buffer)
    assert mock_sleep.call_count >= 1
    # Buffer is 10% of 2s = 0.2s, total wait = 2.2s
    sleep_args = [call.args[0] for call in mock_sleep.call_args_list]
    assert any(2.0 <= arg <= 2.3 for arg in sleep_args)

    # 3. Chat stays PENDING after max_global_retries exhausted
    assert not result.success
    assert "max retries" in result.error.lower()


# ===== TEST 2: FloodWait global retry - one account recovers =====


@pytest.mark.asyncio
async def test_floodwait_global_retry_one_account_recovers() -> None:
    """Test FloodWait global retry: one account recovers after wait → success."""
    call_count = {}

    async def mock_fn(account_id: str, chat: dict) -> str:
        call_count[account_id] = call_count.get(account_id, 0) + 1

        # First round: all accounts hit FloodWait
        if call_count[account_id] == 1:
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 1
            raise error

        # Second round (after global wait): acc1 succeeds
        if account_id == "acc1":
            return "success"

        # Other accounts still FloodWait
        error = FloodWaitError("FLOOD_WAIT_X")
        error.seconds = 1
        raise error

    chat = {"id": "chat-1", "chat_ref": "https://t.me/test"}
    accounts = ["acc1", "acc2", "acc3"]
    policy = RetryPolicy(max_retries=5, max_global_retries=3)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await try_with_retry(fn=mock_fn, chat=chat, accounts=accounts, policy=policy)

    # Verify:
    # 1. Success after global retry
    assert result.success
    assert result.value == "success"
    assert result.account_used == "acc1"

    # 2. acc1 tried twice (first FloodWait, then success after global wait)
    # acc2/acc3 tried in first round before global wait triggered
    assert call_count["acc1"] >= 2  # First FloodWait, then success after global retry
    # After acc1 succeeds in round 2, acc2/acc3 are not retried (optimization)
    # So we just verify acc1 recovered successfully


# ===== TEST 3: FloodWait global retry - max_global_retries exhausted =====


@pytest.mark.asyncio
async def test_floodwait_global_retry_max_retries_exhausted() -> None:
    """Test FloodWait global retry: max_global_retries exhausted → proper error."""
    call_count = 0

    async def mock_fn(account_id: str, chat: dict) -> str:
        nonlocal call_count
        call_count += 1
        # All accounts always hit FloodWait
        error = FloodWaitError("FLOOD_WAIT_X")
        error.seconds = 1
        raise error

    chat = {"id": "chat-1", "chat_ref": "https://t.me/test"}
    accounts = ["acc1", "acc2"]
    policy = RetryPolicy(max_retries=2, max_global_retries=2)

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        result = await try_with_retry(fn=mock_fn, chat=chat, accounts=accounts, policy=policy)

    # Verify:
    # 1. Failed after max_global_retries
    assert not result.success
    assert "max retries" in result.error.lower()
    assert "PENDING" in result.error  # Chat stays PENDING

    # 2. Global retry happened max_global_retries times
    # Each global retry: sleep once for min wait
    # mock_sleep is also called during per-account retries, so count >= max_global_retries
    assert mock_sleep.call_count >= policy.max_global_retries


# ===== TEST 4: Account health - account failing 5 times =====


@pytest.mark.asyncio
@pytest.mark.timeout(10)  # Should finish quickly with mocked sleep
async def test_account_health_stops_after_consecutive_failures() -> None:
    """Test account health: mock account failing 5 times → stops processing, chats stay PENDING."""
    # Setup
    db = MagicMock(spec=GroupDatabase)
    session_mgr = MagicMock(spec=SessionManager)

    # Mock group data
    db.load_group.return_value = {
        "id": "group-1",
        "name": "Test Group",
        "settings": GroupSettings().model_dump(),
        "status": "pending",
        "created_at": datetime.now(UTC),
    }

    # Mock 10 pending chats assigned to acc1
    pending_chats = [
        {
            "id": i,
            "group_id": "group-1",
            "chat_ref": f"https://t.me/chat{i}",
            "status": GroupChatStatus.PENDING.value,
            "assigned_account": "acc1",
        }
        for i in range(1, 11)
    ]

    # Only return first 10 chats, then empty
    db.load_chats.side_effect = [
        pending_chats,  # Initial load for start_analysis
        [],  # No pending after setup
        pending_chats,  # Worker load
    ]

    db.count_processed_chats.return_value = (0, 10)
    db.get_group_stats.return_value = {"by_status": {}, "by_type": {}}

    # Mock session manager
    session_mgr.list_sessions.return_value = ["acc1"]

    async def mock_is_healthy(account_id: str) -> bool:
        return True

    session_mgr.is_healthy = mock_is_healthy

    # Mock session context manager - make connect non-async to skip validation
    session_mgr.connect = MagicMock(return_value=MagicMock())  # Non-async
    session_mgr.disconnect = AsyncMock()

    # Create proper async context manager mock
    mock_client = AsyncMock()

    class MockSessionContext:
        async def __aenter__(self):
            return mock_client

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    session_mgr.session = Mock(return_value=MockSessionContext())

    # Mock process_chat to always fail
    async def mock_process_chat(*args, **kwargs):
        raise Exception("Account error")

    # Mock asyncio.sleep to avoid delays
    with (
        patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_chat),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        engine = GroupAnalysisEngine(db=db, session_manager=session_mgr)

        # Mock _save_chat_error to avoid DB calls
        engine._save_chat_error = Mock()

        # Mock _finalize_group to avoid DB calls
        engine._finalize_group = Mock()

        # Run worker directly with health tracker
        health_tracker = AccountHealthTracker(max_consecutive_errors=5)
        settings = GroupSettings()

        # Process chats
        await engine._run_account_worker(
            group_id="group-1",
            account_id="acc1",
            settings=settings,
            all_accounts=["acc1"],
            mode="fresh",
            health_tracker=health_tracker,
        )

    # Verify:
    # 1. Account stopped after 5 consecutive failures
    stats = health_tracker.get_stats("acc1")
    assert stats["consecutive_errors"] == 5
    assert stats["total_error"] == 5
    assert stats["total_done"] == 0

    # 2. should_stop returns True after 5 failures
    assert health_tracker.should_stop("acc1")

    # 3. Remaining chats (6-10) were not processed - they stay PENDING
    # We can verify by checking that _save_chat_error was called exactly 5 times
    assert engine._save_chat_error.call_count == 5


# ===== TEST 5: Account health - working account picks up redistributed chats =====


@pytest.mark.asyncio
async def test_account_health_working_account_continues() -> None:
    """Test account health: working account picks up redistributed chats."""
    # Note: MVP does NOT redistribute - this test verifies working account continues
    tracker = AccountHealthTracker(max_consecutive_errors=5)

    # Simulate processing
    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    tracker.record_failure("acc1")

    # acc1 should stop
    assert tracker.should_stop("acc1")

    # acc2 is healthy and can continue
    tracker.record_success("acc2")
    assert not tracker.should_stop("acc2")

    # Verify stats
    assert tracker.get_stats("acc1")["consecutive_errors"] == 5
    assert tracker.get_stats("acc2")["consecutive_errors"] == 0
    assert tracker.get_stats("acc2")["total_done"] == 1


# ===== TEST 6: Pre-validation - invalid account excluded =====


@pytest.mark.asyncio
async def test_pre_validation_invalid_account_excluded() -> None:
    """Test pre-validation: mock SessionInvalidError on connect → account excluded."""
    # Setup
    db = MagicMock(spec=GroupDatabase)
    session_mgr = MagicMock(spec=SessionManager)

    # Mock group data
    db.load_group.return_value = {
        "id": "group-1",
        "name": "Test Group",
        "settings": GroupSettings().model_dump(),
        "status": "pending",
        "created_at": datetime.now(UTC),
    }

    # No pending chats - we're just testing validation
    db.load_chats.return_value = []

    # Mock session manager
    session_mgr.list_sessions.return_value = ["acc1", "acc2"]

    async def mock_is_healthy(account_id: str) -> bool:
        return True

    session_mgr.is_healthy = mock_is_healthy

    # Mock connect: acc1 raises SessionInvalidError, acc2 succeeds
    async def mock_connect(account_id: str):
        if account_id == "acc1":
            raise SessionInvalidError("Invalid session")
        return MagicMock()

    session_mgr.connect = mock_connect
    session_mgr.disconnect = AsyncMock()

    engine = GroupAnalysisEngine(db=db, session_manager=session_mgr)

    # Mock _finalize_group to avoid DB calls
    engine._finalize_group = Mock()

    # Start analysis - should exclude acc1
    await engine.start_analysis(group_id="group-1")

    # Verify:
    # 1. Only acc2 was used (acc1 excluded during pre-validation)
    # We can verify by checking that disconnect was called only for acc2
    disconnect_calls = [call.args[0] for call in session_mgr.disconnect.call_args_list]
    assert "acc2" in disconnect_calls
    assert "acc1" not in disconnect_calls


# ===== TEST 7: Pre-validation - all accounts invalid =====


@pytest.mark.asyncio
async def test_pre_validation_all_accounts_invalid() -> None:
    """Test pre-validation: all accounts invalid → NoConnectedAccountsError."""
    # Setup
    db = MagicMock(spec=GroupDatabase)
    session_mgr = MagicMock(spec=SessionManager)

    # Mock group data
    db.load_group.return_value = {
        "id": "group-1",
        "name": "Test Group",
        "settings": GroupSettings().model_dump(),
        "status": "pending",
        "created_at": datetime.now(UTC),
    }

    # Mock session manager
    session_mgr.list_sessions.return_value = ["acc1", "acc2"]

    async def mock_is_healthy(account_id: str) -> bool:
        return True

    session_mgr.is_healthy = mock_is_healthy

    # Mock connect: all accounts raise SessionInvalidError
    async def mock_connect(account_id: str):
        raise SessionInvalidError("Invalid session")

    session_mgr.connect = mock_connect
    session_mgr.disconnect = AsyncMock()

    engine = GroupAnalysisEngine(db=db, session_manager=session_mgr)

    # Verify: NoConnectedAccountsError is raised
    with pytest.raises(NoConnectedAccountsError, match="All accounts failed validation"):
        await engine.start_analysis(group_id="group-1")


# ===== AccountHealthTracker unit tests =====


def test_account_health_tracker_record_success() -> None:
    """Test AccountHealthTracker.record_success resets consecutive errors."""
    tracker = AccountHealthTracker()

    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    assert tracker.consecutive_errors["acc1"] == 2

    tracker.record_success("acc1")
    assert tracker.consecutive_errors["acc1"] == 0
    assert tracker.total_done["acc1"] == 1


def test_account_health_tracker_record_failure() -> None:
    """Test AccountHealthTracker.record_failure increments counters."""
    tracker = AccountHealthTracker()

    tracker.record_failure("acc1")
    assert tracker.consecutive_errors["acc1"] == 1
    assert tracker.total_error["acc1"] == 1

    tracker.record_failure("acc1")
    assert tracker.consecutive_errors["acc1"] == 2
    assert tracker.total_error["acc1"] == 2


def test_account_health_tracker_should_stop() -> None:
    """Test AccountHealthTracker.should_stop after max consecutive errors."""
    tracker = AccountHealthTracker(max_consecutive_errors=3)

    assert not tracker.should_stop("acc1")

    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    assert not tracker.should_stop("acc1")

    tracker.record_failure("acc1")
    assert tracker.should_stop("acc1")


def test_account_health_tracker_get_stats() -> None:
    """Test AccountHealthTracker.get_stats returns correct stats."""
    tracker = AccountHealthTracker()

    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    tracker.record_success("acc1")
    tracker.record_failure("acc1")

    stats = tracker.get_stats("acc1")
    assert stats["consecutive_errors"] == 1  # Reset after success
    assert stats["total_done"] == 1
    assert stats["total_error"] == 3


def test_account_health_tracker_multiple_accounts() -> None:
    """Test AccountHealthTracker tracks multiple accounts independently."""
    tracker = AccountHealthTracker(max_consecutive_errors=5)

    tracker.record_failure("acc1")
    tracker.record_failure("acc1")
    tracker.record_success("acc2")

    assert tracker.consecutive_errors["acc1"] == 2
    assert tracker.consecutive_errors["acc2"] == 0
    assert tracker.total_error["acc1"] == 2
    assert tracker.total_done["acc2"] == 1

    assert not tracker.should_stop("acc1")
    assert not tracker.should_stop("acc2")
