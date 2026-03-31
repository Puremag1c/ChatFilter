"""Tests for the background scheduler lifecycle.

Tests cover:
- Scheduler initialization on app startup
- Update cycle execution (mocked Telegram calls)
- Error resilience (exceptions don't crash the loop)
- Clean shutdown
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.scheduler.updater import ChatMetricsUpdater
from chatfilter.telegram.session.models import SessionState


@pytest.fixture
def mock_session_manager() -> MagicMock:
    """Provide a mock SessionManager."""
    manager = MagicMock()
    manager.get_info = MagicMock(return_value=None)
    manager._sessions = {}
    return manager


@pytest.fixture
def mock_db() -> MagicMock:
    """Provide a mock GroupDatabase."""
    db = MagicMock()
    db.get_subscribed_chats = MagicMock(return_value=[])
    db.update_catalog_metrics = MagicMock()
    return db


@pytest.fixture
def updater(mock_session_manager: MagicMock, mock_db: MagicMock) -> ChatMetricsUpdater:
    """Provide a ChatMetricsUpdater instance for testing."""
    return ChatMetricsUpdater(mock_session_manager, mock_db)


class TestSchedulerStartup:
    """Tests for scheduler initialization on app startup."""

    @pytest.mark.asyncio
    async def test_start_creates_task(self, updater: ChatMetricsUpdater) -> None:
        """Test that start() creates an asyncio task."""
        assert updater._task is None
        updater.start()
        assert updater._task is not None
        assert isinstance(updater._task, asyncio.Task)
        # Cleanup
        await updater.stop()

    @pytest.mark.asyncio
    async def test_start_idempotent(self, updater: ChatMetricsUpdater) -> None:
        """Test that calling start() twice doesn't create duplicate tasks."""
        updater.start()
        task1 = updater._task
        updater.start()
        task2 = updater._task
        assert task1 is task2
        # Cleanup
        await updater.stop()

    @pytest.mark.asyncio
    async def test_stop_event_cleared_on_start(self, updater: ChatMetricsUpdater) -> None:
        """Test that stop_event is cleared when starting."""
        updater._stop_event.set()
        assert updater._stop_event.is_set()
        updater.start()
        assert not updater._stop_event.is_set()
        # Cleanup
        await updater.stop()


class TestSchedulerExecution:
    """Tests for scheduler update cycle execution."""

    @pytest.mark.asyncio
    async def test_run_update_cycle_no_subscriptions(
        self, updater: ChatMetricsUpdater, mock_db: MagicMock
    ) -> None:
        """Test that update cycle handles no subscriptions gracefully."""
        mock_db.get_subscribed_chats.return_value = []
        await updater._run_update_cycle()
        # Should complete without error
        assert mock_db.update_catalog_metrics.call_count == 0

    @pytest.mark.asyncio
    async def test_run_update_cycle_skips_disconnected_accounts(
        self, updater: ChatMetricsUpdater, mock_session_manager: MagicMock, mock_db: MagicMock
    ) -> None:
        """Test that update cycle skips accounts that are not connected."""
        # Setup subscription
        mock_db.get_subscribed_chats.return_value = [("account1", "chat1", 12345)]
        # Account is not connected
        mock_session_manager.get_info.return_value = None

        await updater._run_update_cycle()

        # Should not try to update metrics
        assert mock_db.update_catalog_metrics.call_count == 0

    @pytest.mark.asyncio
    async def test_run_update_cycle_updates_metrics_for_connected_chats(
        self,
        updater: ChatMetricsUpdater,
        mock_session_manager: MagicMock,
        mock_db: MagicMock,
        mock_telegram_client: MagicMock,
    ) -> None:
        """Test that update cycle fetches and updates metrics for connected chats."""
        # Setup subscription
        account_id = "account1"
        catalog_chat_id = "chat1"
        telegram_chat_id = 12345
        mock_db.get_subscribed_chats.return_value = [
            (account_id, catalog_chat_id, telegram_chat_id)
        ]

        # Account is connected
        session_state = MagicMock()
        session_state.state = SessionState.CONNECTED
        session_state.client = mock_telegram_client
        mock_session_manager.get_info.return_value = session_state
        mock_session_manager._sessions = {account_id: session_state}

        # Mock the client's iter_messages
        async def mock_iter_messages(chat_id: int, limit: int | None = None) -> Any:
            # Create a mock message
            msg = MagicMock()
            msg.date = datetime.now(UTC)
            msg.from_id = 123
            yield msg

        mock_telegram_client.iter_messages = mock_iter_messages

        # Patch _fetch_chat_metrics to return metrics
        with patch.object(
            updater,
            "_fetch_chat_metrics",
            new_callable=AsyncMock,
            return_value={"messages_per_hour": 5.0, "unique_authors_per_hour": 2.0},
        ):
            await updater._run_update_cycle()

        # Should have updated metrics
        assert mock_db.update_catalog_metrics.call_count == 1
        call_args = mock_db.update_catalog_metrics.call_args
        assert call_args[0][0] == catalog_chat_id
        assert call_args[1]["use_ema"] is True
        assert call_args[1]["alpha"] == 0.3

    @pytest.mark.asyncio
    async def test_run_update_cycle_continues_on_chat_error(
        self,
        updater: ChatMetricsUpdater,
        mock_session_manager: MagicMock,
        mock_db: MagicMock,
        mock_telegram_client: MagicMock,
    ) -> None:
        """Test that error updating one chat doesn't crash the loop."""
        # Setup two subscriptions
        mock_db.get_subscribed_chats.return_value = [
            ("account1", "chat1", 111),
            ("account1", "chat2", 222),
        ]

        # Account is connected
        session_state = MagicMock()
        session_state.state = SessionState.CONNECTED
        session_state.client = mock_telegram_client
        mock_session_manager.get_info.return_value = session_state
        mock_session_manager._sessions = {"account1": session_state}

        # First chat fails, second succeeds
        async def mock_fetch_metrics(client: object, chat_id: int) -> dict[str, float] | None:
            if chat_id == 111:
                raise RuntimeError("Network error")
            return {"messages_per_hour": 3.0, "unique_authors_per_hour": 1.0}

        with patch.object(updater, "_fetch_chat_metrics", side_effect=mock_fetch_metrics):
            # Should not raise despite error in first chat
            await updater._run_update_cycle()

        # Should have updated the second chat despite error in first
        assert mock_db.update_catalog_metrics.call_count == 1


class TestSchedulerResilience:
    """Tests for error resilience and exception handling."""

    @pytest.mark.asyncio
    async def test_scheduler_loop_continues_on_cycle_error(
        self, updater: ChatMetricsUpdater
    ) -> None:
        """Test that exception in _run_update_cycle doesn't crash the loop."""
        call_count = 0

        async def failing_cycle() -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Simulated error")
            # Second call succeeds

        with (
            patch.object(updater, "_run_update_cycle", side_effect=failing_cycle),
            patch("chatfilter.scheduler.updater.UPDATE_INTERVAL_SECONDS", 0.01),
        ):
            # Start the loop
            updater._task = asyncio.create_task(updater._scheduler_loop())

            # Let the loop run through one error and recovery
            await asyncio.sleep(0.1)
            assert call_count >= 2  # Error + retry

            # Cleanup
            updater._stop_event.set()
            await asyncio.sleep(0.01)

    @pytest.mark.asyncio
    async def test_scheduler_stops_on_stop_event(self, updater: ChatMetricsUpdater) -> None:
        """Test that scheduler loop stops when stop_event is set."""
        cycle_count = 0

        async def counting_cycle() -> None:
            nonlocal cycle_count
            cycle_count += 1

        with patch.object(updater, "_run_update_cycle", side_effect=counting_cycle):
            updater._task = asyncio.create_task(updater._scheduler_loop())
            await asyncio.sleep(0.05)

            # Set stop event
            updater._stop_event.set()
            await asyncio.sleep(0.05)

            # Task should be done
            assert updater._task.done()
            assert cycle_count >= 1

    @pytest.mark.asyncio
    async def test_scheduler_cancelled_error_propagates(self, updater: ChatMetricsUpdater) -> None:
        """Test that CancelledError is properly propagated in the loop."""

        async def raising_cycle() -> None:
            raise asyncio.CancelledError()

        with patch.object(updater, "_run_update_cycle", side_effect=raising_cycle):
            updater._task = asyncio.create_task(updater._scheduler_loop())
            await asyncio.sleep(0.05)
            # Task should be done (cancelled)
            assert updater._task.done()


class TestSchedulerShutdown:
    """Tests for clean shutdown."""

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, updater: ChatMetricsUpdater) -> None:
        """Test that stop() cancels the scheduler task."""
        updater.start()
        task = updater._task
        assert task is not None
        assert not task.done()

        await updater.stop()

        assert task.done()

    @pytest.mark.asyncio
    async def test_stop_idempotent(self, updater: ChatMetricsUpdater) -> None:
        """Test that calling stop() multiple times is safe."""
        updater.start()
        task = updater._task

        await updater.stop()
        await updater.stop()  # Should not raise

        assert task.done()

    @pytest.mark.asyncio
    async def test_stop_when_not_started(self, updater: ChatMetricsUpdater) -> None:
        """Test that stop() is safe when scheduler was never started."""
        # Should not raise
        await updater.stop()
        assert updater._task is None

    @pytest.mark.asyncio
    async def test_stop_waits_for_task_completion(self, updater: ChatMetricsUpdater) -> None:
        """Test that stop() waits for the task to complete."""
        cycle_count = 0

        async def slow_cycle() -> None:
            nonlocal cycle_count
            cycle_count += 1
            await asyncio.sleep(0.05)

        with patch.object(updater, "_run_update_cycle", side_effect=slow_cycle):
            updater.start()
            await asyncio.sleep(0.02)  # Let first cycle start

            # Stop should wait for task
            await updater.stop()

            # Task should be fully cancelled
            assert updater._task.done()


class TestSchedulerIntegration:
    """Integration tests for scheduler lifecycle."""

    @pytest.mark.asyncio
    async def test_full_startup_execution_shutdown_cycle(
        self,
        updater: ChatMetricsUpdater,
        mock_db: MagicMock,
    ) -> None:
        """Test full lifecycle: start → execute → stop."""
        # Setup a subscription
        mock_db.get_subscribed_chats.return_value = []

        # Start scheduler
        updater.start()
        assert updater._task is not None

        # Let it run briefly
        await asyncio.sleep(0.05)

        # Stop scheduler
        await updater.stop()
        assert updater._task.done()

    @pytest.mark.asyncio
    async def test_multiple_cycles_with_recovery(
        self,
        updater: ChatMetricsUpdater,
        mock_db: MagicMock,
    ) -> None:
        """Test that scheduler recovers and continues after errors."""
        cycle_errors = []

        async def cycle_with_occasional_error() -> None:
            if len(cycle_errors) < 2:
                cycle_errors.append("error")
                raise RuntimeError("Simulated transient error")

        mock_db.get_subscribed_chats.return_value = []

        with (
            patch.object(updater, "_run_update_cycle", side_effect=cycle_with_occasional_error),
            patch("chatfilter.scheduler.updater.UPDATE_INTERVAL_SECONDS", 0.01),
        ):
            updater.start()
            await asyncio.sleep(0.1)

            # Should have tried multiple cycles
            assert len(cycle_errors) >= 2

            await updater.stop()
