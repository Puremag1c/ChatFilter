"""AccountWatchdog — auto-reconnect of admin-pool sessions."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from chatfilter.service.account_watchdog import (
    BACKOFF_LADDER,
    AccountWatchdog,
    _AccountRetryState,
)
from chatfilter.web.routers.sessions.helpers import SessionListItem


class _FakeSessionManager:
    """Minimal SessionManager stand-in."""

    def __init__(self, registered: set[str]) -> None:
        self._factories = {sid: object() for sid in registered}
        self.connect = AsyncMock()


@pytest.fixture
def mock_listing(monkeypatch: Any):
    """Patches ``listing.list_stored_sessions`` at import source so
    ``account_watchdog``'s ``from .listing import list_stored_sessions``
    sees the stub."""
    items: list[SessionListItem] = []

    def fake_list(**_kw):
        return list(items)

    import chatfilter.web.routers.sessions.listing as listing_mod

    monkeypatch.setattr(listing_mod, "list_stored_sessions", fake_list)
    return items  # Tests mutate this list.


class TestBackoffLadder:
    def test_ladder_grows_and_caps(self) -> None:
        rs = _AccountRetryState()
        t = 1000.0
        # ladder_idx grows from 0 up to len(BACKOFF_LADDER) - 1, then caps.
        for _ in BACKOFF_LADDER:
            rs.record_attempt(t)
        assert rs.ladder_idx == len(BACKOFF_LADDER) - 1
        rs.record_attempt(t)
        assert rs.ladder_idx == len(BACKOFF_LADDER) - 1

    def test_reset_clears_state(self) -> None:
        rs = _AccountRetryState()
        rs.record_attempt(1000.0)
        assert rs.next_attempt_at > 0
        rs.reset()
        assert rs.ladder_idx == 0
        assert rs.next_attempt_at == 0.0

    def test_should_retry(self) -> None:
        rs = _AccountRetryState()
        assert rs.should_retry(now=0.0)
        rs.record_attempt(now=1000.0)
        assert not rs.should_retry(now=1000.0)
        assert rs.should_retry(now=1000.0 + BACKOFF_LADDER[0] + 1)


class TestTickOnce:
    @pytest.mark.asyncio
    async def test_admin_error_session_triggers_reconnect(self, mock_listing) -> None:
        mock_listing.append(SessionListItem(session_id="Adm", state="error", error_message="boom"))
        sm = _FakeSessionManager(registered={"Adm"})

        wd = AccountWatchdog(session_manager=sm, poll_interval=60.0)
        stats = await wd.tick_once()
        await asyncio.sleep(0.05)

        assert stats["retried"] == 1
        sm.connect.assert_awaited_once_with("Adm")

    @pytest.mark.asyncio
    async def test_session_not_registered_is_skipped(self, mock_listing) -> None:
        mock_listing.append(SessionListItem(session_id="Cold", state="error"))
        sm = _FakeSessionManager(registered=set())

        wd = AccountWatchdog(session_manager=sm)
        stats = await wd.tick_once()

        assert stats["skipped_not_registered"] == 1
        assert stats["retried"] == 0
        sm.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_banned_or_needs_auth_is_left_alone(self, mock_listing) -> None:
        mock_listing.extend(
            [
                SessionListItem(session_id="B", state="banned"),
                SessionListItem(session_id="N", state="needs_code"),
            ]
        )
        sm = _FakeSessionManager(registered={"B", "N"})

        wd = AccountWatchdog(session_manager=sm)
        stats = await wd.tick_once()

        assert stats["retried"] == 0
        assert stats["skipped_human_needed"] == 2
        sm.connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_backoff_blocks_second_attempt_after_failed_reconnect(self, mock_listing) -> None:
        """When reconnect fails the backoff state must survive and
        prevent another attempt in the same window."""
        mock_listing.append(SessionListItem(session_id="X", state="error"))
        sm = _FakeSessionManager(registered={"X"})
        sm.connect.side_effect = RuntimeError("boom")

        wd = AccountWatchdog(session_manager=sm)
        first = await wd.tick_once()
        # Wait for the fire-and-forget task to hit the exception path.
        await asyncio.sleep(0.05)
        second = await wd.tick_once()

        assert first["retried"] == 1
        assert second["retried"] == 0
        assert second["skipped_backoff"] == 1

    @pytest.mark.asyncio
    async def test_successful_reconnect_resets_backoff(self, mock_listing) -> None:
        mock_listing.append(SessionListItem(session_id="R", state="error"))
        sm = _FakeSessionManager(registered={"R"})

        wd = AccountWatchdog(session_manager=sm)
        await wd.tick_once()
        await asyncio.sleep(0.05)

        # Simulate the session becoming healthy on next tick.
        mock_listing.clear()
        mock_listing.append(SessionListItem(session_id="R", state="connected"))

        stats = await wd.tick_once()
        assert stats["skipped_human_needed"] == 1
        rs = wd._retry_state.get("R")
        assert rs is None or rs.ladder_idx == 0

    @pytest.mark.asyncio
    async def test_busy_reconnect_skipped_on_next_tick(self, mock_listing) -> None:
        """If a previous reconnect is still running when the next tick
        fires, we must NOT kick off another one for the same session —
        otherwise a slow ``connect()`` can accumulate duplicate retries
        (seen with 10 error-state accounts and a hanging Telegram)."""
        mock_listing.append(SessionListItem(session_id="Slow", state="error"))
        sm = _FakeSessionManager(registered={"Slow"})

        # Make connect() hang until we release it.
        gate = asyncio.Event()

        async def _hold(_sid: str):
            await gate.wait()

        sm.connect.side_effect = _hold

        wd = AccountWatchdog(session_manager=sm)
        first = await wd.tick_once()
        # Don't wait for the task — it's stuck inside connect().
        second = await wd.tick_once()

        assert first["retried"] == 1
        assert second["retried"] == 0
        assert second["skipped_already_retrying"] == 1

        gate.set()
        # Let the hanging reconnect finish so pytest teardown is clean.
        rs = wd._retry_state["Slow"]
        assert rs.active_task is not None
        await rs.active_task

    @pytest.mark.asyncio
    async def test_stop_cancels_pending_reconnect_tasks(self, mock_listing) -> None:
        """``stop()`` must not leak fire-and-forget reconnect tasks
        that are sleeping inside a hung ``session_manager.connect``.
        Before 0.42.1 those tasks survived shutdown and raced with
        ``disconnect_all`` on SIGINT (client.connect() on a closed
        client → noisy tracebacks + partial sessions).
        """
        mock_listing.append(SessionListItem(session_id="Hung", state="error"))
        sm = _FakeSessionManager(registered={"Hung"})

        # connect() hangs forever — simulates a dead Telegram handshake.
        never = asyncio.Event()

        async def _block(_sid: str):
            await never.wait()

        sm.connect.side_effect = _block

        wd = AccountWatchdog(session_manager=sm, poll_interval=60.0)
        await wd.start()
        await wd.tick_once()
        # Give create_task a cycle to schedule.
        await asyncio.sleep(0)

        rs = wd._retry_state["Hung"]
        assert rs.active_task is not None
        assert not rs.active_task.done()

        await wd.stop(timeout=1.0)

        assert rs.active_task.done(), "stop() must cancel in-flight reconnects"
        assert rs.active_task.cancelled() or rs.active_task.exception() is not None

    @pytest.mark.asyncio
    async def test_user_pool_not_involved(self, mock_listing) -> None:
        """Watchdog calls ``list_stored_sessions(user_id="admin")`` —
        user-owned sessions are filtered out at the listing layer by the
        owner field. This test pins that wiring by asserting the
        ``user_id`` kwarg passed in."""
        import chatfilter.web.routers.sessions.listing as listing_mod

        captured: dict[str, Any] = {}

        def capture(**kw):
            captured.update(kw)
            return []

        # Override the fixture's stub for this one test.
        listing_mod.list_stored_sessions = capture  # type: ignore[assignment]

        sm = _FakeSessionManager(registered=set())
        wd = AccountWatchdog(session_manager=sm)
        await wd.tick_once()

        assert captured.get("user_id") == "admin"
