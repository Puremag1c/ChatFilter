"""AccountWatchdog — keeps the shared admin pool alive.

When an admin-pool session falls into ``error`` / ``disconnected``
(not a human-needs-to-help state like ``banned`` / ``needs_code``
/ ``needs_2fa`` / ``needs_config``), this background task tries to
reconnect it automatically through the existing
``SessionManager.connect(session_id)`` path. Per-account exponential
backoff prevents the loop from hammering a dead account.

Scope is admin-pool only — user-owned sessions are never touched.
The watchdog uses ``list_stored_sessions(user_id="admin")`` which
filters by the session's ``.account_info.json`` owner.

Lifespan is managed from ``web/app.py`` alongside the existing
``ProxyHealthMonitor``. Shutdown is co-operative (``_stop`` event).

Limitation: the watchdog can only reconnect sessions whose factory is
already registered in the ``SessionManager`` (it was connected at
least once in this process). After a fresh server start this means
the admin has to click Connect once per account; from then on we
hold the line.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# States the watchdog will retry on its own — everything else needs a human.
AUTO_RECOVERABLE_STATES = frozenset({"error", "disconnected"})

# Exponential-backoff ladder (seconds). After reaching the top the
# watchdog keeps retrying at that cadence, which is 30 min.
BACKOFF_LADDER = (30, 120, 600, 1800)


@dataclass
class _AccountRetryState:
    """Per-account backoff bookkeeping — purely in-memory."""

    ladder_idx: int = 0
    next_attempt_at: float = 0.0  # unix timestamp
    # Handle on the in-flight reconnect task so a slow ``connect()``
    # doesn't accumulate duplicate retries across ticks.
    active_task: asyncio.Task[None] | None = None

    def should_retry(self, now: float) -> bool:
        return now >= self.next_attempt_at

    def is_busy(self) -> bool:
        return self.active_task is not None and not self.active_task.done()

    def record_attempt(self, now: float) -> None:
        delay = BACKOFF_LADDER[min(self.ladder_idx, len(BACKOFF_LADDER) - 1)]
        self.next_attempt_at = now + delay
        self.ladder_idx = min(self.ladder_idx + 1, len(BACKOFF_LADDER) - 1)

    def reset(self) -> None:
        self.ladder_idx = 0
        self.next_attempt_at = 0.0


class AccountWatchdog:
    """Background task that auto-reconnects admin-pool accounts."""

    def __init__(
        self,
        session_manager: Any,
        *,
        poll_interval: float = 60.0,
    ) -> None:
        self._sm = session_manager
        self._poll_interval = poll_interval
        self._retry_state: dict[str, _AccountRetryState] = {}
        self._stop = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None

    # ---- lifecycle ---------------------------------------------------

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._loop(), name="account-watchdog")
        logger.info("AccountWatchdog started (poll=%ss)", self._poll_interval)

    async def stop(self, *, timeout: float = 5.0) -> None:
        if self._loop_task is None:
            return
        self._stop.set()

        # Fire-and-forget reconnect tasks from prior ticks may still be
        # sleeping inside ``session_manager.connect``. Cancel them before
        # we wait on the loop — otherwise they leak past shutdown and
        # race with ``session_manager.disconnect_all`` on SIGINT.
        pending = [
            rs.active_task
            for rs in self._retry_state.values()
            if rs.active_task is not None and not rs.active_task.done()
        ]
        for t in pending:
            t.cancel()

        try:
            await asyncio.wait_for(self._loop_task, timeout=timeout)
        except TimeoutError:
            self._loop_task.cancel()
        self._loop_task = None

        if pending:
            import contextlib

            for t in pending:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await t
        logger.info("AccountWatchdog stopped")

    # ---- loop --------------------------------------------------------

    async def _loop(self) -> None:
        import contextlib

        while not self._stop.is_set():
            try:
                await self.tick_once()
            except Exception:
                logger.exception("AccountWatchdog tick raised")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._poll_interval)

    async def tick_once(self) -> dict[str, Any]:
        """One pass over admin sessions. Kicks off reconnect for those
        whose state is recoverable and whose backoff window has elapsed.

        Returns a stats dict ``{"scanned", "retried", "skipped_backoff",
        "skipped_not_registered", "skipped_human_needed"}``.
        """
        from chatfilter.web.routers.sessions.listing import list_stored_sessions

        stats = {
            "scanned": 0,
            "retried": 0,
            "skipped_backoff": 0,
            "skipped_not_registered": 0,
            "skipped_human_needed": 0,
            "skipped_already_retrying": 0,
        }
        now = time.time()

        try:
            sessions = list_stored_sessions(user_id="admin")
        except Exception:
            logger.exception("watchdog: list_stored_sessions failed")
            return stats

        for sess in sessions:
            stats["scanned"] += 1
            state = sess.state or "disconnected"

            if state not in AUTO_RECOVERABLE_STATES:
                stats["skipped_human_needed"] += 1
                # Clear backoff — state transitioned away from error.
                self._retry_state.pop(sess.session_id, None)
                continue

            if not self._is_factory_registered(sess.session_id):
                stats["skipped_not_registered"] += 1
                continue

            rs = self._retry_state.setdefault(sess.session_id, _AccountRetryState())
            if rs.is_busy():
                # Previous connect() is still running — don't pile on.
                stats["skipped_already_retrying"] += 1
                continue
            if not rs.should_retry(now):
                stats["skipped_backoff"] += 1
                continue

            rs.record_attempt(now)
            stats["retried"] += 1
            # Fire-and-forget; SessionManager.connect publishes SSE on
            # its own and the watchdog resets backoff when the next
            # tick sees CONNECTED.
            rs.active_task = asyncio.create_task(
                self._reconnect_one(sess.session_id),
                name=f"watchdog-reconnect-{sess.session_id}",
            )

        # Reset backoff for sessions that are now healthy.
        healthy = {s.session_id for s in sessions if s.state == "connected"}
        for sid in list(self._retry_state):
            if sid in healthy:
                self._retry_state[sid].reset()

        return stats

    # ---- helpers -----------------------------------------------------

    def _is_factory_registered(self, session_id: str) -> bool:
        """True when the SessionManager has a loader for this session.

        The watchdog can only reconnect what was at least once connected
        in the current process. Freshly-booted server → factories
        empty → skip until the admin clicks Connect once.
        """
        factories = getattr(self._sm, "_factories", None)
        if factories is None:
            return False
        return session_id in factories

    async def _reconnect_one(self, session_id: str) -> None:
        """Trigger one reconnect. Backoff reset is the NEXT tick's job —
        it only clears state when it observes ``state == "connected"``,
        which is the real proof of success. ``connect()`` can return
        without raising even when the session is still broken (e.g. it
        surfaced a non-fatal internal error), so we don't treat a
        successful await as definitive."""
        try:
            logger.info("watchdog: reconnecting '%s'", session_id)
            await self._sm.connect(session_id)
            logger.info("watchdog: '%s' reconnect call returned", session_id)
        except Exception as e:
            logger.warning("watchdog: reconnect of '%s' failed: %s", session_id, e)


# ---------------------------------------------------------------------------
# Module-level singleton — attached to the app via lifespan.
# ---------------------------------------------------------------------------

_watchdog: AccountWatchdog | None = None


def get_account_watchdog() -> AccountWatchdog | None:
    return _watchdog


def set_account_watchdog(wd: AccountWatchdog | None) -> None:
    global _watchdog
    _watchdog = wd
