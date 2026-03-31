"""Background scheduler for periodic chat metrics updates.

Runs every 24 hours, fetching recent messages for all subscribed chats
and updating catalog metrics with EMA averaging.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from chatfilter.telegram.client.messages import _telethon_message_to_model
from chatfilter.telegram.flood_tracker import get_flood_tracker
from chatfilter.telegram.rate_limiter import get_rate_limiter
from chatfilter.telegram.session.models import SessionState

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.telegram.session import SessionManager

logger = logging.getLogger(__name__)

UPDATE_INTERVAL_SECONDS = 24 * 60 * 60  # 24 hours
MESSAGES_WINDOW_HOURS = 24
FETCH_TIMEOUT = 60  # seconds per chat
INTER_CHAT_DELAY = (1.0, 2.0)  # random delay between chats


class ChatMetricsUpdater:
    """Periodically updates metrics for all subscribed chats."""

    def __init__(
        self,
        session_manager: SessionManager,
        db: GroupDatabase,
    ) -> None:
        self._session_manager = session_manager
        self._db = db
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._cycle_running = False

    def start(self) -> None:
        """Start the scheduler background task."""
        if self._task is not None and not self._task.done():
            logger.warning("Chat metrics updater already running")
            return

        self._stop_event.clear()
        self._task = asyncio.create_task(self._scheduler_loop())
        logger.info("Chat metrics updater started (interval=%ds)", UPDATE_INTERVAL_SECONDS)

    async def stop(self) -> None:
        """Stop the scheduler background task."""
        if self._task is None or self._task.done():
            return

        self._stop_event.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        logger.info("Chat metrics updater stopped")

    async def _scheduler_loop(self) -> None:
        """Main loop: run update cycle, sleep, repeat."""
        while not self._stop_event.is_set():
            try:
                await self._run_update_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Unexpected error in metrics update cycle")

            # Wait for next cycle or stop
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=UPDATE_INTERVAL_SECONDS,
                )
                break  # stop event set
            except TimeoutError:
                continue  # time for next cycle

    async def _run_update_cycle(self) -> None:
        """Fetch messages and update metrics for all subscribed chats."""
        if self._cycle_running:
            logger.warning("Previous cycle still running, skipping")
            return

        self._cycle_running = True
        try:
            await self._run_update_cycle_inner()
        finally:
            self._cycle_running = False

    async def _run_update_cycle_inner(self) -> None:
        """Internal implementation of the update cycle."""
        start = time.monotonic()
        subscriptions = self._db.get_subscribed_chats()

        if not subscriptions:
            logger.debug("No subscribed chats to update")
            return

        # Group by account_id for sequential processing per account
        by_account: dict[str, list[tuple[str, int]]] = {}
        for account_id, catalog_chat_id, telegram_chat_id in subscriptions:
            by_account.setdefault(account_id, []).append((catalog_chat_id, telegram_chat_id))

        updated = 0
        errors = 0

        for account_id, chats in by_account.items():
            # Skip accounts that are flood-waited
            flood_tracker = get_flood_tracker()
            if flood_tracker.is_blocked(account_id):
                logger.info("Skipping account '%s' — flood-waited", account_id)
                continue

            # Check if session is connected
            info = self._session_manager.get_info(account_id)
            if info is None or info.state != SessionState.CONNECTED:
                logger.debug(
                    "Skipping account '%s' — not connected (state=%s)",
                    account_id,
                    info.state if info else "unknown",
                )
                continue

            # Get the client from the managed session
            session = self._session_manager._sessions.get(account_id)
            if session is None or session.state != SessionState.CONNECTED:
                continue
            client = session.client

            for catalog_chat_id, telegram_chat_id in chats:
                if self._stop_event.is_set():
                    break

                try:
                    metrics = await self._fetch_chat_metrics(client, telegram_chat_id)
                    if metrics is not None:
                        self._db.update_catalog_metrics(
                            catalog_chat_id, metrics, use_ema=True, alpha=0.3
                        )
                        updated += 1
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.warning(
                        "Failed to update metrics for chat '%s' via account '%s'",
                        catalog_chat_id,
                        account_id,
                        exc_info=True,
                    )
                    errors += 1

                # Inter-chat delay
                await asyncio.sleep(random.uniform(*INTER_CHAT_DELAY))

        elapsed = time.monotonic() - start
        logger.info(
            "Metrics update cycle complete: updated=%d, errors=%d, took=%.1fs",
            updated,
            errors,
            elapsed,
        )

    async def _fetch_chat_metrics(
        self, client: object, telegram_chat_id: int
    ) -> dict[str, float] | None:
        """Fetch messages for last 24h and compute activity metrics.

        Returns:
            Dict with messages_per_hour and unique_authors_per_hour, or None if no data.
        """
        from telethon import TelegramClient

        assert isinstance(client, TelegramClient)

        rate_limiter = get_rate_limiter()
        cutoff_time = datetime.now(UTC) - timedelta(hours=MESSAGES_WINDOW_HOURS)
        msg_count = 0
        authors: set[int] = set()

        async def _fetch() -> None:
            nonlocal msg_count, authors
            await rate_limiter.wait_if_needed("get_messages")
            async for msg in client.iter_messages(telegram_chat_id, limit=5000):
                converted = _telethon_message_to_model(msg, telegram_chat_id)
                if converted is None:
                    continue
                if converted.timestamp < cutoff_time:
                    break
                msg_count += 1
                authors.add(converted.author_id)

        try:
            await asyncio.wait_for(_fetch(), timeout=FETCH_TIMEOUT)
        except TimeoutError:
            logger.debug(
                "Fetch timeout for chat %d (partial data: %d messages)",
                telegram_chat_id,
                msg_count,
            )

        if msg_count == 0 and not authors:
            return {
                "messages_per_hour": 0.0,
                "unique_authors_per_hour": 0.0,
            }

        hours = MESSAGES_WINDOW_HOURS
        return {
            "messages_per_hour": round(msg_count / hours, 2),
            "unique_authors_per_hour": round(len(authors) / hours, 2),
        }
