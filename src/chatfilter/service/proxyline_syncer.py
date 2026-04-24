"""Hourly background sync of ProxyLine expiry dates for admin-pool proxies.

Reads every entry in ``proxies_admin.json`` that carries a
``proxyline_id``, looks up the matching order via
``ProxylineClient.list_proxies()``, and updates ``expires_at`` so the
Monitor dashboard's "expiring in <N days" banner stays fresh without
calling ProxyLine on every dashboard poll.

Admin-pool only — user-pool proxies have no ``proxyline_id`` because
power-users can use any proxy source, and the syncer would ignore
them even if they did.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


DEFAULT_INTERVAL = 3600.0  # 1 hour — ProxyLine expiries change at day granularity


class ProxylineSyncer:
    """Background task that keeps ``expires_at`` fresh for admin proxies.

    Lifecycle mirrors ``ProxyHealthMonitor`` / ``AccountWatchdog``
    (start/stop + internal stop event). Tolerant of missing API key
    (silently no-ops).
    """

    def __init__(self, *, interval: float = DEFAULT_INTERVAL) -> None:
        self._interval = interval
        self._stop = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._loop(), name="proxyline-syncer")
        logger.info("ProxylineSyncer started (interval=%ss)", self._interval)

    async def stop(self, *, timeout: float = 5.0) -> None:
        if self._loop_task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._loop_task, timeout=timeout)
        except TimeoutError:
            self._loop_task.cancel()
        self._loop_task = None
        logger.info("ProxylineSyncer stopped")

    async def _loop(self) -> None:
        # First run slightly delayed so startup is quick; subsequent
        # runs on the full interval. ``wait_for(stop.wait(), timeout)``
        # acts like ``sleep(timeout)`` but returns early on shutdown —
        # plain ``asyncio.sleep`` here would delay shutdown by up to 30 s.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=30.0)
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:
                logger.exception("ProxylineSyncer tick failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)

    async def run_once(self) -> dict[str, Any]:
        """One sync pass. Returns stats."""
        from chatfilter.service.proxyline_client import ProxylineError, get_proxyline_client
        from chatfilter.storage.proxy_pool import load_proxy_pool, save_proxy_pool

        stats = {"synced": 0, "unchanged": 0, "missing_remote": 0, "skipped_no_key": 0}

        api_key = _get_proxyline_api_key()
        if not api_key:
            stats["skipped_no_key"] = 1
            return stats

        client = get_proxyline_client(api_key)
        if client is None:
            stats["skipped_no_key"] = 1
            return stats

        try:
            remote = await client.list_proxies(status="active")
        except ProxylineError as e:
            logger.warning("proxyline sync: list_proxies failed: %s", e)
            return stats

        # Build {remote_id: expires_at} index.
        remote_by_id: dict[int, datetime | None] = {}
        for item in remote:
            try:
                rid = int(item["id"])
            except (KeyError, TypeError, ValueError):
                continue
            remote_by_id[rid] = _parse_expires(item.get("expires_at"))

        proxies = load_proxy_pool("admin")
        changed = False
        updated: list[Any] = []
        for p in proxies:
            if p.proxyline_id is None:
                updated.append(p)
                continue
            new_expiry = remote_by_id.get(p.proxyline_id)
            if new_expiry is None:
                stats["missing_remote"] += 1
                updated.append(p)
                continue
            if p.expires_at == new_expiry:
                stats["unchanged"] += 1
                updated.append(p)
                continue
            # ProxyEntry is frozen — use model_copy.
            updated.append(p.model_copy(update={"expires_at": new_expiry}))
            stats["synced"] += 1
            changed = True

        if changed:
            save_proxy_pool(updated, "admin")
        return stats


def _get_proxyline_api_key() -> str | None:
    """Read the ProxyLine API key from app_settings.

    Falls back to ``None`` when the system isn't fully wired yet (e.g.
    during tests that don't seed the settings table).
    """
    try:
        from chatfilter.config import get_settings
        from chatfilter.storage.group_database import GroupDatabase

        settings = get_settings()
        db = GroupDatabase(settings.effective_database_url)
        raw = db.get_setting("proxyline_api_key")
        return str(raw).strip() if raw else None
    except Exception:
        logger.debug("proxyline sync: could not read API key from settings", exc_info=True)
        return None


def _parse_expires(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            # ProxyLine sends ISO-8601 dates.
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


_syncer: ProxylineSyncer | None = None


def get_proxyline_syncer() -> ProxylineSyncer | None:
    return _syncer


def set_proxyline_syncer(s: ProxylineSyncer | None) -> None:
    global _syncer
    _syncer = s
