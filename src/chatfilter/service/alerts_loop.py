"""Background loop that evaluates the admin-pool dashboard snapshot
against configured thresholds and dispatches webhook alerts.

Split out from ``notifications.py`` so dependencies flow one way only:

  * ``notifications``   — dispatch primitives, no knowledge of monitor
  * ``monitor``         — snapshot + trigger rules, uses ``notifications``
  * ``alerts_loop``     — scheduling glue that ticks ``monitor`` periodically

Previously the loop lived in ``notifications.py`` and reached into
``monitor.py`` via a late import; that worked but created a visible
cycle. This file avoids the cycle.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

logger = logging.getLogger(__name__)

DEFAULT_ALERTS_INTERVAL = 300.0  # 5 min — balances are cached 5 min anyway
INITIAL_DELAY = 60.0  # let the app settle before the first check


class MonitorAlertsLoop:
    """Runs ``MonitorService.check_and_notify`` on a fixed interval.

    Lifecycle mirrors other background tasks (start/stop + internal
    stop event). On each tick: gather snapshot, dispatch any triggers,
    log failures. A failed tick never crashes the loop.
    """

    def __init__(self, *, interval: float = DEFAULT_ALERTS_INTERVAL) -> None:
        self._interval = interval
        self._stop = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._loop(), name="monitor-alerts")
        logger.info("MonitorAlertsLoop started (interval=%ss)", self._interval)

    async def stop(self, *, timeout: float = 5.0) -> None:
        if self._loop_task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._loop_task, timeout=timeout)
        except TimeoutError:
            self._loop_task.cancel()
            with contextlib.suppress(Exception):
                await self._loop_task
        self._loop_task = None
        logger.info("MonitorAlertsLoop stopped")

    async def _loop(self) -> None:
        # Interruptible initial delay — plain ``asyncio.sleep`` would
        # delay shutdown by up to ``INITIAL_DELAY`` seconds if the stop
        # event arrives before the first tick.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=INITIAL_DELAY)
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:
                logger.exception("MonitorAlertsLoop tick failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)

    async def _tick(self) -> list[str]:
        # Late import — alerts_loop depends on monitor, but monitor
        # already depends on notifications (for WebhookEvent). A direct
        # top-level import here would drag monitor into every import
        # of notifications transitively; the lazy lookup keeps both
        # ``monitor`` and ``alerts_loop`` loadable on their own.
        from chatfilter.service.monitor import get_monitor_service

        svc = get_monitor_service()
        snapshot = await svc.gather()
        return await svc.check_and_notify(snapshot)


_alerts_loop: MonitorAlertsLoop | None = None


def get_alerts_loop() -> MonitorAlertsLoop | None:
    return _alerts_loop


def set_alerts_loop(loop: MonitorAlertsLoop | None) -> None:
    global _alerts_loop
    _alerts_loop = loop
