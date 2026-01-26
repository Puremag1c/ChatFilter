"""Proxy health monitoring service.

Provides background health checks for proxies to detect and auto-disable
non-working proxies. Proxies are tested via TCP connection and optionally
SOCKS5/HTTP handshake.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime

from chatfilter.config import ProxyStatus
from chatfilter.models.proxy import ProxyEntry
from chatfilter.storage.proxy_pool import load_proxy_pool, update_proxy

logger = logging.getLogger(__name__)

# Health check configuration
HEALTH_CHECK_TIMEOUT = 10.0  # seconds per proxy
MAX_CONSECUTIVE_FAILURES = 3  # failures before auto-disable


async def check_proxy_health(proxy: ProxyEntry, timeout: float = HEALTH_CHECK_TIMEOUT) -> bool:
    """Test if a proxy is reachable via TCP connection.

    Performs a simple TCP connect to verify the proxy server is accepting
    connections. Does not perform full SOCKS5/HTTP protocol handshake to
    keep checks fast and avoid triggering rate limits.

    Args:
        proxy: The proxy to test.
        timeout: Connection timeout in seconds.

    Returns:
        True if proxy is reachable, False otherwise.
    """
    try:
        # Create TCP connection to proxy
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port),
            timeout=timeout,
        )

        # Close connection
        writer.close()
        await writer.wait_closed()

        logger.debug(f"Proxy health check passed: {proxy.name} ({proxy.host}:{proxy.port})")
        return True

    except TimeoutError:
        logger.debug(f"Proxy health check timeout: {proxy.name} ({proxy.host}:{proxy.port})")
        return False
    except OSError as e:
        logger.debug(f"Proxy health check failed: {proxy.name} ({proxy.host}:{proxy.port}) - {e}")
        return False
    except Exception as e:
        logger.warning(
            f"Unexpected error during proxy health check: {proxy.name} "
            f"({proxy.host}:{proxy.port}) - {e}"
        )
        return False


async def update_proxy_health(proxy: ProxyEntry, success: bool) -> ProxyEntry:
    """Update proxy health status in storage.

    Args:
        proxy: The proxy to update.
        success: Whether the health check was successful.

    Returns:
        Updated ProxyEntry instance.
    """
    now = datetime.now(UTC)
    updated_proxy = proxy.with_health_update(success=success, ping_time=now)

    # Log status changes
    if updated_proxy.status != proxy.status:
        if updated_proxy.status == ProxyStatus.NO_PING:
            logger.warning(
                f"Proxy auto-disabled after {MAX_CONSECUTIVE_FAILURES} failures: "
                f"{proxy.name} ({proxy.host}:{proxy.port})"
            )
        elif updated_proxy.status == ProxyStatus.WORKING:
            logger.info(f"Proxy now working: {proxy.name} ({proxy.host}:{proxy.port})")

    # Save to storage
    try:
        update_proxy(proxy.id, updated_proxy)
    except Exception as e:
        logger.error(f"Failed to save proxy health status: {proxy.name} - {e}")

    return updated_proxy


async def check_single_proxy(proxy: ProxyEntry) -> ProxyEntry:
    """Check health of a single proxy and update its status.

    Args:
        proxy: The proxy to check.

    Returns:
        Updated ProxyEntry with new health status.
    """
    success = await check_proxy_health(proxy)
    return await update_proxy_health(proxy, success)


async def check_all_proxies() -> dict[str, ProxyEntry]:
    """Check health of all proxies in the pool.

    Runs checks concurrently for efficiency.

    Returns:
        Dict mapping proxy ID to updated ProxyEntry.
    """
    proxies = load_proxy_pool()
    if not proxies:
        logger.debug("No proxies to health check")
        return {}

    logger.info(f"Starting health check for {len(proxies)} proxies")

    # Run all checks concurrently
    tasks = [check_single_proxy(proxy) for proxy in proxies]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    updated_proxies: dict[str, ProxyEntry] = {}
    for proxy, result in zip(proxies, results, strict=True):
        if isinstance(result, Exception):
            logger.error(f"Failed to check proxy {proxy.name}: {result}")
        elif isinstance(result, ProxyEntry):
            updated_proxies[result.id] = result

    # Summary logging
    working = sum(1 for p in updated_proxies.values() if p.status == ProxyStatus.WORKING)
    no_ping = sum(1 for p in updated_proxies.values() if p.status == ProxyStatus.NO_PING)
    untested = sum(1 for p in updated_proxies.values() if p.status == ProxyStatus.UNTESTED)

    logger.info(
        f"Health check complete: {working} working, {no_ping} disabled, {untested} untested"
    )

    return updated_proxies


async def retest_proxy(proxy_id: str) -> ProxyEntry | None:
    """Reset and retest a specific proxy.

    Resets the failure counter and status, then performs a health check.
    Used when user clicks "Retest" button.

    Args:
        proxy_id: ID of the proxy to retest.

    Returns:
        Updated ProxyEntry, or None if proxy not found.
    """
    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id

    try:
        proxy = get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        logger.warning(f"Proxy not found for retest: {proxy_id}")
        return None

    # Reset status to untested
    reset_proxy = proxy.with_status_reset()
    try:
        update_proxy(proxy_id, reset_proxy)
    except Exception as e:
        logger.error(f"Failed to reset proxy status: {proxy.name} - {e}")
        return None

    # Perform health check
    logger.info(f"Retesting proxy: {proxy.name} ({proxy.host}:{proxy.port})")
    return await check_single_proxy(reset_proxy)


class ProxyHealthMonitor:
    """Background health monitor for proxies.

    Periodically checks all proxies and updates their status.
    Can be started/stopped as part of application lifecycle.
    """

    def __init__(self, interval_seconds: float = 300.0):
        """Initialize the health monitor.

        Args:
            interval_seconds: Seconds between health checks (default: 5 minutes).
        """
        self.interval = interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._running = False

    async def _run_loop(self) -> None:
        """Main monitoring loop."""
        logger.info(f"Proxy health monitor started (interval: {self.interval}s)")

        # Run initial check after short delay
        await asyncio.sleep(10.0)

        while self._running:
            try:
                await check_all_proxies()
            except Exception as e:
                logger.error(f"Error in proxy health check loop: {e}")

            # Wait for next interval
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break

        logger.info("Proxy health monitor stopped")

    def start(self) -> None:
        """Start the health monitor background task."""
        if self._running:
            logger.warning("Proxy health monitor already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.debug("Proxy health monitor task created")

    async def stop(self) -> None:
        """Stop the health monitor background task."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        logger.debug("Proxy health monitor stopped")


# Global instance (singleton pattern)
_health_monitor: ProxyHealthMonitor | None = None


def get_proxy_health_monitor() -> ProxyHealthMonitor:
    """Get or create the global proxy health monitor instance."""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = ProxyHealthMonitor()
    return _health_monitor
