"""Proxy health monitoring service.

Provides background health checks for proxies to detect and auto-disable
non-working proxies. Proxies are tested via TCP connection and optionally
SOCKS5/HTTP handshake.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import socks

from chatfilter.config import ProxyStatus, ProxyType
from chatfilter.models.proxy import ProxyEntry
from chatfilter.storage.proxy_pool import load_proxy_pool, update_proxy

logger = logging.getLogger(__name__)

# Health check configuration
HEALTH_CHECK_TIMEOUT = 10.0  # seconds per proxy
MAX_CONSECUTIVE_FAILURES = 3  # failures before auto-disable

# Telegram DC2 for SOCKS5 tunnel verification
TELEGRAM_DC2_HOST = "149.154.167.51"
TELEGRAM_DC2_PORT = 443

# Thread pool for blocking SOCKS5 operations
_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    """Get or create thread pool executor for SOCKS5 operations."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="socks5-health")
    return _executor


class ProxyCheckError(Exception):
    """Sanitized proxy check error that doesn't leak credentials."""

    pass


def _socks5_connect_sync(
    proxy_host: str,
    proxy_port: int,
    proxy_username: str | None,
    proxy_password: str | None,
    target_host: str,
    target_port: int,
    timeout: float,
) -> bool:
    """Synchronous SOCKS5 tunnel check (runs in thread pool).

    Args:
        proxy_host: Proxy server hostname/IP
        proxy_port: Proxy server port
        proxy_username: SOCKS5 auth username (optional)
        proxy_password: SOCKS5 auth password (optional)
        target_host: Target host to connect through proxy
        target_port: Target port
        timeout: Connection timeout in seconds

    Returns:
        True if tunnel established successfully

    Raises:
        ProxyCheckError: Sanitized error (no credentials leaked)
    """
    sock = None
    try:
        # Create SOCKS5 socket
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Configure proxy
        sock.set_proxy(
            proxy_type=socks.SOCKS5,
            addr=proxy_host,
            port=proxy_port,
            username=proxy_username,
            password=proxy_password,
        )

        # Connect through SOCKS5 to target
        sock.connect((target_host, target_port))

        # Success
        return True

    except socks.SOCKS5AuthError as e:
        # Auth failure - sanitize to avoid leaking username/password
        raise ProxyCheckError("Authentication failed") from e

    except Exception as e:
        # All other errors - sanitize to avoid leaking proxy details
        raise ProxyCheckError("Proxy unreachable") from e

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


async def socks5_tunnel_check(
    proxy: ProxyEntry,
    target_host: str = TELEGRAM_DC2_HOST,
    target_port: int = TELEGRAM_DC2_PORT,
    timeout: float = HEALTH_CHECK_TIMEOUT,
) -> bool:
    """Test SOCKS5 proxy by establishing tunnel to target host.

    Performs full SOCKS5 handshake and connection to verify the proxy
    can actually tunnel traffic (not just accept TCP connections).

    Args:
        proxy: The proxy to test (must be SOCKS5 type)
        target_host: Target host to connect through proxy
        target_port: Target port
        timeout: Connection timeout in seconds

    Returns:
        True if SOCKS5 tunnel established successfully, False otherwise.

    Note:
        Exceptions are sanitized to prevent credential leakage in logs.
    """
    try:
        # Run blocking SOCKS5 connect in thread pool
        result = await asyncio.get_event_loop().run_in_executor(
            _get_executor(),
            _socks5_connect_sync,
            proxy.host,
            proxy.port,
            proxy.username,
            proxy.password,
            target_host,
            target_port,
            timeout,
        )
        return result

    except ProxyCheckError as e:
        # Sanitized error - safe to log
        logger.debug(f"SOCKS5 tunnel check failed for {proxy.name}: {e}")
        return False

    except Exception as e:
        # Unexpected error - log generically without proxy details
        logger.warning(f"Unexpected error during SOCKS5 tunnel check: {type(e).__name__}")
        return False


async def check_proxy_health(proxy: ProxyEntry, timeout: float = HEALTH_CHECK_TIMEOUT) -> bool:
    """Test if a proxy is reachable and functional.

    For SOCKS5 proxies: Performs full SOCKS5 handshake + tunnel to Telegram DC.
    For HTTP proxies: Performs TCP-only check (HTTP CONNECT handled by Telethon).

    Args:
        proxy: The proxy to test.
        timeout: Connection timeout in seconds.

    Returns:
        True if proxy is reachable and functional, False otherwise.
    """
    # SOCKS5 proxies: full tunnel check
    if proxy.type == ProxyType.SOCKS5:
        tunnel_success = await socks5_tunnel_check(proxy, timeout=timeout)

        if tunnel_success:
            logger.debug(f"SOCKS5 tunnel check passed: {proxy.name} ({proxy.host}:{proxy.port})")
            return True

        # SOCKS5 tunnel failed - try TCP-only for diagnostics
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()

            # TCP works but SOCKS5 tunnel failed - log for diagnostics
            logger.warning(
                f"SOCKS5 tunnel failed but TCP works: {proxy.name} ({proxy.host}:{proxy.port}) "
                f"- possible auth/protocol issue"
            )

        except Exception:
            # Both tunnel and TCP failed - normal failure
            pass

        return False

    # HTTP proxies: TCP-only check (HTTP CONNECT is protocol-specific)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port),
            timeout=timeout,
        )

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

    # Save to storage (let errors propagate)
    update_proxy(proxy.id, updated_proxy)
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

    Resets the failure counter in-memory and performs a health check.
    The health check result (WORKING or NO_PING) is saved directly by check_single_proxy.
    No intermediate UNTESTED status is saved.

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

    # Reset consecutive_failures in-memory only (don't save UNTESTED)
    reset_proxy = proxy.with_status_reset()

    # Perform health check - this will save WORKING or NO_PING directly
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
