"""Network connectivity checker for graceful degradation.

Provides utilities to detect network connectivity issues and handle
offline scenarios gracefully.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Protocol

logger = logging.getLogger(__name__)


@dataclass
class NetworkStatus:
    """Network connectivity status."""

    is_online: bool
    last_check: datetime
    error_message: str | None = None
    check_duration_ms: float | None = None  # Time taken for the check


class NetworkCheckStrategy(Protocol):
    """Protocol for network check strategies."""

    async def check(self) -> NetworkStatus:
        """Check network connectivity.

        Returns:
            NetworkStatus indicating connectivity state
        """
        ...


class DNSCheckStrategy:
    """Check connectivity by resolving well-known DNS names."""

    def __init__(
        self,
        hosts: list[str] | None = None,
        timeout: float = 3.0,
    ) -> None:
        """Initialize DNS check strategy.

        Args:
            hosts: List of hostnames to check (default: major DNS servers)
            timeout: Timeout in seconds for DNS resolution
        """
        self.hosts = hosts or [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "dns.google",  # Google DNS hostname
        ]
        self.timeout = timeout

    async def check(self) -> NetworkStatus:
        """Check network by attempting DNS resolution."""
        start_time = datetime.now(UTC)

        try:
            # Try to resolve each host
            for host in self.hosts:
                try:
                    # Use asyncio to timeout the socket operation
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(
                            None,
                            partial(socket.gethostbyname, host),
                        ),
                        timeout=self.timeout,
                    )
                    # Success - network is online
                    duration = (datetime.now(UTC) - start_time).total_seconds() * 1000
                    return NetworkStatus(
                        is_online=True,
                        last_check=datetime.now(UTC),
                        check_duration_ms=duration,
                    )
                except (TimeoutError, socket.gaierror):
                    # This host failed, try next one
                    continue
                except Exception as e:
                    logger.debug(f"DNS check failed for {host}: {e}")
                    continue

            # All hosts failed
            duration = (datetime.now(UTC) - start_time).total_seconds() * 1000
            return NetworkStatus(
                is_online=False,
                last_check=datetime.now(UTC),
                error_message="Failed to resolve any DNS hosts (network offline)",
                check_duration_ms=duration,
            )

        except Exception as e:
            duration = (datetime.now(UTC) - start_time).total_seconds() * 1000
            logger.warning(f"Network check failed: {e}")
            return NetworkStatus(
                is_online=False,
                last_check=datetime.now(UTC),
                error_message=f"Network check error: {e}",
                check_duration_ms=duration,
            )


class NetworkMonitor:
    """Monitor network connectivity with caching and automatic retry.

    This class provides:
    - Cached network status to avoid excessive checks
    - Configurable check strategies (DNS, Telegram API, etc.)
    - Automatic health monitoring with periodic checks
    - Graceful degradation support

    Example:
        ```python
        monitor = NetworkMonitor(strategy=DNSCheckStrategy())

        # Check current status
        status = await monitor.get_status()
        if not status.is_online:
            # Handle offline scenario
            print("Network is offline, showing cached data")

        # Or check and raise if offline
        await monitor.ensure_online()
        ```
    """

    def __init__(
        self,
        strategy: NetworkCheckStrategy | None = None,
        cache_ttl_seconds: float = 30.0,
        auto_recheck_on_failure: bool = True,
        failure_recheck_delay: float = 5.0,
    ) -> None:
        """Initialize network monitor.

        Args:
            strategy: Network check strategy (default: DNSCheckStrategy)
            cache_ttl_seconds: How long to cache status before rechecking
            auto_recheck_on_failure: If True, automatically recheck after failure
            failure_recheck_delay: Delay before rechecking after failure
        """
        self._strategy = strategy or DNSCheckStrategy()
        self._cache_ttl_seconds = cache_ttl_seconds
        self._auto_recheck_on_failure = auto_recheck_on_failure
        self._failure_recheck_delay = failure_recheck_delay
        self._cached_status: NetworkStatus | None = None
        self._check_lock = asyncio.Lock()

    def _is_cache_valid(self) -> bool:
        """Check if cached status is still valid."""
        if self._cached_status is None:
            return False

        age = (datetime.now(UTC) - self._cached_status.last_check).total_seconds()
        return age < self._cache_ttl_seconds

    async def get_status(self, force_check: bool = False) -> NetworkStatus:
        """Get current network status.

        Args:
            force_check: If True, bypass cache and perform fresh check

        Returns:
            NetworkStatus indicating connectivity state
        """
        # Use cached status if valid and not forcing check
        if not force_check and self._is_cache_valid():
            assert self._cached_status is not None  # Guaranteed by _is_cache_valid()
            return self._cached_status

        # Perform fresh check (with lock to prevent concurrent checks)
        async with self._check_lock:
            # Double-check cache inside lock (another task may have checked)
            if not force_check and self._is_cache_valid():
                assert self._cached_status is not None  # Guaranteed by _is_cache_valid()
                return self._cached_status

            # Perform actual network check
            status = await self._strategy.check()
            self._cached_status = status

            # Log status changes
            duration_str = (
                f"{status.check_duration_ms:.0f}ms" if status.check_duration_ms else "N/A"
            )
            if status.is_online:
                logger.info(f"Network check: ONLINE (took {duration_str})")
            else:
                logger.warning(
                    f"Network check: OFFLINE - {status.error_message} (took {duration_str})"
                )

            return status

    async def is_online(self, force_check: bool = False) -> bool:
        """Check if network is currently online.

        Args:
            force_check: If True, bypass cache and perform fresh check

        Returns:
            True if online, False otherwise
        """
        status = await self.get_status(force_check=force_check)
        return status.is_online

    async def ensure_online(
        self,
        error_message: str = "Network connection unavailable. Please check your internet connection.",
    ) -> None:
        """Ensure network is online, raise exception if offline.

        Args:
            error_message: Error message to include in exception

        Raises:
            NetworkOfflineError: If network is offline
        """
        status = await self.get_status()
        if not status.is_online:
            raise NetworkOfflineError(
                error_message,
                last_check=status.last_check,
                check_error=status.error_message,
            )

    async def wait_for_connectivity(
        self,
        max_wait_seconds: float = 60.0,
        check_interval: float = 5.0,
    ) -> bool:
        """Wait for network connectivity to be restored.

        Args:
            max_wait_seconds: Maximum time to wait in seconds
            check_interval: Interval between checks in seconds

        Returns:
            True if connectivity restored, False if timeout reached
        """
        start_time = datetime.now(UTC)
        logger.info(f"Waiting for network connectivity (max {max_wait_seconds}s)...")

        while True:
            status = await self.get_status(force_check=True)
            if status.is_online:
                elapsed = (datetime.now(UTC) - start_time).total_seconds()
                logger.info(f"Network connectivity restored after {elapsed:.1f}s")
                return True

            # Check if timeout reached
            elapsed = (datetime.now(UTC) - start_time).total_seconds()
            if elapsed >= max_wait_seconds:
                logger.warning(f"Network connectivity not restored after {elapsed:.1f}s (timeout)")
                return False

            # Wait before next check
            await asyncio.sleep(check_interval)


class NetworkOfflineError(Exception):
    """Raised when network is offline and operation requires connectivity."""

    def __init__(
        self,
        message: str,
        last_check: datetime | None = None,
        check_error: str | None = None,
    ):
        """Initialize error.

        Args:
            message: Error message for user
            last_check: Timestamp of last connectivity check
            check_error: Technical error from connectivity check
        """
        super().__init__(message)
        self.last_check = last_check
        self.check_error = check_error


def detect_network_error(error: Exception) -> bool:
    """Detect if an exception is network-related.

    This function analyzes exceptions to determine if they were caused
    by network connectivity issues, helping with graceful degradation.

    Args:
        error: Exception to analyze

    Returns:
        True if error is network-related, False otherwise

    Example:
        ```python
        try:
            await fetch_data()
        except Exception as e:
            if detect_network_error(e):
                # Show offline UI
                return render_offline_page()
            else:
                # Show generic error
                raise
        ```
    """
    # Check exception type
    # Note: socket.error is an alias for OSError since Python 3.3
    # We handle OSError separately below to filter by errno
    if isinstance(
        error,
        ConnectionError
        | TimeoutError
        | asyncio.TimeoutError
        | socket.gaierror
        | socket.timeout
        | NetworkOfflineError,
    ):
        return True

    # Special handling for OSError (includes PermissionError, FileNotFoundError, etc)
    # Only treat OSError as network error if errno is network-related
    if isinstance(error, OSError):
        import errno

        # Network-related errno codes
        network_errno = {
            errno.ENETUNREACH,  # Network is unreachable
            errno.EHOSTUNREACH,  # Host is unreachable
            errno.ENETDOWN,  # Network is down
            errno.ECONNREFUSED,  # Connection refused
            errno.ECONNRESET,  # Connection reset
            errno.ECONNABORTED,  # Connection aborted
            errno.ETIMEDOUT,  # Connection timed out
            errno.EHOSTDOWN,  # Host is down
        }

        # Check errno if available
        if error.errno in network_errno:
            return True

        # If errno is not set or not network-related, check message keywords
        # (falls through to keyword check below)

    # Check exception message for network keywords
    error_msg = str(error).lower()
    network_keywords = [
        "connection",
        "network",
        "timeout",
        "unreachable",
        "offline",
        "no internet",
        "dns",
        "socket",
        "ssl",
        "certificate",
        "handshake",
    ]

    return any(keyword in error_msg for keyword in network_keywords)


# Global network monitor instance
_network_monitor: NetworkMonitor | None = None


def get_network_monitor(
    strategy: NetworkCheckStrategy | None = None,
    cache_ttl_seconds: float = 30.0,
) -> NetworkMonitor:
    """Get the global network monitor instance.

    Args:
        strategy: Network check strategy (only used on first call)
        cache_ttl_seconds: Cache TTL in seconds (only used on first call)

    Returns:
        NetworkMonitor singleton
    """
    global _network_monitor
    if _network_monitor is None:
        _network_monitor = NetworkMonitor(
            strategy=strategy,
            cache_ttl_seconds=cache_ttl_seconds,
        )
    return _network_monitor


def reset_network_monitor() -> None:
    """Reset the global network monitor (for testing)."""
    global _network_monitor
    _network_monitor = None
