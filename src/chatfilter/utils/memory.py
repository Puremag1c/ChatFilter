"""Memory monitoring utilities for long-running tasks.

Provides:
- Process memory usage tracking
- Memory threshold monitoring
- Periodic memory logging
- Circuit breaker for memory limits
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory statistics snapshot."""

    rss_bytes: int  # Resident Set Size (physical memory)
    vms_bytes: int  # Virtual Memory Size
    rss_mb: float  # RSS in megabytes
    vms_mb: float  # VMS in megabytes
    percent: float  # Memory usage as percentage of total


def get_memory_usage() -> MemoryStats:
    """Get current process memory usage.

    Returns:
        MemoryStats with current memory usage

    Raises:
        ImportError: If psutil is not available
    """
    try:
        import psutil
    except ImportError:
        raise ImportError(
            "psutil is required for memory monitoring. Install with: pip install psutil"
        ) from None

    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    mem_percent = process.memory_percent()

    return MemoryStats(
        rss_bytes=mem_info.rss,
        vms_bytes=mem_info.vms,
        rss_mb=mem_info.rss / 1024 / 1024,
        vms_mb=mem_info.vms / 1024 / 1024,
        percent=mem_percent,
    )


def log_memory_usage(prefix: str = "") -> None:
    """Log current memory usage.

    Args:
        prefix: Optional prefix for log message
    """
    try:
        stats = get_memory_usage()
        msg = f"Memory usage: RSS={stats.rss_mb:.1f}MB, VMS={stats.vms_mb:.1f}MB, {stats.percent:.1f}%"
        if prefix:
            msg = f"{prefix}: {msg}"
        logger.info(msg)
    except ImportError:
        logger.debug("Memory monitoring unavailable (psutil not installed)")
    except Exception as e:
        logger.warning(f"Failed to log memory usage: {e}")


class MemoryMonitor:
    """Monitor memory usage and trigger alerts/circuit breakers.

    Example:
        ```python
        monitor = MemoryMonitor(
            threshold_mb=1024,
            on_threshold_exceeded=lambda stats: print(f"Memory high: {stats.rss_mb}MB")
        )

        # Check memory periodically
        if monitor.check():
            print("Memory within limits")
        else:
            print("Memory limit exceeded!")
        ```
    """

    def __init__(
        self,
        threshold_mb: float = 1024.0,
        on_threshold_exceeded: Callable[[MemoryStats], None] | None = None,
        circuit_breaker: bool = False,
    ) -> None:
        """Initialize memory monitor.

        Args:
            threshold_mb: Memory threshold in megabytes (default 1024MB)
            on_threshold_exceeded: Optional callback when threshold exceeded
            circuit_breaker: If True, raises MemoryError when threshold exceeded
        """
        self._threshold_mb = threshold_mb
        self._on_threshold_exceeded = on_threshold_exceeded
        self._circuit_breaker = circuit_breaker
        self._exceeded_count = 0

    def check(self) -> bool:
        """Check if memory usage is within threshold.

        Returns:
            True if memory is within threshold, False otherwise

        Raises:
            MemoryError: If circuit_breaker is enabled and threshold exceeded
        """
        try:
            stats = get_memory_usage()

            if stats.rss_mb > self._threshold_mb:
                self._exceeded_count += 1
                logger.warning(
                    f"Memory threshold exceeded: {stats.rss_mb:.1f}MB > {self._threshold_mb:.1f}MB "
                    f"(count: {self._exceeded_count})"
                )

                # Call threshold callback
                if self._on_threshold_exceeded:
                    try:
                        self._on_threshold_exceeded(stats)
                    except Exception as e:
                        logger.exception(f"Error in threshold callback: {e}")

                # Circuit breaker
                if self._circuit_breaker:
                    raise MemoryError(
                        f"Memory limit exceeded: {stats.rss_mb:.1f}MB > {self._threshold_mb:.1f}MB"
                    )

                return False

            # Reset counter on successful check
            if self._exceeded_count > 0:
                logger.info(
                    f"Memory usage back within threshold: {stats.rss_mb:.1f}MB <= {self._threshold_mb:.1f}MB"
                )
                self._exceeded_count = 0

            return True

        except ImportError:
            logger.debug("Memory monitoring unavailable (psutil not installed)")
            return True
        except MemoryError:
            raise
        except Exception as e:
            logger.warning(f"Failed to check memory: {e}")
            return True

    def get_stats(self) -> MemoryStats | None:
        """Get current memory statistics.

        Returns:
            MemoryStats or None if unavailable
        """
        try:
            return get_memory_usage()
        except Exception as e:
            logger.debug(f"Failed to get memory stats: {e}")
            return None


class MemoryTracker:
    """Track memory usage over time for leak detection.

    Example:
        ```python
        tracker = MemoryTracker()
        tracker.snapshot("start")

        # ... do work ...

        tracker.snapshot("end")
        tracker.log_diff("start", "end")
        ```
    """

    def __init__(self) -> None:
        """Initialize memory tracker."""
        self._snapshots: dict[str, MemoryStats] = {}

    def snapshot(self, label: str) -> MemoryStats | None:
        """Take a memory snapshot with a label.

        Args:
            label: Label for this snapshot

        Returns:
            MemoryStats or None if unavailable
        """
        try:
            stats = get_memory_usage()
            self._snapshots[label] = stats
            logger.debug(f"Memory snapshot '{label}': {stats.rss_mb:.1f}MB")
            return stats
        except Exception as e:
            logger.debug(f"Failed to take snapshot '{label}': {e}")
            return None

    def get_diff(self, label1: str, label2: str) -> tuple[float, float] | None:
        """Get memory difference between two snapshots.

        Args:
            label1: First snapshot label
            label2: Second snapshot label

        Returns:
            Tuple of (rss_diff_mb, vms_diff_mb) or None if snapshots not found
        """
        if label1 not in self._snapshots or label2 not in self._snapshots:
            return None

        stats1 = self._snapshots[label1]
        stats2 = self._snapshots[label2]

        rss_diff = stats2.rss_mb - stats1.rss_mb
        vms_diff = stats2.vms_mb - stats1.vms_mb

        return rss_diff, vms_diff

    def log_diff(self, label1: str, label2: str) -> None:
        """Log memory difference between two snapshots.

        Args:
            label1: First snapshot label
            label2: Second snapshot label
        """
        diff = self.get_diff(label1, label2)
        if diff is None:
            logger.warning(f"Cannot compute diff: snapshots '{label1}' or '{label2}' not found")
            return

        rss_diff, vms_diff = diff
        logger.info(
            f"Memory diff ({label1} -> {label2}): RSS={rss_diff:+.1f}MB, VMS={vms_diff:+.1f}MB"
        )

    def clear(self) -> None:
        """Clear all snapshots."""
        self._snapshots.clear()
