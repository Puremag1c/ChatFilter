"""Tests for memory monitoring utilities.

Tests cover:
- MemoryStats: memory statistics dataclass
- get_memory_usage: current memory usage
- log_memory_usage: memory logging
- MemoryMonitor: threshold monitoring
- MemoryTracker: leak detection tracking
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from chatfilter.utils.memory import (
    MemoryMonitor,
    MemoryStats,
    MemoryTracker,
    get_memory_usage,
    log_memory_usage,
)


class TestMemoryStats:
    """Tests for MemoryStats dataclass."""

    def test_creation(self) -> None:
        """Should initialize with correct values."""
        stats = MemoryStats(
            rss_bytes=1024 * 1024 * 100,  # 100MB
            vms_bytes=1024 * 1024 * 200,  # 200MB
            rss_mb=100.0,
            vms_mb=200.0,
            percent=5.0,
        )

        assert stats.rss_bytes == 104857600
        assert stats.vms_bytes == 209715200
        assert stats.rss_mb == 100.0
        assert stats.vms_mb == 200.0
        assert stats.percent == 5.0


class TestGetMemoryUsage:
    """Tests for get_memory_usage function."""

    def test_returns_memory_stats(self) -> None:
        """Should return MemoryStats with current usage."""
        pytest.importorskip('psutil')
        # Test with real psutil since it's available
        result = get_memory_usage()

        assert isinstance(result, MemoryStats)
        assert result.rss_bytes > 0
        assert result.vms_bytes > 0
        assert result.rss_mb > 0
        assert result.vms_mb > 0
        assert result.percent >= 0

    def test_memory_values_consistent(self) -> None:
        """Memory values should be consistent (bytes = mb * 1024 * 1024)."""
        pytest.importorskip('psutil')
        result = get_memory_usage()

        # Check that MB values are derived from bytes correctly
        expected_rss_mb = result.rss_bytes / 1024 / 1024
        expected_vms_mb = result.vms_bytes / 1024 / 1024

        assert abs(result.rss_mb - expected_rss_mb) < 0.01
        assert abs(result.vms_mb - expected_vms_mb) < 0.01


class TestLogMemoryUsage:
    """Tests for log_memory_usage function."""

    def test_logs_memory(self) -> None:
        """Should log current memory usage."""
        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            mock_get.return_value = MemoryStats(
                rss_bytes=104857600,
                vms_bytes=209715200,
                rss_mb=100.0,
                vms_mb=200.0,
                percent=5.0,
            )

            with patch("chatfilter.utils.memory.logger") as mock_logger:
                log_memory_usage()

                mock_logger.info.assert_called_once()
                log_msg = mock_logger.info.call_args[0][0]
                assert "100.0MB" in log_msg

    def test_logs_with_prefix(self) -> None:
        """Should include prefix in log message."""
        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            mock_get.return_value = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=50.0,
                vms_mb=100.0,
                percent=2.0,
            )

            with patch("chatfilter.utils.memory.logger") as mock_logger:
                log_memory_usage(prefix="After task")

                log_msg = mock_logger.info.call_args[0][0]
                assert "After task" in log_msg


class TestMemoryMonitor:
    """Tests for MemoryMonitor class."""

    def test_initialization(self) -> None:
        """Should initialize with correct defaults."""
        monitor = MemoryMonitor()

        assert monitor._threshold_mb == 1024.0
        assert monitor._circuit_breaker is False
        assert monitor._exceeded_count == 0

    def test_custom_threshold(self) -> None:
        """Should accept custom threshold."""
        monitor = MemoryMonitor(threshold_mb=512.0)

        assert monitor._threshold_mb == 512.0

    def test_check_within_threshold(self) -> None:
        """Should return True when within threshold."""
        monitor = MemoryMonitor(threshold_mb=200.0)

        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            mock_get.return_value = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=100.0,  # Below 200MB threshold
                vms_mb=150.0,
                percent=5.0,
            )

            result = monitor.check()

            assert result is True

    def test_check_exceeds_threshold(self) -> None:
        """Should return False when threshold exceeded."""
        monitor = MemoryMonitor(threshold_mb=100.0)

        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            mock_get.return_value = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=150.0,  # Above 100MB threshold
                vms_mb=200.0,
                percent=10.0,
            )

            result = monitor.check()

            assert result is False
            assert monitor._exceeded_count == 1

    def test_circuit_breaker(self) -> None:
        """Should raise MemoryError when circuit breaker enabled."""
        monitor = MemoryMonitor(threshold_mb=100.0, circuit_breaker=True)

        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            mock_get.return_value = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=150.0,
                vms_mb=200.0,
                percent=10.0,
            )

            with pytest.raises(MemoryError):
                monitor.check()

    def test_threshold_callback(self) -> None:
        """Should call callback when threshold exceeded."""
        callback = MagicMock()
        monitor = MemoryMonitor(threshold_mb=100.0, on_threshold_exceeded=callback)

        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            stats = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=150.0,
                vms_mb=200.0,
                percent=10.0,
            )
            mock_get.return_value = stats

            monitor.check()

            callback.assert_called_once_with(stats)

    def test_get_stats(self) -> None:
        """Should return current memory stats."""
        monitor = MemoryMonitor()

        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            expected = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=100.0,
                vms_mb=200.0,
                percent=5.0,
            )
            mock_get.return_value = expected

            result = monitor.get_stats()

            assert result is expected


class TestMemoryTracker:
    """Tests for MemoryTracker class."""

    def test_initialization(self) -> None:
        """Should initialize with empty snapshots."""
        tracker = MemoryTracker()

        assert tracker._snapshots == {}

    def test_snapshot(self) -> None:
        """Should take and store snapshot."""
        tracker = MemoryTracker()

        with patch("chatfilter.utils.memory.get_memory_usage") as mock_get:
            expected = MemoryStats(
                rss_bytes=0,
                vms_bytes=0,
                rss_mb=100.0,
                vms_mb=200.0,
                percent=5.0,
            )
            mock_get.return_value = expected

            result = tracker.snapshot("test")

            assert result is expected
            assert "test" in tracker._snapshots

    def test_get_diff(self) -> None:
        """Should calculate memory difference."""
        tracker = MemoryTracker()

        # Store two snapshots manually
        tracker._snapshots["start"] = MemoryStats(
            rss_bytes=0,
            vms_bytes=0,
            rss_mb=100.0,
            vms_mb=200.0,
            percent=5.0,
        )
        tracker._snapshots["end"] = MemoryStats(
            rss_bytes=0,
            vms_bytes=0,
            rss_mb=150.0,
            vms_mb=250.0,
            percent=7.0,
        )

        result = tracker.get_diff("start", "end")

        assert result is not None
        rss_diff, vms_diff = result
        assert rss_diff == 50.0
        assert vms_diff == 50.0

    def test_get_diff_missing_snapshot(self) -> None:
        """Should return None if snapshot not found."""
        tracker = MemoryTracker()

        result = tracker.get_diff("start", "end")

        assert result is None

    def test_log_diff(self) -> None:
        """Should log memory difference."""
        tracker = MemoryTracker()

        tracker._snapshots["start"] = MemoryStats(
            rss_bytes=0, vms_bytes=0, rss_mb=100.0, vms_mb=200.0, percent=5.0
        )
        tracker._snapshots["end"] = MemoryStats(
            rss_bytes=0, vms_bytes=0, rss_mb=150.0, vms_mb=250.0, percent=7.0
        )

        with patch("chatfilter.utils.memory.logger") as mock_logger:
            tracker.log_diff("start", "end")

            mock_logger.info.assert_called_once()
            log_msg = mock_logger.info.call_args[0][0]
            assert "+50.0MB" in log_msg

    def test_clear(self) -> None:
        """Should clear all snapshots."""
        tracker = MemoryTracker()
        tracker._snapshots["test"] = MagicMock()

        tracker.clear()

        assert tracker._snapshots == {}
